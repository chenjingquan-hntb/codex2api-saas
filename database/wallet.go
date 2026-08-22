package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// 钱包账本服务。
//
// 权威约束（见 PLAN.md P6）：
//   - 金额一律为整数微元（1e-7 元），禁浮点，见 money.go；
//   - 余额不足直接拒绝，不允许透支；
//   - 请求前一次原子预留、成功后一次幂等结算、失败一次幂等释放；
//   - request_id/usage_log_id/订单号作为幂等键，重试/重复回调不得重复扣款；
//   - 第一版以 PostgreSQL 条件更新 + 事务为权威，Redis 只做缓存/锁。

type WalletTxType string

const (
	WalletTxRecharge   WalletTxType = "recharge"
	WalletTxConsume    WalletTxType = "consume"
	WalletTxReserve    WalletTxType = "reserve"
	WalletTxRelease    WalletTxType = "release"
	WalletTxRefund     WalletTxType = "refund"
	WalletTxRedeem     WalletTxType = "redeem"
	WalletTxAdjustment WalletTxType = "adjustment"
)

var (
	// ErrInsufficientBalance 表示可用余额不足，拒绝该操作（不透支）。
	ErrInsufficientBalance = errors.New("wallet: insufficient balance")
	// ErrInsufficientReserved 表示预留额度不足（释放/结算时预留已不存在）。
	ErrInsufficientReserved = errors.New("wallet: insufficient reserved")
	// ErrWalletAccountNotFound 表示钱包账户不存在（修复余额等操作）。
	ErrWalletAccountNotFound = errors.New("wallet: account not found")
	// errWalletReplay 是内部哨兵：表示幂等键已存在，本次为重放（应回滚事务）。
	errWalletReplay = errors.New("wallet: idempotent replay")
)

// WalletAccount 是单个用户的 CNY 钱包账户。
type WalletAccount struct {
	UserID         int64
	Currency       string
	AvailableMicro int64
	ReservedMicro  int64
	Version        int64
	UpdatedAt      time.Time
}

// WalletLedgerEntry 是不可变账本条目。
type WalletLedgerEntry struct {
	ID                 int64
	UserID             int64
	Type               WalletTxType
	AmountMicro        int64
	BalanceBeforeMicro int64
	BalanceAfterMicro  int64
	ReferenceType      string
	ReferenceID        string
	IdempotencyKey     string
	OperatorID         int64
	Reason             string
	CreatedAt          time.Time
}

// GetWalletAccount 读取钱包账户；不存在时返回 nil, nil（由调用方决定是否视为零余额）。
func (db *DB) GetWalletAccount(ctx context.Context, userID int64) (*WalletAccount, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT user_id, currency, available_micro, reserved_micro, version, updated_at
		FROM wallet_accounts
		WHERE user_id = $1`, userID)

	var acc WalletAccount
	var updatedRaw interface{}
	if err := row.Scan(&acc.UserID, &acc.Currency, &acc.AvailableMicro, &acc.ReservedMicro, &acc.Version, &updatedRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	acc.UpdatedAt = decodeTimeValue(updatedRaw)
	return &acc, nil
}

// WalletReserve 请求前原子预留：available -= X，reserved += X。
// 返回 replayed=true 表示该幂等键已处理过（未做任何变更）。
func (db *DB) WalletReserve(ctx context.Context, userID int64, amountMicro int64, refType, refID, idempotencyKey string) (bool, error) {
	if amountMicro <= 0 {
		return false, fmt.Errorf("wallet: reserve amount must be positive, got %d", amountMicro)
	}
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		return db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxReserve,
			AmountMicro:     -amountMicro,
			DeltaAvailable:  -amountMicro,
			DeltaReserved:   amountMicro,
			RefType:         refType,
			RefID:           refID,
			IdempotencyKey:  idempotencyKey,
			InsufficientErr: ErrInsufficientBalance,
		})
	})
	return walletResult(err)
}

// WalletRelease 失败/超时/客户端中止时释放预留：available += X，reserved -= X。
func (db *DB) WalletRelease(ctx context.Context, userID int64, amountMicro int64, refType, refID, idempotencyKey string) (bool, error) {
	if amountMicro <= 0 {
		return false, fmt.Errorf("wallet: release amount must be positive, got %d", amountMicro)
	}
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		return db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxRelease,
			AmountMicro:     amountMicro,
			DeltaAvailable:  amountMicro,
			DeltaReserved:   -amountMicro,
			RefType:         refType,
			RefID:           refID,
			IdempotencyKey:  idempotencyKey,
			InsufficientErr: ErrInsufficientReserved,
		})
	})
	return walletResult(err)
}

// WalletSettle 请求成功后按实际 usage 幂等结算：先释放全部预留 X，再扣实际费用 Y。
// 多退少补：Y<X 时差额退回 available；Y>X 时多扣部分从 available 扣除（仍不允许透支）。
// 结算产生两条账本条目（release + consume），共用同一个业务幂等键（内部加命名空间）。
func (db *DB) WalletSettle(ctx context.Context, userID int64, reservedMicro int64, actualMicro int64, refType, refID, idempotencyKey string) (bool, error) {
	if reservedMicro <= 0 {
		return false, fmt.Errorf("wallet: reserved amount must be positive, got %d", reservedMicro)
	}
	if actualMicro < 0 {
		return false, fmt.Errorf("wallet: actual amount must be non-negative, got %d", actualMicro)
	}
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		// 1) 释放预留（available += X，reserved -= X）。
		if err := db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxRelease,
			AmountMicro:     reservedMicro,
			DeltaAvailable:  reservedMicro,
			DeltaReserved:   -reservedMicro,
			RefType:         refType,
			RefID:           refID,
			IdempotencyKey:  "rel:" + idempotencyKey,
			InsufficientErr: ErrInsufficientReserved,
		}); err != nil {
			return err
		}

		// 2) 扣实际费用（available -= Y）。
		return db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxConsume,
			AmountMicro:     -actualMicro,
			DeltaAvailable:  -actualMicro,
			DeltaReserved:   0,
			RefType:         refType,
			RefID:           refID,
			IdempotencyKey:  "cns:" + idempotencyKey,
			InsufficientErr: ErrInsufficientBalance,
		})
	})
	return walletResult(err)
}

// WalletCredit 入账（recharge/redeem/refund/adjustment）。amountMicro 可为负
// （例如管理员冲正扣减）；正数增加 available，负数扣减 available。
func (db *DB) WalletCredit(ctx context.Context, userID int64, amountMicro int64, typ WalletTxType, refType, refID, idempotencyKey string, operatorID int64, reason string) (bool, error) {
	if amountMicro == 0 {
		return false, fmt.Errorf("wallet: credit amount must be non-zero")
	}
	switch typ {
	case WalletTxRecharge, WalletTxRedeem, WalletTxRefund, WalletTxAdjustment:
	default:
		return false, fmt.Errorf("wallet: invalid credit type %q", typ)
	}
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		return db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            typ,
			AmountMicro:     amountMicro,
			DeltaAvailable:  amountMicro,
			DeltaReserved:   0,
			RefType:         refType,
			RefID:           refID,
			IdempotencyKey:  idempotencyKey,
			OperatorID:      operatorID,
			Reason:          reason,
			InsufficientErr: ErrInsufficientBalance,
		})
	})
	return walletResult(err)
}

// ListWalletLedger 分页读取用户的账本流水（按创建时间倒序）。
func (db *DB) ListWalletLedger(ctx context.Context, userID int64, limit, offset int) ([]WalletLedgerEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, user_id, type, amount_micro, balance_before_micro, balance_after_micro,
		       reference_type, reference_id, idempotency_key, operator_id, reason, created_at
		FROM wallet_ledger_entries
		WHERE user_id = $1
		ORDER BY id DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]WalletLedgerEntry, 0, limit)
	for rows.Next() {
		var e WalletLedgerEntry
		var typeRaw string
		var createdRaw interface{}
		if err := rows.Scan(
			&e.ID, &e.UserID, &typeRaw, &e.AmountMicro, &e.BalanceBeforeMicro, &e.BalanceAfterMicro,
			&e.ReferenceType, &e.ReferenceID, &e.IdempotencyKey, &e.OperatorID, &e.Reason, &createdRaw,
		); err != nil {
			return nil, err
		}
		e.Type = WalletTxType(typeRaw)
		e.CreatedAt = decodeTimeValue(createdRaw)
		out = append(out, e)
	}
	return out, rows.Err()
}

// walletApply 是一次原子钱包变动的参数集合。
type walletApply struct {
	UserID          int64
	Type            WalletTxType
	AmountMicro     int64 // 账本记录的带符号金额（available 变动）
	DeltaAvailable  int64 // available 变动
	DeltaReserved   int64 // reserved 变动
	RefType         string
	RefID           string
	IdempotencyKey  string
	OperatorID      int64
	Reason          string
	InsufficientErr error
}

// walletApplyTx 在给定事务内施加一次钱包变动并写一条不可变账本。
//
// 幂等实现：先条件更新余额，再以 (user_id, idempotency_key) 唯一约束插入账本；
// 若键已存在（RowsAffected==0）说明是重放，返回 errWalletReplay，由 withWriteTx
// 回滚本次事务撤销刚做的余额变动，从而保证重放绝不重复扣款。
// 幂等键按用户维度唯一（复合唯一索引），同一键在不同用户下互不冲突。
func (db *DB) walletApplyTx(ctx context.Context, tx *sql.Tx, a walletApply) error {
	// 先查幂等键：已存在则直接判定为重放，避免在余额已被上次操作变更后
	// 触发“余额/预留不足”误判。并发竞争仍由下面的唯一约束 + 回滚兜底。
	var one int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM wallet_ledger_entries WHERE user_id = $1 AND idempotency_key = $2`,
		a.UserID, a.IdempotencyKey).Scan(&one)
	switch {
	case err == nil:
		return errWalletReplay
	case errors.Is(err, sql.ErrNoRows):
		// 继续
	default:
		return err
	}

	if err := db.ensureWalletAccountTx(ctx, tx, a.UserID); err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE wallet_accounts
		SET available_micro = available_micro + $1,
		    reserved_micro  = reserved_micro + $2,
		    version         = version + 1,
		    updated_at      = $3
		WHERE user_id = $4
		  AND available_micro + $1 >= 0
		  AND reserved_micro  + $2 >= 0`,
		a.DeltaAvailable, a.DeltaReserved, db.timeArg(time.Now().UTC()), a.UserID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return a.InsufficientErr
	}

	var availableMicro, reservedMicro int64
	if err := tx.QueryRowContext(ctx, `
		SELECT available_micro, reserved_micro FROM wallet_accounts WHERE user_id = $1`, a.UserID).
		Scan(&availableMicro, &reservedMicro); err != nil {
		return err
	}

	balanceBefore := availableMicro - a.DeltaAvailable
	balanceAfter := availableMicro

	ins, err := tx.ExecContext(ctx, `
		INSERT INTO wallet_ledger_entries
			(user_id, type, amount_micro, balance_before_micro, balance_after_micro,
			 reference_type, reference_id, idempotency_key, operator_id, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id, idempotency_key) DO NOTHING`,
		a.UserID, string(a.Type), a.AmountMicro, balanceBefore, balanceAfter,
		a.RefType, a.RefID, a.IdempotencyKey, a.OperatorID, a.Reason)
	if err != nil {
		return err
	}
	insN, err := ins.RowsAffected()
	if err != nil {
		return err
	}
	if insN == 0 {
		// 幂等键已存在 → 重放。返回哨兵让 withWriteTx 回滚，撤销上面的余额变动。
		return errWalletReplay
	}
	return nil
}

// walletResult 把内部哨兵错误映射为对外幂等语义。
func walletResult(err error) (bool, error) {
	if errors.Is(err, errWalletReplay) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// ensureWalletAccountTx 幂等创建钱包账户（不存在时插入零余额账户）。
func (db *DB) ensureWalletAccountTx(ctx context.Context, tx *sql.Tx, userID int64) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO wallet_accounts (user_id, currency, available_micro, reserved_micro)
		VALUES ($1, 'CNY', 0, 0)
		ON CONFLICT (user_id) DO NOTHING`, userID)
	return err
}

// ReconcileOrphanedWalletReservations 释放「孤儿预留」：超过 olderThan 仍没有对应
// release/consume（结算或释放）的 reserve 条目。
//
// 背景：数据面在请求开始预留、请求收尾结算/释放；若进程在预留后崩溃、或收尾时
// 钱包 DB 持续故障，reserved_micro 会永久占用、available 永久减少。本函数按
// reference_type='request' + reference_id 配对，找出未收尾的预留并整批恢复。
// 恢复动作本身也是一条 release 账本（refType=orphan_recovery，幂等键 recover:<id>），
// 保持账本可重算与不变量；重复对账由幂等键哨兵幂等跳过。
// limit 限制单批处理条数（防一次扫全表）；返回恢复条数与释放的微元总数。
func (db *DB) ReconcileOrphanedWalletReservations(ctx context.Context, olderThan time.Duration, limit int) (int, int64, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if olderThan <= 0 {
		olderThan = 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-olderThan)

	var recovered int
	var recoveredMicro int64
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT l.id, l.user_id, l.amount_micro
			FROM wallet_ledger_entries l
			WHERE l.type = 'reserve'
			  AND l.reference_type = 'request'
			  AND l.created_at < $1
			  AND NOT EXISTS (
				SELECT 1 FROM wallet_settlement_intents si
				WHERE si.user_id = l.user_id
				  AND si.reference_type = l.reference_type
				  AND si.reference_id = l.reference_id
			  )
			  AND NOT EXISTS (
				SELECT 1 FROM wallet_ledger_entries p
				WHERE p.type IN ('release', 'consume')
				  AND (
					(p.reference_type = l.reference_type AND p.reference_id = l.reference_id)
					OR (p.reference_type = 'orphan_recovery' AND p.reference_id = CAST(l.id AS TEXT))
				  )
			  )
			LIMIT $2`, db.timeArg(cutoff), limit)
		if err != nil {
			return err
		}
		type orphan struct {
			id, userID  int64
			amountMicro int64 // 账本里的 reserve 金额为负
		}
		var orphans []orphan
		for rows.Next() {
			var o orphan
			if err := rows.Scan(&o.id, &o.userID, &o.amountMicro); err != nil {
				rows.Close()
				return err
			}
			orphans = append(orphans, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, o := range orphans {
			amount := -o.amountMicro // reserve 记负额，恢复为正向释放
			if amount <= 0 {
				continue
			}
			// 复用统一 walletApplyTx：条件更新 + 账本不变量 + 幂等键兜底。
			if err := db.walletApplyTx(ctx, tx, walletApply{
				UserID:          o.userID,
				Type:            WalletTxRelease,
				AmountMicro:     amount,
				DeltaAvailable:  amount,
				DeltaReserved:   -amount,
				RefType:         "orphan_recovery",
				RefID:           strconv.FormatInt(o.id, 10),
				IdempotencyKey:  "recover:" + strconv.FormatInt(o.id, 10),
				InsufficientErr: ErrInsufficientReserved,
				Reason:          "orphan reservation auto-recovered",
			}); err != nil {
				// 已被并发对账处理（幂等重放）则跳过；其余错误终止本轮（整批回滚重试）。
				if errors.Is(err, errWalletReplay) {
					continue
				}
				return err
			}
			recovered++
			recoveredMicro += amount
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return recovered, recoveredMicro, nil
}

// decodeTimeValue 把数据库返回的时间值解码为 time.Time（兼容 SQLite 字符串与 PG time.Time）。
func decodeTimeValue(raw interface{}) time.Time {
	switch v := raw.(type) {
	case time.Time:
		return v
	case *time.Time:
		if v != nil {
			return *v
		}
	case string:
		t, err := parseDBTimeValue(v)
		if err == nil {
			return t
		}
	case []byte:
		t, err := parseDBTimeValue(string(v))
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

// ==================== 管理员：对账看板 / 账本重算（P6 收尾） ====================

// PaymentSummary 是管理员对账看板的聚合指标。
type PaymentSummary struct {
	TodayPaidCount   int64            `json:"today_paid_count"`   // 今日（UTC 日界）已入账订单数
	TodayPaidMicro   int64            `json:"today_paid_micro"`   // 今日已入账金额（微元）
	WeekPaidMicro    int64            `json:"week_paid_micro"`    // 近 7 日已入账金额
	TotalPaidMicro   int64            `json:"total_paid_micro"`   // 累计已入账金额
	StatusCounts     map[string]int64 `json:"status_counts"`      // 各状态订单数
	PendingExpiring  int64            `json:"pending_expiring"`   // pending 且 1 小时内过期（待跟进）
	RefundedCount    int64            `json:"refunded_count"`     // 退款订单数
	RefundedMicro    int64            `json:"refunded_micro"`     // 退款总额（微元，正值）
	AdjustmentCount  int64            `json:"adjustment_count"`   // 余额调整次数
	LedgerEntryCount int64            `json:"ledger_entry_count"` // 账本总条数
}

// GetPaymentSummary 汇总充值/退款/调整的对账指标。
func (db *DB) GetPaymentSummary(ctx context.Context) (*PaymentSummary, error) {
	s := &PaymentSummary{StatusCounts: make(map[string]int64)}
	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	weekAgo := now.Add(-7 * 24 * time.Hour)
	expiringSoon := now.Add(time.Hour)

	// 订单状态计数。
	rows, err := db.conn.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM wallet_transactions GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("wallet: summary status counts: %w", err)
	}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return nil, err
		}
		s.StatusCounts[status] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 入账金额聚合。
	type aggRow struct {
		cnt, micro int64
	}
	scanAgg := func(q string, args ...interface{}) (aggRow, error) {
		var a aggRow
		if err := db.conn.QueryRowContext(ctx, q, args...).Scan(&a.cnt, &a.micro); err != nil {
			return a, err
		}
		return a, nil
	}
	if a, err := scanAgg(`SELECT COUNT(*), COALESCE(SUM(amount_micro),0) FROM wallet_transactions
		WHERE status = $1 AND created_at >= $2`, RechargeOrderStatusPaid, db.timeArg(todayStart)); err != nil {
		return nil, err
	} else {
		s.TodayPaidCount, s.TodayPaidMicro = a.cnt, a.micro
	}
	if a, err := scanAgg(`SELECT COUNT(*), COALESCE(SUM(amount_micro),0) FROM wallet_transactions
		WHERE status = $1 AND created_at >= $2`, RechargeOrderStatusPaid, db.timeArg(weekAgo)); err != nil {
		return nil, err
	} else {
		s.WeekPaidMicro = a.micro
	}
	if a, err := scanAgg(`SELECT COUNT(*), COALESCE(SUM(amount_micro),0) FROM wallet_transactions
		WHERE status = $1`, RechargeOrderStatusPaid); err != nil {
		return nil, err
	} else {
		s.TotalPaidMicro = a.micro
	}
	// pending 且即将过期（含无过期时间的视为不紧急，只统计有 expires_at 的）。
	if err := db.conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM wallet_transactions
		WHERE status = $1 AND expires_at IS NOT NULL AND expires_at < $2`,
		RechargeOrderStatusPending, db.timeArg(expiringSoon)).Scan(&s.PendingExpiring); err != nil {
		return nil, err
	}

	// 退款（订单 status=refunded + 账本 refund 双口径核对）。
	if a, err := scanAgg(`SELECT COUNT(*), COALESCE(SUM(amount_micro),0) FROM wallet_transactions
		WHERE status = $1`, RechargeOrderStatusRefunded); err != nil {
		return nil, err
	} else {
		s.RefundedCount, s.RefundedMicro = a.cnt, a.micro
	}
	// 余额调整次数（账本）。
	if err := db.conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM wallet_ledger_entries WHERE type = $1`,
		string(WalletTxAdjustment)).Scan(&s.AdjustmentCount); err != nil {
		return nil, err
	}
	// 账本总条数。
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_ledger_entries`).Scan(&s.LedgerEntryCount); err != nil {
		return nil, err
	}
	return s, nil
}

// BalanceDrift 是账本重算发现的余额差异条目。
type BalanceDrift struct {
	UserID        int64  `json:"user_id"`
	Email         string `json:"email"`
	ExpectedMicro int64  `json:"expected_micro"` // 账本流水重算值
	ActualMicro   int64  `json:"actual_micro"`   // wallet_accounts 当前值
	ReservedMicro int64  `json:"reserved_micro"` // 修复前 reserved 快照
	Version       int64  `json:"version"`        // 修复前版本快照
	DiffMicro     int64  `json:"diff_micro"`     // expected - actual（>0 表示少记/被多扣）
}

// ReconcileWalletBalances 对比「账本流水重算余额」与「钱包账户当前余额」，
// 返回全部差异（无差异时为空列表）。账本 amount_micro 记录的是 available 变动，
// 故期望余额 = SUM(amount_micro)。reserved 不参与重算（预留/释放自身即成对账目）。
func (db *DB) ReconcileWalletBalances(ctx context.Context) ([]BalanceDrift, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT wa.user_id, COALESCE(wa.available_micro, 0),
               COALESCE(wa.reserved_micro, 0), COALESCE(wa.version, 0),
               COALESCE(SUM(l.amount_micro), 0), COALESCE(u.email, '')
		FROM wallet_accounts wa
		LEFT JOIN wallet_ledger_entries l ON l.user_id = wa.user_id
		LEFT JOIN users u ON u.id = wa.user_id
		GROUP BY wa.user_id, wa.available_micro, wa.reserved_micro, wa.version, u.email
		ORDER BY wa.user_id`)
	if err != nil {
		return nil, fmt.Errorf("wallet: reconcile: %w", err)
	}
	defer rows.Close()
	var drifts []BalanceDrift
	for rows.Next() {
		var d BalanceDrift
		if err := rows.Scan(&d.UserID, &d.ActualMicro, &d.ReservedMicro, &d.Version, &d.ExpectedMicro, &d.Email); err != nil {
			return nil, err
		}
		d.DiffMicro = d.ExpectedMicro - d.ActualMicro
		if d.DiffMicro != 0 {
			drifts = append(drifts, d)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return drifts, nil
}

// FixWalletBalanceIfUnchanged 仅在对账快照仍然有效时修复余额。
// 账本是权威，但不能用旧快照覆盖并发中的正常充值/扣费；version、available、reserved
// 三重条件保证修复与财务写入不会互相踩踏。返回 false 表示快照已过期。
func (db *DB) FixWalletBalanceIfUnchanged(ctx context.Context, drift BalanceDrift) (bool, error) {
	if drift.UserID <= 0 {
		return false, fmt.Errorf("wallet: fix balance: invalid user")
	}
	if drift.ExpectedMicro < 0 {
		return false, fmt.Errorf("wallet: fix balance: expected must be non-negative, got %d", drift.ExpectedMicro)
	}
	res, err := db.conn.ExecContext(ctx, `UPDATE wallet_accounts SET available_micro = $1, version = version + 1, updated_at = $2 WHERE user_id = $3 AND available_micro = $4 AND reserved_micro = $5 AND version = $6`, drift.ExpectedMicro, db.timeArg(time.Now().UTC()), drift.UserID, drift.ActualMicro, drift.ReservedMicro, drift.Version)
	if err != nil {
		return false, fmt.Errorf("wallet: fix balance: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// FixWalletBalance 把指定钱包账户的 available 修复为账本重算值（管理员操作）。
// 直接更新余额、不写账本：账本是权威，重算值即期望值，写账本反而引入新一轮漂移。
func (db *DB) FixWalletBalance(ctx context.Context, userID, expectedMicro int64) error {
	if userID <= 0 {
		return fmt.Errorf("wallet: fix balance: invalid user")
	}
	if expectedMicro < 0 {
		return fmt.Errorf("wallet: fix balance: expected must be non-negative, got %d", expectedMicro)
	}
	res, err := db.conn.ExecContext(ctx, `
		UPDATE wallet_accounts
		SET available_micro = $1, version = version + 1, updated_at = $2
		WHERE user_id = $3`,
		expectedMicro, db.timeArg(time.Now().UTC()), userID)
	if err != nil {
		return fmt.Errorf("wallet: fix balance: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrWalletAccountNotFound
	}
	return nil
}

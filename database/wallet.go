package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
// 幂等实现：先条件更新余额，再以 idempotency_key 唯一约束插入账本；若键已存在
// （RowsAffected==0）说明是重放，返回 errWalletReplay，由 withWriteTx 回滚本次
// 事务撤销刚做的余额变动，从而保证重放绝不重复扣款。
func (db *DB) walletApplyTx(ctx context.Context, tx *sql.Tx, a walletApply) error {
	// 先查幂等键：已存在则直接判定为重放，避免在余额已被上次操作变更后
	// 触发“余额/预留不足”误判。并发竞争仍由下面的唯一约束 + 回滚兜底。
	var one int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM wallet_ledger_entries WHERE idempotency_key = $1`, a.IdempotencyKey).Scan(&one)
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
		ON CONFLICT (idempotency_key) DO NOTHING`,
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

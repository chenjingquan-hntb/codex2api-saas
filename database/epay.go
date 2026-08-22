package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 充值订单（P6 易支付）。
//
// 一致性约束（与 PLAN.md P6 对齐）：
//   - order_no 全局唯一；同一订单只允许入账一次；
//   - 回调入账在单事务内完成：读订单 → 校验金额 → 写钱包账本（幂等键
//     epay:<order_no>，复合唯一 (user_id, idempotency_key)）→ 标记订单 paid；
//   - 重复回调（网关重试 / 并发）返回 replayed=true，绝不重复加钱；
//   - 浏览器同步跳转（return）不是入账依据，仅用于前端轮询订单状态；
//   - 入账不依赖 FOR UPDATE：并发由账本幂等键 + 条件更新兜底（PG 复合唯一
//     约束回滚竞态事务，SQLite 由 withSQLiteWriteLock 串行化写事务）。

// 充值订单状态。
const (
	RechargeOrderStatusPending   = "pending"
	RechargeOrderStatusPaid      = "paid"
	RechargeOrderStatusExpired   = "expired"
	RechargeOrderStatusCancelled = "cancelled"
	RechargeOrderStatusRefunded  = "refunded"
)

var (
	// ErrEpayOrderNotFound 表示回调订单号不存在。
	ErrEpayOrderNotFound = errors.New("epay: order not found")
	// ErrEpayOrderClosed 表示订单已取消（不再接受入账）。
	ErrEpayOrderClosed = errors.New("epay: order closed")
	// ErrEpayAmountMismatch 表示回调金额与订单金额不一致。
	ErrEpayAmountMismatch = errors.New("epay: callback amount mismatch")
	// ErrEpayOrderNotPaid 表示订单尚未入账（pending/expired/cancelled 不能退款）。
	ErrEpayOrderNotPaid = errors.New("epay: order not paid")
	// ErrEpayRefundAlreadyDone 表示该订单已退款（重放，幂等语义）。
	ErrEpayRefundAlreadyDone = errors.New("epay: refund already done")
)

// RechargeOrder 是充值订单记录（wallet_transactions）。
type RechargeOrder struct {
	ID              int64
	UserID          int64
	OrderNo         string
	Channel         string
	AmountMicro     int64
	Status          string
	PayURL          string
	CallbackPayload string
	VerifiedAt      *time.Time
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const rechargeOrderSelectColumns = `
	id, user_id, order_no, channel, amount_micro, status, pay_url,
	callback_payload, verified_at, expires_at, created_at, updated_at`

func scanRechargeOrder(row interface{ Scan(...any) error }) (*RechargeOrder, error) {
	var o RechargeOrder
	var verifiedRaw, expiresRaw, createdRaw, updatedRaw interface{}
	if err := row.Scan(&o.ID, &o.UserID, &o.OrderNo, &o.Channel, &o.AmountMicro,
		&o.Status, &o.PayURL, &o.CallbackPayload, &verifiedRaw, &expiresRaw,
		&createdRaw, &updatedRaw); err != nil {
		return nil, err
	}
	if t, ok := optionalTimeValue(verifiedRaw); ok {
		o.VerifiedAt = &t
	}
	if t, ok := optionalTimeValue(expiresRaw); ok {
		o.ExpiresAt = &t
	}
	o.CreatedAt = decodeTimeValue(createdRaw)
	o.UpdatedAt = decodeTimeValue(updatedRaw)
	return &o, nil
}

// optionalTimeValue 把 NULL 兼容的时间值解码为 (time, true)，NULL 返回 (_, false)。
func optionalTimeValue(raw interface{}) (time.Time, bool) {	switch v := raw.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return v, true
	case *time.Time:
		if v != nil {
			return *v, true
		}
		return time.Time{}, false
	case string:
		t, err := parseDBTimeValue(v)
		if err == nil {
			return t, true
		}
	case []byte:
		t, err := parseDBTimeValue(string(v))
		if err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// CreateRechargeOrder 创建一笔待支付充值订单。orderNo 由调用方生成（全局唯一）。
// expiresAt 为支付截止时间（<=now 视为永不过期，一般应传未来时间）。
func (db *DB) CreateRechargeOrder(ctx context.Context, userID int64, orderNo, channel string, amountMicro int64, payURL string, expiresAt time.Time) (*RechargeOrder, error) {
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return nil, fmt.Errorf("epay: order_no is required")
	}
	channel = strings.TrimSpace(channel)
	if channel == "" {
		channel = "epay"
	}
	if amountMicro <= 0 {
		return nil, fmt.Errorf("epay: amount must be positive, got %d", amountMicro)
	}
	now := time.Now().UTC()
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO wallet_transactions
			(user_id, order_no, channel, amount_micro, status, pay_url, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		userID, orderNo, channel, amountMicro, RechargeOrderStatusPending, payURL,
		db.timeArg(expiresAt), db.timeArg(now), db.timeArg(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("epay: order_no %q already exists", orderNo)
		}
		return nil, err
	}
	return &RechargeOrder{
		UserID:      userID,
		OrderNo:     orderNo,
		Channel:     channel,
		AmountMicro: amountMicro,
		Status:      RechargeOrderStatusPending,
		PayURL:      payURL,
		ExpiresAt:   &expiresAt,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// GetRechargeOrder 按用户 + 订单号读取（用户侧 API 用，防止跨用户查询）。
// 不存在时返回 nil, nil。
func (db *DB) GetRechargeOrder(ctx context.Context, userID int64, orderNo string) (*RechargeOrder, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT `+rechargeOrderSelectColumns+`
		FROM wallet_transactions
		WHERE user_id = $1 AND order_no = $2`, userID, orderNo)
	o, err := scanRechargeOrder(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// GetRechargeOrderByOrderNo 按订单号读取（支付回调用，不限定用户）。
// 不存在时返回 nil, nil。
func (db *DB) GetRechargeOrderByOrderNo(ctx context.Context, orderNo string) (*RechargeOrder, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT `+rechargeOrderSelectColumns+`
		FROM wallet_transactions
		WHERE order_no = $1`, orderNo)
	o, err := scanRechargeOrder(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// ListRechargeOrders 分页读取用户充值订单（创建时间倒序）。
func (db *DB) ListRechargeOrders(ctx context.Context, userID int64, limit, offset int) ([]RechargeOrder, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT `+rechargeOrderSelectColumns+`
		FROM wallet_transactions
		WHERE user_id = $1
		ORDER BY id DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orders []RechargeOrder
	for rows.Next() {
		o, err := scanRechargeOrder(rows)
		if err != nil {
			return nil, err
		}
		orders = append(orders, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return orders, nil
}

// CreditEpayCallback 在支付回调验证通过后原子入账：
//   - 订单不存在 → ErrEpayOrderNotFound；
//   - 订单已 paid → replayed=true（重复回调，不重复加钱）；
//   - 订单已取消 → ErrEpayOrderClosed；
//   - 回调金额与订单金额不一致 → ErrEpayAmountMismatch；
//   - 校验通过：同一事务内 WalletCredit（幂等键 epay:<order_no>）+ 标记订单 paid。
//
// 返回 replayed=true 表示该订单已处理过（本次未做任何余额变动）。
func (db *DB) CreditEpayCallback(ctx context.Context, orderNo, callbackPayload string, amountMicro int64) (bool, error) {
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return false, fmt.Errorf("epay: order_no is required")
	}
	replayed := false
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		var userID, orderAmount int64
		var status string
		err := tx.QueryRowContext(ctx, `
			SELECT user_id, amount_micro, status
			FROM wallet_transactions
			WHERE order_no = $1`, orderNo).Scan(&userID, &orderAmount, &status)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEpayOrderNotFound
			}
			return err
		}
		switch status {
		case RechargeOrderStatusPaid:
			replayed = true
			return nil
		case RechargeOrderStatusCancelled:
			return ErrEpayOrderClosed
		}
		if amountMicro != orderAmount {
			return ErrEpayAmountMismatch
		}
		// 入账：账本幂等键 epay:<order_no> 兜底并发/崩溃重放。
		if err := db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxRecharge,
			AmountMicro:     amountMicro,
			DeltaAvailable:  amountMicro,
			DeltaReserved:   0,
			RefType:         "epay_order",
			RefID:           orderNo,
			IdempotencyKey:  "epay:" + orderNo,
			Reason:          "epay callback verified",
			InsufficientErr: ErrInsufficientBalance,
		}); err != nil {
			if errors.Is(err, errWalletReplay) {
				replayed = true
				return nil
			}
			return err
		}
		now := db.timeArg(time.Now().UTC())
		if _, err := tx.ExecContext(ctx, `
			UPDATE wallet_transactions
			SET status = $1, callback_payload = $2, verified_at = $3, updated_at = $4
			WHERE order_no = $5`,
			RechargeOrderStatusPaid, callbackPayload, now, now, orderNo); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return replayed, nil
}

// ExpireStaleRechargeOrders 把「已过支付截止时间且仍为 pending」的订单批量标记为
// expired（对账/清理用）。返回本次更新的订单数。
func (db *DB) ExpireStaleRechargeOrders(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	cutoff := time.Now().UTC().Add(-grace)
	// PG 不支持 UPDATE ... LIMIT；统一用子查询取前 N 个 id，PG/SQLite 通用。
	res, err := db.conn.ExecContext(ctx, `
		UPDATE wallet_transactions
		SET status = $1, updated_at = $2
		WHERE id IN (
			SELECT id FROM wallet_transactions
			WHERE status = $3
			  AND expires_at IS NOT NULL
			  AND expires_at < $4
			LIMIT $5
		)`,
		RechargeOrderStatusExpired, db.timeArg(time.Now().UTC()),
		RechargeOrderStatusPending, db.timeArg(cutoff), limit)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// ==================== 管理员：订单管理 / 冲正（P6 收尾） ====================

// RechargeOrderWithUser 是管理员视图的充值订单（附带用户邮箱）。
type RechargeOrderWithUser struct {
	RechargeOrder
	Email string
}

// RechargeOrderFilter 是管理员订单列表的过滤条件（全部可选）。
type RechargeOrderFilter struct {
	OrderNo string // 精确匹配
	Email   string // 精确匹配用户邮箱
	Status  string // 空=全部
	UserID  int64  // >0 时按用户过滤
}

// ListAllRechargeOrders 跨用户分页列出充值订单（管理员），JOIN 用户邮箱。
func (db *DB) ListAllRechargeOrders(ctx context.Context, f RechargeOrderFilter, limit, offset int) ([]RechargeOrderWithUser, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT t.id, t.user_id, t.order_no, t.channel, t.amount_micro, t.status, t.pay_url,
	             t.callback_payload, t.verified_at, t.expires_at, t.created_at, t.updated_at, u.email
	      FROM wallet_transactions t
	      JOIN users u ON u.id = t.user_id
	      WHERE 1 = 1`
	var args []interface{}
	add := func(cond string, val interface{}) {
		args = append(args, val)
		q += fmt.Sprintf(" AND %s = $%d", cond, len(args))
	}
	if f.OrderNo != "" {
		add("t.order_no", f.OrderNo)
	}
	if f.Email != "" {
		add("u.email", f.Email)
	}
	if f.Status != "" {
		add("t.status", f.Status)
	}
	if f.UserID > 0 {
		add("t.user_id", f.UserID)
	}
	args = append(args, limit, offset)
	q += fmt.Sprintf(" ORDER BY t.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("epay: list all orders: %w", err)
	}
	defer rows.Close()

	out := make([]RechargeOrderWithUser, 0, limit)
	for rows.Next() {
		var o RechargeOrderWithUser
		var verifiedRaw, expiresRaw, createdRaw, updatedRaw interface{}
		if err := rows.Scan(
			&o.ID, &o.UserID, &o.OrderNo, &o.Channel, &o.AmountMicro, &o.Status, &o.PayURL,
			&o.CallbackPayload, &verifiedRaw, &expiresRaw, &createdRaw, &updatedRaw, &o.Email,
		); err != nil {
			return nil, err
		}
		if t, ok := optionalTimeValue(verifiedRaw); ok {
			o.VerifiedAt = &t
		}
		if t, ok := optionalTimeValue(expiresRaw); ok {
			o.ExpiresAt = &t
		}
		o.CreatedAt = decodeTimeValue(createdRaw)
		o.UpdatedAt = decodeTimeValue(updatedRaw)
		out = append(out, o)
	}
	return out, rows.Err()
}

// RefundRechargeOrder 对已入账订单做整单退款冲正（管理员）。
//
// 单事务语义（与充值回调同构）：
//   - 只允许 refund paid 订单；pending/expired/cancelled 拒绝（ErrEpayOrderNotPaid）；
//   - 幂等键 admin_refund:<order_no>：重复退款返回 replayed=true，绝不重复扣款；
//   - 从 available 扣回订单金额（不允许透支：用户已花掉的部分无法退回，
//     管理员需先用 balance adjustment 处理，保持 fail-closed 不透支）；
//   - 成功后订单状态置 refunded，账本记 type=refund 反向条目。
func (db *DB) RefundRechargeOrder(ctx context.Context, orderNo string, operatorID int64, reason string) (bool, error) {
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return false, fmt.Errorf("epay: order_no is required")
	}
	replayed := false
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		var userID, amountMicro int64
		var status string
		err := tx.QueryRowContext(ctx, `
			SELECT user_id, amount_micro, status
			FROM wallet_transactions
			WHERE order_no = $1`, orderNo).Scan(&userID, &amountMicro, &status)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEpayOrderNotFound
			}
			return err
		}
		switch status {
		case RechargeOrderStatusRefunded:
			replayed = true
			return nil
		case RechargeOrderStatusPaid:
			// 继续
		default:
			return ErrEpayOrderNotPaid
		}
		if err := db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxRefund,
			AmountMicro:     -amountMicro,
			DeltaAvailable:  -amountMicro,
			DeltaReserved:   0,
			RefType:         "epay_refund",
			RefID:           orderNo,
			IdempotencyKey:  "admin_refund:" + orderNo,
			OperatorID:      operatorID,
			Reason:          reason,
			InsufficientErr: ErrInsufficientBalance,
		}); err != nil {
			if errors.Is(err, errWalletReplay) {
				replayed = true
				return nil
			}
			return err
		}
		now := db.timeArg(time.Now().UTC())
		if _, err := tx.ExecContext(ctx, `
			UPDATE wallet_transactions
			SET status = $1, updated_at = $2
			WHERE order_no = $3`, RechargeOrderStatusRefunded, now, orderNo); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return replayed, nil
}

// AdminConfirmEpayOrder 网关漏回调时的管理员补录入账。
// 复用 CreditEpayCallback 的单事务入账路径（幂等键 epay:<order_no> 与网关回调
// 共用，重复补录/回调双发都不会重复加钱）。
func (db *DB) AdminConfirmEpayOrder(ctx context.Context, orderNo string) (bool, error) {
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return false, fmt.Errorf("epay: order_no is required")
	}
	var amountMicro int64
	err := db.conn.QueryRowContext(ctx,
		`SELECT amount_micro FROM wallet_transactions WHERE order_no = $1`, orderNo).Scan(&amountMicro)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrEpayOrderNotFound
		}
		return false, err
	}
	return db.CreditEpayCallback(ctx, orderNo, "manual_confirm_by_admin", amountMicro)
}

// AdminAdjustWalletBalance 管理员余额调整（补偿/扣错）。
// deltaMicro 可正可负；不允许把余额调到负（walletApplyTx 兜底）。
// 幂等键由调用方生成（建议 UUID），内部加命名空间 admin_adjust: 防与其他业务冲突。
func (db *DB) AdminAdjustWalletBalance(ctx context.Context, userID, deltaMicro int64, idempotencyKey, reason string, operatorID int64) (bool, error) {
	if deltaMicro == 0 {
		return false, fmt.Errorf("wallet: adjust amount must be non-zero")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return false, fmt.Errorf("wallet: adjust idempotency key is required")
	}
	return db.WalletCredit(ctx, userID, deltaMicro, WalletTxAdjustment,
		"admin_adjust", strings.TrimSpace(idempotencyKey),
		"admin_adjust:"+strings.TrimSpace(idempotencyKey), operatorID, reason)
}

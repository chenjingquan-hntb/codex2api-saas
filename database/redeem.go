package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 兑换码（P6）。
//
// 安全与一致性基线：
//   - 明文码只在批次创建时返回一次，数据库只存 SHA-256 摘要 + 展示前缀；
//   - 核销是「条件更新（unused 且未过期且批次 active）+ 账本幂等键」双保险，
//     并发/重复兑换不会重复入账；
//   - 已核销 / 已撤销 / 已过期的码不可再兑换；
//   - 撤销只影响未核销码；已核销码的冲正走管理员调整（后续步骤）。

// 兑换码与批次状态。
const (
	RedeemCodeStatusUnused  = "unused"
	RedeemCodeStatusUsed    = "used"
	RedeemCodeStatusRevoked = "revoked"

	RedeemBatchStatusActive = "active"
	RedeemBatchStatusClosed = "closed"
)

var (
	ErrRedeemCodeInvalid  = errors.New("redeem: invalid code format")
	ErrRedeemCodeNotFound = errors.New("redeem: code not found")
	ErrRedeemCodeUsed     = errors.New("redeem: code already used")
	ErrRedeemCodeRevoked  = errors.New("redeem: code revoked")
	ErrRedeemCodeExpired  = errors.New("redeem: code expired")
	ErrRedeemBatchClosed  = errors.New("redeem: batch closed")
	ErrRedeemBatchNotFound = errors.New("redeem: batch not found")
)

// redeemCodeAlphabet 兑换码字母表：去掉易混淆字符 0/O/1/I/L。
const redeemCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	// RedeemCodePlainLength 兑换码明文长度（16 位，80 bit 熵）。
	RedeemCodePlainLength = 16
	// maxRedeemBatchCount 单批次最大生成数量。
	maxRedeemBatchCount = 10000
)

// NormalizeRedeemCode 规范化兑换码输入：去分隔符/空白并大写。
func NormalizeRedeemCode(code string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// FormatRedeemCode 把 16 位码格式化为 XXXX-XXXX-XXXX-XXXX（展示/导出用）。
func FormatRedeemCode(code string) string {
	code = NormalizeRedeemCode(code)
	if len(code) != RedeemCodePlainLength {
		return code
	}
	return code[:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16]
}

// HashRedeemCode 返回兑换码的 SHA-256 摘要（数据库唯一存储形态）。
func HashRedeemCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRedeemCode(code)))
	return hex.EncodeToString(sum[:])
}

// RedeemCodePrefix 返回用于展示的码前缀（前 8 位 + 长度校验位样式）。
func RedeemCodePrefix(code string) string {
	c := NormalizeRedeemCode(code)
	if len(c) < 8 {
		return c
	}
	return c[:8]
}

func newRedeemCodePlaintext() (string, error) {
	b := make([]byte, RedeemCodePlainLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, RedeemCodePlainLength)
	for i, v := range b {
		// 拒绝采样消除偏差：31 字符字母表，取 v < 8*31 的字节再取模。
		for int(v) >= len(redeemCodeAlphabet)*8 {
			if _, err := rand.Read(b[i : i+1]); err != nil {
				return "", err
			}
			v = b[i]
		}
		out[i] = redeemCodeAlphabet[int(v)%len(redeemCodeAlphabet)]
	}
	return string(out), nil
}

// RedeemCodeBatch 是兑换码批次。
type RedeemCodeBatch struct {
	ID           int64
	Name         string
	AmountMicro  int64
	TotalCount   int
	UsedCount    int
	RevokedCount int
	Status       string
	ExpiresAt    *time.Time
	CreatedBy    int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RedeemCodeRow 是兑换码记录（不含明文）。
type RedeemCodeRow struct {
	ID           int64
	BatchID      int64
	CodePrefix   string
	AmountMicro  int64
	Status       string
	UsedByUserID int64
	UsedAt       *time.Time
	ExpiresAt    *time.Time
	CreatedAt    time.Time
}

// CreateRedeemBatch 生成一个兑换码批次：创建批次行 + count 个码（只存摘要）。
// 返回批次与明文码列表（仅在本次返回中出现一次）。expiresAt 零值表示不过期。
func (db *DB) CreateRedeemBatch(ctx context.Context, name string, amountMicro int64, count int, expiresAt time.Time, createdBy int64) (*RedeemCodeBatch, []string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil, fmt.Errorf("redeem: batch name is required")
	}
	if amountMicro <= 0 {
		return nil, nil, fmt.Errorf("redeem: amount must be positive")
	}
	if count <= 0 || count > maxRedeemBatchCount {
		return nil, nil, fmt.Errorf("redeem: count must be 1..%d", maxRedeemBatchCount)
	}
	now := time.Now().UTC()

	var batch RedeemCodeBatch
	plaintexts := make([]string, 0, count)
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		// 插入批次。
		var batchID int64
		if db.isSQLite() {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO redeem_code_batches
					(name, amount_micro, total_count, status, expires_at, created_by, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				name, amountMicro, count, RedeemBatchStatusActive,
				db.timeArgOrNil(expiresAt), createdBy, db.timeArg(now), db.timeArg(now))
			if err != nil {
				return err
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			batchID = id
		} else {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO redeem_code_batches
					(name, amount_micro, total_count, status, expires_at, created_by, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
				name, amountMicro, count, RedeemBatchStatusActive,
				db.timeArgOrNil(expiresAt), createdBy, db.timeArg(now), db.timeArg(now)).Scan(&batchID); err != nil {
				return err
			}
		}

		// 批量插入码（摘要）。哈希碰撞概率可忽略，但仍以唯一约束重试兜底。
		insertStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO redeem_codes
				(batch_id, code_hash, code_prefix, amount_micro, status, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`)
		if err != nil {
			return err
		}
		defer insertStmt.Close()
		for i := 0; i < count; i++ {
			var plaintext string
			for attempt := 0; ; attempt++ {
				pt, genErr := newRedeemCodePlaintext()
				if genErr != nil {
					return genErr
				}
				_, insErr := insertStmt.ExecContext(ctx, batchID, HashRedeemCode(pt),
					RedeemCodePrefix(pt), amountMicro, RedeemCodeStatusUnused,
					db.timeArgOrNil(expiresAt), db.timeArg(now))
				if insErr == nil {
					plaintext = pt
					break
				}
				if !isUniqueViolation(insErr) || attempt >= 5 {
					return insErr
				}
			}
			plaintexts = append(plaintexts, FormatRedeemCode(plaintext))
		}
		batch = RedeemCodeBatch{
			ID:          batchID,
			Name:        name,
			AmountMicro: amountMicro,
			TotalCount:  count,
			Status:      RedeemBatchStatusActive,
			ExpiresAt:   optionalTimePtr(expiresAt),
			CreatedBy:   createdBy,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &batch, plaintexts, nil
}

// GetRedeemBatch 读取批次。
func (db *DB) GetRedeemBatch(ctx context.Context, batchID int64) (*RedeemCodeBatch, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT id, name, amount_micro, total_count, used_count, revoked_count,
		       status, expires_at, created_by, created_at, updated_at
		FROM redeem_code_batches WHERE id = $1`, batchID)
	b, err := scanRedeemBatch(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRedeemBatchNotFound
		}
		return nil, err
	}
	return b, nil
}

// ListRedeemBatches 分页读取批次（创建时间倒序）。
func (db *DB) ListRedeemBatches(ctx context.Context, limit, offset int) ([]RedeemCodeBatch, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, name, amount_micro, total_count, used_count, revoked_count,
		       status, expires_at, created_by, created_at, updated_at
		FROM redeem_code_batches
		ORDER BY id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RedeemCodeBatch
	for rows.Next() {
		b, err := scanRedeemBatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func scanRedeemBatch(row interface{ Scan(...any) error }) (*RedeemCodeBatch, error) {
	var b RedeemCodeBatch
	var expiresRaw, createdRaw, updatedRaw interface{}
	if err := row.Scan(&b.ID, &b.Name, &b.AmountMicro, &b.TotalCount, &b.UsedCount,
		&b.RevokedCount, &b.Status, &expiresRaw, &b.CreatedBy, &createdRaw, &updatedRaw); err != nil {
		return nil, err
	}
	if t, ok := optionalTimeValue(expiresRaw); ok {
		b.ExpiresAt = &t
	}
	b.CreatedAt = decodeTimeValue(createdRaw)
	b.UpdatedAt = decodeTimeValue(updatedRaw)
	return &b, nil
}

// ListRedeemCodesByBatch 分页读取批次内的码（不含明文，仅前缀/状态）。
func (db *DB) ListRedeemCodesByBatch(ctx context.Context, batchID int64, limit, offset int) ([]RedeemCodeRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, batch_id, code_prefix, amount_micro, status, used_by_user_id,
		       used_at, expires_at, created_at
		FROM redeem_codes
		WHERE batch_id = $1
		ORDER BY id ASC
		LIMIT $2 OFFSET $3`, batchID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RedeemCodeRow
	for rows.Next() {
		var c RedeemCodeRow
		var usedRaw, expiresRaw, createdRaw interface{}
		if err := rows.Scan(&c.ID, &c.BatchID, &c.CodePrefix, &c.AmountMicro, &c.Status,
			&c.UsedByUserID, &usedRaw, &expiresRaw, &createdRaw); err != nil {
			return nil, err
		}
		if t, ok := optionalTimeValue(usedRaw); ok {
			c.UsedAt = &t
		}
		if t, ok := optionalTimeValue(expiresRaw); ok {
			c.ExpiresAt = &t
		}
		c.CreatedAt = decodeTimeValue(createdRaw)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeRedeemBatch 撤销批次内所有未核销码（已核销码不受影响），并把批次置为
// closed。返回本次撤销的码数量。
func (db *DB) RevokeRedeemBatch(ctx context.Context, batchID int64) (int, error) {
	var revoked int
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE redeem_codes
			SET status = $1
			WHERE batch_id = $2 AND status = $3`,
			RedeemCodeStatusRevoked, batchID, RedeemCodeStatusUnused)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		revoked = int(n)
		now := db.timeArg(time.Now().UTC())
		up, err := tx.ExecContext(ctx, `
			UPDATE redeem_code_batches
			SET status = $1, revoked_count = revoked_count + $2, updated_at = $3
			WHERE id = $4`,
			RedeemBatchStatusClosed, revoked, now, batchID)
		if err != nil {
			return err
		}
		if nUp, err := up.RowsAffected(); err != nil {
			return err
		} else if nUp == 0 {
			return ErrRedeemBatchNotFound
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// RedeemCode 核销兑换码并入账（微元）。返回入账金额。
// 并发/重复核销由条件更新保证：同一码只会成功一次；钱包账本幂等键
// redeem:<hash> 是第二道保险。已核销码的明文记录在账本 ref_id（便于客服溯源，
// 码为一次性，核销后无残留价值）。
func (db *DB) RedeemCode(ctx context.Context, userID int64, code string) (int64, error) {
	code = NormalizeRedeemCode(code)
	if len(code) != RedeemCodePlainLength {
		return 0, ErrRedeemCodeInvalid
	}
	hash := HashRedeemCode(code)
	now := time.Now().UTC()

	var credited int64
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		// 条件更新：仅 unused + 未过期 + 批次 active 的码可以被核销。
		res, err := tx.ExecContext(ctx, `
			UPDATE redeem_codes
			SET status = $1, used_by_user_id = $2, used_at = $3
			WHERE code_hash = $4
			  AND status = $5
			  AND (expires_at IS NULL OR expires_at > $6)
			  AND batch_id IN (SELECT id FROM redeem_code_batches WHERE status = $7)`,
			RedeemCodeStatusUsed, userID, db.timeArg(now), hash,
			RedeemCodeStatusUnused, db.timeArg(now), RedeemBatchStatusActive)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			// 读取现状给出准确错误。
			var status string
			var expiresRaw interface{}
			var cnt int
			if err := tx.QueryRowContext(ctx, `
				SELECT COUNT(*), COALESCE(MAX(status), ''), MAX(expires_at)
				FROM redeem_codes WHERE code_hash = $1`, hash).
				Scan(&cnt, &status, &expiresRaw); err != nil {
				return err
			}
			if cnt == 0 {
				return ErrRedeemCodeNotFound
			}
			switch status {
			case RedeemCodeStatusUsed:
				return ErrRedeemCodeUsed
			case RedeemCodeStatusRevoked:
				return ErrRedeemCodeRevoked
			}
			if t, ok := optionalTimeValue(expiresRaw); ok && !t.After(now) {
				return ErrRedeemCodeExpired
			}
			return ErrRedeemBatchClosed
		}

		var amount int64
		if err := tx.QueryRowContext(ctx, `
			SELECT amount_micro FROM redeem_codes WHERE code_hash = $1`, hash).Scan(&amount); err != nil {
			return err
		}

		// 入账（幂等键 redeem:<hash>；已被并发核销时回滚）。
		if err := db.walletApplyTx(ctx, tx, walletApply{
			UserID:          userID,
			Type:            WalletTxRedeem,
			AmountMicro:     amount,
			DeltaAvailable:  amount,
			DeltaReserved:   0,
			RefType:         "redeem_code",
			RefID:           code,
			IdempotencyKey:  "redeem:" + hash,
			Reason:          "兑换码核销",
			InsufficientErr: ErrInsufficientBalance,
		}); err != nil {
			if errors.Is(err, errWalletReplay) {
				return ErrRedeemCodeUsed
			}
			return err
		}

		// 批次已核销计数 +1。
		if _, err := tx.ExecContext(ctx, `
			UPDATE redeem_code_batches
			SET used_count = used_count + 1, updated_at = $1
			WHERE id = (SELECT batch_id FROM redeem_codes WHERE code_hash = $2)`,
			db.timeArg(now), hash); err != nil {
			return err
		}
		credited = amount
		return nil
	})
	if err != nil {
		return 0, err
	}
	return credited, nil
}

// optionalTimePtr 把零值时间转为 nil（未设置过期）。
func optionalTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// timeArgOrNil 数据库时间参数：零值时间 → NULL。
func (db *DB) timeArgOrNil(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return db.timeArg(t)
}

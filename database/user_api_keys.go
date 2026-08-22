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

// 用户自建 API Key（P5 用户门户）。
//
// 安全基线：
//   - 明文 key 只在创建时返回一次；数据库只存 SHA-256 摘要（key 列与 key_hash 列
//     均为摘要，key 列仅承担唯一约束），另存展示前缀（前 12 位）；
//   - 鉴权热路径 GetAPIKeyByValue 只命中 active 的 key，撤销即刻失效（DB 层过滤 +
//     运行时缓存双键失效）；
//   - 撤销为条件更新，重复撤销/越权撤销不产生副作用。

const (
	APIKeyStatusActive  = "active"
	APIKeyStatusRevoked = "revoked"
)

const (
	// UserAPIKeyPrefix 用户自建 key 的前缀（与管理员 sk- 区分）。
	UserAPIKeyPrefix = "ck-"
	// userAPIKeySecretLen 随机明文长度（32 字节 → 64 hex 字符，256 bit 熵）。
	userAPIKeySecretLen = 32
	// userAPIKeyMaxCount 单个用户最多同时持有的 active key 数。
	userAPIKeyMaxCount = 50
)

var (
	ErrAPIKeyNotFound     = errors.New("api key: not found")
	ErrAPIKeyNotOwned     = errors.New("api key: not owned by user")
	ErrAPIKeyLimitReached = errors.New("api key: max active keys reached")
	ErrAPIKeyNotActive    = errors.New("api key: not active")
)

// HashAPIKeySecret 返回 API key 明文的 SHA-256 十六进制摘要（存储与缓存键形态）。
func HashAPIKeySecret(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

// NewUserAPIKeySecret 生成用户 API key 明文（ck- + 64 hex，256 bit 熵）。
func NewUserAPIKeySecret() (string, error) {
	b := make([]byte, userAPIKeySecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return UserAPIKeyPrefix + hex.EncodeToString(b), nil
}

// UserAPIKeyDisplayPrefix 返回用于展示的 key 前缀（ck- + 前 9 位 = 12 字符）。
func UserAPIKeyDisplayPrefix(secret string) string {
	s := strings.TrimSpace(secret)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// CreateUserAPIKey 为用户创建 API key：明文只返回一次，库中只存摘要。
// 同名 key 不限制；达到 active 上限时返回 ErrAPIKeyLimitReached。
func (db *DB) CreateUserAPIKey(ctx context.Context, userID int64, name string) (*APIKeyRow, string, error) {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		return nil, "", fmt.Errorf("api key: name too long (max 64)")
	}
	now := time.Now().UTC()

	var plaintext string
	var row *APIKeyRow
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		// active 数量上限检查。
		var active int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND status = $2`,
			userID, APIKeyStatusActive).Scan(&active); err != nil {
			return err
		}
		if active >= userAPIKeyMaxCount {
			return ErrAPIKeyLimitReached
		}
		// 生成唯一明文（sha256 摘要撞库概率可忽略，唯一约束重试兜底）。
		for attempt := 0; ; attempt++ {
			secret, genErr := NewUserAPIKeySecret()
			if genErr != nil {
				return genErr
			}
			hash := HashAPIKeySecret(secret)
			_, insErr := tx.ExecContext(ctx, `
				INSERT INTO api_keys
					(name, key, user_id, key_hash, key_prefix, status, last_used_at, created_by, created_at, limits, allowed_group_ids)
				VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10)`,
				name, hash, userID, hash, UserAPIKeyDisplayPrefix(secret),
				APIKeyStatusActive, userID, db.timeArg(now), "{}", "[]")
			if insErr == nil {
				plaintext = secret
				break
			}
			if !isUniqueViolation(insErr) || attempt >= 5 {
				return insErr
			}
		}
		// 读回完整行。
		r, err := db.getAPIKeyByValueTx(ctx, tx, HashAPIKeySecret(plaintext))
		if err != nil {
			return err
		}
		row = r
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return row, plaintext, nil
}

// ListUserAPIKeys 列出用户自己的 key（新在前）。
func (db *DB) ListUserAPIKeys(ctx context.Context, userID int64) ([]*APIKeyRow, error) {
	rows, err := db.conn.QueryContext(ctx, `SELECT `+apiKeySelectColumns+` FROM api_keys WHERE user_id = $1 ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIKeyRow
	for rows.Next() {
		row, err := scanAPIKeyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetUserAPIKey 读取用户自己的 key；不存在或不属于该用户返回 ErrAPIKeyNotFound。
func (db *DB) GetUserAPIKey(ctx context.Context, userID, keyID int64) (*APIKeyRow, error) {
	rows, err := db.conn.QueryContext(ctx, `SELECT `+apiKeySelectColumns+` FROM api_keys WHERE id = $1 AND user_id = $2`, keyID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrAPIKeyNotFound
	}
	return scanAPIKeyRow(rows)
}

// RenameUserAPIKey 重命名用户自己的 key。
func (db *DB) RenameUserAPIKey(ctx context.Context, userID, keyID int64, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return fmt.Errorf("api key: name must be 1..64 chars")
	}
	res, err := db.conn.ExecContext(ctx, `
		UPDATE api_keys SET name = $1
		WHERE id = $2 AND user_id = $3 AND status = $4`,
		name, keyID, userID, APIKeyStatusActive)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// RevokeUserAPIKey 撤销用户自己的 key（条件更新：仅 active 可被撤销）。
// 撤销后 DB 层立即拒绝该 key 鉴权；运行时缓存由调用方按 row.Key 失效。
func (db *DB) RevokeUserAPIKey(ctx context.Context, userID, keyID int64, reason string) (*APIKeyRow, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 200 {
		reason = reason[:200]
	}
	now := time.Now().UTC()

	var revoked *APIKeyRow
	err := db.withWriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE api_keys
			SET status = $1, revoked_at = $2, revoked_reason = $3
			WHERE id = $4 AND user_id = $5 AND status = $6`,
			APIKeyStatusRevoked, db.timeArg(now), reason, keyID, userID, APIKeyStatusActive)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			// 已撤销或不存在：区分错误信息。
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys WHERE id = $1 AND user_id = $2`, keyID, userID).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return ErrAPIKeyNotFound
			}
			return ErrAPIKeyNotActive
		}
		// 按 id 读回撤销后的行。
		rows, err := tx.QueryContext(ctx, `SELECT `+apiKeySelectColumns+` FROM api_keys WHERE id = $1 AND user_id = $2`, keyID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			return ErrAPIKeyNotFound
		}
		revoked, err = scanAPIKeyRow(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

// getAPIKeyByValueTx 事务内按摘要/明文查找 key（CreateUserAPIKey 内部使用）。
func (db *DB) getAPIKeyByValueTx(ctx context.Context, tx *sql.Tx, hash string) (*APIKeyRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+apiKeySelectColumns+` FROM api_keys WHERE key_hash = $1`, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanAPIKeyRow(rows)
}

package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// 用户与会话（控制面，P5/P6）。
//
// 安全基线：
//   - 密码使用 Argon2id（golang.org/x/crypto/argon2），OWASP 建议参数；
//   - 会话/验证/重置 token 一律随机 32 字节，数据库只存 SHA-256 十六进制摘要；
//   - 登录、密码校验走常量时间比较；
//   - 邮箱验证 token 一次性使用（used_at 原子置位），且可过期。

// 用户状态与角色。
const (
	UserStatusPending = "pending"
	UserStatusActive  = "active"
	UserStatusBanned  = "banned"

	UserRoleUser  = "user"
	UserRoleAdmin = "admin"
)

var (
	ErrUserNotFound     = errors.New("users: user not found")
	ErrEmailTaken       = errors.New("users: email already registered")
	ErrUserBanned       = errors.New("users: user is banned")
	ErrEmailNotVerified = errors.New("users: email not verified")
	ErrInvalidPassword  = errors.New("users: invalid password")

	ErrTokenNotFound = errors.New("users: token not found")
	ErrTokenExpired  = errors.New("users: token expired")
	ErrTokenUsed     = errors.New("users: token already used")

	ErrPasswordHashFormat = errors.New("users: unsupported password hash format")
)

// Argon2id 参数（OWASP 推荐：m=64MiB, t=3, p=4）。
const (
	Argon2Time    uint32 = 3
	Argon2Memory  uint32 = 64 * 1024 // KiB
	Argon2Threads uint8  = 4
	Argon2KeyLen  uint32 = 32
)

// User 门户用户。
type User struct {
	ID              int64
	Email           string
	PasswordHash    string
	Status          string
	Role            string
	AuthVersion     int64
	EmailVerifiedAt time.Time // zero 表示未验证
	LastLoginAt     time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// EmailVerified 报告邮箱是否已验证。
func (u *User) EmailVerified() bool { return u != nil && !u.EmailVerifiedAt.IsZero() }

// IsBanned 报告用户是否被封禁。
func (u *User) IsBanned() bool { return u != nil && u.Status == UserStatusBanned }

// UserSession 门户会话（token 摘要 + 关联用户快照，一次查询供鉴权用）。
type UserSession struct {
	ID        int64
	UserID    int64
	NodeName  string
	IP        string
	UserAgent string
	ExpiresAt time.Time
	RevokedAt time.Time
	LastSeenAt time.Time
	CreatedAt time.Time

	// 关联用户快照（JOIN users）。
	Email           string
	Status          string
	Role            string
	EmailVerifiedAt time.Time
}

// Valid 报告会话当前是否可用：未过期、未吊销、用户未封禁。
func (s *UserSession) Valid(now time.Time) bool {
	if s == nil {
		return false
	}
	if !s.RevokedAt.IsZero() || s.ExpiresAt.IsZero() || s.ExpiresAt.Before(now) {
		return false
	}
	return s.Status != UserStatusBanned && s.Status != ""
}

// ==================== Argon2id 密码哈希 ====================

// HashPassword 用 Argon2id 派生密码哈希，输出自描述格式：
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("users: generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, Argon2Memory, Argon2Time, Argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
	return encoded, nil
}

// VerifyPassword 校验明文密码是否匹配存储哈希，常量时间比较。
func VerifyPassword(encoded, password string) (bool, error) {
	salt, hash, memory, iterations, threads, err := parseArgon2idHash(encoded)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(hash)))
	if subtle.ConstantTimeCompare(computed, hash) != 1 {
		return false, nil
	}
	return true, nil
}

func parseArgon2idHash(encoded string) (salt, hash []byte, memory uint32, iterations uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	version, verr := strconv.Atoi(parts[2][2:])
	if verr != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	for _, kv := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, nil, 0, 0, 0, ErrPasswordHashFormat
		}
		switch key {
		case "m":
			v, e := strconv.ParseUint(val, 10, 32)
			if e != nil {
				return nil, nil, 0, 0, 0, ErrPasswordHashFormat
			}
			memory = uint32(v)
		case "t":
			v, e := strconv.ParseUint(val, 10, 32)
			if e != nil {
				return nil, nil, 0, 0, 0, ErrPasswordHashFormat
			}
			iterations = uint32(v)
		case "p":
			v, e := strconv.ParseUint(val, 10, 8)
			if e != nil {
				return nil, nil, 0, 0, 0, ErrPasswordHashFormat
			}
			threads = uint8(v)
		default:
			return nil, nil, 0, 0, 0, ErrPasswordHashFormat
		}
	}
	if memory == 0 || iterations == 0 || threads == 0 {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return nil, nil, 0, 0, 0, ErrPasswordHashFormat
	}
	return salt, hash, memory, iterations, threads, nil
}

// ==================== 用户 ====================

// CreateUser 创建用户。邮箱冲突返回 ErrEmailTaken。
func (db *DB) CreateUser(ctx context.Context, email, passwordHash string) (*User, error) {
	var id int64
	if db.isSQLite() {
		res, err := db.conn.ExecContext(ctx, `
			INSERT INTO users (email, password_hash)
			VALUES (?, ?)`, email, passwordHash)
		if err != nil {
			if isUniqueViolation(err) {
				return nil, ErrEmailTaken
			}
			return nil, err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return nil, err
		}
	} else {
		err := db.conn.QueryRowContext(ctx, `
			INSERT INTO users (email, password_hash)
			VALUES ($1, $2)
			RETURNING id`, email, passwordHash).Scan(&id)
		if err != nil {
			if isUniqueViolation(err) {
				return nil, ErrEmailTaken
			}
			return nil, err
		}
	}
	return db.GetUserByID(ctx, id)
}

// GetUserByEmail 按邮箱读取用户；不存在返回 ErrUserNotFound。
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return db.getUserWhere(ctx, `email = $1`, email)
}

// GetUserByID 按 ID 读取用户；不存在返回 ErrUserNotFound。
func (db *DB) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return db.getUserWhere(ctx, `id = $1`, id)
}

func (db *DB) getUserWhere(ctx context.Context, where string, arg interface{}) (*User, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT id, email, password_hash, status, role, auth_version,
		       email_verified_at, last_login_at, created_at, updated_at
		FROM users
		WHERE `+where, arg)
	return scanUser(row)
}

func scanUser(row interface{ Scan(...interface{}) error }) (*User, error) {
	var u User
	var verifiedRaw, loginRaw, createdRaw, updatedRaw interface{}
	if err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Status, &u.Role, &u.AuthVersion,
		&verifiedRaw, &loginRaw, &createdRaw, &updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.EmailVerifiedAt = decodeTimeValue(verifiedRaw)
	u.LastLoginAt = decodeTimeValue(loginRaw)
	u.CreatedAt = decodeTimeValue(createdRaw)
	u.UpdatedAt = decodeTimeValue(updatedRaw)
	return &u, nil
}

// SetUserEmailVerified 标记邮箱已验证（保留首次验证时间）。仅把 pending 用户置为
// active：被封禁/已激活用户保持原状态，防止封禁用户凭未使用验证 token 自解封。
func (db *DB) SetUserEmailVerified(ctx context.Context, userID int64) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE users
		SET email_verified_at = COALESCE(email_verified_at, $1),
		    status            = CASE WHEN status = $2 THEN $3 ELSE status END,
		    updated_at        = $1
		WHERE id = $4`,
		db.timeArg(time.Now().UTC()), UserStatusPending, UserStatusActive, userID)
	return err
}

// UpdateUserLastLogin 记录最近登录时间。
func (db *DB) UpdateUserLastLogin(ctx context.Context, userID int64) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE users SET last_login_at = $1, updated_at = $1 WHERE id = $2`,
		db.timeArg(time.Now().UTC()), userID)
	return err
}

// SetUserPasswordHash 更新密码哈希并递增 auth_version（用于吊销旧会话/旧哈希缓存）。
func (db *DB) SetUserPasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $1, auth_version = auth_version + 1, updated_at = $2
		WHERE id = $3`,
		passwordHash, db.timeArg(time.Now().UTC()), userID)
	return err
}

// UpdateUserStatus 更新用户状态（封禁/恢复，供管理端使用）。
func (db *DB) UpdateUserStatus(ctx context.Context, userID int64, status string) error {
	if status != UserStatusPending && status != UserStatusActive && status != UserStatusBanned {
		return fmt.Errorf("users: invalid status %q", status)
	}
	_, err := db.conn.ExecContext(ctx, `
		UPDATE users SET status = $1, updated_at = $2 WHERE id = $3`,
		status, db.timeArg(time.Now().UTC()), userID)
	return err
}

// ==================== 会话 ====================

// HashSessionToken 计算会话/验证 token 的存储摘要（SHA-256 hex）。
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateUserSession 创建门户会话。调用方负责生成随机 token 并传入其摘要。
func (db *DB) CreateUserSession(ctx context.Context, userID int64, tokenHash, nodeName, ip, userAgent string, expiresAt time.Time) (int64, error) {
	var id int64
	if db.isSQLite() {
		res, err := db.conn.ExecContext(ctx, `
			INSERT INTO user_sessions (user_id, token_hash, node_name, ip, user_agent, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			userID, tokenHash, nodeName, ip, userAgent, db.timeArg(expiresAt))
		if err != nil {
			return 0, err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return 0, err
		}
	} else {
		err := db.conn.QueryRowContext(ctx, `
			INSERT INTO user_sessions (user_id, token_hash, node_name, ip, user_agent, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id`,
			userID, tokenHash, nodeName, ip, userAgent, db.timeArg(expiresAt)).Scan(&id)
		if err != nil {
			return 0, err
		}
	}
	return id, nil
}

// GetUserSessionByTokenHash 按摘要读取会话（JOIN 用户快照）；不存在返回 ErrUserNotFound。
func (db *DB) GetUserSessionByTokenHash(ctx context.Context, tokenHash string) (*UserSession, error) {
	row := db.conn.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.node_name, s.ip, s.user_agent,
		       s.expires_at, s.revoked_at, s.last_seen_at, s.created_at,
		       u.email, u.status, u.role, u.email_verified_at
		FROM user_sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`, tokenHash)

	var s UserSession
	var revokedRaw, lastSeenRaw, createdRaw interface{}
	var verifiedRaw interface{}
	if err := row.Scan(
		&s.ID, &s.UserID, &s.NodeName, &s.IP, &s.UserAgent,
		&s.ExpiresAt, &revokedRaw, &lastSeenRaw, &createdRaw,
		&s.Email, &s.Status, &s.Role, &verifiedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	s.RevokedAt = decodeTimeValue(revokedRaw)
	s.LastSeenAt = decodeTimeValue(lastSeenRaw)
	s.CreatedAt = decodeTimeValue(createdRaw)
	s.EmailVerifiedAt = decodeTimeValue(verifiedRaw)
	return &s, nil
}

// RevokeUserSession 吊销指定会话（仅限该用户自己的会话）。
func (db *DB) RevokeUserSession(ctx context.Context, userID, sessionID int64) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE user_sessions
		SET revoked_at = $1
		WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL`,
		db.timeArg(time.Now().UTC()), sessionID, userID)
	return err
}

// RevokeAllUserSessions 吊销用户全部会话（改密/重置后调用）。
func (db *DB) RevokeAllUserSessions(ctx context.Context, userID int64) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE user_sessions
		SET revoked_at = $1
		WHERE user_id = $2 AND revoked_at IS NULL`,
		db.timeArg(time.Now().UTC()), userID)
	return err
}

// RevokeUserSessionsExcept 吊销用户除 exceptSessionID 外的全部会话（改密后保留当前会话）。
func (db *DB) RevokeUserSessionsExcept(ctx context.Context, userID, exceptSessionID int64) error {
	_, err := db.conn.ExecContext(ctx, `
		UPDATE user_sessions
		SET revoked_at = $1
		WHERE user_id = $2 AND id != $3 AND revoked_at IS NULL`,
		db.timeArg(time.Now().UTC()), userID, exceptSessionID)
	return err
}

// ListUserSessions 列出用户全部会话（按最近创建倒序）。
func (db *DB) ListUserSessions(ctx context.Context, userID int64) ([]UserSession, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, user_id, node_name, ip, user_agent, expires_at, revoked_at, last_seen_at, created_at
		FROM user_sessions
		WHERE user_id = $1
		ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserSession
	for rows.Next() {
		var s UserSession
		var revokedRaw, lastSeenRaw, createdRaw interface{}
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.NodeName, &s.IP, &s.UserAgent,
			&s.ExpiresAt, &revokedRaw, &lastSeenRaw, &createdRaw,
		); err != nil {
			return nil, err
		}
		s.RevokedAt = decodeTimeValue(revokedRaw)
		s.LastSeenAt = decodeTimeValue(lastSeenRaw)
		s.CreatedAt = decodeTimeValue(createdRaw)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ==================== 一次性 token（邮箱验证 / 密码重置） ====================

// CreateEmailVerificationToken 签发邮箱验证 token（摘要入库），并把该用户此前未用的
// 验证 token 作废，避免无限堆积。
func (db *DB) CreateEmailVerificationToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	now := db.timeArg(time.Now().UTC())
	if _, err := db.conn.ExecContext(ctx, `
		UPDATE user_email_verification_tokens
		SET used_at = $1
		WHERE user_id = $2 AND used_at IS NULL`, now, userID); err != nil {
		return err
	}
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO user_email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`, userID, tokenHash, db.timeArg(expiresAt))
	return err
}

// ConsumeEmailVerificationToken 原子消费邮箱验证 token，返回对应用户 ID。
// 失败原因区分：ErrTokenNotFound / ErrTokenExpired / ErrTokenUsed。
func (db *DB) ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) (int64, error) {
	now := db.timeArg(time.Now().UTC())
	res, err := db.conn.ExecContext(ctx, `
		UPDATE user_email_verification_tokens
		SET used_at = $1
		WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1`,
		now, tokenHash)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		var userID int64
		err := db.conn.QueryRowContext(ctx, `
			SELECT user_id FROM user_email_verification_tokens WHERE token_hash = $1`, tokenHash).Scan(&userID)
		return userID, err
	}
	return 0, db.tokenFailureReason(ctx, "user_email_verification_tokens", tokenHash)
}

// CreatePasswordResetToken 签发密码重置 token（摘要入库），作废该用户旧的重置 token。
func (db *DB) CreatePasswordResetToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	now := db.timeArg(time.Now().UTC())
	if _, err := db.conn.ExecContext(ctx, `
		UPDATE user_password_reset_tokens
		SET used_at = $1
		WHERE user_id = $2 AND used_at IS NULL`, now, userID); err != nil {
		return err
	}
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO user_password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`, userID, tokenHash, db.timeArg(expiresAt))
	return err
}

// ConsumePasswordResetToken 原子消费密码重置 token，返回对应用户 ID。
func (db *DB) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (int64, error) {
	now := db.timeArg(time.Now().UTC())
	res, err := db.conn.ExecContext(ctx, `
		UPDATE user_password_reset_tokens
		SET used_at = $1
		WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1`,
		now, tokenHash)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		var userID int64
		err := db.conn.QueryRowContext(ctx, `
			SELECT user_id FROM user_password_reset_tokens WHERE token_hash = $1`, tokenHash).Scan(&userID)
		return userID, err
	}
	return 0, db.tokenFailureReason(ctx, "user_password_reset_tokens", tokenHash)
}

// tokenFailureReason 在消费失败时区分「不存在 / 已用 / 已过期」。
func (db *DB) tokenFailureReason(ctx context.Context, table, tokenHash string) error {
	var usedRaw, expiresRaw interface{}
	err := db.conn.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT used_at, expires_at FROM %s WHERE token_hash = $1`, table), tokenHash).
		Scan(&usedRaw, &expiresRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTokenNotFound
	}
	if err != nil {
		return err
	}
	if !decodeTimeValue(usedRaw).IsZero() {
		return ErrTokenUsed
	}
	expires := decodeTimeValue(expiresRaw)
	// 统一用 UTC 与 DB 存储时间比较，避免非 UTC 服务器误报「已过期」。
	if !expires.IsZero() && expires.Before(time.Now().UTC()) {
		return ErrTokenExpired
	}
	return ErrTokenNotFound
}

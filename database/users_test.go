package database

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newUsersTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestHashPasswordVerifyRoundTrip(t *testing.T) {
	const password = "S3cure!密码123"
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected hash format: %s", encoded)
	}
	ok, err := VerifyPassword(encoded, password)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("correct password rejected")
	}
	ok, err = VerifyPassword(encoded, "wrong-password")
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	a, _ := HashPassword("same-password")
	b, _ := HashPassword("same-password")
	if a == b {
		t.Fatal("two hashes of same password should differ (random salt)")
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"",
		"plaintext",
		"$bcrypt$v=19$m=65536,t=3,p=4$AAAA$BBBB",
		"$argon2id$v=18$m=65536,t=3,p=4$AAAA$BBBB", // 版本不匹配
		"$argon2id$v=19$m=abc,t=3,p=4$AAAA$BBBB",  // 参数非法
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$BBBB", // base64 非法
	} {
		if _, err := VerifyPassword(bad, "x"); !errors.Is(err, ErrPasswordHashFormat) {
			t.Fatalf("hash %q: err = %v, want ErrPasswordHashFormat", bad, err)
		}
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	hash, _ := HashPassword("pw-123456")

	u, err := db.CreateUser(ctx, "alice@example.com", hash)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == 0 || u.Email != "alice@example.com" || u.Status != UserStatusPending {
		t.Fatalf("unexpected user: %+v", u)
	}
	if u.EmailVerified() {
		t.Fatal("new user should not be verified")
	}

	if _, err := db.CreateUser(ctx, "alice@example.com", hash); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate: err = %v, want ErrEmailTaken", err)
	}

	// 大小写不敏感？schema 是 UNIQUE(email) 精确匹配；此处验证精确匹配即可。
	byEmail, err := db.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Fatalf("get by email id = %d, want %d", byEmail.ID, u.ID)
	}
	if _, err := db.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user: err = %v, want ErrUserNotFound", err)
	}
}

func TestEmailVerificationFlow(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "bob@example.com", mustHash(t, "pw-123456"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// 未验证时不可用错误语义正确。
	if err := db.SetUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := db.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.EmailVerified() {
		t.Fatal("user should be verified")
	}
	if got.Status != UserStatusActive {
		t.Fatalf("status = %s, want active", got.Status)
	}
}

func TestEmailVerificationTokenConsume(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "carol@example.com", mustHash(t, "pw-123456"))

	const plain = "verify-token-abc123"
	tokenHash := HashSessionToken(plain)
	if err := db.CreateEmailVerificationToken(ctx, user.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create token: %v", err)
	}

	uid, err := db.ConsumeEmailVerificationToken(ctx, tokenHash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if uid != user.ID {
		t.Fatalf("userID = %d, want %d", uid, user.ID)
	}

	// 二次消费 → 已使用。
	if _, err := db.ConsumeEmailVerificationToken(ctx, tokenHash); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume: err = %v, want ErrTokenUsed", err)
	}
	// 不存在。
	if _, err := db.ConsumeEmailVerificationToken(ctx, HashSessionToken("nope")); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("missing token: err = %v, want ErrTokenNotFound", err)
	}
}

func TestEmailVerificationTokenExpired(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "dave@example.com", mustHash(t, "pw-123456"))

	tokenHash := HashSessionToken("expired-token")
	if err := db.CreateEmailVerificationToken(ctx, user.ID, tokenHash, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := db.ConsumeEmailVerificationToken(ctx, tokenHash); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired consume: err = %v, want ErrTokenExpired", err)
	}
}

func TestEmailVerificationTokenNewInvalidatesOld(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "erin@example.com", mustHash(t, "pw-123456"))

	oldHash := HashSessionToken("old-token")
	if err := db.CreateEmailVerificationToken(ctx, user.ID, oldHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create old: %v", err)
	}
	newHash := HashSessionToken("new-token")
	if err := db.CreateEmailVerificationToken(ctx, user.ID, newHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create new: %v", err)
	}
	// 旧 token 应已被作废。
	if _, err := db.ConsumeEmailVerificationToken(ctx, oldHash); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("old token consume: err = %v, want ErrTokenUsed", err)
	}
	if _, err := db.ConsumeEmailVerificationToken(ctx, newHash); err != nil {
		t.Fatalf("new token consume: %v", err)
	}
}

func TestPasswordResetTokenFlow(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "frank@example.com", mustHash(t, "pw-123456"))

	const plain = "reset-token-xyz"
	tokenHash := HashSessionToken(plain)
	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create reset token: %v", err)
	}
	uid, err := db.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if uid != user.ID {
		t.Fatalf("userID = %d, want %d", uid, user.ID)
	}
	if _, err := db.ConsumePasswordResetToken(ctx, tokenHash); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume: err = %v, want ErrTokenUsed", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "grace@example.com", mustHash(t, "pw-123456"))
	if err := db.SetUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// 创建会话。
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	const plainA = "session-token-a"
	sessionID, err := db.CreateUserSession(ctx, user.ID, HashSessionToken(plainA), "", "127.0.0.1", "test-agent", expires)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	sess, err := db.GetUserSessionByTokenHash(ctx, HashSessionToken(plainA))
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if !sess.Valid(now.Add(time.Hour)) {
		t.Fatal("session should be valid")
	}
	if sess.UserID != user.ID || sess.Email != "grace@example.com" || sess.Status != UserStatusActive {
		t.Fatalf("session join wrong: %+v", sess)
	}

	// 未知 token。
	if _, err := db.GetUserSessionByTokenHash(ctx, HashSessionToken("unknown")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown token: err = %v, want ErrUserNotFound", err)
	}

	// 吊销单条。
	if err := db.RevokeUserSession(ctx, user.ID, sessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	sess, _ = db.GetUserSessionByTokenHash(ctx, HashSessionToken(plainA))
	if sess.Valid(now.Add(time.Hour)) {
		t.Fatal("revoked session should be invalid")
	}

	// 全部吊销。
	const plainB = "session-token-b"
	if _, err := db.CreateUserSession(ctx, user.ID, HashSessionToken(plainB), "", "", "", expires); err != nil {
		t.Fatalf("create session b: %v", err)
	}
	if err := db.RevokeAllUserSessions(ctx, user.ID); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	sess, _ = db.GetUserSessionByTokenHash(ctx, HashSessionToken(plainB))
	if sess.Valid(now.Add(time.Hour)) {
		t.Fatal("session b should be revoked")
	}
	sessions, err := db.ListUserSessions(ctx, user.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range sessions {
		if s.Valid(now.Add(time.Hour)) {
			t.Fatalf("session %d should be revoked", s.ID)
		}
	}
}

func TestSessionExpiredInvalid(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "heidi@example.com", mustHash(t, "pw-123456"))

	now := time.Now().UTC()
	if _, err := db.CreateUserSession(ctx, user.ID, HashSessionToken("expired-session"), "", "", "", now.Add(-time.Minute)); err != nil {
		t.Fatalf("create: %v", err)
	}
	sess, err := db.GetUserSessionByTokenHash(ctx, HashSessionToken("expired-session"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if sess.Valid(now) {
		t.Fatal("expired session should be invalid")
	}
}

func TestSetUserPasswordHashBumpsAuthVersion(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "ivan@example.com", mustHash(t, "pw-123456"))

	if err := db.SetUserPasswordHash(ctx, user.ID, mustHash(t, "new-pw-123456")); err != nil {
		t.Fatalf("set hash: %v", err)
	}
	got, _ := db.GetUserByID(ctx, user.ID)
	if got.AuthVersion != user.AuthVersion+1 {
		t.Fatalf("auth_version = %d, want %d", got.AuthVersion, user.AuthVersion+1)
	}
}

func TestUserStatusBannedInvalidatesSession(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()
	user, _ := db.CreateUser(ctx, "judy@example.com", mustHash(t, "pw-123456"))

	if _, err := db.CreateUserSession(ctx, user.ID, HashSessionToken("sess"), "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := db.UpdateUserStatus(ctx, user.ID, UserStatusBanned); err != nil {
		t.Fatalf("ban: %v", err)
	}
	sess, err := db.GetUserSessionByTokenHash(ctx, HashSessionToken("sess"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if sess.Valid(time.Now()) {
		t.Fatal("session of banned user should be invalid")
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash %q: %v", password, err)
	}
	return h
}

// TestSetUserEmailVerifiedPreservesBannedStatus 校验邮箱验证不会把封禁用户解封
// （封禁只能由管理员恢复，验证 token 不能绕过）。
func TestSetUserEmailVerifiedPreservesBannedStatus(t *testing.T) {
	db := newUsersTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "banned-verify@test.dev", "x")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if user.Status != UserStatusPending {
		t.Fatalf("new user status = %s, want pending", user.Status)
	}
	if err := db.UpdateUserStatus(ctx, user.ID, UserStatusBanned); err != nil {
		t.Fatalf("ban: %v", err)
	}
	if err := db.SetUserEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	after, err := db.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Status != UserStatusBanned {
		t.Fatalf("banned user was un-banned by email verification: status=%s", after.Status)
	}
	if !after.EmailVerified() {
		t.Fatal("email should still be marked verified")
	}

	// 正常 pending 用户验证后进入 active（回归）。
	user2, err := db.CreateUser(ctx, "normal-verify@test.dev", "x")
	if err != nil {
		t.Fatalf("create user2: %v", err)
	}
	if err := db.SetUserEmailVerified(ctx, user2.ID); err != nil {
		t.Fatalf("verify user2: %v", err)
	}
	after2, err := db.GetUserByID(ctx, user2.ID)
	if err != nil {
		t.Fatalf("get user2: %v", err)
	}
	if after2.Status != UserStatusActive {
		t.Fatalf("pending user verify status = %s, want active", after2.Status)
	}
}

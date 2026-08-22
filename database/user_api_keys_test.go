package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newUserKeysTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "userkeys.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCreateUserAPIKeyHashesAtRest(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()
	const userID = 1

	row, secret, err := db.CreateUserAPIKey(ctx, userID, "dev key")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(secret, UserAPIKeyPrefix) {
		t.Fatalf("secret prefix = %q", secret)
	}
	if row.KeyPrefix == "" || len(row.KeyPrefix) > 12 {
		t.Fatalf("prefix = %q", row.KeyPrefix)
	}
	hash := HashAPIKeySecret(secret)
	if row.Key != hash || row.KeyHash != hash {
		t.Fatalf("key=%q key_hash=%q want %q", row.Key, row.KeyHash, hash)
	}
	if strings.Contains(row.Key, secret) {
		t.Fatalf("plaintext leaked into key column")
	}
	// 库中无明文。
	var stored string
	if err := db.conn.QueryRowContext(ctx, `SELECT key FROM api_keys WHERE id = $1`, row.ID).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if stored != hash {
		t.Fatalf("stored key = %q, want hash only", stored)
	}
	// 鉴权查找按明文也能命中（hash 分支）。
	got, err := db.GetAPIKeyByValue(ctx, secret)
	if err != nil || got == nil || got.ID != row.ID {
		t.Fatalf("GetAPIKeyByValue(secret) = %+v err=%v", got, err)
	}
	if got.Status != APIKeyStatusActive {
		t.Fatalf("status = %q", got.Status)
	}
}

func TestGetAPIKeyByValueLegacyPlaintextStillWorks(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()
	id, err := db.InsertAPIKey(ctx, "legacy", "sk-legacy-1234567890")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := db.GetAPIKeyByValue(ctx, "sk-legacy-1234567890")
	if err != nil || got == nil || got.ID != id {
		t.Fatalf("legacy lookup failed: %+v err=%v", got, err)
	}
	// 未知 key → sql.ErrNoRows。
	if _, err := db.GetAPIKeyByValue(ctx, "sk-nope-0000000000"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown key err = %v", err)
	}
}

func TestListAndOwnership(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()

	row1, _, err := db.CreateUserAPIKey(ctx, 1, "k1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := db.CreateUserAPIKey(ctx, 1, "k2"); err != nil {
		t.Fatalf("create k2: %v", err)
	}
	if _, _, err := db.CreateUserAPIKey(ctx, 2, "other"); err != nil {
		t.Fatalf("create other: %v", err)
	}
	keys, err := db.ListUserAPIKeys(ctx, 1)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list = %d err=%v", len(keys), err)
	}
	// 越权读取他人 key → NotFound。
	if _, err := db.GetUserAPIKey(ctx, 2, row1.ID); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("cross-user get err = %v", err)
	}
	if _, err := db.GetUserAPIKey(ctx, 1, row1.ID); err != nil {
		t.Fatalf("own get err = %v", err)
	}
}

func TestRenameAndRevokeUserAPIKey(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()

	row, secret, err := db.CreateUserAPIKey(ctx, 1, "before")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.RenameUserAPIKey(ctx, 1, row.ID, "after"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := db.GetUserAPIKey(ctx, 1, row.ID)
	if err != nil || got.Name != "after" {
		t.Fatalf("rename not applied: %+v err=%v", got, err)
	}
	// 撤销。
	revoked, err := db.RevokeUserAPIKey(ctx, 1, row.ID, "test")
	if err != nil || revoked.Status != APIKeyStatusRevoked {
		t.Fatalf("revoke: %+v err=%v", revoked, err)
	}
	// 撤销后鉴权立即失效（DB 层 status 过滤）。
	if _, err := db.GetAPIKeyByValue(ctx, secret); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoked key still authable: err=%v", err)
	}
	// 重复撤销 → NotActive。
	if _, err := db.RevokeUserAPIKey(ctx, 1, row.ID, ""); !errors.Is(err, ErrAPIKeyNotActive) {
		t.Fatalf("double revoke err = %v", err)
	}
	// 越权撤销 → NotFound。
	if _, err := db.RevokeUserAPIKey(ctx, 2, row.ID, ""); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("cross-user revoke err = %v", err)
	}
	// 撤销后的 key 不可再改名。
	if err := db.RenameUserAPIKey(ctx, 1, row.ID, "x"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("rename revoked err = %v", err)
	}
}

func TestUserAPIKeyLimit(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()
	for i := 0; i < userAPIKeyMaxCount; i++ {
		if _, _, err := db.CreateUserAPIKey(ctx, 1, "k"); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, _, err := db.CreateUserAPIKey(ctx, 1, "k"); !errors.Is(err, ErrAPIKeyLimitReached) {
		t.Fatalf("limit err = %v", err)
	}
	// 撤销一个后可再创建。
	if _, err := db.RevokeUserAPIKey(ctx, 1, 1, ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := db.CreateUserAPIKey(ctx, 1, "new"); err != nil {
		t.Fatalf("create after revoke: %v", err)
	}
}

func TestGetUserUsageReportAndDaily(t *testing.T) {
	db := newUserKeysTestDB(t)
	ctx := context.Background()

	row, _, err := db.CreateUserAPIKey(ctx, 7, "usage key")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	now := time.Now().UTC()
	// 插入两条该用户的用量 + 一条他人 key 的用量（不应被聚合）。
	insertUsage := func(apiKeyID int64, model string, tokens int64, billed float64, at time.Time, status int) {
		t.Helper()
		_, err := db.conn.ExecContext(ctx, `
			INSERT INTO usage_logs
				(api_key_id, model, effective_model, inbound_endpoint, endpoint, total_tokens,
				 input_tokens, output_tokens, cached_tokens, user_billed, status_code, duration_ms, created_at)
			VALUES ($1, $2, $2, '/v1/messages', '/v1/messages', $3, $3/2, $3/2, 0, $4, $5, 100, $6)`,
			apiKeyID, model, tokens, billed, status, db.timeArg(at))
		if err != nil {
			t.Fatalf("insert usage: %v", err)
		}
	}
	insertUsage(row.ID, "gpt-5.6", 1000, 1.25, now.Add(-time.Hour), 200)
	insertUsage(row.ID, "gpt-5.6", 500, 0.5, now.Add(-2*time.Hour), 200)
	insertUsage(row.ID, "gpt-5.5", 200, 0.2, now.Add(-3*time.Hour), 200)
	other, _, _ := db.CreateUserAPIKey(ctx, 8, "other")
	insertUsage(other.ID, "gpt-5.6", 99999, 999.0, now.Add(-time.Hour), 200)

	start := now.AddDate(0, 0, -7)
	report, err := db.GetUserUsageReport(ctx, 7, start, now, 1, 25)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Summary.Requests != 3 {
		t.Fatalf("requests = %d, want 3 (others excluded)", report.Summary.Requests)
	}
	if report.Summary.Tokens != 1700 {
		t.Fatalf("tokens = %d, want 1700", report.Summary.Tokens)
	}
	if report.Summary.UserBilled != 1.95 {
		t.Fatalf("billed = %v, want 1.95", report.Summary.UserBilled)
	}
	if report.Summary.ErrorCount != 0 {
		t.Fatalf("errors = %d", report.Summary.ErrorCount)
	}
	if len(report.RecentLogs) != 3 || report.RecentLogsTotal != 3 {
		t.Fatalf("recent = %d/%d", len(report.RecentLogs), report.RecentLogsTotal)
	}
	foundModel := false
	for _, m := range report.Models {
		if m.Name == "gpt-5.6" {
			foundModel = true
			if m.Requests != 2 {
				t.Fatalf("gpt-5.6 requests = %d", m.Requests)
			}
		}
	}
	if !foundModel {
		t.Fatalf("models breakdown missing gpt-5.6: %+v", report.Models)
	}
	if report.Windows.Today.Requests != 3 {
		t.Fatalf("today requests = %d", report.Windows.Today.Requests)
	}

	daily, err := db.GetUserDailyUsage(ctx, 7, 7)
	if err != nil {
		t.Fatalf("daily: %v", err)
	}
	if len(daily) != 7 {
		t.Fatalf("daily len = %d", len(daily))
	}
	if daily[6].Requests != 3 || daily[6].Tokens != 1700 {
		t.Fatalf("latest day = %+v", daily[6])
	}
	for i := 0; i < 6; i++ {
		if daily[i].Requests != 0 {
			t.Fatalf("day %d should be empty: %+v", i, daily[i])
		}
	}
}

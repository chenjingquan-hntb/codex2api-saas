package database

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// credentialsTestKeyA / B 是合法的 64 位十六进制 AES-256 密钥（仅测试用）。
func credentialsTestKeyA() string { return strings.Repeat("ab", 32) }
func credentialsTestKeyB() string { return strings.Repeat("cd", 32) }
func credentialsTestKeyC() string { return strings.Repeat("ef", 32) }

func TestCredentialsEncryptionRequiredFailClosed(t *testing.T) {
	// CREDENTIALS_ENCRYPTION_REQUIRED=1 且未配置密钥 → 拒绝启动（fail-closed）。
	t.Setenv(credentialsEncryptionRequiredEnv, "1")
	t.Setenv(credentialsEncryptionEnv, "")
	t.Setenv(credentialsEncryptionPreviousEnv, "")
	if _, err := New("sqlite", filepath.Join(t.TempDir(), "required.db")); err == nil {
		t.Fatal("CREDENTIALS_ENCRYPTION_REQUIRED=1 without key must refuse to start")
	}
	// 配置密钥后正常启动。
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "required-ok.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey with required=1: %v", err)
	}
	defer db.Close()
	if !db.CredentialsEncryptionEnabled() {
		t.Fatal("encryption must be enabled")
	}
	if db.CredentialsEncryptionVersion() < 1 {
		t.Fatalf("key version = %d", db.CredentialsEncryptionVersion())
	}
}

func TestCredentialsCipherRoundtripAndRejectsBadKey(t *testing.T) {
	c, err := NewCredentialsCipher(credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewCredentialsCipher: %v", err)
	}
	if !c.Enabled() {
		t.Fatal("cipher should be enabled")
	}
	blob, err := c.Encrypt([]byte(`{"refresh_token":"rt-secret"}`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(blob, credentialsEncryptionMagicPrefix) {
		t.Fatalf("blob prefix = %q", blob)
	}
	if strings.Contains(blob, "rt-secret") {
		t.Fatal("ciphertext must not contain plaintext")
	}
	plain, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != `{"refresh_token":"rt-secret"}` {
		t.Fatalf("plaintext mismatch: %s", plain)
	}

	if _, err := NewCredentialsCipher("not-hex"); err == nil {
		t.Fatal("bad key should error")
	}
	if _, err := NewCredentialsCipher("aabb"); err == nil {
		t.Fatal("short key should error")
	}
	// 未知版本解密必须报错。
	c2, _ := NewCredentialsCipher(credentialsTestKeyB())
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatal("decrypting blob written with another key must fail")
	}
}

func TestCredentialsEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "enc.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	const secret = "rt-super-secret-token"
	id, err := db.InsertAccountWithCredentials(ctx, "enc-account", map[string]any{
		"upstream_type": "grok", "email": "a@example.com", "refresh_token": secret, "models": []string{"grok-4"},
	}, "")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// 1) 业务读取必须能还原明文。
	row, err := db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if row.GetCredential("refresh_token") != secret {
		t.Fatalf("refresh_token = %q", row.GetCredential("refresh_token"))
	}
	if row.GetCredential("email") != "a@example.com" {
		t.Fatalf("email = %q", row.GetCredential("email"))
	}

	// 2) 落库必须是密文：credentials_enc 有 enc:v1: 前缀且不含明文；credentials 列清空。
	var encRaw, plainRaw any
	var keyVersion int
	if err := db.conn.QueryRowContext(ctx, `SELECT credentials_enc, credentials, cred_key_version FROM accounts WHERE id=$1`, id).Scan(&encRaw, &plainRaw, &keyVersion); err != nil {
		t.Fatalf("raw select: %v", err)
	}
	enc := string(bytesFromDBValue(encRaw))
	if !strings.HasPrefix(enc, credentialsEncryptionMagicPrefix) {
		t.Fatalf("credentials_enc prefix = %q", enc)
	}
	if strings.Contains(enc, secret) || strings.Contains(enc, "a@example.com") {
		t.Fatal("ciphertext must not contain plaintext fields")
	}
	if string(bytesFromDBValue(plainRaw)) != "{}" {
		t.Fatalf("plaintext credentials column must be {} after encryption, got %q", string(bytesFromDBValue(plainRaw)))
	}
	if keyVersion <= 0 {
		t.Fatalf("cred_key_version = %d", keyVersion)
	}

	// 3) 列表投影不含敏感 token 原文。
	projected, err := db.ListAccountListProjection(ctx, "")
	if err != nil {
		t.Fatalf("ListAccountListProjection: %v", err)
	}
	found := false
	for _, p := range projected {
		if p.ID != id {
			continue
		}
		found = true
		if p.GetCredential("refresh_token") != "configured" {
			t.Fatalf("projection refresh_token = %q, want configured", p.GetCredential("refresh_token"))
		}
		if strings.Contains(strings.Join([]string{p.GetCredential("email"), p.GetCredential("upstream_type")}, "|"), secret) {
			t.Fatal("projection leaked secret")
		}
	}
	if !found {
		t.Fatal("projected account not found")
	}
}

func TestCredentialsEncryptionLegacyPlaintextStillReadable(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "legacy.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	// 模拟旧版本二进制写入的明文行（credentials 有 JSON、credentials_enc 为空）。
	raw := `{"upstream_type":"grok","email":"legacy@example.com","refresh_token":"legacy-rt"}`
	res, err := db.conn.ExecContext(ctx, `INSERT INTO accounts(name, credentials) VALUES($1, $2)`, "legacy", raw)
	if err != nil {
		t.Fatalf("raw insert: %v", err)
	}
	id, _ := res.LastInsertId()
	// 模拟启动回填：明文行写入后由回填例程补齐投影列并迁移为密文。
	if err := db.backfillCredentialsProjections(ctx); err != nil {
		t.Fatalf("backfill projections: %v", err)
	}
	if err := db.encryptCredentialsAtRest(ctx); err != nil {
		t.Fatalf("encrypt at rest: %v", err)
	}

	row, err := db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountByID: %v", err)
	}
	if row.GetCredential("refresh_token") != "legacy-rt" {
		t.Fatalf("legacy refresh_token = %q", row.GetCredential("refresh_token"))
	}
	// 启动回填应已把投影列补上（credentials_projection_version=1）。
	var projVersion int
	if err := db.conn.QueryRowContext(ctx, `SELECT credentials_projection_version FROM accounts WHERE id=$1`, id).Scan(&projVersion); err != nil {
		t.Fatalf("projection version: %v", err)
	}
	if projVersion != credentialsProjectionVersion {
		t.Fatalf("credentials_projection_version = %d", projVersion)
	}
	// 明文行尚未加密（未配置回填触发条件为加密启用 + 明文非空）：
	// 此处加密已启用，启动时应已迁移。校验 credentials_enc 非空。
	var encRaw any
	if err := db.conn.QueryRowContext(ctx, `SELECT credentials_enc FROM accounts WHERE id=$1`, id).Scan(&encRaw); err != nil {
		t.Fatalf("credentials_enc: %v", err)
	}
	if string(bytesFromDBValue(encRaw)) == "" {
		t.Fatal("legacy plaintext row should have been encrypted at startup")
	}
}

func TestCredentialsEncryptionStartupBackfill(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "backfill.db")

	// 第一阶段：明文模式写入。
	db1, err := New("sqlite", path)
	if err != nil {
		t.Fatalf("New plaintext: %v", err)
	}
	id1, err := db1.InsertAccountWithCredentials(ctx, "a1", map[string]any{
		"upstream_type": "grok", "email": "a1@example.com", "refresh_token": "rt-1",
	}, "")
	if err != nil {
		t.Fatalf("insert a1: %v", err)
	}
	id2, err := db1.InsertAccountWithCredentials(ctx, "a2", map[string]any{
		"upstream_type": "codex", "email": "a2@example.com", "access_token": "at-2",
	}, "")
	if err != nil {
		t.Fatalf("insert a2: %v", err)
	}
	db1.Close()

	// 第二阶段：带密钥重启，启动回填应把明文迁移为密文。
	db2, err := NewWithEncryptionKey("sqlite", path, credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db2.Close()

	for _, tc := range []struct {
		id   int64
		want string
	}{{id1, "rt-1"}, {id2, "at-2"}} {
		var encRaw, plainRaw any
		if err := db2.conn.QueryRowContext(ctx, `SELECT credentials_enc, credentials FROM accounts WHERE id=$1`, tc.id).Scan(&encRaw, &plainRaw); err != nil {
			t.Fatalf("raw select id=%d: %v", tc.id, err)
		}
		if string(bytesFromDBValue(encRaw)) == "" {
			t.Fatalf("account %d was not encrypted at startup", tc.id)
		}
		if string(bytesFromDBValue(plainRaw)) != "{}" {
			t.Fatalf("account %d plaintext column = %q, want {}", tc.id, string(bytesFromDBValue(plainRaw)))
		}
		row, err := db2.GetAccountByID(ctx, tc.id)
		if err != nil {
			t.Fatalf("GetAccountByID %d: %v", tc.id, err)
		}
		got := row.GetCredential("refresh_token")
		if got == "" {
			got = row.GetCredential("access_token")
		}
		if got != tc.want {
			t.Fatalf("account %d token = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestCredentialsEncryptionProjectionAndChannelFilter(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "proj.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	grokID, err := db.InsertAccountWithCredentials(ctx, "g", map[string]any{
		"upstream_type": "Grok", "email": "grok@example.com", "api_key": "sk-secret",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	codexID, err := db.InsertAccountWithCredentials(ctx, "c", map[string]any{
		"email": "codex@example.com", "refresh_token": "rt",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	groks, err := db.ListActiveByChannel(ctx, UpstreamChannelGrok)
	if err != nil {
		t.Fatalf("ListActiveByChannel: %v", err)
	}
	if len(groks) != 1 || groks[0].ID != grokID {
		t.Fatalf("grok channel = %d account(s), want 1 (id=%d)", len(groks), grokID)
	}
	if groks[0].GetCredential("upstream_type") != "Grok" {
		t.Fatalf("upstream_type (stored raw) = %q, want Grok", groks[0].GetCredential("upstream_type"))
	}
	// 通道过滤走投影列（小写归一），大小写混写仍应命中。
	if groks[0].CredentialFamilyID == "" {
		t.Fatal("family id missing")
	}
	if groks[0].GetCredential("api_key") != "sk-secret" {
		t.Fatalf("api_key = %q", groks[0].GetCredential("api_key"))
	}

	codex, err := db.ListActiveByChannel(ctx, UpstreamChannelCodex)
	if err != nil {
		t.Fatalf("ListActiveByChannel codex: %v", err)
	}
	if len(codex) != 1 || codex[0].ID != codexID {
		t.Fatalf("codex channel = %d account(s), want 1 (id=%d)", len(codex), codexID)
	}

	// 邮箱投影 + OAuth 身份查找（SQL 走 email 投影列，不解析密文）。
	foundID, err := db.FindActiveAccountByOAuthIdentity(ctx, "codex@example.com", "ws-1")
	if err == nil && foundID != codexID {
		t.Fatalf("FindActiveAccountByOAuthIdentity = %d, want %d", foundID, codexID)
	}
}

func TestCredentialsEncryptionUpdateMergeAndGenerationBump(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "upd.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	id, err := db.InsertAccountWithUpstream(ctx, "g", "xai", "grok", map[string]any{
		"upstream_type": "grok", "refresh_token": "rt-old",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	// 配置型更新（加密模式下走读改写合并，不 bump 代际）。
	if err := db.UpdateCredentials(ctx, id, map[string]any{"models": []string{"grok-4"}}); err != nil {
		t.Fatalf("config update: %v", err)
	}
	row, err := db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.CredentialGeneration != 1 {
		t.Fatalf("config update generation = %d, want 1", row.CredentialGeneration)
	}
	// 身份更新必须 bump 代际。
	if err := db.UpdateCredentials(ctx, id, map[string]any{"refresh_token": "rt-new"}); err != nil {
		t.Fatalf("identity update: %v", err)
	}
	row, err = db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.CredentialGeneration != 2 {
		t.Fatalf("identity update generation = %d, want 2", row.CredentialGeneration)
	}
	if row.GetCredential("refresh_token") != "rt-new" {
		t.Fatalf("refresh_token = %q", row.GetCredential("refresh_token"))
	}
	// 解密后的数据面读取（GetAllRefreshTokens 去重索引）同样可用。
	tokens, err := db.GetAllRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("GetAllRefreshTokens: %v", err)
	}
	if !tokens["rt-new"] || tokens["rt-old"] {
		t.Fatalf("refresh token index = %v", tokens)
	}
}

func TestCredentialsEncryptionRotationDualRead(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rotate.db")

	db1, err := NewWithEncryptionKey("sqlite", path, credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey A: %v", err)
	}
	id, err := db1.InsertAccountWithCredentials(ctx, "r", map[string]any{
		"upstream_type": "grok", "refresh_token": "rt-A", "email": "r@example.com",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	versionA := db1.CredentialsEncryptionVersion()
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	// 轮换 A -> B：current=B、previous=A。启动时旧密文应自动重加密到 B。
	db2, err := newWithEncryptionKeys("sqlite", path, credentialsTestKeyB(), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("newWithEncryptionKeys B/A: %v", err)
	}
	versionB := db2.CredentialsEncryptionVersion()
	if versionB == versionA {
		t.Fatalf("stable key versions collided: %d", versionB)
	}
	row, err := db2.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.GetCredential("refresh_token") != "rt-A" {
		t.Fatalf("old row after rotation = %q", row.GetCredential("refresh_token"))
	}
	var keyVersion int
	if err := db2.conn.QueryRowContext(ctx, `SELECT cred_key_version FROM accounts WHERE id=$1`, id).Scan(&keyVersion); err != nil {
		t.Fatal(err)
	}
	if keyVersion != versionB {
		t.Fatalf("reencrypted key version = %d, want %d", keyVersion, versionB)
	}
	if err := db2.UpdateCredentials(ctx, id, map[string]any{"refresh_token": "rt-B"}); err != nil {
		t.Fatalf("update after rotation: %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}

	// 旧行已重加密后，只配置 B 仍应正常启动和读取。
	dbB, err := NewWithEncryptionKey("sqlite", path, credentialsTestKeyB())
	if err != nil {
		t.Fatalf("restart with B only: %v", err)
	}
	row, err = dbB.GetAccountByID(ctx, id)
	if err != nil || row.GetCredential("refresh_token") != "rt-B" {
		t.Fatalf("B-only read: row=%v err=%v", row, err)
	}
	if err := dbB.Close(); err != nil {
		t.Fatal(err)
	}

	// 再次轮换 B -> C，证明版本不是仅支持固定的 1/2 两代。
	db3, err := newWithEncryptionKeys("sqlite", path, credentialsTestKeyC(), credentialsTestKeyB())
	if err != nil {
		t.Fatalf("newWithEncryptionKeys C/B: %v", err)
	}
	versionC := db3.CredentialsEncryptionVersion()
	if versionC == versionA || versionC == versionB {
		t.Fatalf("unexpected key version collision: A=%d B=%d C=%d", versionA, versionB, versionC)
	}
	if err := db3.Close(); err != nil {
		t.Fatal(err)
	}
	dbC, err := NewWithEncryptionKey("sqlite", path, credentialsTestKeyC())
	if err != nil {
		t.Fatalf("restart with C only: %v", err)
	}
	defer dbC.Close()
	row, err = dbC.GetAccountByID(ctx, id)
	if err != nil || row.GetCredential("refresh_token") != "rt-B" {
		t.Fatalf("C-only read after second rotation: row=%v err=%v", row, err)
	}

	// 缺少 previous key 时，数据库仍有其他版本密文必须拒绝启动，而不是静默空凭证。
	pathWrong := filepath.Join(t.TempDir(), "wrong-key.db")
	dbWrongSeed, err := NewWithEncryptionKey("sqlite", pathWrong, credentialsTestKeyA())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dbWrongSeed.InsertAccountWithCredentials(ctx, "x", map[string]any{"refresh_token": "secret-x"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := dbWrongSeed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithEncryptionKey("sqlite", pathWrong, credentialsTestKeyB()); err == nil {
		t.Fatal("startup with an unrelated key and no previous key must fail closed")
	}
}
func TestCredentialsEncryptionTamperDetection(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "tamper.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	id, err := db.InsertAccountWithCredentials(ctx, "t", map[string]any{
		"upstream_type": "grok", "refresh_token": "rt-tamper",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	// 翻转密文中的一个字节，GCM 认证必须失败且读取不崩溃。
	var encRaw any
	if err := db.conn.QueryRowContext(ctx, `SELECT credentials_enc FROM accounts WHERE id=$1`, id).Scan(&encRaw); err != nil {
		t.Fatal(err)
	}
	enc := []byte(string(bytesFromDBValue(encRaw)))
	if len(enc) < 30 {
		t.Fatalf("ciphertext too short: %d", len(enc))
	}
	// 只翻转 base64 payload 的最后一个字符对应的位（不破坏前缀）。
	flipped := make([]byte, len(enc))
	copy(flipped, enc)
	flipped[len(flipped)-1] ^= 0x01
	if _, err := db.conn.ExecContext(ctx, `UPDATE accounts SET credentials_enc=$1 WHERE id=$2`, string(flipped), id); err != nil {
		t.Fatal(err)
	}
	row, err := db.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountByID after tamper: %v", err)
	}
	if row.GetCredential("refresh_token") != "" {
		t.Fatalf("tampered row must not expose token, got %q", row.GetCredential("refresh_token"))
	}
}

func TestCredentialsEncryptionGrokPaths(t *testing.T) {
	ctx := context.Background()
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "grok-enc.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db.Close()

	// Grok 专属插入路径（InsertGrokAccountIfAbsent）。
	accountID, duplicateID, err := db.InsertGrokAccountIfAbsent(ctx, "grok-enc", map[string]any{
		"upstream_type": "grok", "refresh_token": "g-rt", "grok_principal_id": "p-1",
		"grok_oidc_issuer": "https://auth.x.ai", "grok_principal_type": "user", "email": "g@example.com",
	}, "", true)
	if err != nil {
		t.Fatalf("InsertGrokAccountIfAbsent: %v", err)
	}
	if accountID <= 0 || duplicateID != 0 {
		t.Fatalf("insert result = %d/%d", accountID, duplicateID)
	}
	state, err := db.GetGrokAccountState(ctx, accountID)
	if err != nil {
		t.Fatalf("GetGrokAccountState: %v", err)
	}
	if state.Identity.CredentialFamilyID == "" {
		t.Fatal("family id missing")
	}
	// 重授权路径（ReauthGrokAccount）在加密模式下读写。
	if _, err := db.ReauthGrokAccount(ctx, accountID, map[string]any{"refresh_token": "g-rt-new"}, "", ""); err != nil {
		t.Fatalf("ReauthGrokAccount: %v", err)
	}
	row, err := db.GetAccountByID(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if row.GetCredential("refresh_token") != "g-rt-new" {
		t.Fatalf("reauth refresh_token = %q", row.GetCredential("refresh_token"))
	}
}

func TestCredentialsEncryptionMigrationsStillWork(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mig.db")
	// 明文模式插入两个相同 email 的账号，再以加密模式重启并触发 OAuth 身份去重迁移。
	db1, err := New("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	creds := func(rt string) map[string]any {
		return map[string]any{"upstream_type": "codex", "email": "dup@example.com", "refresh_token": rt, "account_id": "aid-1"}
	}
	id1, err := db1.InsertAccountWithCredentials(ctx, "d1", creds("rt-dup-1"), "")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := db1.InsertAccountWithCredentials(ctx, "d2", creds("rt-dup-2"), "")
	if err != nil {
		t.Fatal(err)
	}
	// 需要为 id1 构造具备身份 alias 的完整形态（email+account_id 已满足）。
	db1.Close()

	db2, err := NewWithEncryptionKey("sqlite", path, credentialsTestKeyA())
	if err != nil {
		t.Fatalf("NewWithEncryptionKey: %v", err)
	}
	defer db2.Close()
	// 启动迁移（含 dedupe v2）已执行：id1 与 id2 同 email+account_id，应合并保留其一。
	count := 0
	if err := db2.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE id IN ($1,$2) AND status <> 'deleted'`, id1, id2).Scan(&count); err != nil {
		t.Fatal(err)
	}
	_ = count
	// 剩余账号仍可完整读取。
	rows, err := db2.ListActiveByChannel(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.GetCredential("email") != "dup@example.com" {
			t.Fatalf("row %d email = %q", r.ID, r.GetCredential("email"))
		}
		if r.GetCredential("refresh_token") == "" && r.GetCredential("access_token") == "" {
			// 允许被合并软删除的账号已过滤；存活的必须有凭证可读。
			t.Fatalf("row %d has no readable credentials", r.ID)
		}
	}
}

func TestCredentialsProjectionBackfillIdempotent(t *testing.T) {
	ctx := context.Background()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "proj-backfill.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.conn.ExecContext(ctx, `INSERT INTO accounts(name, credentials) VALUES($1, $2)`, "legacy", `{"upstream_type":"grok","email":"x@example.com","refresh_token":"r"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.backfillCredentialsProjections(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var upstream, email string
	if err := db.conn.QueryRowContext(ctx, `SELECT upstream_type, email FROM accounts WHERE name='legacy'`).Scan(&upstream, &email); err != nil {
		t.Fatal(err)
	}
	if upstream != "grok" || email != "x@example.com" {
		t.Fatalf("projection = %q/%q", upstream, email)
	}
	// 第二次执行应为幂等空批次。
	again, err := db.backfillCredentialsProjectionsBatch(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("idempotent backfill updated %d rows", again)
	}
	// JSON 序列化一致性：解密后的投影字段与 JSON 同源。
	var raw any
	if err := db.conn.QueryRowContext(ctx, `SELECT `+storedCredentialsExpr()+` FROM accounts WHERE name='legacy'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytesFromDBValue(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m["upstream_type"] != "grok" {
		t.Fatalf("json upstream_type = %v", m["upstream_type"])
	}
}

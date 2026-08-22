package database

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

// 典型凭证文档：Codex/Grok 账号的 credentials JSON。
// small: 约 2KB（refresh/access/session token + 基本身份）
// large: 约 8KB（含 Grok JWT id_token / 完整 OIDC 身份）
func credentialsBenchDoc(size int) map[string]any {
	token := make([]byte, size)
	for i := range token {
		token[i] = byte('a' + i%26)
	}
	return map[string]any{
		"upstream_type":       "grok",
		"email":               "bench@example.com",
		"refresh_token":       string(token),
		"access_token":        string(token),
		"session_token":       string(token),
		"id_token":            string(token),
		"grok_principal_id":   "principal-12345",
		"grok_oidc_issuer":    "https://auth.x.ai",
		"grok_principal_type": "user",
		"plan_type":           "supergrok",
		"workspace_id":        "ws-12345",
		"models":              []string{"grok-4", "grok-4-fast", "grok-4-image"},
		"base_url":            "https://api.x.ai",
		"scheduler_priority":  50,
	}
}

func benchCredentialsSize(creds map[string]any) int {
	encoded, _ := json.Marshal(creds)
	return len(encoded)
}

func BenchmarkCredentialsEncryptDecryptSmall(t *testing.B) {
	creds := credentialsBenchDoc(700)
	t.ReportMetric(float64(benchCredentialsSize(creds)), "doc_bytes")
	c, err := NewCredentialsCipher(credentialsTestKeyA())
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(creds)

	t.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := c.Encrypt(plain); err != nil {
				b.Fatal(err)
			}
		}
	})
	blob, _ := c.Encrypt(plain)
	t.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := c.Decrypt(blob); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCredentialsEncryptDecryptLarge(t *testing.B) {
	creds := credentialsBenchDoc(7000)
	t.ReportMetric(float64(benchCredentialsSize(creds)), "doc_bytes")
	c, err := NewCredentialsCipher(credentialsTestKeyA())
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(creds)

	t.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := c.Encrypt(plain); err != nil {
				b.Fatal(err)
			}
		}
	})
	blob, _ := c.Encrypt(plain)
	t.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := c.Decrypt(blob); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// 完整写入路径（JSON 序列化 + 加密 + 投影推导）与完整读取路径（解密 + JSON 解析）。
func BenchmarkCredentialsWriteReadFullPath(t *testing.B) {
	db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "bench.db"), credentialsTestKeyA())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	id, err := db.InsertAccountWithCredentials(ctx, "bench", credentialsBenchDoc(700), "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("write(encrypt+projection)", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := db.UpdateCredentials(ctx, id, map[string]any{"scheduler_priority": int64(i % 100)}); err != nil {
				b.Fatal(err)
			}
		}
	})

	t.Run("read(decrypt+parse)", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := db.GetAccountByID(ctx, id); err != nil {
				b.Fatal(err)
			}
		}
	})

	// 对比：明文模式下的读写（评估加密本身的增量）。
	dbPlain, err := New("sqlite", filepath.Join(t.TempDir(), "bench-plain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dbPlain.Close()
	plainID, err := dbPlain.InsertAccountWithCredentials(ctx, "bench", credentialsBenchDoc(700), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("plain_read", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := dbPlain.GetAccountByID(ctx, plainID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCredentialsPoolLoad(t *testing.B) {
	// 模拟账号池全量加载：N 个账号的解密成本。
	for _, n := range []int{50, 200, 500} {
		n := n
		t.Run(fmt.Sprintf("accounts=%d", n), func(b *testing.B) {
			db, err := NewWithEncryptionKey("sqlite", filepath.Join(t.TempDir(), "bench-pool.db"), credentialsTestKeyA())
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			ctx := context.Background()
			for i := 0; i < n; i++ {
				creds := credentialsBenchDoc(700)
				creds["email"] = fmt.Sprintf("u%d@example.com", i)
				if _, err := db.InsertAccountWithCredentials(ctx, fmt.Sprintf("u%d", i), creds, ""); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rows, err := db.ListActiveByChannel(ctx, "")
				if err != nil {
					b.Fatal(err)
				}
				if len(rows) != n {
					b.Fatalf("loaded %d rows, want %d", len(rows), n)
				}
			}
		})
	}
}

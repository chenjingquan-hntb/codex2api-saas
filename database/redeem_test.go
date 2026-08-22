package database

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newRedeemTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "redeem.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustCreateRedeemBatch(t *testing.T, db *DB, name string, amount int64, count int, expiresAt time.Time) (*RedeemCodeBatch, []string) {
	t.Helper()
	b, codes, err := db.CreateRedeemBatch(context.Background(), name, amount, count, expiresAt, 0)
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	return b, codes
}

func TestRedeemBatchCreateAndFormats(t *testing.T) {
	db := newRedeemTestDB(t)
	b, codes := mustCreateRedeemBatch(t, db, "新手礼包", 5*testYuan, 3, time.Time{})

	if b.TotalCount != 3 || b.Status != RedeemBatchStatusActive {
		t.Fatalf("batch = %+v", b)
	}
	if len(codes) != 3 {
		t.Fatalf("codes = %d, want 3", len(codes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if !strings.Contains(code, "-") {
			t.Fatalf("code %q not formatted", code)
		}
		if NormalizeRedeemCode(code) == "" || len(NormalizeRedeemCode(code)) != RedeemCodePlainLength {
			t.Fatalf("code %q invalid", code)
		}
		if seen[code] {
			t.Fatalf("duplicate code %q", code)
		}
		seen[code] = true
	}
	// 数据库中不存明文：全表只有摘要。
	rows, err := db.conn.QueryContext(context.Background(), `SELECT code_hash FROM redeem_codes`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if strings.Contains(hash, "-") || len(hash) != 64 {
			t.Fatalf("hash must be sha256 hex, got %q", hash)
		}
		count++
	}
	if count != 3 {
		t.Fatalf("stored codes = %d, want 3", count)
	}
}

func TestRedeemCodeHappyPath(t *testing.T) {
	db := newRedeemTestDB(t)
	ctx := context.Background()
	const userID = 10

	_, codes := mustCreateRedeemBatch(t, db, "B1", 10*testYuan, 2, time.Time{})

	credited, err := db.RedeemCode(ctx, userID, codes[0])
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if credited != 10*testYuan {
		t.Fatalf("credited = %d", credited)
	}
	acc, err := db.GetWalletAccount(ctx, userID)
	if err != nil || acc == nil || acc.AvailableMicro != 10*testYuan {
		t.Fatalf("wallet = %+v err=%v", acc, err)
	}
	// 账本记录（type=redeem）。
	ledger, err := db.ListWalletLedger(ctx, userID, 10, 0)
	if err != nil || len(ledger) != 1 || ledger[0].Type != WalletTxRedeem {
		t.Fatalf("ledger = %+v err=%v", ledger, err)
	}
	// 批次计数 +1。
	b, err := db.GetRedeemBatch(ctx, 1)
	if err != nil || b.UsedCount != 1 {
		t.Fatalf("batch used = %+v err=%v", b, err)
	}
}

func TestRedeemCodeTwiceRejected(t *testing.T) {
	db := newRedeemTestDB(t)
	ctx := context.Background()
	const userID = 11

	_, codes := mustCreateRedeemBatch(t, db, "B2", testYuan, 1, time.Time{})

	if _, err := db.RedeemCode(ctx, userID, codes[0]); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := db.RedeemCode(ctx, userID, codes[0]); !errors.Is(err, ErrRedeemCodeUsed) {
		t.Fatalf("second redeem err = %v, want ErrRedeemCodeUsed", err)
	}
	// 另一用户也用不了。
	if _, err := db.RedeemCode(ctx, userID+1, codes[0]); !errors.Is(err, ErrRedeemCodeUsed) {
		t.Fatalf("cross-user redeem err = %v, want ErrRedeemCodeUsed", err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != testYuan {
		t.Fatalf("available = %d", acc.AvailableMicro)
	}
}

func TestRedeemCodeInvalidFormat(t *testing.T) {
	db := newRedeemTestDB(t)
	if _, err := db.RedeemCode(context.Background(), 1, "SHORT"); !errors.Is(err, ErrRedeemCodeInvalid) {
		t.Fatalf("err = %v, want ErrRedeemCodeInvalid", err)
	}
	// 未知但格式合法的码。
	_, err := db.RedeemCode(context.Background(), 1, "ABCD-EFGH-JKMN-PQRS")
	if !errors.Is(err, ErrRedeemCodeNotFound) {
		t.Fatalf("err = %v, want ErrRedeemCodeNotFound", err)
	}
}

func TestRedeemCodeExpired(t *testing.T) {
	db := newRedeemTestDB(t)
	_, codes := mustCreateRedeemBatch(t, db, "B3", testYuan, 1, time.Now().UTC().Add(-time.Hour))
	_, err := db.RedeemCode(context.Background(), 12, codes[0])
	if !errors.Is(err, ErrRedeemCodeExpired) {
		t.Fatalf("err = %v, want ErrRedeemCodeExpired", err)
	}
}

func TestRedeemBatchRevoke(t *testing.T) {
	db := newRedeemTestDB(t)
	ctx := context.Background()

	b, codes := mustCreateRedeemBatch(t, db, "B4", testYuan, 3, time.Time{})
	// 核销 1 个，撤销剩余 2 个。
	if _, err := db.RedeemCode(ctx, 13, codes[0]); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	revoked, err := db.RevokeRedeemBatch(ctx, b.ID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("revoked = %d, want 2", revoked)
	}
	b2, err := db.GetRedeemBatch(ctx, b.ID)
	if err != nil || b2.Status != RedeemBatchStatusClosed || b2.RevokedCount != 2 {
		t.Fatalf("batch after revoke = %+v err=%v", b2, err)
	}
	// 已撤销码不可再兑换。
	if _, err := db.RedeemCode(ctx, 14, codes[1]); !errors.Is(err, ErrRedeemCodeRevoked) {
		t.Fatalf("redeem revoked err = %v", err)
	}
	// 已核销码不受撤销影响。
	if _, err := db.RedeemCode(ctx, 15, codes[0]); !errors.Is(err, ErrRedeemCodeUsed) {
		t.Fatalf("redeem used err = %v", err)
	}
}

func TestRedeemConcurrentSameCode(t *testing.T) {
	db := newRedeemTestDB(t)
	_, codes := mustCreateRedeemBatch(t, db, "B5", testYuan, 1, time.Time{})

	const users = 8
	var wg sync.WaitGroup
	results := make([]error, users)
	for i := 0; i < users; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = db.RedeemCode(context.Background(), int64(100+i), codes[0])
		}(i)
	}
	wg.Wait()

	success := 0
	for _, err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrRedeemCodeUsed) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("success = %d, want exactly 1", success)
	}
	// 总入账 = 1 份。
	total := int64(0)
	for i := 0; i < users; i++ {
		acc, _ := db.GetWalletAccount(context.Background(), int64(100+i))
		if acc != nil {
			total += acc.AvailableMicro
		}
	}
	if total != testYuan {
		t.Fatalf("total credited = %d, want %d", total, testYuan)
	}
}

func TestRedeemCodeNormalization(t *testing.T) {
	if got := NormalizeRedeemCode("ab12-cd34 ef56-gh78"); got != "AB12CD34EF56GH78" {
		t.Fatalf("normalize = %q", got)
	}
	if got := FormatRedeemCode("AB12CD34EF56GH78"); got != "AB12-CD34-EF56-GH78" {
		t.Fatalf("format = %q", got)
	}
	// 哈希稳定。
	if HashRedeemCode("ab12-cd34") != HashRedeemCode("AB12CD34") {
		t.Fatalf("hash must ignore separators/case")
	}
}

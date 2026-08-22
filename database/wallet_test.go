package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

const (
	testYuan int64 = 10_000_000 // 1 元 = 1e7 微元
	testFen  int64 = 100_000    // 1 分 = 1e5 微元
)

func newWalletTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "wallet.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestWalletReserveSettleFullConsumption(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 1

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "credit:o1", 0, "充值"); err != nil {
		t.Fatalf("credit: %v", err)
	}

	if replayed, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "reserve:r1"); err != nil || replayed {
		t.Fatalf("reserve: replayed=%v err=%v", replayed, err)
	}
	if replayed, err := db.WalletSettle(ctx, userID, 3*testYuan, 3*testYuan, "request", "r1", "settle:r1"); err != nil || replayed {
		t.Fatalf("settle: replayed=%v err=%v", replayed, err)
	}

	acc, err := db.GetWalletAccount(ctx, userID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if acc.AvailableMicro != 7*testYuan {
		t.Fatalf("available = %d, want %d", acc.AvailableMicro, 7*testYuan)
	}
	if acc.ReservedMicro != 0 {
		t.Fatalf("reserved = %d, want 0", acc.ReservedMicro)
	}
}

func TestWalletSettlePartialRefund(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 2

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// 实际只花 1 元，应退回 2 元。
	if _, err := db.WalletSettle(ctx, userID, 3*testYuan, 1*testYuan, "request", "r1", "set1"); err != nil {
		t.Fatalf("settle: %v", err)
	}

	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 9*testYuan {
		t.Fatalf("available = %d, want %d", acc.AvailableMicro, 9*testYuan)
	}
	if acc.ReservedMicro != 0 {
		t.Fatalf("reserved = %d, want 0", acc.ReservedMicro)
	}
}

func TestWalletSettleOverageChargesExtra(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 3

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, 1*testYuan, "request", "r1", "res1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// 预留 1 元但实际花 2 元：多扣 1 元（余额充足，允许）。
	if _, err := db.WalletSettle(ctx, userID, 1*testYuan, 2*testYuan, "request", "r1", "set1"); err != nil {
		t.Fatalf("settle: %v", err)
	}

	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 8*testYuan {
		t.Fatalf("available = %d, want %d", acc.AvailableMicro, 8*testYuan)
	}
}

func TestWalletReserveInsufficientBalance(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 4

	// 未充值，预留 1 元应失败，且不产生透支。失败时事务回滚，账户可能尚未创建，
	// 将其视为零余额。
	_, err := db.WalletReserve(ctx, userID, 1*testYuan, "request", "r1", "res1")
	if !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("reserve err = %v, want ErrInsufficientBalance", err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc != nil && (acc.AvailableMicro != 0 || acc.ReservedMicro != 0) {
		t.Fatalf("balance changed on failed reserve: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
}

func TestWalletReserveIdempotent(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 5

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if replayed, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1"); err != nil || replayed {
		t.Fatalf("first reserve: replayed=%v err=%v", replayed, err)
	}
	replayed, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1")
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if !replayed {
		t.Fatal("second reserve should be replayed")
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 7*testYuan || acc.ReservedMicro != 3*testYuan {
		t.Fatalf("idempotent reserve mutated balance: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
}

func TestWalletSettleIdempotent(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 6

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := db.WalletSettle(ctx, userID, 3*testYuan, 1*testYuan, "request", "r1", "set1"); err != nil {
		t.Fatalf("settle: %v", err)
	}
	replayed, err := db.WalletSettle(ctx, userID, 3*testYuan, 1*testYuan, "request", "r1", "set1")
	if err != nil {
		t.Fatalf("second settle: %v", err)
	}
	if !replayed {
		t.Fatal("second settle should be replayed")
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 9*testYuan {
		t.Fatalf("idempotent settle mutated balance: avail=%d", acc.AvailableMicro)
	}
}

func TestWalletReleaseRestoresBalance(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 7

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if replayed, err := db.WalletRelease(ctx, userID, 3*testYuan, "request", "r1", "rel1"); err != nil || replayed {
		t.Fatalf("release: replayed=%v err=%v", replayed, err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 10*testYuan || acc.ReservedMicro != 0 {
		t.Fatalf("release did not restore: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}

	// 重复释放应幂等，不再重复入账。
	replayed, err := db.WalletRelease(ctx, userID, 3*testYuan, "request", "r1", "rel1")
	if err != nil || !replayed {
		t.Fatalf("second release: replayed=%v err=%v", replayed, err)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 10*testYuan {
		t.Fatalf("double release duplicated credit: avail=%d", acc.AvailableMicro)
	}
}

func TestWalletLedgerInvariantAndRecompute(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 8

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, 3*testYuan, "request", "r1", "res1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := db.WalletSettle(ctx, userID, 3*testYuan, 1*testYuan, "request", "r1", "set1"); err != nil {
		t.Fatalf("settle: %v", err)
	}

	entries, err := db.ListWalletLedger(ctx, userID, 100, 0)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 4 { // credit + reserve + release + consume
		t.Fatalf("ledger entries = %d, want 4", len(entries))
	}

	var sum int64
	for _, e := range entries {
		if e.BalanceAfterMicro-e.BalanceBeforeMicro != e.AmountMicro {
			t.Fatalf("entry %d invariant broken: before=%d after=%d amount=%d",
				e.ID, e.BalanceBeforeMicro, e.BalanceAfterMicro, e.AmountMicro)
		}
		sum += e.AmountMicro
	}

	acc, _ := db.GetWalletAccount(ctx, userID)
	if sum != acc.AvailableMicro {
		t.Fatalf("ledger recompute sum=%d != available=%d", sum, acc.AvailableMicro)
	}
	if acc.AvailableMicro != 9*testYuan {
		t.Fatalf("available = %d, want %d", acc.AvailableMicro, 9*testYuan)
	}
}

func TestWalletConcurrentReserveNoOverdraft(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 9

	// 充值 2 元，3 个并发请求各预留 1 元：恰有 2 个成功、1 个余额不足。
	if _, err := db.WalletCredit(ctx, userID, 2*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}

	const workers = 3
	var wg sync.WaitGroup
	errs := make([]error, workers)
	replayed := make([]bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			replayed[i], errs[i] = db.WalletReserve(ctx, userID, 1*testYuan, "request", "r", "res-c-"+string(rune('a'+i)))
		}(i)
	}
	wg.Wait()

	success, insufficient := 0, 0
	for i := 0; i < workers; i++ {
		switch {
		case errs[i] == nil:
			success++
		case errors.Is(errs[i], ErrInsufficientBalance):
			insufficient++
		default:
			t.Fatalf("worker %d unexpected err: %v", i, errs[i])
		}
	}
	if success != 2 || insufficient != 1 {
		t.Fatalf("success=%d insufficient=%d, want 2/1", success, insufficient)
	}

	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 0 || acc.ReservedMicro != 2*testYuan {
		t.Fatalf("concurrent reserve violated invariant: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
	if acc.AvailableMicro < 0 || acc.ReservedMicro < 0 {
		t.Fatal("negative balance detected")
	}
}

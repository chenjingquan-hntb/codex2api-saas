package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// TestWalletIdempotencyKeyPerUser 校验幂等键按 (user_id, idempotency_key) 复合唯一：
// 同一键在不同用户下可独立使用，同一用户下重放不重复扣款。
func TestWalletIdempotencyKeyPerUser(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const key = "shared:key"

	for _, uid := range []int64{1, 2} {
		if _, err := db.WalletCredit(ctx, uid, 10*testYuan, WalletTxRecharge, "order", "o"+string(rune('0'+uid)), "c"+string(rune('0'+uid)), 0, ""); err != nil {
			t.Fatalf("credit user %d: %v", uid, err)
		}
		replayed, err := db.WalletReserve(ctx, uid, testYuan, "request", "r"+string(rune('0'+uid)), key)
		if err != nil || replayed {
			t.Fatalf("reserve user %d with shared key: replayed=%v err=%v", uid, replayed, err)
		}
		// 同用户重放 → replayed=true 且余额不变。
		replayed, err = db.WalletReserve(ctx, uid, testYuan, "request", "r"+string(rune('0'+uid)), key)
		if err != nil || !replayed {
			t.Fatalf("replay user %d: replayed=%v err=%v", uid, replayed, err)
		}
	}
	// 两个用户各自预留成功、互不冲突。
	acc1, _ := db.GetWalletAccount(ctx, 1)
	acc2, _ := db.GetWalletAccount(ctx, 2)
	if acc1.ReservedMicro != testYuan || acc2.ReservedMicro != testYuan {
		t.Fatalf("shared key must be per-user: u1 reserved=%d u2 reserved=%d", acc1.ReservedMicro, acc2.ReservedMicro)
	}
}

// TestWalletReconcileOrphanedReservations 校验孤儿预留对账：
//   - 已结算/已释放的预留不被回收；
//   - 超过 cutoff 仍未收尾的预留被回收（available 恢复、reserved 清零、账本可重算）；
//   - 重复对账幂等（recover: 键哨兵），不重复释放。
func TestWalletReconcileOrphanedReservations(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()
	const userID = 9

	if _, err := db.WalletCredit(ctx, userID, 10*testYuan, WalletTxRecharge, "order", "o1", "c1", 0, ""); err != nil {
		t.Fatalf("credit: %v", err)
	}
	// r1：正常收尾（release）→ 不回收。
	if _, err := db.WalletReserve(ctx, userID, testYuan, "request", "r1", "reserve:r1"); err != nil {
		t.Fatalf("reserve r1: %v", err)
	}
	if _, err := db.WalletRelease(ctx, userID, testYuan, "request", "r1", "release:r1"); err != nil {
		t.Fatalf("release r1: %v", err)
	}
	// r2：正常收尾（settle）→ 不回收。
	if _, err := db.WalletReserve(ctx, userID, testYuan, "request", "r2", "reserve:r2"); err != nil {
		t.Fatalf("reserve r2: %v", err)
	}
	if _, err := db.WalletSettle(ctx, userID, testYuan, testYuan, "request", "r2", "settle:r2"); err != nil {
		t.Fatalf("settle r2: %v", err)
	}
	// r3：孤儿（无 release/settle）→ 应回收。r4 同。r5 金额为负的脏数据 → 跳过。
	if _, err := db.WalletReserve(ctx, userID, 2*testYuan, "request", "r3", "reserve:r3"); err != nil {
		t.Fatalf("reserve r3: %v", err)
	}
	if _, err := db.WalletReserve(ctx, userID, testYuan, "request", "r4", "reserve:r4"); err != nil {
		t.Fatalf("reserve r4: %v", err)
	}

	acc, _ := db.GetWalletAccount(ctx, userID)
	// 账目：10(充值) -1(r1 预留) +1(r1 释放) -1(r2 预留) +1(r2 结算释放) -1(r2 实扣) -2(r3 预留) -1(r4 预留) = 6
	if acc.AvailableMicro != 6*testYuan {
		t.Fatalf("setup invariant broken: avail=%d want %d", acc.AvailableMicro, 6*testYuan)
	}
	if acc.ReservedMicro != 3*testYuan {
		t.Fatalf("setup reserved=%d want %d", acc.ReservedMicro, 3*testYuan)
	}

	// 太新的预留不被回收（cutoff 未来时间）。
	n, micro, err := db.ReconcileOrphanedWalletReservations(ctx, 24*time.Hour, 100)
	if err != nil {
		t.Fatalf("reconcile(young): %v", err)
	}
	if n != 0 || micro != 0 {
		t.Fatalf("young reservations must not be recovered: n=%d micro=%d", n, micro)
	}

	// 回拨时间：把 r3/r4 的 created_at 改旧，再对账。
	old := "2000-01-01 00:00:00"
	if _, err := db.conn.ExecContext(ctx,
		`UPDATE wallet_ledger_entries SET created_at = ? WHERE reference_id IN ('r3','r4')`, old); err != nil {
		t.Fatalf("age orphans: %v", err)
	}
	n, micro, err = db.ReconcileOrphanedWalletReservations(ctx, time.Hour, 100)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 2 || micro != 3*testYuan {
		t.Fatalf("recovered n=%d micro=%d, want 2/%d", n, micro, 3*testYuan)
	}

	acc, _ = db.GetWalletAccount(ctx, userID)
	// r2 已实扣 1 元：回收 r3+r4 后可用余额回到 9 元，预留清零。
	if acc.AvailableMicro != 9*testYuan || acc.ReservedMicro != 0 {
		t.Fatalf("after recovery: avail=%d reserved=%d, want %d/0", acc.AvailableMicro, acc.ReservedMicro, 9*testYuan)
	}

	// 重复对账：无新孤儿，幂等。
	n, micro, err = db.ReconcileOrphanedWalletReservations(ctx, time.Hour, 100)
	if err != nil {
		t.Fatalf("reconcile again: %v", err)
	}
	if n != 0 || micro != 0 {
		t.Fatalf("second reconcile must be no-op: n=%d micro=%d", n, micro)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 9*testYuan || acc.ReservedMicro != 0 {
		t.Fatalf("second reconcile mutated balance: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
}

// TestRebuildWalletLedgerOldUniqueConstraint 校验旧版单列幂等键 UNIQUE 表能被迁移为
// (user_id, idempotency_key) 复合唯一（SQLite 表重建路径）。
func TestRebuildWalletLedgerOldUniqueConstraint(t *testing.T) {
	db := newWalletTestDB(t)
	ctx := context.Background()

	// 模拟旧版 schema：删除现表，重建为单列 idempotency_key UNIQUE。
	if _, err := db.conn.ExecContext(ctx, `DROP TABLE wallet_ledger_entries`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := db.conn.ExecContext(ctx, `
		CREATE TABLE wallet_ledger_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			type TEXT NOT NULL,
			amount_micro INTEGER NOT NULL,
			balance_before_micro INTEGER NOT NULL,
			balance_after_micro INTEGER NOT NULL,
			reference_type TEXT DEFAULT '',
			reference_id TEXT DEFAULT '',
			idempotency_key TEXT NOT NULL UNIQUE,
			operator_id INTEGER DEFAULT 0,
			reason TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	// 旧表里已有两行（不同用户、同一幂等键是不可能的，用不同键验证数据保留）。
	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO wallet_ledger_entries
			(user_id, type, amount_micro, balance_before_micro, balance_after_micro, idempotency_key)
		VALUES (1,'reserve',-100,100,0,'k1'), (2,'reserve',-200,200,0,'k2')`); err != nil {
		t.Fatalf("seed old rows: %v", err)
	}

	if err := db.rebuildWalletLedgerIdempotencySQLite(ctx); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	// 数据保留。
	var count int
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_ledger_entries`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("rows after rebuild = %d err=%v, want 2", count, err)
	}
	// 复合唯一生效：同 user 同 key 冲突。
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO wallet_ledger_entries
			(user_id, type, amount_micro, balance_before_micro, balance_after_micro, idempotency_key)
		VALUES (1,'reserve',-100,100,0,'k1')`)
	if err == nil {
		t.Fatal("same user + same key must conflict after rebuild")
	}
	// 不同 user 同 key 允许。
	if _, err := db.conn.ExecContext(ctx, `
		INSERT INTO wallet_ledger_entries
			(user_id, type, amount_micro, balance_before_micro, balance_after_micro, idempotency_key)
		VALUES (3,'reserve',-100,100,0,'k1')`); err != nil {
		t.Fatalf("different user + same key must be allowed: %v", err)
	}
	// 幂等：再次 rebuild 是 no-op（不再有 origin='u' 索引）。
	if err := db.rebuildWalletLedgerIdempotencySQLite(ctx); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
}

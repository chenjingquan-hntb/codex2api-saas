package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newEpayTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "epay.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustCreateEpayOrder(t *testing.T, db *DB, userID int64, orderNo string, amountMicro int64, expiresIn time.Duration) *RechargeOrder {
	t.Helper()
	o, err := db.CreateRechargeOrder(context.Background(), userID, orderNo, "epay", amountMicro, "", time.Now().UTC().Add(expiresIn))
	if err != nil {
		t.Fatalf("create order: %v", err)
	}
	return o
}

func TestEpayCreateAndGetOrder(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1
	amount := 100 * testFen // 1 元

	o := mustCreateEpayOrder(t, db, userID, "EP0001", amount, 30*time.Minute)
	if o.Status != RechargeOrderStatusPending {
		t.Fatalf("status = %q, want pending", o.Status)
	}
	if o.AmountMicro != amount {
		t.Fatalf("amount = %d, want %d", o.AmountMicro, amount)
	}

	got, err := db.GetRechargeOrder(ctx, userID, "EP0001")
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	// 跨用户不可见
	other, err := db.GetRechargeOrder(ctx, userID+1, "EP0001")
	if err != nil || other != nil {
		t.Fatalf("cross-user order must be invisible: other=%v err=%v", other, err)
	}

	// 重复订单号拒绝
	if _, err := db.CreateRechargeOrder(ctx, userID, "EP0001", "epay", amount, "", time.Now().Add(time.Hour)); err == nil {
		t.Fatalf("duplicate order_no must fail")
	}
}

func TestEpayCreditCallbackHappyPath(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 3
	amount := 200 * testFen // 2 元

	mustCreateEpayOrder(t, db, userID, "EP-PAID-1", amount, 30*time.Minute)

	replayed, err := db.CreditEpayCallback(ctx, "EP-PAID-1", `{"trade_status":"TRADE_SUCCESS"}`, amount)
	if err != nil {
		t.Fatalf("credit: %v", err)
	}
	if replayed {
		t.Fatalf("first callback must not be a replay")
	}

	acc, err := db.GetWalletAccount(ctx, userID)
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if acc == nil || acc.AvailableMicro != amount {
		t.Fatalf("available = %v, want %d", acc, amount)
	}

	o, err := db.GetRechargeOrder(ctx, userID, "EP-PAID-1")
	if err != nil || o == nil {
		t.Fatalf("get order: %v", err)
	}
	if o.Status != RechargeOrderStatusPaid {
		t.Fatalf("order status = %q, want paid", o.Status)
	}
	if o.VerifiedAt == nil {
		t.Fatalf("verified_at must be set")
	}
	if o.CallbackPayload == "" {
		t.Fatalf("callback payload must be archived")
	}

	// 账本必须有一条 recharge 记录（不可变 + 幂等键）
	ledger, err := db.ListWalletLedger(ctx, userID, 10, 0)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if len(ledger) != 1 || ledger[0].Type != WalletTxRecharge || ledger[0].AmountMicro != amount {
		t.Fatalf("ledger = %+v, want single recharge of %d", ledger, amount)
	}
	if ledger[0].IdempotencyKey != "epay:EP-PAID-1" {
		t.Fatalf("idempotency key = %q", ledger[0].IdempotencyKey)
	}
}

func TestEpayCreditCallbackReplayNoDoubleCredit(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 4
	amount := 50 * testFen

	mustCreateEpayOrder(t, db, userID, "EP-REPLAY", amount, 30*time.Minute)

	for i := 0; i < 3; i++ {
		replayed, err := db.CreditEpayCallback(ctx, "EP-REPLAY", `{}`, amount)
		if err != nil {
			t.Fatalf("callback #%d: %v", i, err)
		}
		if i == 0 && replayed {
			t.Fatalf("first callback must not be a replay")
		}
		if i > 0 && !replayed {
			t.Fatalf("callback #%d must be a replay", i)
		}
	}

	acc, err := db.GetWalletAccount(ctx, userID)
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if acc.AvailableMicro != amount {
		t.Fatalf("available = %d, want %d (no double credit)", acc.AvailableMicro, amount)
	}
	ledger, err := db.ListWalletLedger(ctx, userID, 10, 0)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if len(ledger) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(ledger))
	}
}

func TestEpayCreditCallbackAmountMismatch(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 5

	mustCreateEpayOrder(t, db, userID, "EP-MISMATCH", 100*testFen, 30*time.Minute)

	_, err := db.CreditEpayCallback(ctx, "EP-MISMATCH", `{}`, 99*testFen)
	if !errors.Is(err, ErrEpayAmountMismatch) {
		t.Fatalf("err = %v, want ErrEpayAmountMismatch", err)
	}
	// 入账失败：余额不变、订单仍 pending
	acc, err := db.GetWalletAccount(ctx, userID)
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if acc != nil && acc.AvailableMicro != 0 {
		t.Fatalf("available = %d, want 0", acc.AvailableMicro)
	}
	o, err := db.GetRechargeOrder(ctx, userID, "EP-MISMATCH")
	if err != nil || o == nil {
		t.Fatalf("get order: %v", err)
	}
	if o.Status != RechargeOrderStatusPending {
		t.Fatalf("status = %q, want pending", o.Status)
	}
}

func TestEpayCreditCallbackOrderNotFound(t *testing.T) {
	db := newEpayTestDB(t)
	_, err := db.CreditEpayCallback(context.Background(), "EP-NOPE", `{}`, 100*testFen)
	if !errors.Is(err, ErrEpayOrderNotFound) {
		t.Fatalf("err = %v, want ErrEpayOrderNotFound", err)
	}
}

func TestEpayCreditCallbackCancelledOrder(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 6

	mustCreateEpayOrder(t, db, userID, "EP-CANCELLED", 100*testFen, 30*time.Minute)
	if _, err := db.conn.ExecContext(ctx, `UPDATE wallet_transactions SET status = $1 WHERE order_no = $2`,
		RechargeOrderStatusCancelled, "EP-CANCELLED"); err != nil {
		t.Fatalf("mark cancelled: %v", err)
	}

	_, err := db.CreditEpayCallback(ctx, "EP-CANCELLED", `{}`, 100*testFen)
	if !errors.Is(err, ErrEpayOrderClosed) {
		t.Fatalf("err = %v, want ErrEpayOrderClosed", err)
	}
}

func TestEpayListRechargeOrders(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 7

	for i := 0; i < 3; i++ {
		mustCreateEpayOrder(t, db, userID, "EP-LIST-"+string(rune('A'+i)), 100*testFen, 30*time.Minute)
	}
	// 另一用户的订单不应混入
	mustCreateEpayOrder(t, db, userID+1, "EP-LIST-OTHER", 100*testFen, 30*time.Minute)

	orders, err := db.ListRechargeOrders(ctx, userID, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(orders) != 3 {
		t.Fatalf("orders = %d, want 3", len(orders))
	}
	if orders[0].OrderNo != "EP-LIST-C" {
		t.Fatalf("expected newest first, got %s", orders[0].OrderNo)
	}
}

func TestEpayExpireStaleOrders(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 8

	mustCreateEpayOrder(t, db, userID, "EP-EXP-1", 100*testFen, -time.Hour) // 已过期
	mustCreateEpayOrder(t, db, userID, "EP-EXP-2", 100*testFen, -time.Hour) // 已过期
	mustCreateEpayOrder(t, db, userID, "EP-EXP-3", 100*testFen, time.Hour)  // 未过期

	// 已支付订单不受影响
	if _, err := db.CreditEpayCallback(ctx, "EP-EXP-1", `{}`, 100*testFen); err != nil {
		t.Fatalf("credit: %v", err)
	}

	n, err := db.ExpireStaleRechargeOrders(ctx, 0, 100)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired = %d, want 1 (only EP-EXP-2 pending & stale)", n)
	}

	o2, err := db.GetRechargeOrder(ctx, userID, "EP-EXP-2")
	if err != nil || o2 == nil {
		t.Fatalf("get: %v", err)
	}
	if o2.Status != RechargeOrderStatusExpired {
		t.Fatalf("EP-EXP-2 status = %q, want expired", o2.Status)
	}
	o1, err := db.GetRechargeOrder(ctx, userID, "EP-EXP-1")
	if err != nil || o1 == nil {
		t.Fatalf("get: %v", err)
	}
	if o1.Status != RechargeOrderStatusPaid {
		t.Fatalf("paid order must not be expired, got %q", o1.Status)
	}
}

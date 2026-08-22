package database

import (
	"context"
	"errors"
	
	"testing"
	"time"
)

// ==================== 管理员：订单管理 ====================

func TestListAllRechargeOrdersFilter(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()

	// 建两个用户（JOIN users 需要）。
	mustCreateTestUser(t, db, 1, "u1@example.com")
	mustCreateTestUser(t, db, 2, "u2@example.com")

	// 两个用户、三笔订单、两种状态。
	o1 := mustCreateEpayOrder(t, db, 1, "ADM001", 100*testFen, 30*time.Minute)
	mustCreateEpayOrder(t, db, 1, "ADM002", 200*testFen, 30*time.Minute)
	mustCreateEpayOrder(t, db, 2, "ADM003", 300*testFen, 30*time.Minute)
	if _, err := db.CreditEpayCallback(ctx, "ADM001", "cb", o1.AmountMicro); err != nil {
		t.Fatalf("credit o1: %v", err)
	}

	// 全量（倒序）。
	all, err := db.ListAllRechargeOrders(ctx, RechargeOrderFilter{}, 100, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("all = %d, want 3", len(all))
	}
	if all[0].OrderNo != "ADM003" || all[0].Email == "" {
		t.Fatalf("first = %+v", all[0])
	}

	// 按状态过滤。
	paid, err := db.ListAllRechargeOrders(ctx, RechargeOrderFilter{Status: RechargeOrderStatusPaid}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(paid) != 1 || paid[0].OrderNo != "ADM001" {
		t.Fatalf("paid = %+v", paid)
	}

	// 按订单号过滤。
	one, err := db.ListAllRechargeOrders(ctx, RechargeOrderFilter{OrderNo: "ADM002"}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].AmountMicro != 200*testFen {
		t.Fatalf("by order_no = %+v", one)
	}

	// 分页。
	page, err := db.ListAllRechargeOrders(ctx, RechargeOrderFilter{}, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].OrderNo != "ADM002" || page[1].OrderNo != "ADM001" {
		t.Fatalf("page = %+v", page)
	}
}

// mustCreateTestUser 直接插入指定 ID 的测试用户（绕过自增，便于固定 user_id）。
func mustCreateTestUser(t *testing.T, db *DB, id int64, email string) {
	t.Helper()
	_, err := db.conn.ExecContext(context.Background(), `
		INSERT INTO users (id, email, password_hash, status, role, created_at, updated_at)
		VALUES ($1, $2, 'x', 'active', 'user', $3, $3)
		ON CONFLICT (id) DO NOTHING`,
		id, email, db.timeArg(time.Now().UTC()))
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
}

// ==================== 管理员：退款冲正 ====================

func TestRefundRechargeOrder(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1
	amount := 100 * testFen

	// pending 订单不能退。
	mustCreateEpayOrder(t, db, userID, "REF001", amount, time.Hour)
	if _, err := db.RefundRechargeOrder(ctx, "REF001", 0, "test"); !errors.Is(err, ErrEpayOrderNotPaid) {
		t.Fatalf("refund pending err = %v, want ErrEpayOrderNotPaid", err)
	}

	// paid 后入账成功 → 余额 = amount。
	o := mustCreateEpayOrder(t, db, userID, "REF002", amount, time.Hour)
	if _, err := db.CreditEpayCallback(ctx, "REF002", "cb", o.AmountMicro); err != nil {
		t.Fatalf("credit: %v", err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != amount {
		t.Fatalf("after credit available = %d", acc.AvailableMicro)
	}

	// 退款 → 余额归零、订单 refunded、账本 refund 条目。
	replayed, err := db.RefundRechargeOrder(ctx, "REF002", 42, "customer requested")
	if err != nil || replayed {
		t.Fatalf("refund: replayed=%v err=%v", replayed, err)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 0 {
		t.Fatalf("after refund available = %d, want 0", acc.AvailableMicro)
	}
	ord, err := db.GetRechargeOrderByOrderNo(ctx, "REF002")
	if err != nil || ord.Status != RechargeOrderStatusRefunded {
		t.Fatalf("order status = %v err=%v", ord, err)
	}

	// 重复退款 → replayed=true 不重复扣（余额仍 0）。
	replayed, err = db.RefundRechargeOrder(ctx, "REF002", 42, "again")
	if err != nil || !replayed {
		t.Fatalf("second refund: replayed=%v err=%v", replayed, err)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 0 {
		t.Fatalf("replayed refund changed balance: %d", acc.AvailableMicro)
	}

	// 已消费后余额不足 → 拒绝退款（不透支）。
	o2 := mustCreateEpayOrder(t, db, userID, "REF003", amount, time.Hour)
	if _, err := db.CreditEpayCallback(ctx, "REF003", "cb", o2.AmountMicro); err != nil {
		t.Fatalf("credit o2: %v", err)
	}
	// 花掉全部余额。
	if _, err := db.WalletReserve(ctx, userID, amount, "request", "req-1", "req-1"); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := db.WalletSettle(ctx, userID, amount, amount, "request", "req-1", "req-1"); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if _, err := db.RefundRechargeOrder(ctx, "REF003", 0, "x"); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("refund after spend err = %v, want ErrInsufficientBalance", err)
	}

	// 不存在的订单。
	if _, err := db.RefundRechargeOrder(ctx, "NOPE", 0, "x"); !errors.Is(err, ErrEpayOrderNotFound) {
		t.Fatalf("refund missing err = %v", err)
	}
}

// ==================== 管理员：补录入账 / 余额调整 ====================

func TestAdminConfirmEpayOrder(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1
	amount := 50 * testFen

	mustCreateEpayOrder(t, db, userID, "CNF001", amount, time.Hour)
	replayed, err := db.AdminConfirmEpayOrder(ctx, "CNF001")
	if err != nil || replayed {
		t.Fatalf("confirm: replayed=%v err=%v", replayed, err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != amount {
		t.Fatalf("after confirm available = %d", acc.AvailableMicro)
	}
	// 再次补录 → 幂等重放，不重复加钱（复用 epay:<order_no> 幂等键）。
	replayed, err = db.AdminConfirmEpayOrder(ctx, "CNF001")
	if err != nil || !replayed {
		t.Fatalf("re-confirm: replayed=%v err=%v", replayed, err)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != amount {
		t.Fatalf("replay changed balance: %d", acc.AvailableMicro)
	}
	// 已取消订单拒绝。
	o2 := mustCreateEpayOrder(t, db, userID, "CNF002", amount, time.Hour)
	_ = o2
	// 直接置为 cancelled 模拟。
	if _, err := db.conn.ExecContext(ctx, `UPDATE wallet_transactions SET status=$1 WHERE order_no=$2`,
		RechargeOrderStatusCancelled, "CNF002"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdminConfirmEpayOrder(ctx, "CNF002"); !errors.Is(err, ErrEpayOrderClosed) {
		t.Fatalf("confirm cancelled err = %v", err)
	}
}

func TestAdminAdjustWalletBalance(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1

	// 正调整。
	replayed, err := db.AdminAdjustWalletBalance(ctx, userID, 300*testFen, "adj-1", "compensation", 0)
	if err != nil || replayed {
		t.Fatalf("adjust +: replayed=%v err=%v", replayed, err)
	}
	acc, _ := db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 300*testFen {
		t.Fatalf("after +adjust = %d", acc.AvailableMicro)
	}
	// 负调整。
	replayed, err = db.AdminAdjustWalletBalance(ctx, userID, -100*testFen, "adj-2", "chargeback", 0)
	if err != nil || replayed {
		t.Fatalf("adjust -: replayed=%v err=%v", replayed, err)
	}
	acc, _ = db.GetWalletAccount(ctx, userID)
	if acc.AvailableMicro != 200*testFen {
		t.Fatalf("after -adjust = %d", acc.AvailableMicro)
	}
	// 幂等键重复 → replayed。
	replayed, err = db.AdminAdjustWalletBalance(ctx, userID, -100*testFen, "adj-2", "again", 0)
	if err != nil || !replayed {
		t.Fatalf("replay adjust: replayed=%v err=%v", replayed, err)
	}
	// 负调整超额 → 拒绝（不透支）。
	if _, err := db.AdminAdjustWalletBalance(ctx, userID, -999*testFen, "adj-3", "too much", 0); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("overdraw adjust err = %v", err)
	}
	// 零金额/空幂等键拒绝。
	if _, err := db.AdminAdjustWalletBalance(ctx, userID, 0, "k", "r", 0); err == nil {
		t.Fatal("zero amount accepted")
	}
	if _, err := db.AdminAdjustWalletBalance(ctx, userID, 1, " ", "r", 0); err == nil {
		t.Fatal("empty key accepted")
	}
}

// ==================== 对账看板 / 账本重算 ====================

func TestPaymentSummary(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1
	amount := 100 * testFen

	// 1 笔 paid、1 笔 pending、1 笔退款。
	o1 := mustCreateEpayOrder(t, db, userID, "SUM001", amount, time.Hour)
	if _, err := db.CreditEpayCallback(ctx, "SUM001", "cb", o1.AmountMicro); err != nil {
		t.Fatalf("credit: %v", err)
	}
	mustCreateEpayOrder(t, db, userID, "SUM002", amount, time.Hour) // pending
	o3 := mustCreateEpayOrder(t, db, userID, "SUM003", amount, time.Hour)
	if _, err := db.CreditEpayCallback(ctx, "SUM003", "cb", o3.AmountMicro); err != nil {
		t.Fatalf("credit o3: %v", err)
	}
	if _, err := db.RefundRechargeOrder(ctx, "SUM003", 0, "refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}

	s, err := db.GetPaymentSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	// SUM003 退款后不再是 paid：paid 只有 SUM001 一笔。
	if s.TotalPaidMicro != 100*testFen {
		t.Fatalf("total paid = %d, want %d", s.TotalPaidMicro, 100*testFen)
	}
	if s.TodayPaidCount != 1 || s.TodayPaidMicro != 100*testFen {
		t.Fatalf("today = %d/%d", s.TodayPaidCount, s.TodayPaidMicro)
	}
	if s.RefundedCount != 1 || s.RefundedMicro != 100*testFen {
		t.Fatalf("refunded = %d/%d", s.RefundedCount, s.RefundedMicro)
	}
	if s.StatusCounts[RechargeOrderStatusPaid] != 1 || s.StatusCounts[RechargeOrderStatusPending] != 1 || s.StatusCounts[RechargeOrderStatusRefunded] != 1 {
		t.Fatalf("status counts = %+v", s.StatusCounts)
	}
	if s.LedgerEntryCount != 3 { // recharge x2 + refund x1
		t.Fatalf("ledger entries = %d, want 3", s.LedgerEntryCount)
	}
}

func TestReconcileWalletBalances(t *testing.T) {
	db := newEpayTestDB(t)
	ctx := context.Background()
	const userID = 1
	amount := 100 * testFen

	o := mustCreateEpayOrder(t, db, userID, "REC001", amount, time.Hour)
	if _, err := db.CreditEpayCallback(ctx, "REC001", "cb", o.AmountMicro); err != nil {
		t.Fatalf("credit: %v", err)
	}
	// 一致：无差异。
	drifts, err := db.ReconcileWalletBalances(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(drifts) != 0 {
		t.Fatalf("drifts = %+v, want none", drifts)
	}

	// 人为制造漂移：直接改余额表（模拟历史 bug）。
	if _, err := db.conn.ExecContext(ctx,
		`UPDATE wallet_accounts SET available_micro = available_micro - 30 WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	drifts, err = db.ReconcileWalletBalances(ctx)
	if err != nil {
		t.Fatalf("reconcile after drift: %v", err)
	}
	if len(drifts) != 1 || drifts[0].UserID != userID || drifts[0].DiffMicro != 30 {
		t.Fatalf("drifts = %+v", drifts)
	}
	// 修复后一致。
	if err := db.FixWalletBalance(ctx, userID, drifts[0].ExpectedMicro); err != nil {
		t.Fatalf("fix: %v", err)
	}
	drifts, err = db.ReconcileWalletBalances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 0 {
		t.Fatalf("drifts after fix = %+v", drifts)
	}
	// 修复不存在用户报错。
	if err := db.FixWalletBalance(ctx, 99999, 0); err == nil {
		t.Fatal("fix missing account accepted")
	}
	// 负数期望值拒绝。
	if err := db.FixWalletBalance(ctx, userID, -1); err == nil {
		t.Fatal("negative expected accepted")
	}
}

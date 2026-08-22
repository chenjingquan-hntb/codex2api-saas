package admin

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/tidwall/gjson"
)

// newPaymentAdminTestHandler：管理员（ADMIN_SECRET 注入）+ 用户（注册/验证/登录），
// 返回 handler、db、用户会话 cookie、用户 ID。
func newPaymentAdminTestHandler(t *testing.T) (*Handler, *database.DB, []*http.Cookie, int64) {
	t.Helper()
	h, db := newUserAuthTestHandler(t)
	h.adminSecretEnv = testAdminSecret

	_, verifyToken := registerUser(t, h, "pay@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	rec = loginUser(t, h, "pay@example.com", "S3curePass!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d", rec.Code)
	}
	userID := gjson.Get(rec.Body.String(), "user_id").Int()
	return h, db, sessionCookie(rec), userID
}

// createPaidOrder 直接走 DB 造一笔已入账订单（模拟回调成功）。
func createPaidOrder(t *testing.T, h *Handler, db *database.DB, userID int64, orderNo string, amountMicro int64) {
	t.Helper()
	o, err := db.CreateRechargeOrder(t.Context(), userID, orderNo, "epay", amountMicro, "", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("create order: %v", err)
	}
	replayed, err := db.CreditEpayCallback(t.Context(), orderNo, "cb", o.AmountMicro)
	if err != nil || replayed {
		t.Fatalf("credit: replayed=%v err=%v", replayed, err)
	}
}

func TestAdminPaymentEndpoints(t *testing.T) {
	h, db, _, userID := newPaymentAdminTestHandler(t)
	const amount = int64(10000000) // 1 元

	createPaidOrder(t, h, db, userID, "PAY001", amount)

	// 无鉴权 → 401。
	rec := doJSON(t, h, http.MethodGet, "/api/admin/payments/orders", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d", rec.Code)
	}

	// 列表。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/payments/orders", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "count").Int(); got != 1 {
		t.Fatalf("count = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "orders.0.OrderNo").String(); got != "PAY001" {
		t.Fatalf("OrderNo = %q", got)
	}
	if got := gjson.Get(rec.Body.String(), "orders.0.Email").String(); got != "pay@example.com" {
		t.Fatalf("Email = %q", got)
	}

	// 状态过滤（pending 无结果）。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/payments/orders?status=pending", "")
	if got := gjson.Get(rec.Body.String(), "count").Int(); got != 0 {
		t.Fatalf("pending filter count = %d", got)
	}

	// 详情 + 关联账本。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/payments/orders/PAY001", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "order.AmountMicro").Int(); got != amount {
		t.Fatalf("detail amount = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "ledger.#").Int(); got < 1 {
		t.Fatalf("ledger count = %d", got)
	}

	// 详情不存在 → 404。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/payments/orders/NOPE", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing detail status = %d", rec.Code)
	}

	// 看板。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/payments/summary", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "today_paid_micro").Int(); got != amount {
		t.Fatalf("summary today_paid = %d", got)
	}

	// 重算（dry_run 默认）：无差异。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/reconcile", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "dry_run").Bool(); !got {
		t.Fatalf("reconcile dry_run = %v", got)
	}
	if got := gjson.Get(rec.Body.String(), "drifts.#").Int(); got != 0 {
		t.Fatalf("reconcile drifts = %d", got)
	}
}

func TestAdminPaymentRefundFlow(t *testing.T) {
	h, db, _, userID := newPaymentAdminTestHandler(t)
	const amount = int64(10000000) // 1 元

	// pending 订单退款 → 409。
	o, err := db.CreateRechargeOrder(t.Context(), userID, "PAYREF0", "epay", amount, "", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = o
	rec := doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/PAYREF0/refund", `{"reason":"test"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("refund pending status = %d body=%s", rec.Code, rec.Body.String())
	}

	// paid 订单退款 → 余额归零、订单 refunded。
	createPaidOrder(t, h, db, userID, "PAYREF1", amount)
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/PAYREF1/refund", `{"reason":"customer requested"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("refund status = %d body=%s", rec.Code, rec.Body.String())
	}
	ord, _ := db.GetRechargeOrderByOrderNo(t.Context(), "PAYREF1")
	if ord.Status != database.RechargeOrderStatusRefunded {
		t.Fatalf("order status = %q", ord.Status)
	}
	acc, _ := db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != 0 {
		t.Fatalf("available after refund = %d", acc.AvailableMicro)
	}

	// 重复退款 → 幂等重放 200（不再扣）。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/PAYREF1/refund", `{"reason":"again"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-refund status = %d", rec.Code)
	}
	acc, _ = db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != 0 {
		t.Fatalf("replay changed balance: %d", acc.AvailableMicro)
	}

	// 退款订单号不存在 → 404。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/NOPE/refund", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("refund missing status = %d", rec.Code)
	}
}

func TestAdminPaymentConfirmAndAdjust(t *testing.T) {
	h, db, _, userID := newPaymentAdminTestHandler(t)
	const amount = int64(10000000) // 1 元

	// 补录 pending 订单。
	_, err := db.CreateRechargeOrder(t.Context(), userID, "PAYCNF1", "epay", amount, "", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/PAYCNF1/confirm", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d body=%s", rec.Code, rec.Body.String())
	}
	acc, _ := db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != amount {
		t.Fatalf("after confirm = %d", acc.AvailableMicro)
	}
	// 重复补录 → 幂等。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/orders/PAYCNF1/confirm", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-confirm status = %d", rec.Code)
	}
	acc, _ = db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != amount {
		t.Fatalf("replay changed balance: %d", acc.AvailableMicro)
	}

	// 余额调整：-4000000（-4 角）。
	rec = doAdmin(t, h, http.MethodPost, fmt.Sprintf("/api/admin/payments/users/%d/adjust", userID),
		`{"amount_micro":-4000000,"idempotency_key":"adj-001","reason":"chargeback"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("adjust status = %d body=%s", rec.Code, rec.Body.String())
	}
	acc, _ = db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != amount-4000000 {
		t.Fatalf("after adjust = %d", acc.AvailableMicro)
	}
	// 同幂等键重复 → 幂等重放。
	rec = doAdmin(t, h, http.MethodPost, fmt.Sprintf("/api/admin/payments/users/%d/adjust", userID),
		`{"amount_micro":-4000000,"idempotency_key":"adj-001","reason":"again"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-adjust status = %d", rec.Code)
	}
	acc, _ = db.GetWalletAccount(t.Context(), userID)
	if acc.AvailableMicro != amount-4000000 {
		t.Fatalf("replay changed balance: %d", acc.AvailableMicro)
	}
	// 超额扣减 → 409（不透支）。
	rec = doAdmin(t, h, http.MethodPost, fmt.Sprintf("/api/admin/payments/users/%d/adjust", userID),
		`{"amount_micro":-999999999,"idempotency_key":"adj-002","reason":"too much"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("overdraw adjust status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 缺幂等键 → 400。
	rec = doAdmin(t, h, http.MethodPost, fmt.Sprintf("/api/admin/payments/users/%d/adjust", userID),
		`{"amount_micro":100,"reason":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing key status = %d", rec.Code)
	}
	// 非法用户 ID → 400。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/users/abc/adjust", `{"amount_micro":1,"idempotency_key":"k"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad user id status = %d", rec.Code)
	}
}

func TestAdminPaymentReconcileAPI(t *testing.T) {
	h, db, _, userID := newPaymentAdminTestHandler(t)
	const amount = int64(10000000) // 1 元
	createPaidOrder(t, h, db, userID, "PAYREC1", amount)

	// 正常态：无差异，dry_run 默认 true。
	rec := doAdmin(t, h, http.MethodPost, "/api/admin/payments/reconcile", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "dry_run").Bool(); !got {
		t.Fatalf("dry_run = %v", got)
	}
	if got := gjson.Get(rec.Body.String(), "drifts.#").Int(); got != 0 {
		t.Fatalf("drifts = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "fixed").Int(); got != 0 {
		t.Fatalf("fixed = %d", got)
	}
	// 显式 dry_run=false 且无差异：fixed=0。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/payments/reconcile", `{"dry_run":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile fix status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "fixed").Int(); got != 0 {
		t.Fatalf("fixed = %d", got)
	}
}

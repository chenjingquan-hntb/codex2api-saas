package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	testEpayMerchant = "1001"
	testEpayKey      = "test-epay-secret-key"
	testEpayGateway  = "https://pay.example.com/submit.php"
	testEpayBase     = "https://api.example.com"
)

func setupEpayTest(t *testing.T) (*Handler, *database.DB, []*http.Cookie, int64) {
	t.Helper()
	h, db := newUserAuthTestHandler(t)

	// 启用易支付配置。
	if err := db.SetSettingValue(t.Context(), database.SettingKeyEpay,
		fmt.Sprintf(`{"enabled":true,"merchant_id":%q,"key":%q,"gateway_url":%q,"callback_base_url":%q,"notify_path":"/api/pay/epay/notify","return_path":"/portal/pay/result"}`,
			testEpayMerchant, testEpayKey, testEpayGateway, testEpayBase), 0); err != nil {
		t.Fatalf("set epay config: %v", err)
	}

	// 注册 + 验证 + 登录一个用户。
	userID, verifyToken := registerUser(t, h, "pay@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = loginUser(t, h, "pay@example.com", "S3curePass!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := sessionCookie(rec)
	if len(cookies) == 0 {
		t.Fatal("no session cookie")
	}
	return h, db, cookies, int64(userID)
}

func doForm(t *testing.T, h *Handler, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// epayCallbackParams 构造一笔带合法签名的网关回调。
func epayCallbackParams(orderNo, money string) url.Values {
	params := map[string]string{
		"pid":          testEpayMerchant,
		"trade_no":     "TR202608220001",
		"out_trade_no": orderNo,
		"type":         "alipay",
		"name":         "API 余额充值",
		"money":        money,
		"trade_status": "TRADE_SUCCESS",
		"sign_type":    "MD5",
	}
	params["sign"] = epaySign(params, testEpayKey)
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	return form
}

func TestEpayCreateRechargeOrder(t *testing.T) {
	h, db, cookies, userID := setupEpayTest(t)

	rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
		`{"amount_micro":100000,"channel":"alipay"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("recharge status = %d body=%s", rec.Code, rec.Body.String())
	}
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()
	if orderNo == "" {
		t.Fatalf("missing order_no: %s", rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "gateway_url").String(); got != testEpayGateway {
		t.Fatalf("gateway_url = %s", got)
	}
	if got := gjson.Get(rec.Body.String(), "amount_micro").Int(); got != 100000 {
		t.Fatalf("amount = %d", got)
	}

	// 表单签名必须可由商户密钥验证（响应不携带密钥本身）。
	form := gjson.Get(rec.Body.String(), "form").Map()
	params := make(map[string]string, len(form))
	for k, v := range form {
		params[k] = v.String()
	}
	if !epayVerifySign(params, testEpayKey) {
		t.Fatalf("recharge form sign invalid: %v", params)
	}
	if _, ok := params["key"]; ok {
		t.Fatalf("form must not contain merchant key")
	}
	if params["out_trade_no"] != orderNo {
		t.Fatalf("form out_trade_no = %s, want %s", params["out_trade_no"], orderNo)
	}
	if params["money"] != "0.01" {
		t.Fatalf("form money = %s, want 0.01", params["money"])
	}
	if params["pid"] != testEpayMerchant {
		t.Fatalf("form pid = %s", params["pid"])
	}

	// 订单已入库且归属当前用户。
	o, err := db.GetRechargeOrder(t.Context(), userID, orderNo)
	if err != nil || o == nil {
		t.Fatalf("order not found: %v", err)
	}
	if o.Status != database.RechargeOrderStatusPending {
		t.Fatalf("status = %s", o.Status)
	}
}

func TestEpayRechargeValidation(t *testing.T) {
	h, _, cookies, _ := setupEpayTest(t)

	cases := []struct {
		name string
		body string
		want int
	}{
		{"too small", `{"amount_micro":100}`, http.StatusBadRequest},
		{"too large", `{"amount_micro":1000000000001}`, http.StatusBadRequest},
		{"not multiple of fen", `{"amount_micro":150000}`, http.StatusBadRequest},
		{"bad channel", `{"amount_micro":100000,"channel":"qqpay"}`, http.StatusBadRequest},
		{"bad body", `not-json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge", tc.body, cookies)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestEpayRechargeRequiresVerifiedEmail(t *testing.T) {
	h, _, _, _ := setupEpayTest(t)

	// 未验证用户：注册但不验证。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"unverified@example.com","password":"S3curePass!123"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d", rec.Code)
	}
	rec = loginUser(t, h, "unverified@example.com", "S3curePass!123")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unverified login must be rejected, got %d", rec.Code)
	}

	// 未登录：401。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge", `{"amount_micro":100000}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth recharge status = %d", rec.Code)
	}
}

func TestEpayNotifyCreditsOnce(t *testing.T) {
	h, db, cookies, userID := setupEpayTest(t)

	// 创建订单。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
		`{"amount_micro":100000,"channel":"alipay"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("recharge status = %d", rec.Code)
	}
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()

	// 第一次回调 → success + 入账。
	form := epayCallbackParams(orderNo, "0.01")
	rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", form)
	if rec.Code != http.StatusOK || rec.Body.String() != "success" {
		t.Fatalf("notify = %d %q", rec.Code, rec.Body.String())
	}
	acc, err := db.GetWalletAccount(t.Context(), userID)
	if err != nil || acc == nil || acc.AvailableMicro != 100000 {
		t.Fatalf("wallet after notify: %+v err=%v", acc, err)
	}

	// 订单状态。
	o, err := db.GetRechargeOrder(t.Context(), userID, orderNo)
	if err != nil || o == nil || o.Status != database.RechargeOrderStatusPaid {
		t.Fatalf("order after notify: %+v err=%v", o, err)
	}

	// 重复回调（网关重试）→ 仍 success，但不重复入账。
	for i := 0; i < 2; i++ {
		rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", epayCallbackParams(orderNo, "0.01"))
		if rec.Code != http.StatusOK || rec.Body.String() != "success" {
			t.Fatalf("re-notify #%d = %d %q", i, rec.Code, rec.Body.String())
		}
	}
	acc, err = db.GetWalletAccount(t.Context(), userID)
	if err != nil || acc.AvailableMicro != 100000 {
		t.Fatalf("wallet after replay: %+v err=%v", acc, err)
	}
	ledger, err := db.ListWalletLedger(t.Context(), userID, 10, 0)
	if err != nil || len(ledger) != 1 {
		t.Fatalf("ledger after replay: %v entries=%d", err, len(ledger))
	}
}

func TestEpayNotifyIgnoresNonSuccessTradeStatus(t *testing.T) {
	statuses := []struct {
		name   string
		status string
	}{
		{name: "pending", status: "TRADE_PENDING"},
		{name: "failed", status: "TRADE_FAILED"},
		{name: "missing", status: ""},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			h, db, cookies, userID := setupEpayTest(t)
			rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
				`{"amount_micro":100000}`, cookies)
			orderNo := gjson.Get(rec.Body.String(), "order_no").String()

			form := epayCallbackParams(orderNo, "0.01")
			if tc.status == "" {
				form.Del("trade_status")
			} else {
				form.Set("trade_status", tc.status)
			}
			form.Set("sign", epaySign(formToMap(form), testEpayKey))
			rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", form)
			if rec.Code != http.StatusOK || rec.Body.String() != "success" {
				t.Fatalf("non-success notify = %d %q", rec.Code, rec.Body.String())
			}

			acc, err := db.GetWalletAccount(t.Context(), userID)
			if err != nil || (acc != nil && (acc.AvailableMicro != 0 || acc.ReservedMicro != 0)) {
				t.Fatalf("wallet changed: %+v err=%v", acc, err)
			}
			order, err := db.GetRechargeOrder(t.Context(), userID, orderNo)
			if err != nil || order == nil || order.Status != database.RechargeOrderStatusPending {
				t.Fatalf("order must remain pending: %+v err=%v", order, err)
			}
			ledger, err := db.ListWalletLedger(t.Context(), userID, 10, 0)
			if err != nil || len(ledger) != 0 {
				t.Fatalf("ledger must stay empty: entries=%d err=%v", len(ledger), err)
			}
		})
	}
}

func TestEpayNotifyRejectsBadSign(t *testing.T) {
	h, db, cookies, userID := setupEpayTest(t)

	rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
		`{"amount_micro":100000}`, cookies)
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()

	form := epayCallbackParams(orderNo, "0.01")
	form.Set("sign", "deadbeef")
	rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", form)
	if rec.Body.String() != "fail" {
		t.Fatalf("bad sign must be rejected, got %d %q", rec.Code, rec.Body.String())
	}
	acc, _ := db.GetWalletAccount(t.Context(), userID)
	if acc != nil && acc.AvailableMicro != 0 {
		t.Fatalf("wallet must stay 0, got %+v", acc)
	}
}

func TestEpayNotifyFailureRateLimit(t *testing.T) {
	h, _, cookies, _ := setupEpayTest(t)
	rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
		`{"amount_micro":100000}`, cookies)
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()

	for i := 0; i < epayCallbackFailureLimit; i++ {
		form := epayCallbackParams(orderNo, "0.01")
		form.Set("sign", "deadbeef")
		rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad callback #%d status=%d body=%q", i, rec.Code, rec.Body.String())
		}
	}
	// 达到失败阈值后，即使后续报文签名正确，也先对该来源短暂限流。
	rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", epayCallbackParams(orderNo, "0.01"))
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != "fail" {
		t.Fatalf("rate limited notify=%d %q", rec.Code, rec.Body.String())
	}
	if got := h.epayBadSignCount.Load(); got != epayCallbackFailureLimit {
		t.Fatalf("bad sign count=%d", got)
	}
	if got := h.epayRejectedCount.Load(); got != epayCallbackFailureLimit {
		t.Fatalf("rejected count=%d", got)
	}
	if got := h.epayRateLimitedCount.Load(); got != 1 {
		t.Fatalf("rate limited count=%d", got)
	}
}
func TestEpayNotifyRejectsAmountMismatch(t *testing.T) {
	h, db, cookies, userID := setupEpayTest(t)

	rec := doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge",
		`{"amount_micro":100000}`, cookies)
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()

	// 签名字段与订单金额一致（1.00），但 money 参数改小为 0.99 → 签名随之变化，
	// 因此这里直接构造“签名有效但金额不符”需要服务端重算签名。
	form := epayCallbackParams(orderNo, "0.01")
	form.Set("money", "0.99")
	form.Set("sign", epaySign(formToMap(form), testEpayKey))
	rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", form)
	if rec.Body.String() != "fail" {
		t.Fatalf("amount mismatch must fail, got %d %q", rec.Code, rec.Body.String())
	}
	acc, _ := db.GetWalletAccount(t.Context(), userID)
	if acc != nil && acc.AvailableMicro != 0 {
		t.Fatalf("wallet must stay 0, got %+v", acc)
	}
	o, _ := db.GetRechargeOrder(t.Context(), userID, orderNo)
	if o == nil || o.Status != database.RechargeOrderStatusPending {
		t.Fatalf("order must stay pending, got %+v", o)
	}
}

func TestEpayNotifyUnknownOrder(t *testing.T) {
	h, _, _, _ := setupEpayTest(t)
	rec := doForm(t, h, http.MethodPost, "/api/pay/epay/notify", epayCallbackParams("EP-NO-SUCH", "1.00"))
	if rec.Body.String() != "fail" {
		t.Fatalf("unknown order must fail, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestEpayNotifyWhenDisabled(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	// 未启用易支付：回调被拒绝。
	rec := doForm(t, h, http.MethodPost, "/api/pay/epay/notify", epayCallbackParams("EP-X", "1.00"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled epay notify status = %d", rec.Code)
	}

	// 未启用：充值下单也被拒绝（未登录 → 401）。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge", `{"amount_micro":100000}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth = %d", rec.Code)
	}
}

func TestEpayWalletAndOrdersEndpoints(t *testing.T) {
	h, _, cookies, _ := setupEpayTest(t)

	// 初始余额 0。
	rec := doJSON(t, h, http.MethodGet, "/api/auth/wallet", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("wallet status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "available_micro").Int(); got != 0 {
		t.Fatalf("available = %d", got)
	}

	// 下单 + 支付。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/wallet/recharge", `{"amount_micro":200000}`, cookies)
	orderNo := gjson.Get(rec.Body.String(), "order_no").String()
	rec = doForm(t, h, http.MethodPost, "/api/pay/epay/notify", epayCallbackParams(orderNo, "0.02"))
	if rec.Body.String() != "success" {
		t.Fatalf("notify = %q", rec.Body.String())
	}

	rec = doJSON(t, h, http.MethodGet, "/api/auth/wallet", "", cookies)
	if got := gjson.Get(rec.Body.String(), "available_micro").Int(); got != 200000 {
		t.Fatalf("available = %d, want 200000", got)
	}

	// 订单列表与详情。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/wallet/orders", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("orders status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "orders.#").Int(); got != 1 {
		t.Fatalf("orders count = %d", got)
	}
	rec = doJSON(t, h, http.MethodGet, "/api/auth/wallet/orders/"+orderNo, "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("order detail status = %d", rec.Code)
	}
	if got := gjson.Get(rec.Body.String(), "status").String(); got != database.RechargeOrderStatusPaid {
		t.Fatalf("order status = %s", got)
	}

	// 跨用户订单不可见。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/wallet/orders/"+orderNo, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous order detail status = %d", rec.Code)
	}
}

func formToMap(form url.Values) map[string]string {
	out := make(map[string]string, len(form))
	for k, vs := range form {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

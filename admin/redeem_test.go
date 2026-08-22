package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const testAdminSecret = "test-admin-secret"

// newRedeemTestHandler 与 newUserAuthTestHandler 相同，但配置了 ADMIN_SECRET
// 以便测试 /api/admin/redeem/* 端点。
func newRedeemTestHandler(t *testing.T) (*Handler, *database.DB, []*http.Cookie) {
	t.Helper()
	h, db := newUserAuthTestHandler(t)
	h.adminSecretEnv = testAdminSecret

	// 注册 + 验证 + 登录用户。
	_, verifyToken := registerUser(t, h, "redeem@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	rec = loginUser(t, h, "redeem@example.com", "S3curePass!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d", rec.Code)
	}
	return h, db, sessionCookie(rec)
}

func doAdmin(t *testing.T, h *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", testAdminSecret)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAdminCreateRedeemBatchReturnsPlaintextOnce(t *testing.T) {
	h, _, _ := newRedeemTestHandler(t)

	rec := doAdmin(t, h, http.MethodPost, "/api/admin/redeem/batches",
		`{"name":"B1","amount_micro":1000000,"count":2}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create batch status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "codes.#").Int(); got != 2 {
		t.Fatalf("codes count = %d", got)
	}
	code0 := gjson.Get(rec.Body.String(), "codes.0").String()
	if code0 == "" {
		t.Fatalf("missing plaintext code: %s", rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "batch.amount_micro").Int(); got != 1000000 {
		t.Fatalf("amount = %d", got)
	}

	// 批次列表与详情不返回明文。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/redeem/batches", "")
	if rec.Code != http.StatusOK || gjson.Get(rec.Body.String(), "batches.#").Int() != 1 {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	batchID := gjson.Get(rec.Body.String(), "batches.0.id").Int()
	rec = doAdmin(t, h, http.MethodGet, fmt.Sprintf("/api/admin/redeem/batches/%d/codes", batchID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("codes status = %d", rec.Code)
	}
	if gjson.Get(rec.Body.String(), "codes.#").Int() != 2 {
		t.Fatalf("codes list count: %s", rec.Body.String())
	}
	for _, c := range gjson.Get(rec.Body.String(), "codes").Array() {
		if c.Get("prefix").String() == "" {
			t.Fatalf("missing prefix: %s", rec.Body.String())
		}
	}

	// 校验：非法请求被拒。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/redeem/batches", `{"name":"","amount_micro":1,"count":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name must be rejected, got %d", rec.Code)
	}
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/redeem/batches", `{"name":"B","amount_micro":0,"count":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("zero amount must be rejected, got %d", rec.Code)
	}
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/redeem/batches", `{"name":"B","amount_micro":1,"count":10001}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("count>10000 must be rejected, got %d", rec.Code)
	}
	// 无管理密钥 → 401。
	rec = doJSON(t, h, http.MethodPost, "/api/admin/redeem/batches", `{"name":"B","amount_micro":1,"count":1}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no admin key status = %d", rec.Code)
	}
}

func TestRedeemUserFlow(t *testing.T) {
	h, db, cookies := newRedeemTestHandler(t)

	// 管理员创建批次（含过期批次与有效批次）。
	rec := doAdmin(t, h, http.MethodPost, "/api/admin/redeem/batches",
		`{"name":"B2","amount_micro":2000000,"count":2}`)
	code0 := gjson.Get(rec.Body.String(), "codes.0").String()
	code1 := gjson.Get(rec.Body.String(), "codes.1").String()

	// 用户兑换第一个码。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/redeem",
		fmt.Sprintf(`{"code":%q}`, code0), cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "credited_micro").Int(); got != 2000000 {
		t.Fatalf("credited = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "balance_micro").Int(); got != 2000000 {
		t.Fatalf("balance = %d", got)
	}

	// 重复兑换同一码 → 409。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/redeem",
		fmt.Sprintf(`{"code":%q}`, code0), cookies)
	if rec.Code != http.StatusConflict {
		t.Fatalf("repeat redeem status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 未登录兑换 → 401。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/redeem",
		fmt.Sprintf(`{"code":%q}`, code1), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous redeem status = %d", rec.Code)
	}

	// 管理员撤销批次 → 剩余未核销码不可再用。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/redeem/batches", "")
	batchID := gjson.Get(rec.Body.String(), "batches.0.id").Int()
	rec = doAdmin(t, h, http.MethodPost, fmt.Sprintf("/api/admin/redeem/batches/%d/revoke", batchID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "revoked_codes").Int(); got != 1 {
		t.Fatalf("revoked = %d, want 1", got)
	}

	// 金额已入账。
	acc, err := db.GetWalletAccount(t.Context(), 1)
	if err != nil || acc == nil || acc.AvailableMicro != 2000000 {
		t.Fatalf("wallet = %+v err=%v", acc, err)
	}
}

func TestRedeemCodeInvalidFormatHTTP(t *testing.T) {
	h, _, cookies := newRedeemTestHandler(t)
	rec := doJSON(t, h, http.MethodPost, "/api/auth/redeem", `{"code":"BAD"}`, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid code status = %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/auth/redeem", `{"code":"ABCD-EFGH-JKMN-PQRS"}`, cookies)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown code status = %d body=%s", rec.Code, rec.Body.String())
	}
}

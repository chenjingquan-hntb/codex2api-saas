package admin

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const testEndpointToken = "test-endpoint-token"

// newEndpointTestHandler：ADMIN_SECRET + 节点 token 双注入。
func newEndpointTestHandler(t *testing.T) (*Handler, *database.DB) {
	t.Helper()
	h, db := newUserAuthTestHandler(t)
	h.adminSecretEnv = testAdminSecret
	t.Setenv("CODEX_ENDPOINT_REGISTRATION_TOKEN", testEndpointToken)
	return h, db
}

// doEndpoint 以节点 token 调 /api/endpoints/*。
func doEndpoint(t *testing.T, h *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Endpoint-Token", testEndpointToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	h, _ := newEndpointTestHandler(t)
	h.epayBadSignCount.Store(2)
	h.epayRejectedCount.Store(3)
	h.epayRateLimitedCount.Store(1)
	r := gin.New()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "status").String(); got != "ok" {
		t.Fatalf("status = %q", got)
	}
	if got := gjson.Get(rec.Body.String(), "dependencies.postgres").String(); got != "ok" {
		t.Fatalf("postgres dep = %q", got)
	}
	if got := gjson.Get(rec.Body.String(), "dependencies.financial").String(); got != "ok" {
		t.Fatalf("financial dep = %q body=%s", got, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "dependencies.credentials_encryption").String(); got != "plaintext" {
		t.Fatalf("credentials_encryption dep = %q body=%s", got, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "financial.epay_bad_sign").Int(); got != 2 {
		t.Fatalf("epay_bad_sign = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "financial.epay_rejected").Int(); got != 3 {
		t.Fatalf("epay_rejected = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "financial.epay_rate_limited").Int(); got != 1 {
		t.Fatalf("epay_rate_limited = %d", got)
	}

	// DB 故障 → 503 down。
	h2, _ := newUserAuthTestHandler(t)
	h2.db = nil
	r2 := gin.New()
	h2.RegisterRoutes(r2)
	rec2 := httptest.NewRecorder()
	r2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz down status = %d", rec2.Code)
	}
	if got := gjson.Get(rec2.Body.String(), "status").String(); got != "down" {
		t.Fatalf("down status = %q", got)
	}
}

func TestEndpointTokenGateFailClosed(t *testing.T) {
	// 未配置 token → 503（fail-closed，不暴露协议）。
	h, _ := newUserAuthTestHandler(t)
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPost, "/api/endpoints/register",
		strings.NewReader(`{"endpoint_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no-token status = %d", rec.Code)
	}
}

func TestEndpointProtocolFlow(t *testing.T) {
	h, db := newEndpointTestHandler(t)

	// 错误 token → 401。
	rec := doEndpoint(t, h, http.MethodPost, "/api/endpoints/register", `{"endpoint_id":"hk-01"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 注册成功 → offline。
	got := gjson.Get(rec.Body.String(), "endpoint.status").String()
	if got != database.EndpointStatusOffline {
		t.Fatalf("registered status = %q", got)
	}

	// 心跳 → active + drain=false。
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{"endpoint_id":"hk-01","version":"1.2.3","capacity":300}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "status").String(); got != database.EndpointStatusActive {
		t.Fatalf("hb status = %q", got)
	}
	if gjson.Get(rec.Body.String(), "drain").Bool() {
		t.Fatal("drain should be false")
	}

	// 管理端 drain → 心跳响应 drain=true。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/endpoints/hk-01/drain", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("drain status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{"endpoint_id":"hk-01"}`)
	if rec.Code != http.StatusOK || !gjson.Get(rec.Body.String(), "drain").Bool() {
		t.Fatalf("drain hb = %d body=%s", rec.Code, rec.Body.String())
	}

	// 管理端 revoke → 心跳 403。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/endpoints/hk-01/revoke", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{"endpoint_id":"hk-01"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked hb status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 未注册节点心跳 → 404。
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{"endpoint_id":"nope"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing hb status = %d", rec.Code)
	}

	// 列表（管理端）。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/endpoints", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "count").Int(); got != 1 {
		t.Fatalf("list count = %d", got)
	}
	if got := gjson.Get(rec.Body.String(), "endpoints.0.status").String(); got != database.EndpointStatusRevoked {
		t.Fatalf("list status = %q", got)
	}

	// 管理端 activate → 重启用。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/endpoints/hk-01/activate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("activate status = %d", rec.Code)
	}
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{"endpoint_id":"hk-01"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivated hb status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 管理端操作不存在的节点 → 404。
	rec = doAdmin(t, h, http.MethodPost, "/api/admin/endpoints/missing/drain", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("drain missing status = %d", rec.Code)
	}

	// 管理端无鉴权 → 401。
	rec = doJSON(t, h, http.MethodGet, "/api/admin/endpoints", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon list status = %d", rec.Code)
	}
	_ = db
}

func TestEndpointBadRequests(t *testing.T) {
	h, _ := newEndpointTestHandler(t)

	// 注册缺 endpoint_id → 400。
	rec := doEndpoint(t, h, http.MethodPost, "/api/endpoints/register", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 心跳缺 endpoint_id → 400。
	rec = doEndpoint(t, h, http.MethodPost, "/api/endpoints/heartbeat", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing hb id status = %d", rec.Code)
	}
	// 错误 token → 401。
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPost, "/api/endpoints/heartbeat", strings.NewReader(`{"endpoint_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Endpoint-Token", "wrong-token")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d", rec2.Code)
	}
}

// ==================== P7.3/P7.5/P7.6 集成测试 ====================

func TestAdminGroupEndpointBindingAndOverview(t *testing.T) {
	h, db := newEndpointTestHandler(t)

	// 建两个分组 + 两个端点。
	rec := doAdmin(t, h, http.MethodPost, "/api/admin/account-groups", `{"name":"HK Group"}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create group status = %d body=%s", rec.Code, rec.Body.String())
	}
	groupID := gjson.Get(rec.Body.String(), "id").Int()
	if groupID <= 0 {
		t.Fatalf("group id = %d body=%s", groupID, rec.Body.String())
	}
	if _, err := h.db.RegisterServiceEndpoint(t.Context(), database.ServiceEndpoint{
		EndpointID: "hk-01", Region: "hk", Role: "data"}); err != nil {
		t.Fatal(err)
	}

	// PATCH 分组绑定端点（P7.3）。
	rec = doAdmin(t, h, http.MethodPatch, "/api/admin/account-groups/"+strconv.FormatInt(groupID, 10),
		`{"endpoint_ids":["hk-01"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bind status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 分组列表携带 endpoint_ids。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/account-groups", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("groups list status = %d", rec.Code)
	}
	found := false
	raw := rec.Body.String()
	// 分组列表字段结构：groups[].endpoint_ids。
	groupsJSON := gjson.Get(raw, "groups")
	if groupsJSON.Exists() {
		groupsJSON.ForEach(func(key, value gjson.Result) bool {
			if value.Get("id").Int() == groupID &&
				value.Get("endpoint_ids.0").String() == "hk-01" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Fatalf("group endpoint_ids not in list: %s", raw)
	}

	// 端点列表携带 bound_groups（P7.5）。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/endpoints", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("endpoints list status = %d", rec.Code)
	}
	epJSON := gjson.Get(rec.Body.String(), "endpoints")
	if !epJSON.Exists() || !epJSON.Get("0.bound_groups").Exists() {
		t.Fatalf("endpoints list missing bound_groups: %s", rec.Body.String())
	}
	if got := epJSON.Get("0.bound_group_count").Int(); got < 1 {
		t.Fatalf("bound_group_count = %d", got)
	}

	// 端点 overview（P7.5）。
	rec = doAdmin(t, h, http.MethodGet, "/api/admin/endpoints/hk-01/overview", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "allowed_group_ids.#").Int(); got < 1 {
		t.Fatalf("allowed_group_ids = %s", rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "wallet_write").String(); got == "" {
		t.Fatalf("wallet_write missing: %s", rec.Body.String())
	}

	// 清空绑定 = 全端点。
	rec = doAdmin(t, h, http.MethodPatch, "/api/admin/account-groups/"+strconv.FormatInt(groupID, 10),
		`{"endpoint_ids":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbind status = %d", rec.Code)
	}
	// 非法端点 ID → 400。
	rec = doAdmin(t, h, http.MethodPatch, "/api/admin/account-groups/"+strconv.FormatInt(groupID, 10),
		`{"endpoint_ids":["bad id with space"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid endpoint id status = %d", rec.Code)
	}
	_ = db
}

func TestHealthzWalletWriteMode(t *testing.T) {
	h, _ := newEndpointTestHandler(t)
	h.epayBadSignCount.Store(2)
	h.epayRejectedCount.Store(3)
	h.epayRateLimitedCount.Store(1)
	r := gin.New()
	h.RegisterRoutes(r)

	// 默认 shared。
	t.Setenv("CODEX_WALLET_WRITE_MODE", "")
	t.Setenv("CODEX_ENDPOINT_REGION", "")
	t.Setenv("CODEX_WALLET_PRIMARY_REGION", "")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := gjson.Get(rec.Body.String(), "wallet_write").String(); got != "shared" {
		t.Fatalf("default wallet_write = %q", got)
	}

	// primary 且本端点为主区 → primary。
	t.Setenv("CODEX_WALLET_WRITE_MODE", "primary")
	t.Setenv("CODEX_ENDPOINT_REGION", "hk")
	t.Setenv("CODEX_WALLET_PRIMARY_REGION", "hk")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := gjson.Get(rec.Body.String(), "wallet_write").String(); got != "primary" {
		t.Fatalf("primary wallet_write = %q", got)
	}

	// primary 但非主区 → readonly。
	t.Setenv("CODEX_ENDPOINT_REGION", "sg")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := gjson.Get(rec.Body.String(), "wallet_write").String(); got != "readonly" {
		t.Fatalf("readonly wallet_write = %q", got)
	}
}

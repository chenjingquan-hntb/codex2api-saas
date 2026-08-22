package admin

import (
	"net/http"
	"net/http/httptest"
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

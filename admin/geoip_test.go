package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// ==================== 单元：缓存 / 私网判定 / 判定逻辑 ====================

func TestGeoIPCacheTTL(t *testing.T) {
	c := newGeoIPCache()
	now := time.Now()
	c.set("1.2.3.4", "CN", time.Minute, now)
	if code, ok := c.get("1.2.3.4", now.Add(30*time.Second)); !ok || code != "CN" {
		t.Fatalf("fresh entry = %q %v", code, ok)
	}
	if _, ok := c.get("1.2.3.4", now.Add(2*time.Minute)); ok {
		t.Fatal("expired entry still returned")
	}
	// 超限重置不 panic。
	for i := 0; i < geoIPCacheMaxEntries+10; i++ {
		c.set("ip", "US", time.Minute, now) // 重复 key，验证 map 重建路径
	}
	if len(c.m) > geoIPCacheMaxEntries {
		t.Fatalf("cache grew beyond cap: %d", len(c.m))
	}
}

func TestIsPrivateOrLoopback(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.1:8080", "::1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.1.1", "localhost"} {
		if !isPrivateOrLoopback(ip) {
			t.Fatalf("%q should be private/loopback", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "8.8.8.8", "114.114.114.114", "2001:4860:4860::8888"} {
		if isPrivateOrLoopback(ip) {
			t.Fatalf("%q should be public", ip)
		}
	}
}

func TestGeoIPBlockAllowDecision(t *testing.T) {
	cases := []struct {
		mode     string
		countries []string
		code     string
		want     bool // blocked?
	}{
		{"block", []string{"CN"}, "CN", true},
		{"block", []string{"CN"}, "US", false},
		{"block", []string{"cn"}, "CN", true}, // 大小写不敏感
		{"block", []string{}, "US", false},    // 空名单 block 模式放行
		{"allow", []string{"CN"}, "CN", false},
		{"allow", []string{"CN"}, "US", true},
		{"allow", []string{}, "US", true}, // 空名单 allow 模式全拒
	}
	for i, tc := range cases {
		cfg := &database.GeoIPConfig{Mode: tc.mode, Countries: tc.countries}
		inList := false
		for _, cc := range cfg.Countries {
			if strings.EqualFold(strings.TrimSpace(cc), tc.code) {
				inList = true
				break
			}
		}
		blocked := (cfg.Mode == "allow" && !inList) || (cfg.Mode != "allow" && inList)
		if blocked != tc.want {
			t.Fatalf("case %d: mode=%s countries=%v code=%s blocked=%v want=%v",
				i, tc.mode, tc.countries, tc.code, blocked, tc.want)
		}
	}
}

// ==================== 集成：注册闸门 ====================

type stubGeoIPResolver struct {
	code                    string
	err                     error
	gotProvider, gotAPIKey  string
	gotIP                   string
	gotTTL                  time.Duration
}

func (s *stubGeoIPResolver) CountryCode(_ context.Context, provider, apiKey, ip string, ttl time.Duration) (string, error) {
	s.gotProvider, s.gotAPIKey, s.gotIP, s.gotTTL = provider, apiKey, ip, ttl
	if s.err != nil {
		return "", s.err
	}
	return s.code, nil
}

// enableGeoIP 保存 GeoIP 配置并注入 stub resolver。
func enableGeoIP(t *testing.T, h *Handler, cfg database.GeoIPConfig) *stubGeoIPResolver {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.db.SetSettingValue(ctx, database.SettingKeyGeoIP, string(raw), 0); err != nil {
		t.Fatalf("save geoip: %v", err)
	}
	stub := &stubGeoIPResolver{code: "US"}
	h.geoipResolver = stub
	return stub
}

// doJSONWithIP 用指定 RemoteAddr 发起请求（gin 默认不信任 XFF，ClientIP 取 RemoteAddr）。
func doJSONWithIP(t *testing.T, h *Handler, method, path, body string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestGeoIPGateOnRegister(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)

	// 未启用：放行。
	rec := doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-off@example.com","password":"S3curePass!123"}`, "1.2.3.4:12345")
	if rec.Code != http.StatusCreated {
		t.Fatalf("disabled register status = %d", rec.Code)
	}

	// 启用 + block 模式 + CN 在名单 + IP 属 CN → 403。
	stub := enableGeoIP(t, h, database.GeoIPConfig{
		Enabled: true, Provider: "ipinfo", APIKey: "k", Mode: "block",
		Countries: []string{"CN"}, CacheTTLMinutes: 30,
	})
	stub.code = "CN"
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-cn@example.com","password":"S3curePass!123"}`, "1.2.3.4:12345")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked country register status = %d body=%s", rec.Code, rec.Body.String())
	}
	if stub.gotProvider != "ipinfo" || stub.gotAPIKey != "k" || stub.gotIP != "1.2.3.4" {
		t.Fatalf("resolver args = provider=%q key=%q ip=%q", stub.gotProvider, stub.gotAPIKey, stub.gotIP)
	}
	if stub.gotTTL != 30*time.Minute {
		t.Fatalf("resolver ttl = %v", stub.gotTTL)
	}

	// 同一配置下 IP 属 US（非名单）→ 放行。
	stub.code = "US"
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-us@example.com","password":"S3curePass!123"}`, "8.8.8.8:12345")
	if rec.Code != http.StatusCreated {
		t.Fatalf("allowed country register status = %d body=%s", rec.Code, rec.Body.String())
	}

	// allow 模式：仅 CN 放行，US 拒绝。
	stub = enableGeoIP(t, h, database.GeoIPConfig{
		Enabled: true, Provider: "maxmind", APIKey: "acc:lic", Mode: "allow",
		Countries: []string{"CN"}, CacheTTLMinutes: 10,
	})
	stub.code = "US"
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-us2@example.com","password":"S3curePass!123"}`, "8.8.8.8:12345")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("allow-mode non-list register status = %d", rec.Code)
	}
	stub.code = "CN"
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-cn2@example.com","password":"S3curePass!123"}`, "1.2.3.4:12345")
	if rec.Code != http.StatusCreated {
		t.Fatalf("allow-mode listed register status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 启用但 provider 为空 → 403（fail-closed）。
	enableGeoIP(t, h, database.GeoIPConfig{Enabled: true, Mode: "block", Countries: []string{"CN"}})
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-empty@example.com","password":"S3curePass!123"}`, "1.2.3.4:12345")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("enabled-no-provider register status = %d", rec.Code)
	}

	// resolver 失败 → 503（fail-closed）。
	stub = enableGeoIP(t, h, database.GeoIPConfig{
		Enabled: true, Provider: "ipinfo", APIKey: "k", Mode: "block", Countries: []string{"CN"},
	})
	stub.err = context.DeadlineExceeded
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-err@example.com","password":"S3curePass!123"}`, "1.2.3.4:12345")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolver-fail register status = %d", rec.Code)
	}

	// 回环 IP → 放行（不触发 resolver）。
	stub.err = nil
	stub.code = "CN"
	stub.gotIP = ""
	rec = doJSONWithIP(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"g-loop@example.com","password":"S3curePass!123"}`, "127.0.0.1:12345")
	if rec.Code != http.StatusCreated {
		t.Fatalf("loopback register status = %d", rec.Code)
	}
	if stub.gotIP != "" {
		t.Fatal("resolver should not be called for loopback")
	}
}

// TestGeoIPResolverMaxMindAndIPInfo 用本地 mock 验证两个 provider 的 HTTP 解析。
func TestGeoIPResolverMaxMindAndIPInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/maxmind/9.9.9.1" {
			_, _ = w.Write([]byte(`{"country":{"iso_code":"CN"}}`))
			return
		}
		if r.URL.Path == "/ipinfo/9.9.9.2" {
			_, _ = w.Write([]byte(`{"country":"JP"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	oldMaxMindFmt, oldIPInfoFmt := maxMindCountryURLFmt, ipinfoCountryURLFmt
	maxMindCountryURLFmt = srv.URL + "/maxmind/%s"
	ipinfoCountryURLFmt = srv.URL + "/ipinfo/%s"
	defer func() { maxMindCountryURLFmt, ipinfoCountryURLFmt = oldMaxMindFmt, oldIPInfoFmt }()

	r := newHTTPGeoIPResolver()
	code, err := r.CountryCode(context.Background(), "maxmind", "acc:lic", "9.9.9.1", time.Minute)
	if err != nil || code != "CN" {
		t.Fatalf("maxmind code=%q err=%v", code, err)
	}
	code, err = r.CountryCode(context.Background(), "ipinfo", "tok", "9.9.9.2", time.Minute)
	if err != nil || code != "JP" {
		t.Fatalf("ipinfo code=%q err=%v", code, err)
	}
	// 缓存命中：第二次调用直接返回（不请求上游）。
	code, err = r.CountryCode(context.Background(), "ipinfo", "tok", "9.9.9.2", time.Minute)
	if err != nil || code != "JP" {
		t.Fatalf("cached code=%q err=%v", code, err)
	}
	// maxmind key 格式错误（用未缓存过的 IP）。
	if _, err := r.CountryCode(context.Background(), "maxmind", "nocolon", "9.9.9.9", time.Minute); err == nil {
		t.Fatal("bad maxmind key accepted")
	}
	// 未知 provider。
	if _, err := r.CountryCode(context.Background(), "nope", "", "9.9.9.9", time.Minute); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

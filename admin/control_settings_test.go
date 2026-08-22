package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func newControlSettingsTestHandler(t *testing.T) (*Handler, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := newTestAdminDB(t)
	store := auth.NewStore(db, nil, nil)
	store.SetLazyMode(true)
	tc := cache.NewMemory(1)
	t.Cleanup(func() { _ = tc.Close() })
	h := NewHandler(store, db, tc, nil, "admin-secret")
	return h, db
}

func controlSettingsDo(t *testing.T, h *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	h.RegisterRoutes(r)
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", "admin-secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestGetControlSettingsDefaults(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)
	rec := controlSettingsDo(t, h, http.MethodGet, "/api/admin/control-settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if gjson.Get(body, "billing.enabled").Bool() {
		t.Fatalf("billing.enabled should default false: %s", body)
	}
	if gjson.Get(body, "billing.deposit_micro").Int() != 10_000_000 {
		t.Fatalf("billing.deposit_micro default: %s", body)
	}
	if gjson.Get(body, "smtp.port").Int() != 587 {
		t.Fatalf("smtp.port default: %s", body)
	}
	if gjson.Get(body, "smtp.security").String() != "starttls" {
		t.Fatalf("smtp.security default: %s", body)
	}
	if !gjson.Get(body, "geoip").Exists() || !gjson.Get(body, "epay").Exists() ||
		!gjson.Get(body, "turnstile").Exists() {
		t.Fatalf("missing sections: %s", body)
	}
}

func TestUpdateBillingPatchSemantics(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)

	// 只改部分字段 → 其余保持默认
	rec := controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/billing",
		`{"enabled":true,"deposit_micro":2500000}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = controlSettingsDo(t, h, http.MethodGet, "/api/admin/control-settings", "")
	body := rec.Body.String()
	if !gjson.Get(body, "billing.enabled").Bool() {
		t.Fatalf("enabled not persisted: %s", body)
	}
	if gjson.Get(body, "billing.deposit_micro").Int() != 2500000 {
		t.Fatalf("deposit_micro not persisted: %s", body)
	}
	if gjson.Get(body, "billing.cny_per_usd").Float() != 12.0 {
		t.Fatalf("cny_per_usd should keep default 12: %s", body)
	}
}

func TestUpdateBillingValidation(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)

	cases := []struct {
		name string
		body string
	}{
		{"negative deposit", `{"deposit_micro":-1}`},
		{"zero deposit", `{"deposit_micro":0}`},
		{"negative cny", `{"cny_per_usd":-3}`},
		{"cap below min", `{"min_charge_micro":100000,"charge_cap_micro":50000}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/billing", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d want 400 body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUpdateControlSettingsValidation(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)

	// 未知配置段
	rec := controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/nope", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown section status = %d", rec.Code)
	}

	// 启用 SMTP 但缺 host
	rec = controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/smtp",
		`{"enabled":true,"port":587,"from":"a@b.c"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("smtp no host status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 启用易支付但缺 key
	rec = controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/epay",
		`{"enabled":true,"merchant_id":"m1","gateway_url":"https://pay.example.com/submit.php","callback_base_url":"https://api.example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("epay no key status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 启用 Turnstile 但缺 secret
	rec = controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/turnstile",
		`{"enabled":true,"site_key":"abc"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("turnstile status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateSMTPAndGeoIPRoundTrip(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)

	rec := controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/smtp",
		`{"enabled":true,"host":"smtp.example.com","port":465,"security":"ssl","from":"no-reply@example.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("smtp put status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = controlSettingsDo(t, h, http.MethodPut, "/api/admin/control-settings/geoip",
		`{"enabled":true,"provider":"maxmind","mode":"allow","countries":["cn","us"],"api_key":"abc"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("geoip put status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = controlSettingsDo(t, h, http.MethodGet, "/api/admin/control-settings", "")
	body := rec.Body.String()
	if gjson.Get(body, "smtp.host").String() != "smtp.example.com" ||
		gjson.Get(body, "smtp.security").String() != "ssl" {
		t.Fatalf("smtp roundtrip: %s", body)
	}
	if gjson.Get(body, "geoip.mode").String() != "allow" ||
		!gjson.Get(body, "geoip.countries.0").Exists() {
		t.Fatalf("geoip roundtrip: %s", body)
	}
}

func TestTestSMTPConnectionRequiresConfig(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)

	// 未配置 SMTP → 400
	rec := controlSettingsDo(t, h, http.MethodPost, "/api/admin/control-settings/smtp/test", `{"to":"a@b.c"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("smtp test no config status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 非法邮箱 → 400
	rec = controlSettingsDo(t, h, http.MethodPost, "/api/admin/control-settings/smtp/test", `{"to":"not-an-email"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("smtp test bad email status = %d", rec.Code)
	}
}

func TestControlSettingsAdminAuthRequired(t *testing.T) {
	h, _ := newControlSettingsTestHandler(t)
	r := gin.New()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/control-settings", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without admin key status = %d want 401", rec.Code)
	}
}

func TestMailerNotConfiguredSentinel(t *testing.T) {
	// logOnly 与无配置的 smtpMailer 都应返回 ErrMailerNotConfigured，
	// 保证注册/重置接口回落 dev URL 行为。
	if err := (logOnlyUserMailer{}).SendVerificationEmail(t.Context(), "a@b.c", "http://x"); err != ErrMailerNotConfigured {
		t.Fatalf("logOnly mailer should return ErrMailerNotConfigured, got %v", err)
	}
	_, db := newControlSettingsTestHandler(t)
	m := smtpMailer{db: db}
	if err := m.SendVerificationEmail(t.Context(), "a@b.c", "http://x"); err != ErrMailerNotConfigured {
		t.Fatalf("unconfigured smtpMailer should return ErrMailerNotConfigured, got %v", err)
	}
}

func TestBillingConfigJSONShape(t *testing.T) {
	// 前端按微元传值，校验 JSON 序列化/反序列化往返不丢字段。
	cfg := database.DefaultBillingConfig()
	cfg.Enabled = true
	cfg.DepositMicro = 3_000_000
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back database.BillingConfig
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.Enabled || back.DepositMicro != 3_000_000 || back.CNYPerUSD != 12.0 {
		t.Fatalf("roundtrip mismatch: %+v", back)
	}
}

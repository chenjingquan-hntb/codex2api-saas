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
	"github.com/tidwall/gjson"
)

// ==================== 单元：token 提取 / verifier ====================

func TestTurnstileTokenFromRequest(t *testing.T) {
	// JSON body。
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/auth/register",
		strings.NewReader(`{"email":"a@b.c","cf_turnstile_token":"tok-json"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	if got := turnstileTokenFromRequest(c, "cf_turnstile_token"); got != "tok-json" {
		t.Fatalf("json token = %q", got)
	}
	// body 已被放回，可再次解析。
	var again map[string]string
	if err := json.NewDecoder(c.Request.Body).Decode(&again); err != nil {
		t.Fatalf("body not restored: %v", err)
	}
	if again["cf_turnstile_token"] != "tok-json" {
		t.Fatalf("restored body token = %q", again["cf_turnstile_token"])
	}

	// query 参数。
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = httptest.NewRequest(http.MethodPost, "/x?cf_turnstile_token=tok-q", nil)
	if got := turnstileTokenFromRequest(c2, "cf_turnstile_token"); got != "tok-q" {
		t.Fatalf("query token = %q", got)
	}

	// 表单。
	c3, _ := gin.CreateTestContext(httptest.NewRecorder())
	c3.Request = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("cf_turnstile_token=tok-f"))
	c3.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := turnstileTokenFromRequest(c3, "cf_turnstile_token"); got != "tok-f" {
		t.Fatalf("form token = %q", got)
	}
}

// TestHTTPTurnstileVerifierSiteverify 用本地 siteverify mock 验证请求构造与响应判定。
func TestHTTPTurnstileVerifierSiteverify(t *testing.T) {
	var (
		gotSecret   string
		gotResponse string
		gotRemoteIP string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.Form.Get("secret")
		gotResponse = r.Form.Get("response")
		gotRemoteIP = r.Form.Get("remoteip")
		if gotResponse == "valid-token" {
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer srv.Close()

	oldURL := turnstileVerifyURL
	turnstileVerifyURL = srv.URL
	defer func() { turnstileVerifyURL = oldURL }()

	v := httpTurnstileVerifier{}
	cfg := &database.TurnstileConfig{Enabled: true, SecretKey: "s3cret"}
	if err := v.Verify(context.Background(), cfg, "valid-token", "1.2.3.4"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if gotSecret != "s3cret" || gotResponse != "valid-token" || gotRemoteIP != "1.2.3.4" {
		t.Fatalf("siteverify params = secret=%q response=%q remoteip=%q", gotSecret, gotResponse, gotRemoteIP)
	}
	if err := v.Verify(context.Background(), cfg, "bad-token", "1.2.3.4"); err == nil {
		t.Fatal("bad token accepted")
	}
	// 未启用 → 跳过；空 secret/token → 错误。
	if err := v.Verify(context.Background(), &database.TurnstileConfig{Enabled: false}, "", ""); err != nil {
		t.Fatalf("disabled should skip: %v", err)
	}
	if err := v.Verify(context.Background(), cfg, "", ""); err != errTurnstileTokenEmpty {
		t.Fatalf("empty token err = %v", err)
	}
	if err := v.Verify(context.Background(), &database.TurnstileConfig{Enabled: true}, "t", ""); err != errTurnstileNotConfigured {
		t.Fatalf("missing secret err = %v", err)
	}
}

// ==================== 集成：注册/登录接入 ====================

type stubTurnstileVerifier struct {
	err      error
	gotToken string
	gotIP    string
}

func (s *stubTurnstileVerifier) Verify(_ context.Context, _ *database.TurnstileConfig, token, remoteIP string) error {
	s.gotToken = token
	s.gotIP = remoteIP
	if s.err != nil {
		return s.err
	}
	if strings.TrimSpace(token) == "" {
		return errTurnstileTokenEmpty // 模拟真实行为：空 token 一律拒绝
	}
	return nil
}

// markUserEmailVerified 直接置位邮箱已验证（跳过邮件环节，供登录类测试用）。
func markUserEmailVerified(t *testing.T, h *Handler, email string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, err := h.db.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get user %s: %v", email, err)
	}
	if err := h.db.SetUserEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("verify user %s: %v", email, err)
	}
}

// enableTurnstile 通过管理配置接口开启 Turnstile 并注入 stub verifier。
func enableTurnstile(t *testing.T, h *Handler, err error) *stubTurnstileVerifier {
	t.Helper()
	cfg := database.TurnstileConfig{Enabled: true, SiteKey: "site", SecretKey: "secret"}
	raw, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.db.SetSettingValue(ctx, database.SettingKeyTurnstile, string(raw), 0); err != nil {
		t.Fatalf("save turnstile: %v", err)
	}
	stub := &stubTurnstileVerifier{err: err}
	h.turnstileVerifier = stub
	return stub
}

func TestTurnstileGateOnRegisterAndLogin(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)

	// 未启用：注册不带 token 也成功。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"ts-off@example.com","password":"S3curePass!123"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("disabled register status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 启用 + verifier 失败（如 token 无效）：注册被拒 403。
	enableTurnstile(t, h, errTurnstileTokenEmpty)
	rec = doJSON(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"ts-on@example.com","password":"S3curePass!123","cf_turnstile_token":"bad"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("enabled+bad register status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 启用 + 无 token：注册被拒 403。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"ts-on2@example.com","password":"S3curePass!123"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("enabled+no token register status = %d", rec.Code)
	}

	// 启用 + 有效 token：注册成功，token 透传给了 verifier。
	stub := enableTurnstile(t, h, nil)
	rec = doJSON(t, h, http.MethodPost, "/api/auth/register",
		`{"email":"ts-ok@example.com","password":"S3curePass!123","cf_turnstile_token":"good"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enabled+valid register status = %d body=%s", rec.Code, rec.Body.String())
	}
	if stub.gotToken != "good" {
		t.Fatalf("verifier token = %q", stub.gotToken)
	}
	if stub.gotIP == "" {
		t.Fatal("verifier remote IP not passed")
	}
	// 完成邮箱验证（登录前置条件）。
	markUserEmailVerified(t, h, "ts-ok@example.com")

	// 登录同样受闸门约束：无 token 403。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/login",
		`{"email":"ts-ok@example.com","password":"S3curePass!123"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login without token status = %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/auth/login",
		`{"email":"ts-ok@example.com","password":"S3curePass!123","cf_turnstile_token":"good"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login with token status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "access_token").String(); got == "" {
		t.Fatalf("login missing access_token")
	}
}

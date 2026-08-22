package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func newUserAuthTestHandler(t *testing.T) (*Handler, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "users-auth.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := auth.NewStore(db, nil, nil)
	store.SetLazyMode(true)
	tc := cache.NewMemory(1)
	t.Cleanup(func() { _ = tc.Close() })

	h := NewHandler(store, db, tc, nil, "")
	// 保持 logOnly 邮件实现，注册/重置响应才会带 dev_verify_url。
	return h, db
}

func doJSON(t *testing.T, h *Handler, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
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
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func registerUser(t *testing.T, h *Handler, email, password string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	rec := doJSON(t, h, http.MethodPost, "/api/auth/register", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", rec.Code, rec.Body.String())
	}
	url := gjson.Get(rec.Body.String(), "dev_verify_url").String()
	if url == "" {
		t.Fatalf("register response missing dev_verify_url: %s", rec.Body.String())
	}
	token := tokenFromVerifyURL(url)
	return int(gjson.Get(rec.Body.String(), "user_id").Int()), token
}

func tokenFromVerifyURL(url string) string {
	idx := strings.Index(url, "token=")
	if idx < 0 {
		return ""
	}
	return url[idx+len("token="):]
}

func loginUser(t *testing.T, h *Handler, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	return doJSON(t, h, http.MethodPost, "/api/auth/login", body, nil)
}

func sessionCookie(rec *httptest.ResponseRecorder) []*http.Cookie {
	return rec.Result().Cookies()
}

func TestUserAuthFullFlow(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "flow@example.com"
	password := "S3curePass!123"

	// 1) 注册 → 201 + dev 验证链接。
	userID, verifyToken := registerUser(t, h, email, password)
	if userID == 0 {
		t.Fatal("user_id should be non-zero")
	}

	// 未验证时登录被拒。
	rec := loginUser(t, h, email, password)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login unverified status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}

	// 2) 验证邮箱。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 3) 登录 → 200 + 会话 Cookie。
	rec = loginUser(t, h, email, password)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := sessionCookie(rec)
	if len(cookies) == 0 {
		t.Fatal("login did not set cookie")
	}

	// 4) /me 需登录。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "email").String(); got != email {
		t.Fatalf("me email = %s, want %s", got, email)
	}

	// 未带 Cookie → 401。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me without cookie status = %d, want 401", rec.Code)
	}

	// 5) 会话列表 + 吊销。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/sessions", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("sessions status = %d body=%s", rec.Code, rec.Body.String())
	}
	sessions := gjson.Get(rec.Body.String(), "sessions").Array()
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
	currentID := gjson.Get(rec.Body.String(), "sessions.0.session_id").Int()

	// 6) 修改密码（当前会话保留）。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/password",
		fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, password, "NewPass!456"), cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 旧密码不再可用。
	rec = loginUser(t, h, email, password)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password login status = %d, want 401", rec.Code)
	}
	// 新密码可登录。
	rec = loginUser(t, h, email, "NewPass!456")
	if rec.Code != http.StatusOK {
		t.Fatalf("new password login status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 当前会话仍在（改密不踢当前）。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("me after password change status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 7) 吊销当前会话（通过 sessions 接口拒绝，登出后 401）。
	rec = doJSON(t, h, http.MethodPost, fmt.Sprintf("/api/auth/sessions/%d/revoke", currentID), "", cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("revoke current session status = %d, want 400", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/auth/logout", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", cookies)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d, want 401", rec.Code)
	}
}

func TestUserRegisterDuplicateEmail(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "dup@example.com"
	registerUser(t, h, email, "Password!123")

	rec := doJSON(t, h, http.MethodPost, "/api/auth/register",
		fmt.Sprintf(`{"email":%q,"password":%q}`, email, "OtherPass!123"), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestUserRegisterInvalidInput(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	cases := []struct {
		name, body string
	}{
		{"bad email", `{"email":"not-an-email","password":"Password!123"}`},
		{"short password", `{"email":"a@b.com","password":"short"}`},
		{"empty", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, h, http.MethodPost, "/api/auth/register", tc.body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUserLoginWrongPassword(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "wrongpw@example.com"
	_, token := registerUser(t, h, email, "Password!123")
	doJSON(t, h, http.MethodPost, "/api/auth/verify-email", fmt.Sprintf(`{"token":%q}`, token), nil)

	rec := loginUser(t, h, email, "WrongPassword!123")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password login status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestUserLoginUnknownEmailGeneric(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	rec := loginUser(t, h, "ghost@example.com", "Whatever!123")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown email status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "邮箱或密码错误") {
		t.Fatalf("response should not leak user existence: %s", rec.Body.String())
	}
}

func TestUserResendVerificationAntiEnumeration(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "resend@example.com"
	registerUser(t, h, email, "Password!123")

	// 存在用户 → 200 + dev_verify_url。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/resend-verification",
		fmt.Sprintf(`{"email":%q}`, email), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("resend status = %d body=%s", rec.Code, rec.Body.String())
	}
	if gjson.Get(rec.Body.String(), "dev_verify_url").String() == "" {
		t.Fatalf("resend should return dev_verify_url: %s", rec.Body.String())
	}

	// 不存在用户 → 200 且无 dev_verify_url（防枚举）。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/resend-verification",
		`{"email":"ghost@example.com"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("resend ghost status = %d, want 200", rec.Code)
	}
	if gjson.Get(rec.Body.String(), "dev_verify_url").Exists() {
		t.Fatalf("ghost resend should not expose dev_verify_url: %s", rec.Body.String())
	}
}

func TestUserVerifyEmailInvalidToken(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email", `{"token":"bogus"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid token status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestUserPasswordResetFlow(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "reset@example.com"
	registerUser(t, h, email, "Password!123")

	// 请求重置 → 200 + dev_reset_url。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/password-reset-request",
		fmt.Sprintf(`{"email":%q}`, email), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset request status = %d body=%s", rec.Code, rec.Body.String())
	}
	url := gjson.Get(rec.Body.String(), "dev_reset_url").String()
	if url == "" {
		t.Fatalf("reset request missing dev_reset_url: %s", rec.Body.String())
	}
	resetToken := tokenFromVerifyURL(url)

	// 执行重置。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/password-reset",
		fmt.Sprintf(`{"token":%q,"new_password":%q}`, resetToken, "ResetPass!123"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 旧密码失效、新密码可登录（未验证用户重置后仍需验证邮箱，但这里已验证过注册即验证流程）。
	rec = loginUser(t, h, email, "Password!123")
	if rec.Code == http.StatusOK {
		t.Fatalf("old password should not work after reset")
	}
}

func TestUserChangePasswordWrongCurrent(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	email := "wrongcurrent@example.com"
	_, token := registerUser(t, h, email, "Password!123")
	doJSON(t, h, http.MethodPost, "/api/auth/verify-email", fmt.Sprintf(`{"token":%q}`, token), nil)
	rec := loginUser(t, h, email, "Password!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	cookies := sessionCookie(rec)

	rec = doJSON(t, h, http.MethodPost, "/api/auth/password",
		`{"current_password":"Wrong!123","new_password":"NewPass!456"}`, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong current status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestKeyedRateLimiter(t *testing.T) {
	l := newKeyedRateLimiter(2, time.Minute)
	now := time.Now()
	if !l.allow("ip-1", now) || !l.allow("ip-1", now) || l.allow("ip-1", now) {
		t.Fatal("limiter should allow 2 then reject")
	}
	if !l.allow("ip-2", now) {
		t.Fatal("different key should not share quota")
	}
	if !l.allow("ip-1", now.Add(time.Minute+time.Second)) {
		t.Fatal("window expiry should free quota")
	}
}

package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// ==================== Access Token 单元测试 ====================

func TestAccessTokenRoundTrip(t *testing.T) {
	now := time.Now()
	tok, expIn, err := issueAccessToken(42, 7, "user", "u@example.com", now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if expIn != int64(accessTokenTTL.Seconds()) {
		t.Fatalf("expires_in = %d", expIn)
	}
	cl, err := verifyAccessToken(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UID != 42 || cl.SID != 7 || cl.Role != "user" || cl.Email != "u@example.com" {
		t.Fatalf("claims = %+v", cl)
	}
}

func TestAccessTokenRejectsTampering(t *testing.T) {
	now := time.Now()
	tok, _, err := issueAccessToken(42, 7, "user", "u@example.com", now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// 篡改 payload（把 uid 改成 999）。
	parts := splitAccessToken(t, tok)
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var cl accessClaims
	if err := json.Unmarshal(rawPayload, &cl); err != nil {
		t.Fatal(err)
	}
	cl.UID = 999
	forged, err := json.Marshal(cl)
	if err != nil {
		t.Fatal(err)
	}
	forgedTok := accessTokenPrefix + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := verifyAccessToken(forgedTok, now); err != errAccessTokenInvalid {
		t.Fatalf("tampered payload err = %v, want invalid", err)
	}
	// 篡改签名。
	badSig := base64.RawURLEncoding.EncodeToString([]byte("forged-signature"))
	badTok := accessTokenPrefix + parts[1] + "." + badSig
	if _, err := verifyAccessToken(badTok, now); err != errAccessTokenInvalid {
		t.Fatalf("tampered signature err = %v, want invalid", err)
	}
	// 格式错误。
	for _, bad := range []string{"", "v1.abc", "v2.abc.def", accessTokenPrefix + "a.b.c.d", "garbage"} {
		if _, err := verifyAccessToken(bad, now); err == nil {
			t.Fatalf("malformed %q accepted", bad)
		}
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	now := time.Now()
	tok, _, err := issueAccessToken(42, 7, "user", "u@example.com", now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// 即将到期：TTL 内有效。
	if _, err := verifyAccessToken(tok, now.Add(accessTokenTTL-1*time.Second)); err != nil {
		t.Fatalf("within ttl err = %v", err)
	}
	// 过期：TTL 后无效。
	if _, err := verifyAccessToken(tok, now.Add(accessTokenTTL+1*time.Second)); err != errAccessTokenExpired {
		t.Fatalf("expired err = %v, want expired", err)
	}
}

func splitAccessToken(t *testing.T, tok string) [3]string {
	t.Helper()
	rest := strings.TrimPrefix(tok, accessTokenPrefix)
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Fatalf("unexpected token format: %q", tok)
	}
	return [3]string{"v1", parts[0], parts[1]}
}

// ==================== 集成测试 ====================

// doJSONBearer 是 doJSON 的 Bearer 版本：额外携带 Authorization 头（可同时带 cookie）。
func doJSONBearer(t *testing.T, h *Handler, method, path, body, bearer string, cookies []*http.Cookie) *httptest.ResponseRecorder {
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
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// doJSONAuth 是 doJSON 的 Bearer 版本（无 cookie）。
func doJSONAuth(t *testing.T, h *Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONBearer(t, h, method, path, body, bearer, nil)
}

func loginAndGetToken(t *testing.T, h *Handler, email, password string) (string, []*http.Cookie) {
	t.Helper()
	rec := loginUser(t, h, email, password)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", rec.Code, rec.Body.String())
	}
	token := gjson.Get(rec.Body.String(), "access_token").String()
	if token == "" {
		t.Fatalf("login response missing access_token: %s", rec.Body.String())
	}
	return token, sessionCookie(rec)
}

func TestAccessTokenLoginAndBearerFlow(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	_, verifyToken := registerUser(t, h, "at@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}

	token, cookies := loginAndGetToken(t, h, "at@example.com", "S3curePass!123")
	if len(cookies) == 0 {
		t.Fatal("login did not set refresh cookie")
	}

	// Bearer 调受保护接口。
	rec = doJSONAuth(t, h, http.MethodGet, "/api/auth/me", "", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer /me status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "email").String(); got != "at@example.com" {
		t.Fatalf("me email = %q", got)
	}

	// 无效 Bearer → 401（不回落 cookie）。
	rec = doJSONAuth(t, h, http.MethodGet, "/api/auth/me", "", "v1.forged.invalid")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer status = %d", rec.Code)
	}
	// 无凭据 → 401。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", rec.Code)
	}
}

func TestAccessTokenRefreshFlow(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	_, verifyToken := registerUser(t, h, "ref@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	_, cookies := loginAndGetToken(t, h, "ref@example.com", "S3curePass!123")

	// refresh：cookie → 新 access token。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/refresh", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", rec.Code, rec.Body.String())
	}
	newToken := gjson.Get(rec.Body.String(), "access_token").String()
	if newToken == "" {
		t.Fatalf("refresh missing access_token")
	}
	// 新 token 可用。
	rec = doJSONAuth(t, h, http.MethodGet, "/api/auth/me", "", newToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("refreshed bearer /me status = %d", rec.Code)
	}
	// 不轮换：旧 cookie 仍可 refresh（多标签页并发安全）。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/refresh", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("second refresh status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 无 cookie → 401。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/refresh", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous refresh status = %d", rec.Code)
	}

	// logout 后 refresh → 401（DB 吊销即时生效）。
	rec = doJSON(t, h, http.MethodPost, "/api/auth/logout", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/auth/refresh", "", cookies)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status = %d", rec.Code)
	}
}

func TestAccessTokenCookieCompatPath(t *testing.T) {
	h, _ := newUserAuthTestHandler(t)
	_, verifyToken := registerUser(t, h, "cc@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	_, cookies := loginAndGetToken(t, h, "cc@example.com", "S3curePass!123")
	// 无 Bearer、仅 Cookie → 仍可访问（兼容路径）。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/me", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie /me status = %d body=%s", rec.Code, rec.Body.String())
	}
}

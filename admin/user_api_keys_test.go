package admin

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/codex2api/database"
	"github.com/tidwall/gjson"
)

func newPortalTestHandler(t *testing.T) (*Handler, *database.DB, []*http.Cookie) {
	t.Helper()
	h, db := newUserAuthTestHandler(t)
	_, verifyToken := registerUser(t, h, "portal@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	rec = loginUser(t, h, "portal@example.com", "S3curePass!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d", rec.Code)
	}
	return h, db, sessionCookie(rec)
}

func TestPortalAPIKeyLifecycle(t *testing.T) {
	h, db, cookies := newPortalTestHandler(t)

	// 创建：明文只返回一次。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/keys", `{"name":"我的第一个 Key"}`, cookies)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	secret := gjson.Get(rec.Body.String(), "key").String()
	if !strings.HasPrefix(secret, database.UserAPIKeyPrefix) {
		t.Fatalf("secret = %q", secret)
	}
	keyID := gjson.Get(rec.Body.String(), "key_id").Int()
	if keyID <= 0 {
		t.Fatalf("key_id = %d", keyID)
	}

	// 列表：不返回明文，只有前缀。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/keys", "", cookies)
	if rec.Code != http.StatusOK || gjson.Get(rec.Body.String(), "keys.#").Int() != 1 {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "keys.0.key").Exists(); got {
		t.Fatalf("list must not expose plaintext key")
	}
	prefix := gjson.Get(rec.Body.String(), "keys.0.prefix").String()
	if prefix == "" {
		t.Fatalf("missing prefix")
	}

	// 鉴权热路径：DB 层能按摘要命中新 key。
	row, err := db.GetAPIKeyByValue(t.Context(), secret)
	if err != nil || row == nil {
		t.Fatalf("hot-path lookup failed: %v", err)
	}

	// 改名。
	rec = doJSON(t, h, http.MethodPatch, fmt.Sprintf("/api/auth/keys/%d", keyID), `{"name":"renamed"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodGet, "/api/auth/keys", "", cookies)
	if got := gjson.Get(rec.Body.String(), "keys.0.name").String(); got != "renamed" {
		t.Fatalf("name = %q", got)
	}

	// 撤销 → 立即失效。
	rec = doJSON(t, h, http.MethodPost, fmt.Sprintf("/api/auth/keys/%d/revoke", keyID), `{"reason":"leaked"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := db.GetAPIKeyByValue(t.Context(), secret); err == nil {
		t.Fatalf("revoked key still resolves")
	}
	// 重复撤销 → 409。
	rec = doJSON(t, h, http.MethodPost, fmt.Sprintf("/api/auth/keys/%d/revoke", keyID), "", cookies)
	if rec.Code != http.StatusConflict {
		t.Fatalf("double revoke status = %d", rec.Code)
	}
	// 越权：另一个用户操作 → 404。
	otherCookies := registerAndLoginOther(t, h)
	rec = doJSON(t, h, http.MethodPost, fmt.Sprintf("/api/auth/keys/%d/revoke", keyID), "", otherCookies)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user revoke status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 未登录 → 401。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/keys", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list status = %d", rec.Code)
	}
}

func TestPortalUsageLedgerAndPricing(t *testing.T) {
	h, _, cookies := newPortalTestHandler(t)

	// 用量聚合（空数据也应 200 空报告）。
	rec := doJSON(t, h, http.MethodGet, "/api/auth/usage", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "report.summary.requests").Int(); got != 0 {
		t.Fatalf("requests = %d", got)
	}
	// 每日趋势。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/usage/daily?days=7", "", cookies)
	if rec.Code != http.StatusOK || gjson.Get(rec.Body.String(), "days.#").Int() != 7 {
		t.Fatalf("daily status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 账本。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/ledger", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("ledger status = %d body=%s", rec.Code, rec.Body.String())
	}
	// 未登录的 usage → 401。
	rec = doJSON(t, h, http.MethodGet, "/api/auth/usage", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous usage status = %d", rec.Code)
	}
	// 公开价格表（无鉴权）。
	rec = doJSON(t, h, http.MethodGet, "/api/public/model-pricing", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("public pricing status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "models.#").Int(); got == 0 {
		t.Fatalf("pricing models empty: %s", rec.Body.String())
	}
}

func TestPortalAPIKeyPerKeyUsage(t *testing.T) {
	h, _, cookies := newPortalTestHandler(t)

	rec := doJSON(t, h, http.MethodPost, "/api/auth/keys", `{"name":"usage key"}`, cookies)
	keyID := gjson.Get(rec.Body.String(), "key_id").Int()

	rec = doJSON(t, h, http.MethodGet, fmt.Sprintf("/api/auth/keys/%d/usage", keyID), "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("per-key usage status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := gjson.Get(rec.Body.String(), "report.summary.requests").Int(); got != 0 {
		t.Fatalf("requests = %d", got)
	}
	// 越权 key usage → 404。
	otherCookies := registerAndLoginOther(t, h)
	rec = doJSON(t, h, http.MethodGet, fmt.Sprintf("/api/auth/keys/%d/usage", keyID), "", otherCookies)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user usage status = %d", rec.Code)
	}
}

func registerAndLoginOther(t *testing.T, h *Handler) []*http.Cookie {
	t.Helper()
	_, verifyToken := registerUser(t, h, "other@example.com", "S3curePass!123")
	rec := doJSON(t, h, http.MethodPost, "/api/auth/verify-email",
		fmt.Sprintf(`{"token":%q}`, verifyToken), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	rec = loginUser(t, h, "other@example.com", "S3curePass!123")
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d", rec.Code)
	}
	return sessionCookie(rec)
}

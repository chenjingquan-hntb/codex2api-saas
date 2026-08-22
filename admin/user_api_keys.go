package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// 用户门户：API Key 自管理（P5）。
//
// 安全基线：
//   - 明文 key 只在创建响应中出现一次，之后任何接口都不再返回；
//   - 列表只返回前缀与状态；撤销是条件更新 + 运行时缓存精确失效，即刻生效；
//   - 越权（操作他人 key）一律 404，不泄漏 key 存在性。

// ListMyAPIKeys GET /api/auth/keys
func (h *Handler) ListMyAPIKeys(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	keys, err := h.db.ListUserAPIKeys(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		out = append(out, userAPIKeyJSON(k, false))
	}
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

// CreateMyAPIKey POST /api/auth/keys
// 请求：{"name": "..."}；响应含一次性的 key 明文。
func (h *Handler) CreateMyAPIKey(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "default"
	}
	if len(req.Name) > 64 {
		writeError(c, http.StatusBadRequest, "名称最长 64 字符")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	row, secret, err := h.db.CreateUserAPIKey(ctx, sess.UserID, req.Name)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrAPIKeyLimitReached):
			writeError(c, http.StatusTooManyRequests, "已达到单个用户最大 API Key 数量（50）")
		default:
			writeInternalError(c, err)
		}
		return
	}
	security.SecurityAuditLog("USER_API_KEY_CREATED",
		fmt.Sprintf("user_id=%d key_id=%d name=%q", sess.UserID, row.ID, row.Name))
	c.JSON(http.StatusCreated, gin.H{
		"key_id": row.ID,
		"name":   row.Name,
		// 明文只出现这一次，之后仅能通过列表看到前缀。
		"key":        secret,
		"prefix":     row.KeyPrefix,
		"created_at": row.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// RenameMyAPIKey PATCH /api/auth/keys/:id
func (h *Handler) RenameMyAPIKey(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	keyID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || keyID <= 0 {
		writeError(c, http.StatusBadRequest, "key ID 无效")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		writeError(c, http.StatusBadRequest, "名称必须为 1 ~ 64 字符")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	if err := h.db.RenameUserAPIKey(ctx, sess.UserID, keyID, req.Name); err != nil {
		if errors.Is(err, database.ErrAPIKeyNotFound) {
			writeError(c, http.StatusNotFound, "key 不存在或已撤销")
			return
		}
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "name": req.Name})
}

// RevokeMyAPIKey POST /api/auth/keys/:id/revoke
// 请求：{"reason": "..."（可选）}。撤销即刻生效：DB 层过滤 + 运行时缓存精确失效。
func (h *Handler) RevokeMyAPIKey(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	keyID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || keyID <= 0 {
		writeError(c, http.StatusBadRequest, "key ID 无效")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) > 200 {
		req.Reason = req.Reason[:200]
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	row, err := h.db.RevokeUserAPIKey(ctx, sess.UserID, keyID, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrAPIKeyNotFound):
			writeError(c, http.StatusNotFound, "key 不存在")
		case errors.Is(err, database.ErrAPIKeyNotActive):
			writeError(c, http.StatusConflict, "key 已撤销")
		default:
			writeInternalError(c, err)
		}
		return
	}
	// 精确失效运行时缓存：用户 key 的缓存键即摘要（row.Key = key_hash）。
	h.invalidateAPIKeyRuntimeCaches(ctx, row.Key)
	security.SecurityAuditLog("USER_API_KEY_REVOKED",
		fmt.Sprintf("user_id=%d key_id=%d reason=%q", sess.UserID, keyID, req.Reason))
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": row.Status})
}

// GetMyAPIKeyUsage GET /api/auth/keys/:id/usage?start=&end=&page=&page_size=
// 单个 key 的自助用量报告（复用既有报告管线）。
func (h *Handler) GetMyAPIKeyUsage(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	keyID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || keyID <= 0 {
		writeError(c, http.StatusBadRequest, "key ID 无效")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	row, err := h.db.GetUserAPIKey(ctx, sess.UserID, keyID)
	if err != nil {
		if errors.Is(err, database.ErrAPIKeyNotFound) {
			writeError(c, http.StatusNotFound, "key 不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	if row.Status != database.APIKeyStatusActive {
		writeError(c, http.StatusConflict, "key 已撤销，无用量报告")
		return
	}

	now := time.Now().UTC()
	start, end := parseUsageRange(c, now)
	page, _ := strconv.Atoi(strings.TrimSpace(c.Query("page")))
	pageSize, _ := strconv.Atoi(strings.TrimSpace(c.Query("page_size")))
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}

	report, err := h.db.GetAPIKeySelfUsageReport(ctx, row.ID, start, end, page, pageSize)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"key": gin.H{
			"id":         row.ID,
			"name":       row.Name,
			"prefix":     row.KeyPrefix,
			"created_at": row.CreatedAt.UTC().Format(time.RFC3339),
		},
		"range":  gin.H{"start": optionalRFC3339(start), "end": end.UTC().Format(time.RFC3339)},
		"report": report,
	})
}

func userAPIKeyJSON(k *database.APIKeyRow, includeKey bool) gin.H {
	out := gin.H{
		"id":         k.ID,
		"name":       k.Name,
		"prefix":     k.KeyPrefix,
		"status":     k.Status,
		"created_at": k.CreatedAt.UTC().Format(time.RFC3339),
	}
	if k.RevokedAt.Valid {
		out["revoked_at"] = k.RevokedAt.Time.UTC().Format(time.RFC3339)
	}
	if k.RevokedReason != "" {
		out["revoked_reason"] = k.RevokedReason
	}
	if k.LastUsedAt.Valid {
		out["last_used_at"] = k.LastUsedAt.Time.UTC().Format(time.RFC3339)
	}
	if includeKey {
		out["key"] = k.Key
	}
	return out
}

// parseUsageRange 解析 ?start=/?end= 查询参数（RFC3339），缺省近 30 天。
func parseUsageRange(c *gin.Context, now time.Time) (time.Time, time.Time) {
	startStr := strings.TrimSpace(c.Query("start"))
	endStr := strings.TrimSpace(c.Query("end"))
	var start, end time.Time
	if startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			start = t
		}
	}
	if endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			end = t
		}
	}
	if end.IsZero() {
		end = now
	}
	if start.IsZero() {
		start = end.AddDate(0, 0, -30)
	}
	if !start.Before(end) {
		start = end.AddDate(0, 0, -30)
	}
	return start, end
}

func optionalRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

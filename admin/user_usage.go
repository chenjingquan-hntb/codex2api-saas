package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/gin-gonic/gin"
)

// 用户门户：用量 / 账本 / 公开价格表（P5/P6）。

// GetMyUsage GET /api/auth/usage?start=&end=&page=&page_size=
// 聚合用户全部 API key 的用量报告。
func (h *Handler) GetMyUsage(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

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

	report, err := h.db.GetUserUsageReport(ctx, sess.UserID, start, end, page, pageSize)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"range":  gin.H{"start": optionalRFC3339(start), "end": end.UTC().Format(time.RFC3339)},
		"report": report,
	})
}

// GetMyDailyUsage GET /api/auth/usage/daily?days=30
func (h *Handler) GetMyDailyUsage(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	days, _ := strconv.Atoi(strings.TrimSpace(c.Query("days")))
	if days <= 0 {
		days = 30
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	rows, err := h.db.GetUserDailyUsage(ctx, sess.UserID, days)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"days": rows})
}

// ListMyLedger GET /api/auth/ledger?limit=&offset=
// 钱包账本流水（新在前），前端与余额卡共用。
func (h *Handler) ListMyLedger(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(c.Query("offset")))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	entries, err := h.db.ListWalletLedger(ctx, sess.UserID, limit, offset)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(entries))
	for _, e := range entries {
		out = append(out, gin.H{
			"id":                  e.ID,
			"type":                string(e.Type),
			"amount_micro":        e.AmountMicro,
			"balance_before_micro": e.BalanceBeforeMicro,
			"balance_after_micro":  e.BalanceAfterMicro,
			"reference_type":      e.ReferenceType,
			"reference_id":        e.ReferenceID,
			"reason":              e.Reason,
			"created_at":          e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"entries": out})
}

// GetPublicModelPricing GET /api/public/model-pricing
// 公开价格表（无鉴权），供用户门户计价页展示。只暴露模型、来源与定价。
func (h *Handler) GetPublicModelPricing(c *gin.Context) {
	ctx := c.Request.Context()

	seen := map[string]struct{}{}
	collect := func(ids []string) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			key := database.CanonicalBillingModelKey(id)
			if key == "" || strings.Contains(key, "(") {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
		return out
	}
	keys := collect(proxy.SupportedModelIDs(ctx, h.db))
	grokKeys := collect(h.grokBillingModelIDs())
	sortModelKeysNewestFirst(keys)
	sortModelKeysNewestFirst(grokKeys)
	keys = append(keys, grokKeys...)

	rows := make([]gin.H, 0, len(keys))
	for _, key := range keys {
		source := database.ModelPricingSourceFor(key)
		pricing := database.ModelPricingOverrideFromPricing(database.GetModelPricing(key), source)
		rows = append(rows, gin.H{
			"model":   key,
			"source":  source,
			"pricing": pricing,
		})
	}
	c.JSON(http.StatusOK, gin.H{"models": rows})
}

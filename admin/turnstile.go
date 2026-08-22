package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// Cloudflare Turnstile 服务端校验（P5 安全闸门）。
//
// 接入策略（fail-closed）：
//   - 配置未启用（enabled=false）：跳过校验（开发/内网场景）。
//   - 已启用但缺少 secret key：拒绝一切请求（配置不完整视为不可用），防止误开导致裸奔。
//   - 已启用：前端必须提交 cf_turnstile_token，服务端调 siteverify 校验，失败一律拒绝。
//
// 覆盖端点：register / login / resend-verification / password-reset-request
// （均为可被自动化滥用的公开端点；verify-email/password-reset 本身依赖一次性 token，
// 无需额外人机校验）。

const (
	turnstileTokenField = "cf_turnstile_token"
	turnstileVerifyWait  = 5 * time.Second
)

var (
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

var (
	errTurnstileNotConfigured = errors.New("turnstile: secret key 未配置")
	errTurnstileTokenEmpty    = errors.New("turnstile: 缺少 cf_turnstile_token")
)

// turnstileVerifier 校验 Turnstile 前端 token；测试注入 stub。
type turnstileVerifier interface {
	Verify(ctx context.Context, cfg *database.TurnstileConfig, token, remoteIP string) error
}

// httpTurnstileVerifier 生产实现：调用 Cloudflare siteverify。
type httpTurnstileVerifier struct {
	client *http.Client
}

func (httpTurnstileVerifier) Verify(ctx context.Context, cfg *database.TurnstileConfig, token, remoteIP string) error {
	if cfg == nil || !cfg.Enabled {
		return nil // 未启用：防御性跳过（中间件已判断，保持幂等）
	}
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return errTurnstileNotConfigured
	}
	if strings.TrimSpace(token) == "" {
		return errTurnstileTokenEmpty
	}
	form := url.Values{}
	form.Set("secret", cfg.SecretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile: 构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: turnstileVerifyWait}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile: siteverify 请求失败: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("turnstile: 解析 siteverify 响应失败: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("turnstile: 验证未通过: %v", out.ErrorCodes)
	}
	return nil
}

// turnstileTokenFromRequest 从查询参数/表单/JSON body 提取 Turnstile token；
// 读取 JSON body 后会原样放回（io.NopCloser），保证后续 handler 可正常 ShouldBindJSON。
func turnstileTokenFromRequest(c *gin.Context, field string) string {
	if v := strings.TrimSpace(c.Query(field)); v != "" {
		return v
	}
	if v := strings.TrimSpace(c.PostForm(field)); v != "" {
		return v
	}
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return ""
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(data))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// turnstileGate 返回一个中间件：Turnstile 启用时强制校验 cf_turnstile_token。
func (h *Handler) turnstileGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || h.db == nil {
			writeError(c, http.StatusServiceUnavailable, "服务未就绪")
			c.Abort()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), turnstileVerifyWait)
		defer cancel()
		cfg, err := h.db.LoadTurnstileConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			c.Abort()
			return
		}
		if !cfg.Enabled {
			c.Next()
			return
		}
		token := turnstileTokenFromRequest(c, turnstileTokenField)
		if err := h.turnstileVerifier.Verify(ctx, cfg, token, c.ClientIP()); err != nil {
			security.SecurityAuditLog("TURNSTILE_REJECTED",
				"ip="+security.SanitizeLog(c.ClientIP())+" path="+security.SanitizeLog(c.Request.URL.Path)+
					" reason="+security.SanitizeLog(err.Error()))
			writeError(c, http.StatusForbidden, "人机校验未通过，请重试")
			c.Abort()
			return
		}
		security.SecurityAuditLog("TURNSTILE_PASSED", "ip="+security.SanitizeLog(c.ClientIP())+" path="+security.SanitizeLog(c.Request.URL.Path))
		c.Next()
	}
}

package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/internal/version"
	"github.com/codex2api/proxy"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// P7.1 多端点控制面：节点注册/心跳/管理 API + /healthz（CDN 健康检查）。
//
// 协议与安全基线：
//   - 节点注册/心跳走 POST /api/endpoints/*，携带 X-Endpoint-Token（env
//     CODEX_ENDPOINT_REGISTRATION_TOKEN）。未配置 token → 503（fail-closed，
//     单机模式不暴露节点协议）。
//   - 节点身份 = env CODEX_ENDPOINT_ID（数据面节点必须配置才能注册）。
//   - 管理 API 挂 /api/admin/endpoints/*（adminAuthMiddleware 之后，fail-closed），
//     drain/activate/revoke 均记 ADMIN_ENDPOINT_* 审计。
//   - revoked 节点心跳被拒（单节点吊销即时生效），不可自我恢复。
//   - /healthz 供 CDN/GSLB 健康检查：DB ping 失败 → 503（down）；本节点被
//     drain（DB 状态或 env CODEX_ENDPOINT_DRAIN=1）→ 200 + status=draining。
//     依赖状态汇总为 dependencies 供监控消费。

// processStartTime 是进程启动时刻（/healthz uptime 用）。
var processStartTime = time.Now()

// versionForHealthz 返回构建版本（与 /version 一致）。
func versionForHealthz() string {
	return version.Runtime().Version
}

// endpointTokenFromEnv 返回节点注册 token；未配置返回空。
func endpointTokenFromEnv() string {
	return strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_REGISTRATION_TOKEN"))
}

// endpointIDFromEnv 返回本节点身份；单机模式可为空。
func endpointIDFromEnv() string {
	return strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_ID"))
}

// endpointTokenGate 校验 X-Endpoint-Token；未配置 token 一律 503（fail-closed）。
func (h *Handler) endpointTokenGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		want := endpointTokenFromEnv()
		if want == "" {
			writeError(c, http.StatusServiceUnavailable, "节点注册未启用")
			c.Abort()
			return
		}
		got := strings.TrimSpace(c.GetHeader("X-Endpoint-Token"))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			security.SecurityAuditLog("ENDPOINT_AUTH_REJECTED",
				"path="+security.SanitizeLog(c.Request.URL.Path)+" ip="+security.SanitizeLog(c.ClientIP()))
			writeError(c, http.StatusUnauthorized, "节点 token 无效")
			c.Abort()
			return
		}
		c.Next()
	}
}

// registerEndpoint POST /api/endpoints/register
// 节点注册（按 endpoint_id upsert；新节点 offline，首次心跳转 active）。
// body: {endpoint_id, name, region, base_url, role, version, capacity}
func (h *Handler) RegisterEndpoint(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Name       string `json:"name"`
		Region     string `json:"region"`
		BaseURL    string `json:"base_url"`
		Role       string `json:"role"`
		Version    string `json:"version"`
		Capacity   int    `json:"capacity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if req.EndpointID == "" {
		writeError(c, http.StatusBadRequest, "缺少 endpoint_id")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ep, err := h.db.RegisterServiceEndpoint(ctx, database.ServiceEndpoint{
		EndpointID: req.EndpointID,
		Name:       strings.TrimSpace(req.Name),
		Region:     strings.TrimSpace(req.Region),
		BaseURL:    strings.TrimSpace(req.BaseURL),
		Role:       strings.TrimSpace(req.Role),
		Version:    strings.TrimSpace(req.Version),
		Capacity:   req.Capacity,
		Status:     database.EndpointStatusOffline,
	})
	if err != nil {
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("ENDPOINT_REGISTERED",
		"endpoint_id="+security.SanitizeLog(ep.EndpointID)+" region="+security.SanitizeLog(ep.Region)+
			" ip="+security.SanitizeLog(c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"ok": true, "endpoint": ep})
}

// HeartbeatEndpoint POST /api/endpoints/heartbeat
// 节点心跳：更新 last_seen_at；offline→active；draining 保持；revoked 拒绝。
// 响应带 drain 标记供节点自我摘除（CDN 摘除前先由节点自行停新请求）。
// body: {endpoint_id, version, capacity}
func (h *Handler) HeartbeatEndpoint(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Version    string `json:"version"`
		Capacity   int    `json:"capacity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if req.EndpointID == "" {
		writeError(c, http.StatusBadRequest, "缺少 endpoint_id")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	status, err := h.db.HeartbeatServiceEndpoint(ctx, req.EndpointID, req.Version, req.Capacity)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrEndpointNotFound):
			writeError(c, http.StatusNotFound, "节点未注册")
		case errors.Is(err, database.ErrEndpointRevoked):
			security.SecurityAuditLog("ENDPOINT_HEARTBEAT_REJECTED",
				"endpoint_id="+security.SanitizeLog(req.EndpointID)+" ip="+security.SanitizeLog(c.ClientIP()))
			writeError(c, http.StatusForbidden, "节点已被吊销")
		default:
			writeInternalError(c, err)
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":     true,
		"status": status,
		"drain":  status == database.EndpointStatusDraining,
	})
}

// ==================== 管理 API（/api/admin/endpoints/*） ====================

// ListAdminEndpoints GET /api/admin/endpoints
// 节点列表（含动态离线判定）。
func (h *Handler) ListAdminEndpoints(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	eps, err := h.db.ListServiceEndpoints(ctx, "")
	if err != nil {
		writeInternalError(c, err)
		return
	}
	// P7.3/P7.5：附端点↔分组绑定与账号规模（管理视图）。
	bindings, err := h.db.ListEndpointGroupBindings(ctx)
	if err != nil {
		bindings = nil
	}
	byEndpoint := make(map[string][]database.EndpointGroupSummary)
	for _, b := range bindings {
		byEndpoint[b.EndpointID] = append(byEndpoint[b.EndpointID], database.EndpointGroupSummary{
			GroupID: b.GroupID, GroupName: b.GroupName, AccountCnt: b.AccountCnt,
		})
	}
	for i := range eps {
		eps[i].BoundGroups = byEndpoint[eps[i].EndpointID]
		eps[i].BoundGroupCount = len(eps[i].BoundGroups)
	}
	if eps == nil {
		eps = []database.ServiceEndpoint{}
	}
	c.JSON(http.StatusOK, gin.H{"endpoints": eps, "count": len(eps)})
}

// EndpointOverview GET /api/admin/endpoints/:endpoint_id/overview
// 端点全景视图（P7.5 GSLB 衔接的代码侧）：状态/地区/绑定分组/可见账号数/钱包写模式。
func (h *Handler) EndpointOverview(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	endpointID := strings.TrimSpace(c.Param("endpoint_id"))
	if endpointID == "" {
		writeError(c, http.StatusBadRequest, "缺少 endpoint_id")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ep, err := h.db.GetServiceEndpoint(ctx, endpointID)
	if err != nil {
		if errors.Is(err, database.ErrEndpointNotFound) {
			writeError(c, http.StatusNotFound, "节点不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	groups, err := h.db.ListGroupsForEndpoint(ctx, endpointID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	// 可见账号数：与该端点同渠道口径一致（本端点授权视图）。
	accounts, err := h.db.ListActiveByChannelForEndpoint(ctx, "", endpointID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"endpoint":         ep,
		"allowed_group_ids": groups,
		"visible_accounts":  len(accounts),
		"wallet_write":      proxyWalletWriteMode(),
	})
}

// AdminUpsertEndpoint POST /api/admin/endpoints
// 管理员手工注册/编辑节点。
func (h *Handler) AdminUpsertEndpoint(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Name       string `json:"name"`
		Region     string `json:"region"`
		BaseURL    string `json:"base_url"`
		Role       string `json:"role"`
		Status     string `json:"status"`
		Version    string `json:"version"`
		Capacity   int    `json:"capacity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if req.EndpointID == "" {
		writeError(c, http.StatusBadRequest, "缺少 endpoint_id")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	ep, err := h.db.RegisterServiceEndpoint(ctx, database.ServiceEndpoint{
		EndpointID: req.EndpointID,
		Name:       strings.TrimSpace(req.Name),
		Region:     strings.TrimSpace(req.Region),
		BaseURL:    strings.TrimSpace(req.BaseURL),
		Role:       strings.TrimSpace(req.Role),
		Status:     strings.TrimSpace(req.Status),
		Version:    strings.TrimSpace(req.Version),
		Capacity:   req.Capacity,
	})
	if err != nil {
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("ADMIN_ENDPOINT_UPSERT",
		"endpoint_id="+security.SanitizeLog(ep.EndpointID)+" ip="+security.SanitizeLog(c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"ok": true, "endpoint": ep})
}

// AdminDrainEndpoint POST /api/admin/endpoints/:endpoint_id/drain
// 排水：置 draining，CDN/GSLB 摘除；节点心跳响应带 drain=true。
func (h *Handler) AdminDrainEndpoint(c *gin.Context) {
	h.adminEndpointStatusOp(c, database.EndpointStatusDraining, "ADMIN_ENDPOINT_DRAIN")
}

// AdminActivateEndpoint POST /api/admin/endpoints/:endpoint_id/activate
// 恢复 active（含 revoked 重启用）。
func (h *Handler) AdminActivateEndpoint(c *gin.Context) {
	h.adminEndpointStatusOp(c, database.EndpointStatusActive, "ADMIN_ENDPOINT_ACTIVATE")
}

// AdminRevokeEndpoint POST /api/admin/endpoints/:endpoint_id/revoke
// 单节点吊销：心跳被拒，不可自我恢复。
func (h *Handler) AdminRevokeEndpoint(c *gin.Context) {
	h.adminEndpointStatusOp(c, database.EndpointStatusRevoked, "ADMIN_ENDPOINT_REVOKE")
}

func (h *Handler) adminEndpointStatusOp(c *gin.Context, status, auditEvent string) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	endpointID := strings.TrimSpace(c.Param("endpoint_id"))
	if endpointID == "" {
		writeError(c, http.StatusBadRequest, "缺少 endpoint_id")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	var err error
	switch status {
	case database.EndpointStatusDraining:
		err = h.db.SetEndpointDraining(ctx, endpointID)
	case database.EndpointStatusActive:
		err = h.db.SetEndpointActive(ctx, endpointID)
	default:
		err = h.db.RevokeServiceEndpoint(ctx, endpointID)
	}
	if err != nil {
		if errors.Is(err, database.ErrEndpointNotFound) {
			writeError(c, http.StatusNotFound, "节点不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog(auditEvent,
		"endpoint_id="+security.SanitizeLog(endpointID)+" ip="+security.SanitizeLog(c.ClientIP()))
	writeMessage(c, http.StatusOK, "操作成功")
}

// ==================== /healthz（CDN/GSLB 健康检查） ====================

// healthzResponse 是 /healthz 响应；dependencies 供监控消费。
type healthzResponse struct {
	Status       string                  `json:"status"` // ok / draining / degraded / down
	EndpointID   string                  `json:"endpoint_id,omitempty"`
	Version      string                  `json:"version,omitempty"`
	UptimeSec    int64                   `json:"uptime_seconds"`
	WalletWrite  string                  `json:"wallet_write,omitempty"` // shared / primary / readonly（P7.6）
	Dependencies map[string]string       `json:"dependencies"`
	Details      map[string]string       `json:"details,omitempty"`
}

// proxyWalletWriteMode 汇总钱包写模式供 /healthz 展示：
// shared → "shared"；primary 且本端点为主区 → "primary"；primary 但非主区 → "readonly"。
func proxyWalletWriteMode() string {
	mode := proxy.WalletWriteMode()
	if mode == proxy.WalletWriteModeShared {
		return "shared"
	}
	if proxy.WalletWriteEnabled() {
		return "primary"
	}
	return "readonly"
}

// GetHealthz GET /healthz
// 公网健康检查（CDN/GSLB 消费）。DB ping 失败 → 503 down；本节点 drain（DB 状态
// 或 env CODEX_ENDPOINT_DRAIN=1）→ 200 draining；Redis 异常不影响主流程计费
// （fail-closed 兜底），标记 degraded 仍 200。
func (h *Handler) GetHealthz(c *gin.Context) {
	start := time.Now()
	resp := healthzResponse{
		EndpointID:   endpointIDFromEnv(),
		Version:      versionForHealthz(),
		UptimeSec:    int64(time.Since(processStartTime).Seconds()),
		WalletWrite:  proxyWalletWriteMode(),
		Dependencies: map[string]string{},
		Details:      map[string]string{},
	}

	// PG 依赖。
	pgOK := false
	if h != nil && h.db != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := h.db.Ping(ctx); err == nil {
			pgOK = true
		} else {
			resp.Details["postgres_error"] = err.Error()
		}
	}
	resp.Dependencies["postgres"] = map[bool]string{true: "ok", false: "down"}[pgOK]

	// Redis 依赖（可选：未配置为 disabled）。
	redisStatus := "disabled"
	if h != nil && h.cache != nil && h.cache.Driver() == "redis" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := h.cache.Ping(ctx); err == nil {
			redisStatus = "ok"
		} else {
			redisStatus = "down"
			resp.Details["redis_error"] = err.Error()
		}
	}
	resp.Dependencies["redis"] = redisStatus

	// 本节点 drain 判定：本地 env 快速置位优先，其次 DB 状态。
	drain := strings.EqualFold(os.Getenv("CODEX_ENDPOINT_DRAIN"), "1")
	if !drain && resp.EndpointID != "" && pgOK {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if ep, err := h.db.GetServiceEndpoint(ctx, resp.EndpointID); err == nil &&
			ep.Status == database.EndpointStatusDraining {
			drain = true
		}
	}

	switch {
	case !pgOK:
		resp.Status = "down"
		c.JSON(http.StatusServiceUnavailable, resp)
	case drain:
		resp.Status = "draining"
		c.JSON(http.StatusOK, resp)
	case redisStatus == "down":
		resp.Status = "degraded"
		resp.Details["note"] = "redis unavailable; fail-closed billing still enforced"
		c.JSON(http.StatusOK, resp)
	default:
		resp.Status = "ok"
		c.JSON(http.StatusOK, resp)
	}
	_ = start
}

// ==================== 节点心跳常驻任务 ====================

// endpointHeartbeatConfig 描述心跳任务参数（来自 env）。
type endpointHeartbeatConfig struct {
	EndpointID  string
	ControlBase string // 控制面地址（数据面节点心跳到这里；空则不启动）
	Token       string
	Name        string
	Region      string
	BaseURL     string
	Role        string
	Version     string
	Capacity    int
	Interval    time.Duration
}

// EndpointHeartbeatConfigFromEnv 读取心跳任务环境变量。
func EndpointHeartbeatConfigFromEnv() endpointHeartbeatConfig {
	return endpointHeartbeatConfig{
		EndpointID:  strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_ID")),
		ControlBase: strings.TrimSpace(os.Getenv("CODEX_CONTROL_BASE_URL")),
		Token:       strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_REGISTRATION_TOKEN")),
		Name:        strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_NAME")),
		Region:      strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_REGION")),
		BaseURL:     strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_BASE_URL")),
		Role:        strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_ROLE")),
		Version:     versionForHealthz(),
		Capacity:    envPositiveInt("CODEX_ENDPOINT_CAPACITY"),
		Interval:    envDuration("CODEX_ENDPOINT_HEARTBEAT_INTERVAL", 30*time.Second),
	}
}

func envPositiveInt(name string) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return 0
	}
	n := 0
	_, _ = fmt.Sscanf(v, "%d", &n)
	if n < 0 {
		return 0
	}
	return n
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return fallback
}

// StartEndpointHeartbeat 启动节点注册+心跳常驻任务（多端点模式）。
// 仅当 cfg.EndpointID 与控制面地址均配置时启动；每 interval 心跳一次，
// 首次先注册（upsert）。控制面响应 drain=true 时记录日志（运维脚本可据此
// 停止接收新请求），revoked 时停止心跳并记录错误。
func StartEndpointHeartbeat(ctx context.Context, cfg endpointHeartbeatConfig) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.EndpointID == "" || cfg.ControlBase == "" {
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	postJSON := func(path string, body interface{}) (map[string]interface{}, int, error) {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(cfg.ControlBase, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Endpoint-Token", cfg.Token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		var out map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out, resp.StatusCode, nil
	}

	// 首次注册（幂等 upsert；新节点 offline，首次心跳转 active）。
	if out, code, err := postJSON("/api/endpoints/register", map[string]interface{}{
		"endpoint_id": cfg.EndpointID,
		"name":        cfg.Name,
		"region":      cfg.Region,
		"base_url":    cfg.BaseURL,
		"role":        cfg.Role,
		"version":     cfg.Version,
		"capacity":    cfg.Capacity,
	}); err != nil || code != http.StatusOK {
		log.Printf("端点注册失败(id=%s code=%d): %v", cfg.EndpointID, code, err)
	} else if ep, ok := out["endpoint"].(map[string]interface{}); ok {
		log.Printf("端点已注册: %s (status=%v)", cfg.EndpointID, ep["status"])
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			out, code, err := postJSON("/api/endpoints/heartbeat", map[string]interface{}{
				"endpoint_id": cfg.EndpointID,
				"version":     cfg.Version,
				"capacity":    cfg.Capacity,
			})
			if err != nil || code != http.StatusOK {
				log.Printf("端点心跳失败(id=%s code=%d): %v", cfg.EndpointID, code, err)
				continue
			}
			if drain, _ := out["drain"].(bool); drain {
				log.Printf("端点收到 drain 信号(id=%s)：请停止接收新请求（CDN 摘除中）", cfg.EndpointID)
			}
			if status, _ := out["status"].(string); status == database.EndpointStatusRevoked {
				log.Printf("端点已被吊销(id=%s)：停止心跳", cfg.EndpointID)
				return
			}
		}
	}
}

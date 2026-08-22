package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codex2api/security"
)

// P7.2 失效传播总线：多区本地 Redis 形态下，key 撤销/编辑事件经 Redis Pub/Sub
// 扇出到全部节点，各节点收到后清理本地运行态缓存（"api-key" 命名空间）。
//
// 可靠性设计（审计基线：事件幂等 + 死信 + TTL 兜底）：
//   - 幂等：消息负载只携带"要删的缓存键"，重复投递/多节点消费重复删除无害。
//   - 死信：处理失败（解析失败/删缓存失败）记 INVALIDATION_FAILED 审计 + 计数器，
//     不重投（删键幂等，重投无收益）；go-redis 订阅断线自动重连，重连间隙由 TTL 兜底。
//   - TTL 兜底：运行态 key 缓存 TTL 可配置（CODEX_API_KEY_CACHE_TTL，默认 5m，
//     最小 30s）；即使广播完全丢失，缓存过期后回源共享 PG 即见 revoked。
//   - 广播尽力而为：PUBLISH 失败仅日志，不阻塞撤销主路径（DB 状态变更才是事实源）。
//
// 发布点：admin.Handler.invalidateAPIKeyRuntimeCaches（所有撤销/编辑 key 路径的汇聚点）。

// invalidationTopic 是失效广播的 Redis channel。
const invalidationTopic = "codex2api:invalidation:v1"

// invalidationEvent 是总线消息负载。APIKey 即运行态缓存键（用户 key 为摘要，
// 历史 key 为明文），与 SetRuntime(apiKeyCacheNamespace, ...) 的键一致。
type invalidationEvent struct {
	ID     string `json:"id"`      // "ts-随机" 幂等标识，仅用于日志/审计
	Type   string `json:"type"`    // "api_key"（预留扩展：account_credentials 等）
	APIKey string `json:"api_key"` // 要删除的缓存键
	KeyID  int64  `json:"key_id,omitempty"`
	UserID int64  `json:"user_id,omitempty"`
	At     string `json:"at"`
}

// invalidationEventTypeAPIKey 当前唯一事件类型。
const invalidationEventTypeAPIKey = "api_key"

// invalidationStats 统计总线收发（进程内，仅监控/测试断言用）。
var invalidationStats struct {
	published atomic.Int64
	received  atomic.Int64
	failed    atomic.Int64
}

func newInvalidationEvent(typ, apiKey string, keyID, userID int64) invalidationEvent {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return invalidationEvent{
		ID:     fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf[:])),
		Type:   typ,
		APIKey: apiKey,
		KeyID:  keyID,
		UserID: userID,
		At:     time.Now().UTC().Format(time.RFC3339),
	}
}

// publishInvalidation 尽力而为地广播一条失效事件；失败仅日志（DB 状态才是事实源，
// 丢消息窗口由 TTL 兜底）。返回是否发布成功。
func (h *Handler) publishInvalidation(ctx context.Context, ev invalidationEvent) bool {
	if h == nil || h.cache == nil {
		return false
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	start := time.Now()
	if err := h.cache.PublishInvalidation(ctx, invalidationTopic, payload); err != nil {
		log.Printf("失效广播发布失败(type=%s key=%s): %v", ev.Type, security.SanitizeLog(ev.APIKey), err)
		return false
	}
	invalidationStats.published.Add(1)
	security.SecurityAuditLog("INVALIDATION_PUBLISHED",
		fmt.Sprintf("type=%s key=%s key_id=%d user_id=%d dur_ms=%d",
			ev.Type, security.SanitizeLog(ev.APIKey), ev.KeyID, ev.UserID,
			time.Since(start).Milliseconds()))
	return true
}

// handleInvalidationMessage 消费一条广播：按类型清理本地运行态缓存（幂等）。
func (h *Handler) handleInvalidationMessage(ctx context.Context, payload []byte) {
	var ev invalidationEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		invalidationStats.failed.Add(1)
		security.SecurityAuditLog("INVALIDATION_FAILED",
			fmt.Sprintf("reason=parse payload_len=%d", len(payload)))
		return
	}
	invalidationStats.received.Add(1)
	key := strings.TrimSpace(ev.APIKey)
	if ev.Type != invalidationEventTypeAPIKey || key == "" {
		// 未知类型/空键：仍记审计便于排障，不 panic。
		security.SecurityAuditLog("INVALIDATION_SKIPPED",
			fmt.Sprintf("type=%s key=%s id=%s", ev.Type, security.SanitizeLog(key), ev.ID))
		return
	}
	// 清理本地运行态 key 缓存（admin 面板与数据面共用 "api-key" 命名空间）。
	// 删键幂等：同一事件重复投递/多节点消费重复删除无害。
	h.deleteRuntimeCache(ctx, adminAPIKeyCacheNamespace, key)
	h.deleteRuntimeCache(ctx, adminAPIKeyCountNamespace, "all")
	security.SecurityAuditLog("INVALIDATION_PROCESSED",
		fmt.Sprintf("type=%s key=%s key_id=%d user_id=%d id=%s",
			ev.Type, security.SanitizeLog(key), ev.KeyID, ev.UserID, ev.ID))
}

// StartInvalidationBus 订阅失效传播总线并消费（常驻任务）。
// 未配置缓存或内存缓存驱动的单机形态仍订阅（进程内同步扇出，链路完整可测）。
func (h *Handler) StartInvalidationBus(ctx context.Context) {
	if h == nil || h.cache == nil {
		return
	}
	if err := h.cache.SubscribeInvalidation(ctx, invalidationTopic, func(subCtx context.Context, payload []byte) {
		handleCtx, cancel := context.WithTimeout(subCtx, 3*time.Second)
		defer cancel()
		h.handleInvalidationMessage(handleCtx, payload)
	}); err != nil {
		log.Printf("失效广播订阅启动失败(topic=%s): %v", invalidationTopic, err)
		return
	}
	log.Printf("失效传播总线已订阅(topic=%s driver=%s)", invalidationTopic, h.cache.Driver())
}

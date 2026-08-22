package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/codex2api/database"
	"github.com/tidwall/gjson"
)

// primeAPIKeyRuntimeCache 模拟"另一节点把 key 缓存进共享/本地运行态缓存"。
func primeAPIKeyRuntimeCache(t *testing.T, h *Handler, cacheKey string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]interface{}{"id": 1, "name": "cached", "user_id": 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.cache.SetRuntime(ctx, adminAPIKeyCacheNamespace, cacheKey, payload, time.Minute); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if _, ok, _ := h.cache.GetRuntime(ctx, adminAPIKeyCacheNamespace, cacheKey); !ok {
		t.Fatal("prime cache not readable")
	}
}

func TestInvalidationBusRevokeEndToEnd(t *testing.T) {
	h, db, cookies := newPortalTestHandler(t)
	h.StartInvalidationBus(t.Context())

	// 创建用户 key。
	rec := doJSON(t, h, http.MethodPost, "/api/auth/keys", `{"name":"bus-key"}`, cookies)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	secret := gjson.Get(rec.Body.String(), "key").String()
	keyID := gjson.Get(rec.Body.String(), "key_id").Int()
	if secret == "" || keyID <= 0 {
		t.Fatalf("secret=%q key_id=%d", secret, keyID)
	}
	// 缓存键 = 摘要（与 SetRuntime 一致）。
	hash := database.HashAPIKeySecret(secret)
	primeAPIKeyRuntimeCache(t, h, hash)

	before := invalidationStats.received.Load()

	// 撤销 → 本地精确失效 + 总线广播（内存驱动同步扇出 → 订阅者再删一遍，幂等）。
	rec = doJSON(t, h, http.MethodPost,
		fmt.Sprintf("/api/auth/keys/%d/revoke", keyID), `{"reason":"rotate"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", rec.Code, rec.Body.String())
	}

	// 断言：缓存键已被清理（本地失效或总线消费，效果一致）。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, ok, _ := h.cache.GetRuntime(ctx, adminAPIKeyCacheNamespace, hash); ok {
		t.Fatal("revoked key still cached")
	}
	// 断言：订阅者确实消费了广播（链路贯通）。
	if invalidationStats.received.Load() <= before {
		t.Fatalf("bus consumer not invoked: before=%d after=%d", before, invalidationStats.received.Load())
	}
	// DB 层确认 revoked。
	row, err := db.GetAPIKeyByValue(t.Context(), secret)
	if err == nil && row.Status == database.APIKeyStatusActive {
		t.Fatal("key should be revoked in DB")
	}
	_ = t
}

func TestInvalidationBusRemoteBroadcast(t *testing.T) {
	h, _, _ := newPortalTestHandler(t)
	h.StartInvalidationBus(t.Context())

	// 预置两条缓存：kA 保留、kB 应被远端广播清理。
	primeAPIKeyRuntimeCache(t, h, "kA")
	primeAPIKeyRuntimeCache(t, h, "kB")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// 模拟远端节点（A 区）撤销后广播。
	ev := newInvalidationEvent(invalidationEventTypeAPIKey, "kB", 42, 7)
	if !h.publishInvalidation(ctx, ev) {
		t.Fatal("publish failed")
	}
	// 广播消息经 bus 清理本地缓存（同步扇出）。
	if _, ok, _ := h.cache.GetRuntime(ctx, adminAPIKeyCacheNamespace, "kB"); ok {
		t.Fatal("kB should be evicted by remote broadcast")
	}
	if _, ok, _ := h.cache.GetRuntime(ctx, adminAPIKeyCacheNamespace, "kA"); !ok {
		t.Fatal("kA must survive (unrelated key)")
	}
	if invalidationStats.received.Load() == 0 {
		t.Fatal("bus consumer never invoked")
	}
}

func TestInvalidationMessageRobustness(t *testing.T) {
	h, _, _ := newPortalTestHandler(t)
	ctx := context.Background()

	// 坏 JSON：不 panic，记失败计数。
	h.handleInvalidationMessage(ctx, []byte("not-json{"))
	// 未知类型 + 空键：跳过不 panic。
	h.handleInvalidationMessage(ctx, []byte(`{"type":"unknown","api_key":""}`))
	// 空负载：不 panic。
	h.handleInvalidationMessage(ctx, nil)
	// 正常事件：清理缓存。
	primeAPIKeyRuntimeCache(t, h, "cleanme")
	h.handleInvalidationMessage(ctx, mustJSON(newInvalidationEvent(invalidationEventTypeAPIKey, "cleanme", 1, 1)))
	if _, ok, _ := h.cache.GetRuntime(ctx, adminAPIKeyCacheNamespace, "cleanme"); ok {
		t.Fatal("cleanme should be evicted")
	}
}

package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// 数据面钱包计费（P5/P6）。
//
// 流程（与 PLAN.md P6 一致）：
//   - 鉴权通过后，对「用户归属 API Key」的请求预留 deposit（available-=D, reserved+=D）；
//   - 请求处理中每次成功用量（logUsageForRequest，status<400）按计费配置折算微元并累计；
//   - 请求结束（handler 返回，含流式/WebSocket 收尾）统一收尾：有成功用量则
//     WalletSettle(D, actual) 多退少补；无用量（/v1/models、失败、免费路径）则 WalletRelease(D)。
//
// 幂等：每个请求一次预留、一次收尾，键均为 per-request 随机 ID（reserve:/settle:/release:
// 命名空间），重复收尾/重放由账本 (user_id, idempotency_key) 唯一约束 + 哨兵回滚兜底
// （见 database/wallet.go）。
//
// 计费口径：上游美元成本（database/billing.go CalculateCost）× cny_per_usd → 整数微元，
// 低于 min_charge 按 min_charge，高于 charge_cap 按 charge_cap（0=不封顶）。
// 失败/超时/客户端中止的请求不产生成功用量 → 全部释放，用户不扣费。
//
// 容错策略（fail-closed，与 PLAN.md §6/P6 一致）：计费配置读取失败、钱包 DB 故障时，
// 对「用户归属 Key」的计费请求直接 503 拒绝（不放行不扣费），只有非计费路径
// （billing 关闭、非用户 Key）才正常放行；「确认余额不足」仍返回 402。

const (
	walletBillingStateKey = "walletBillingState"
	walletConfigCacheTTL  = 15 * time.Second
	walletRequestRefType  = "request"
	walletFinalizeTimeout = 5 * time.Second
	walletOpTimeout       = 3 * time.Second
)

// WalletWriteMode 钱包写分区模式（P7.6）。
//
//	Shared  （默认/推荐）：全部端点写同一共享主库，walletApplyTx 条件更新 + PG 行锁
//	          串行化并发，任何节点扣费都是库中最新的余额，透支不可能（财务一致性最优）。
//	Primary ：主区形态（预留接口）：仅主区端点执行钱包写，其余端点只读（计费预留
//	          返回 503 不可用）。用于跨洲部署时把写收敛到主区、避免跨洋写放大；
//	          非主区节点需在结算异步化（L3）落地后配合使用。
const (
	WalletWriteModeShared  = "shared"
	WalletWriteModePrimary = "primary"
)

// walletWriteMode 返回当前钱包写模式（env CODEX_WALLET_WRITE_MODE，默认 shared）。
// 未知值回落 shared（fail-safe：绝不默认放行不可验证的模式）。
func walletWriteMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("CODEX_WALLET_WRITE_MODE")))
	switch mode {
	case WalletWriteModePrimary:
		return mode
	default:
		return WalletWriteModeShared
	}
}

// walletWriteEnabled 判断本端点是否允许执行钱包写（P7.6）。
// primary 模式下仅主区端点（CODEX_WALLET_PRIMARY_REGION 命中本端点地区）可写；
// shared 模式全端点可写。
func walletWriteEnabled() bool {
	if walletWriteMode() == WalletWriteModeShared {
		return true
	}
	region := strings.TrimSpace(os.Getenv("CODEX_ENDPOINT_REGION"))
	primary := strings.TrimSpace(os.Getenv("CODEX_WALLET_PRIMARY_REGION"))
	return primary != "" && region != "" && region == primary
}

// WalletWriteMode 导出当前钱包写模式（/healthz 等展示用）。
func WalletWriteMode() string { return walletWriteMode() }

// WalletWriteEnabled 导出本端点是否可写钱包（/healthz 展示用）。
func WalletWriteEnabled() bool { return walletWriteEnabled() }

// walletBillingConfigCache 进程内计费配置缓存（管理页改动最多一个 TTL 生效）。
type walletBillingConfigCache struct {
	mu  sync.Mutex
	cfg *database.BillingConfig
	at  time.Time
}

// walletRequestState 单次请求的钱包计费状态（挂在 gin context）。
type walletRequestState struct {
	UserID         int64
	DepositMicro   int64
	MinChargeMicro int64
	ChargeCapMicro int64
	CNYPerUSD      float64
	RefType        string
	RefID          string

	chargeMicro int64
	mu          sync.Mutex
}

func (s *walletRequestState) addCharge(v int64) {
	if v <= 0 {
		return
	}
	s.mu.Lock()
	s.chargeMicro += v
	s.mu.Unlock()
}

func (s *walletRequestState) total() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chargeMicro
}

// walletBillingConfig 返回（缓存的）计费配置；读取失败时返回旧缓存（若有）或错误。
// 调用方拿到 error 时必须按 fail-closed 处理（拒绝计费请求），不能放行。
func (h *Handler) walletBillingConfig() (*database.BillingConfig, error) {
	if h == nil || h.db == nil {
		return nil, fmt.Errorf("wallet: database unavailable")
	}
	cache := &h.walletCfg
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.cfg != nil && time.Since(cache.at) < walletConfigCacheTTL {
		return cache.cfg, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), walletOpTimeout)
	defer cancel()
	cfg, err := h.db.LoadBillingConfig(ctx)
	if err != nil {
		log.Printf("读取钱包计费配置失败: %v", err)
		if cache.cfg != nil {
			// 有旧缓存：基于上次已知配置做确定性判断（比 fail-open 安全）。
			return cache.cfg, nil
		}
		return nil, err
	}
	cache.cfg = cfg
	cache.at = time.Now()
	return cfg, nil
}

// InvalidateWalletConfigCache 清除数据面计费配置缓存（管理端 PUT billing 后调用）。
func (h *Handler) InvalidateWalletConfigCache() {
	if h == nil {
		return
	}
	h.walletCfg.mu.Lock()
	h.walletCfg.cfg = nil
	h.walletCfg.at = time.Time{}
	h.walletCfg.mu.Unlock()
}

// walletBeginBilling 为「用户归属 Key」的请求预留钱包额度；返回 true 表示已预留，
// 调用方必须 defer finalizeWalletRequest。
//
// fail-closed：计费配置不可读或预留失败（非余额不足）时返回 503 并 Abort，不放行。
func (h *Handler) walletBeginBilling(c *gin.Context, row *database.APIKeyRow) bool {
	if h == nil || h.db == nil || c == nil || row == nil || row.UserID <= 0 {
		return false
	}
	cfg, err := h.walletBillingConfig()
	if err != nil {
		// fail-closed：控制面/DB 故障，无法确定计费开关与额度 → 拒绝计费请求。
		security.SecurityAuditLog("WALLET_CONFIG_UNAVAILABLE",
			fmt.Sprintf("user_id=%d path=%s ip=%s", row.UserID, c.Request.URL.Path, c.ClientIP()))
		api.SendError(c, api.ErrServiceUnavailable)
		c.Abort()
		return false
	}
	if cfg == nil || !cfg.Enabled {
		return false
	}
	// P7.6：钱包写分区决策。primary 模式下非主区端点不执行钱包写（fail-closed 503）。
	if !walletWriteEnabled() {
		security.SecurityAuditLog("WALLET_WRITE_READONLY",
			fmt.Sprintf("user_id=%d path=%s ip=%s mode=%s", row.UserID, c.Request.URL.Path,
				c.ClientIP(), walletWriteMode()))
		api.SendError(c, api.ErrServiceUnavailable)
		c.Abort()
		return false
	}
	deposit := cfg.DepositMicro
	if deposit <= 0 {
		return false
	}
	reqID := newWalletRequestID()
	st := &walletRequestState{
		UserID:         row.UserID,
		DepositMicro:   deposit,
		MinChargeMicro: cfg.MinChargeMicro,
		ChargeCapMicro: cfg.ChargeCapMicro,
		CNYPerUSD:      cfg.CNYPerUSD,
		RefType:        walletRequestRefType,
		RefID:          reqID,
	}

	reserveCtx, reserveCancel := context.WithTimeout(context.Background(), walletOpTimeout)
	replayed, err := h.db.WalletReserve(reserveCtx, st.UserID, deposit, st.RefType, st.RefID, "reserve:"+reqID)
	reserveCancel()
	if err != nil {
		if errors.Is(err, database.ErrInsufficientBalance) {
			security.SecurityAuditLog("WALLET_RESERVE_INSUFFICIENT",
				fmt.Sprintf("user_id=%d path=%s ip=%s", st.UserID, c.Request.URL.Path, c.ClientIP()))
			api.SendError(c, api.ErrInsufficientBalance)
			c.Abort()
			return false
		}
		security.SecurityAuditLog("WALLET_RESERVE_UNAVAILABLE",
			fmt.Sprintf("user_id=%d path=%s ip=%s err=%v", st.UserID, c.Request.URL.Path, c.ClientIP(), err))
		api.SendError(c, api.ErrServiceUnavailable)
		c.Abort()
		return false
	}
	if replayed {
		log.Printf("钱包预留意外重放(user=%d ref=%s)", st.UserID, reqID)
	}

	// 预留成功后、调用上游前必须持久化结算义务。若 intent 无法落库，立即尝试
	// 释放并 fail-closed；绝不把一个无法追踪结算的请求发送给上游。
	intentCtx, intentCancel := context.WithTimeout(context.Background(), walletOpTimeout)
	err = h.db.CreateWalletSettlementIntent(intentCtx, st.UserID, st.DepositMicro, st.RefType, st.RefID)
	intentCancel()
	if err != nil {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), walletOpTimeout)
		_, releaseErr := h.db.WalletRelease(releaseCtx, st.UserID, st.DepositMicro, st.RefType, st.RefID, "release:"+st.RefID)
		releaseCancel()
		detail := fmt.Sprintf("user=%d ref=%s create_error=%s", st.UserID, st.RefID, security.SanitizeLog(err.Error()))
		if releaseErr != nil {
			detail += " release_error=" + security.SanitizeLog(releaseErr.Error())
		}
		security.SecurityAuditLog("WALLET_SETTLEMENT_INTENT_CREATE_FAILED", detail)
		api.SendError(c, api.ErrServiceUnavailable)
		c.Abort()
		return false
	}

	c.Set(walletBillingStateKey, st)
	return true
}

// accumulateWalletCharge 由 logUsageForRequest 调用：把成功用量折算的应扣微元
// 累计到本次请求的预留上下文。仅在钱包状态存在且用量成功（status<400）时生效。
func (h *Handler) accumulateWalletCharge(c *gin.Context, log *database.UsageLogInput) {
	if c == nil || log == nil {
		return
	}
	v, ok := c.Get(walletBillingStateKey)
	if !ok {
		return
	}
	st, ok := v.(*walletRequestState)
	if !ok || st == nil {
		return
	}
	if log.StatusCode > 0 && log.StatusCode >= 400 {
		return // 失败重试轮次不计费
	}
	charge := database.ComputeChargeMicro(log, &database.BillingConfig{CNYPerUSD: st.CNYPerUSD})
	st.addCharge(charge)
}

// finalizeWalletRequest 请求结束收尾：有成功用量则结算（多退少补），否则释放预留。
func (h *Handler) finalizeWalletRequest(c *gin.Context) {
	if h == nil || h.db == nil || c == nil {
		return
	}
	v, ok := c.Get(walletBillingStateKey)
	if !ok {
		return
	}
	st, ok := v.(*walletRequestState)
	if !ok || st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), walletFinalizeTimeout)
	defer cancel()

	actual := st.total()
	if actual <= 0 {
		// 先把释放义务持久化，再执行余额变动。任一步失败都保留 reserved，
		// 后台只对 release_pending 做幂等重试。
		if err := h.db.PrepareWalletRelease(ctx, st.UserID, st.DepositMicro, st.RefType, st.RefID); err != nil {
			h.recordWalletSettlementFailure(ctx, st, "prepare_release", err)
			return
		}
		if _, err := h.db.WalletRelease(ctx, st.UserID, st.DepositMicro, st.RefType, st.RefID, "release:"+st.RefID); err != nil {
			h.recordWalletSettlementFailure(ctx, st, "release", err)
			return
		}
		if err := h.db.CompleteWalletSettlementIntent(ctx, st.UserID, st.RefType, st.RefID, database.WalletSettlementReleased); err != nil {
			h.recordWalletSettlementFailure(ctx, st, "complete_release", err)
		}
		return
	}
	if actual < st.MinChargeMicro {
		actual = st.MinChargeMicro
	}
	if st.ChargeCapMicro > 0 && actual > st.ChargeCapMicro {
		actual = st.ChargeCapMicro
	}

	// 成功用量先落 settle_pending(actual)，再执行钱包结算。结算失败绝不释放
	// 预留，后台依靠同一幂等键继续完成扣款。
	if err := h.db.PrepareWalletSettlement(ctx, st.UserID, st.DepositMicro, actual, st.RefType, st.RefID); err != nil {
		h.recordWalletSettlementFailure(ctx, st, "prepare_settle", err)
		return
	}
	if _, err := h.db.WalletSettle(ctx, st.UserID, st.DepositMicro, actual, st.RefType, st.RefID, "settle:"+st.RefID); err != nil {
		h.recordWalletSettlementFailure(ctx, st, "settle", err)
		return
	}
	if err := h.db.CompleteWalletSettlementIntent(ctx, st.UserID, st.RefType, st.RefID, database.WalletSettlementSettled); err != nil {
		h.recordWalletSettlementFailure(ctx, st, "complete_settle", err)
	}
}

func (h *Handler) recordWalletSettlementFailure(ctx context.Context, st *walletRequestState, phase string, cause error) {
	if h == nil || h.db == nil || st == nil || cause == nil {
		return
	}
	_ = h.db.RecordWalletSettlementFailure(ctx, st.UserID, st.RefType, st.RefID, cause)
	security.SecurityAuditLog("WALLET_SETTLEMENT_CRITICAL",
		fmt.Sprintf("phase=%s user=%d ref=%s reserved_micro=%d error=%s",
			phase, st.UserID, st.RefID, st.DepositMicro, security.SanitizeLog(cause.Error())))
	log.Printf("钱包结算流程失败，保留预留等待补偿(phase=%s user=%d ref=%s): %v", phase, st.UserID, st.RefID, cause)
}

// newWalletRequestID 生成 per-request 随机 ID（账本幂等键的一部分）。
func newWalletRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("w%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// StartWalletReconciliation 启动钱包孤儿预留对账：启动即执行一次，之后按 interval
// 周期执行。释放超过 orphanAge 仍无对应 release/consume 的预留（进程崩溃/收尾失败
// 遗留），避免 reserved 永久占用、available 永久减少。对账动作本身幂等（recover:
// 键），多进程并发/重启重跑安全。interval/orphanAge <=0 时使用默认值。
func StartWalletReconciliation(ctx context.Context, db *database.DB, interval, orphanAge time.Duration) {
	if ctx == nil || db == nil {
		return
	}
	if interval <= 0 {
		interval = time.Hour
	}
	if orphanAge <= 0 {
		orphanAge = 24 * time.Hour
	}
	run := func(why string) {
		reconcileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// 先重试已明确持久化的结算/释放义务，再处理没有 intent 的真实孤儿。
		retry, retryErr := db.RetryWalletSettlementIntents(reconcileCtx, 500)
		if retryErr != nil {
			log.Printf("钱包结算补偿重试失败(%s): %v", why, retryErr)
		} else if retry.Settled > 0 || retry.Released > 0 || retry.Failed > 0 {
			security.SecurityAuditLog("WALLET_SETTLEMENT_RETRY",
				fmt.Sprintf("settled=%d released=%d failed=%d", retry.Settled, retry.Released, retry.Failed))
			log.Printf("钱包结算补偿(%s): settled=%d released=%d failed=%d", why, retry.Settled, retry.Released, retry.Failed)
		}

		n, micro, err := db.ReconcileOrphanedWalletReservations(reconcileCtx, orphanAge, 500)
		if err != nil {
			log.Printf("钱包孤儿预留对账失败(%s): %v", why, err)
			return
		}
		if n > 0 {
			security.SecurityAuditLog("WALLET_ORPHAN_RESERVATION_RECOVERED",
				fmt.Sprintf("count=%d micro=%d", n, micro))
			log.Printf("钱包孤儿预留对账(%s): 恢复 %d 条预留, 合计 %d 微元", why, n, micro)
		}
		if metrics, metricErr := db.GetWalletSettlementMetrics(reconcileCtx, orphanAge); metricErr != nil {
			log.Printf("钱包结算指标读取失败(%s): %v", why, metricErr)
		} else if metrics.SettlePending > 0 || metrics.ReleasePending > 0 || metrics.StaleInFlight > 0 {
			security.SecurityAuditLog("WALLET_SETTLEMENT_BACKLOG",
				fmt.Sprintf("in_flight=%d settle_pending=%d release_pending=%d retried=%d stale_in_flight=%d",
					metrics.InFlight, metrics.SettlePending, metrics.ReleasePending, metrics.Retried, metrics.StaleInFlight))
		}
		// 充值订单到期清理：把已过支付截止时间仍未支付（pending）的订单标记 expired。
		expiredN, expErr := db.ExpireStaleRechargeOrders(reconcileCtx, 0, 200)
		if expErr != nil {
			log.Printf("充值订单到期清理失败(%s): %v", why, expErr)
			return
		}
		if expiredN > 0 {
			log.Printf("充值订单到期清理(%s): 标记 %d 笔订单过期", why, expiredN)
		}
		// P7.1：多端点心跳超时落库（展示判定不依赖它，仅作后台清理）。
		staleEPs, epErr := db.ExpireStaleEndpoints(reconcileCtx, 3*time.Minute, 200)
		if epErr != nil {
			log.Printf("端点超时下线清理失败(%s): %v", why, epErr)
			return
		}
		if staleEPs > 0 {
			log.Printf("端点超时下线清理(%s): %d 个节点标记 offline", why, staleEPs)
		}
	}
	db.RunBackgroundTask(func(taskCtx context.Context) {
		run("startup")
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
				run("periodic")
			}
		}
	})
}

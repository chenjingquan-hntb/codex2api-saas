package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
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
// 命名空间），重复收尾/重放由账本唯一约束 + 哨兵回滚兜底（见 database/wallet.go）。
//
// 计费口径：上游美元成本（database/billing.go CalculateCost）× cny_per_usd → 整数微元，
// 低于 min_charge 按 min_charge，高于 charge_cap 按 charge_cap（0=不封顶）。
// 失败/超时/客户端中止的请求不产生成功用量 → 全部释放，用户不扣费。
//
// 容错策略（fail-open）：计费配置读取失败、钱包 DB 故障时放行请求（记日志/审计），
// 绝不因计费基础设施问题拖垮数据面；只有「确认余额不足」才 402 拒绝。

const (
	walletBillingStateKey = "walletBillingState"
	walletConfigCacheTTL  = 15 * time.Second
	walletRequestRefType  = "request"
	walletFinalizeTimeout = 5 * time.Second
	walletOpTimeout       = 3 * time.Second
)

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

// walletBillingConfig 返回（缓存的）计费配置；读取失败返回旧缓存或 nil（按关闭处理）。
func (h *Handler) walletBillingConfig() *database.BillingConfig {
	if h == nil || h.db == nil {
		return nil
	}
	cache := &h.walletCfg
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.cfg != nil && time.Since(cache.at) < walletConfigCacheTTL {
		return cache.cfg
	}
	ctx, cancel := context.WithTimeout(context.Background(), walletOpTimeout)
	defer cancel()
	cfg, err := h.db.LoadBillingConfig(ctx)
	if err != nil {
		log.Printf("读取钱包计费配置失败: %v", err)
		if cache.cfg != nil {
			return cache.cfg
		}
		return nil
	}
	cache.cfg = cfg
	cache.at = time.Now()
	return cfg
}

// walletBeginBilling 为「用户归属 Key」的请求预留钱包额度；返回 true 表示已预留，
// 调用方必须 defer finalizeWalletRequest。
func (h *Handler) walletBeginBilling(c *gin.Context, row *database.APIKeyRow) bool {
	if h == nil || h.db == nil || c == nil || row == nil || row.UserID <= 0 {
		return false
	}
	cfg := h.walletBillingConfig()
	if cfg == nil || !cfg.Enabled {
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
	ctx, cancel := context.WithTimeout(context.Background(), walletOpTimeout)
	defer cancel()
	// 注意：WalletReserve 返回 (replayed, err)；成功时 err==nil（replayed=false）。
	replayed, err := h.db.WalletReserve(ctx, st.UserID, deposit, st.RefType, st.RefID, "reserve:"+reqID)
	if err != nil {
		if errors.Is(err, database.ErrInsufficientBalance) {
			// 确认余额不足：402 Payment Required。
			security.SecurityAuditLog("WALLET_RESERVE_INSUFFICIENT",
				fmt.Sprintf("user_id=%d path=%s ip=%s", st.UserID, c.Request.URL.Path, c.ClientIP()))
			api.SendError(c, api.ErrInsufficientBalance)
			c.Abort()
			return false
		}
		// 计费基础设施故障：fail-open 放行，避免钱包 DB 抖动拖垮数据面。
		log.Printf("钱包预留失败(user=%d): %v", st.UserID, err)
		return false
	}
	if replayed {
		// 全新 per-request 键理论上不会重放；若发生直接按成功处理（已预留）。
		log.Printf("钱包预留意外重放(user=%d ref=%s)", st.UserID, reqID)
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
		// 无成功用量 → 全额释放。
		if _, err := h.db.WalletRelease(ctx, st.UserID, st.DepositMicro, st.RefType, st.RefID, "release:"+st.RefID); err != nil {
			log.Printf("钱包释放失败(user=%d ref=%s): %v", st.UserID, st.RefID, err)
		}
		return
	}
	if actual < st.MinChargeMicro {
		actual = st.MinChargeMicro
	}
	if st.ChargeCapMicro > 0 && actual > st.ChargeCapMicro {
		actual = st.ChargeCapMicro
	}
	if _, err := h.db.WalletSettle(ctx, st.UserID, st.DepositMicro, actual, st.RefType, st.RefID, "settle:"+st.RefID); err == nil {
		return
	} else {
		log.Printf("钱包结算失败(user=%d ref=%s actual=%d): %v", st.UserID, st.RefID, actual, err)
	}
	// 兜底：多退少补失败（通常余额不足以补差）时，最多消耗到预留额度；
	// 仍失败则最终释放，本次请求免单（账本保持不变量，审计见日志）。
	capActual := actual
	if capActual > st.DepositMicro {
		capActual = st.DepositMicro
	}
	if capActual <= 0 {
		capActual = st.DepositMicro
	}
	if _, err := h.db.WalletSettle(ctx, st.UserID, st.DepositMicro, capActual, st.RefType, st.RefID, "settle:"+st.RefID); err != nil {
		log.Printf("钱包结算兜底失败(user=%d ref=%s): %v", st.UserID, st.RefID, err)
		if _, err2 := h.db.WalletRelease(ctx, st.UserID, st.DepositMicro, st.RefType, st.RefID, "release:"+st.RefID); err2 != nil {
			log.Printf("钱包释放兜底失败(user=%d ref=%s): %v", st.UserID, st.RefID, err2)
		}
	}
}

// newWalletRequestID 生成 per-request 随机 ID（账本幂等键的一部分）。
func newWalletRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("w%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

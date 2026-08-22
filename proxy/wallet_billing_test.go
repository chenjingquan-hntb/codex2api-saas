package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// newWalletBillingTestEnv 创建带用户、充值余额、用户归属 Key 的 SQLite 环境。
func newWalletBillingTestEnv(t *testing.T) (*Handler, *database.DB, int64) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "wallet-billing.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	user, err := db.CreateUser(ctx, "wallet@test.dev", "x")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.WalletCredit(ctx, user.ID, 10_000_000, database.WalletTxRecharge, "seed", "seed-1", "seed:1", 0, "test seed"); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, err := db.InsertAPIKeyWithOptions(ctx, database.APIKeyInput{Name: "user-key", Key: "sk-user-1", UserID: user.ID}); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	return &Handler{db: db}, db, user.ID
}

func enableBilling(t *testing.T, db *database.DB, cfg *database.BillingConfig) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := db.SetSettingValue(context.Background(), database.SettingKeyBilling, string(raw), 0); err != nil {
		t.Fatalf("enable billing: %v", err)
	}
}

func walletGinContext(t *testing.T, path string) *gin.Context {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, path, nil)
	return ctx
}

func walletAccount(t *testing.T, db *database.DB, userID int64) *database.WalletAccount {
	t.Helper()
	acc, err := db.GetWalletAccount(context.Background(), userID)
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if acc == nil {
		t.Fatalf("wallet account missing")
	}
	return acc
}

func TestWalletBeginBillingThenRelease(t *testing.T) {
	h, db, userID := newWalletBillingTestEnv(t)
	enableBilling(t, db, &database.BillingConfig{Enabled: true, DepositMicro: 1_000_000, MinChargeMicro: 100_000, CNYPerUSD: 12.0})

	c := walletGinContext(t, "/v1/responses")
	if !h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("expected billing to begin")
	}

	acc := walletAccount(t, db, userID)
	if acc.ReservedMicro != 1_000_000 || acc.AvailableMicro != 9_000_000 {
		t.Fatalf("after reserve: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}

	// 无成功用量 → 收尾全额释放
	h.finalizeWalletRequest(c)
	acc = walletAccount(t, db, userID)
	if acc.ReservedMicro != 0 || acc.AvailableMicro != 10_000_000 {
		t.Fatalf("after release: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}

	// 幂等：重复收尾不重复变更
	h.finalizeWalletRequest(c)
	acc = walletAccount(t, db, userID)
	if acc.ReservedMicro != 0 || acc.AvailableMicro != 10_000_000 {
		t.Fatalf("after replay finalize: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
}

func TestWalletSettleWithUsage(t *testing.T) {
	h, db, userID := newWalletBillingTestEnv(t)
	enableBilling(t, db, &database.BillingConfig{
		Enabled: true, DepositMicro: 1_000_000, MinChargeMicro: 0, ChargeCapMicro: 0, CNYPerUSD: 12.0,
	})

	c := walletGinContext(t, "/v1/responses")
	if !h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("expected billing to begin")
	}

	usage := &database.UsageLogInput{Model: "gpt-4o", InputTokens: 1000, OutputTokens: 500, StatusCode: 200}
	h.accumulateWalletCharge(c, usage)
	charge := database.ComputeChargeMicro(usage, &database.BillingConfig{CNYPerUSD: 12.0})
	if charge <= 0 {
		t.Fatalf("expected positive charge, got %d", charge)
	}

	h.finalizeWalletRequest(c)
	acc := walletAccount(t, db, userID)
	if acc.AvailableMicro != 10_000_000-charge {
		t.Fatalf("after settle: avail=%d want %d", acc.AvailableMicro, 10_000_000-charge)
	}
	if acc.ReservedMicro != 0 {
		t.Fatalf("reserved not cleared: %d", acc.ReservedMicro)
	}

	// 账本不变量：每条 balance_after-balance_before == amount
	entries, err := db.ListWalletLedger(context.Background(), userID, 100, 0)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected >=3 ledger entries (reserve/release/consume), got %d", len(entries))
	}
	for _, e := range entries {
		if e.BalanceAfterMicro-e.BalanceBeforeMicro != e.AmountMicro {
			t.Fatalf("ledger invariant broken: id=%d type=%s before=%d after=%d amount=%d",
				e.ID, e.Type, e.BalanceBeforeMicro, e.BalanceAfterMicro, e.AmountMicro)
		}
	}
}

func TestWalletSettleAppliesMinChargeAndCap(t *testing.T) {
	h, db, userID := newWalletBillingTestEnv(t)
	enableBilling(t, db, &database.BillingConfig{
		Enabled: true, DepositMicro: 1_000_000, MinChargeMicro: 100_000, ChargeCapMicro: 0, CNYPerUSD: 12.0,
	})
	c := walletGinContext(t, "/v1/responses")
	if !h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("expected billing to begin")
	}
	// 微小用量：折算后远低于最小扣费 → 按最小扣费
	h.accumulateWalletCharge(c, &database.UsageLogInput{Model: "gpt-4o", InputTokens: 1, StatusCode: 200})
	h.finalizeWalletRequest(c)
	acc := walletAccount(t, db, userID)
	if acc.AvailableMicro != 10_000_000-100_000 {
		t.Fatalf("min charge not applied: avail=%d", acc.AvailableMicro)
	}

	// 封顶：cap=50_000，费用远超 → 按 cap
	enableBilling(t, db, &database.BillingConfig{
		Enabled: true, DepositMicro: 1_000_000, MinChargeMicro: 0, ChargeCapMicro: 50_000, CNYPerUSD: 12.0,
	})
	h2 := &Handler{db: db} // 新实例避免缓存旧配置
	c2 := walletGinContext(t, "/v1/responses")
	if !h2.walletBeginBilling(c2, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("expected billing to begin")
	}
	h2.accumulateWalletCharge(c2, &database.UsageLogInput{Model: "gpt-4o", InputTokens: 5_000_000, StatusCode: 200})
	h2.finalizeWalletRequest(c2)
	acc = walletAccount(t, db, userID)
	if acc.AvailableMicro != 9_900_000-50_000 {
		t.Fatalf("cap not applied: avail=%d want %d", acc.AvailableMicro, 9_900_000-50_000)
	}
}

func TestWalletInsufficientBalanceRejects402(t *testing.T) {
	h, db, _ := newWalletBillingTestEnv(t)
	enableBilling(t, db, &database.BillingConfig{Enabled: true, DepositMicro: 1_000_000, CNYPerUSD: 12.0})

	// 空钱包用户：0 余额
	user2, err := db.CreateUser(context.Background(), "poor@test.dev", "x")
	if err != nil {
		t.Fatalf("create user2: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	if h.walletBeginBilling(c, &database.APIKeyRow{ID: 2, UserID: user2.ID}) {
		t.Fatalf("expected billing to be rejected")
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "insufficient_balance") {
		t.Fatalf("body missing insufficient_balance: %s", rec.Body.String())
	}
	// 未预留任何额度
	acc, _ := db.GetWalletAccount(context.Background(), user2.ID)
	if acc != nil && (acc.ReservedMicro != 0) {
		t.Fatalf("insufficient reserve must not reserve anything: %+v", acc)
	}
}

func TestWalletBillingDisabledOrNonUserKeyNoOp(t *testing.T) {
	h, db, userID := newWalletBillingTestEnv(t)
	c := walletGinContext(t, "/v1/responses")
	if h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("billing must be disabled by default")
	}
	acc, _ := db.GetWalletAccount(context.Background(), userID)
	if acc == nil || acc.ReservedMicro != 0 {
		t.Fatalf("default billing must not reserve: %+v", acc)
	}

	// 开启后：非用户归属 Key（user_id=0，如配置文件 Key）不预留
	enableBilling(t, db, &database.BillingConfig{Enabled: true, DepositMicro: 1_000_000, CNYPerUSD: 12.0})
	h2 := &Handler{db: db}
	if h2.walletBeginBilling(c, &database.APIKeyRow{ID: 0, UserID: 0}) {
		t.Fatalf("non-user key must not bill")
	}
}

func TestWalletAccumulateSkipsFailedUsage(t *testing.T) {
	h, db, userID := newWalletBillingTestEnv(t)
	enableBilling(t, db, &database.BillingConfig{Enabled: true, DepositMicro: 1_000_000, MinChargeMicro: 0, CNYPerUSD: 12.0})
	c := walletGinContext(t, "/v1/responses")
	if !h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: userID}) {
		t.Fatalf("expected billing to begin")
	}
	// 失败的用量不计费 → 收尾释放
	h.accumulateWalletCharge(c, &database.UsageLogInput{Model: "gpt-4o", InputTokens: 100_000, StatusCode: 500})
	h.accumulateWalletCharge(c, &database.UsageLogInput{Model: "gpt-4o", InputTokens: 1, StatusCode: 429})
	h.finalizeWalletRequest(c)
	acc := walletAccount(t, db, userID)
	if acc.AvailableMicro != 10_000_000 || acc.ReservedMicro != 0 {
		t.Fatalf("failed usage must not charge: avail=%d reserved=%d", acc.AvailableMicro, acc.ReservedMicro)
	}
}

// TestWalletFailClosedWhenConfigUnavailable 校验 fail-closed：钱包 DB/配置不可用时，
// 用户归属 Key 的计费请求被 503 拒绝，而不是 fail-open 放行。
func TestWalletFailClosedWhenConfigUnavailable(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "wallet-failclosed.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	// DB.Close() 非幂等（内部 close(channel)），用 Once 包装，测试中途与 Cleanup 只关一次。
	var closeOnce sync.Once
	closeDB := func() { closeOnce.Do(func() { _ = db.Close() }) }
	t.Cleanup(closeDB)
	ctx := context.Background()
	user, err := db.CreateUser(ctx, "failclosed@test.dev", "x")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.WalletCredit(ctx, user.ID, 10_000_000, database.WalletTxRecharge, "seed", "fc-1", "seed:fc-1", 0, "test seed"); err != nil {
		t.Fatalf("credit: %v", err)
	}
	// 先写入开启的计费配置，让缓存路径可用。
	enableBilling(t, db, &database.BillingConfig{Enabled: true, DepositMicro: 1_000_000, CNYPerUSD: 12.0})
	h := &Handler{db: db}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	if !h.walletBeginBilling(c, &database.APIKeyRow{ID: 1, UserID: user.ID}) {
		t.Fatalf("expected billing to begin with healthy db (status=%d body=%s)", rec.Code, rec.Body.String())
	}

	// 关闭 DB 并失效缓存后新请求必须 fail-closed 503。
	closeDB()
	h.InvalidateWalletConfigCache()
	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	if h.walletBeginBilling(c2, &database.APIKeyRow{ID: 1, UserID: user.ID}) {
		t.Fatal("billing must NOT begin when wallet DB is down (fail-closed)")
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body=%s)", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "service_unavailable") {
		t.Fatalf("body missing service_unavailable: %s", rec2.Body.String())
	}
}

// TestWalletBillingExemptPaths 校验元数据/本地端点不参与计费。
func TestWalletBillingExemptPaths(t *testing.T) {
	exempt := []string{
		"/v1/models", "/models", "/backend-api/codex/models",
		"/v1/messages/count_tokens", "/messages/count_tokens",
		"/v1/responses/input_tokens", "/responses/input_tokens",
	}
	for _, p := range exempt {
		if !walletBillingExemptPath(p) {
			t.Fatalf("path %s must be exempt from wallet billing", p)
		}
	}
	notExempt := []string{"/v1/responses", "/v1/chat/completions", "/v1/messages", "/v1/images/generations"}
	for _, p := range notExempt {
		if walletBillingExemptPath(p) {
			t.Fatalf("path %s must NOT be exempt from wallet billing", p)
		}
	}
}

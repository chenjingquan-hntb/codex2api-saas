package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// P6 收尾：管理员支付订单管理 / 手工冲正 / 对账看板 / 账本重算。
//
// 安全基线：
//   - 所有金额一律整数微元；余额不足不透支（walletApplyTx 兜底）；
//   - 每笔金额操作都是单事务 + 幂等键（admin_refund:<order_no> /
//     admin_adjust:<key>），重复提交绝不重复扣/加钱；
//   - 每次金额操作写安全审计日志（ADMIN_PAYMENT_*），含操作对象/金额/幂等键；
//   - 退款只允许 paid 订单，且不允许多次退款（幂等重放返回 replayed）。
//
// 路由挂在 /api/admin/payments/*（adminAuthMiddleware 之后，fail-closed）。

// ListAdminPayments GET /api/admin/payments/orders
// 跨用户分页列出充值订单；query：order_no / email / status / limit / offset。
func (h *Handler) ListAdminPayments(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	f := database.RechargeOrderFilter{
		OrderNo: strings.TrimSpace(c.Query("order_no")),
		Email:   strings.TrimSpace(c.Query("email")),
		Status:  strings.TrimSpace(c.Query("status")),
	}
	limit := parsePositiveInt(c.Query("limit"), 50)
	offset := parseNonNegativeInt(c.Query("offset"), 0)

	orders, err := h.db.ListAllRechargeOrders(ctx, f, limit, offset)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if orders == nil {
		orders = []database.RechargeOrderWithUser{}
	}
	c.JSON(http.StatusOK, gin.H{"orders": orders, "count": len(orders)})
}

// GetAdminPayment GET /api/admin/payments/orders/:order_no
// 订单详情 + 关联账本流水（客服溯源）。
func (h *Handler) GetAdminPayment(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	orderNo := strings.TrimSpace(c.Param("order_no"))
	if orderNo == "" {
		writeError(c, http.StatusBadRequest, "缺少订单号")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	orders, err := h.db.ListAllRechargeOrders(ctx, database.RechargeOrderFilter{OrderNo: orderNo}, 1, 0)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if len(orders) == 0 {
		writeError(c, http.StatusNotFound, "订单不存在")
		return
	}
	ledger, err := h.db.ListWalletLedger(ctx, orders[0].UserID, 50, 0)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"order":  orders[0],
		"ledger": ledger,
	})
}

// RefundAdminPayment POST /api/admin/payments/orders/:order_no/refund
// 已入账订单整单退款冲正。body：{ "reason": "..." }
func (h *Handler) RefundAdminPayment(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	orderNo := strings.TrimSpace(c.Param("order_no"))
	if orderNo == "" {
		writeError(c, http.StatusBadRequest, "缺少订单号")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "管理员手工退款"
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	replayed, err := h.db.RefundRechargeOrder(ctx, orderNo, 0, reason)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrEpayOrderNotFound):
			writeError(c, http.StatusNotFound, "订单不存在")
		case errors.Is(err, database.ErrEpayOrderNotPaid):
			writeError(c, http.StatusConflict, "订单未入账（pending/expired/cancelled），不能退款")
		case errors.Is(err, database.ErrInsufficientBalance):
			writeError(c, http.StatusConflict, "用户可用余额不足以完成退款（充值金额可能已消费），请先用余额调整处理")
		default:
			writeInternalError(c, err)
		}
		return
	}
	security.SecurityAuditLog("ADMIN_PAYMENT_REFUND",
		"order_no="+security.SanitizeLog(orderNo)+" reason="+security.SanitizeLog(reason)+
			" replayed="+strconv.FormatBool(replayed)+" ip="+security.SanitizeLog(c.ClientIP()))
	writeMessage(c, http.StatusOK, "退款成功")
}

// ConfirmAdminPayment POST /api/admin/payments/orders/:order_no/confirm
// 网关漏回调时的管理员补录入账（复用回调入账幂等路径）。
func (h *Handler) ConfirmAdminPayment(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	orderNo := strings.TrimSpace(c.Param("order_no"))
	if orderNo == "" {
		writeError(c, http.StatusBadRequest, "缺少订单号")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	replayed, err := h.db.AdminConfirmEpayOrder(ctx, orderNo)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrEpayOrderNotFound):
			writeError(c, http.StatusNotFound, "订单不存在")
		case errors.Is(err, database.ErrEpayOrderClosed):
			writeError(c, http.StatusConflict, "订单已取消，不能补录入账")
		case errors.Is(err, database.ErrEpayAmountMismatch):
			writeError(c, http.StatusConflict, "订单金额异常，请核对")
		default:
			writeInternalError(c, err)
		}
		return
	}
	security.SecurityAuditLog("ADMIN_PAYMENT_CONFIRM",
		"order_no="+security.SanitizeLog(orderNo)+" replayed="+strconv.FormatBool(replayed)+" ip="+security.SanitizeLog(c.ClientIP()))
	if replayed {
		writeMessage(c, http.StatusOK, "该订单此前已入账（重复操作被幂等拦截）")
		return
	}
	writeMessage(c, http.StatusOK, "补录入账成功")
}

// AdjustAdminUserBalance POST /api/admin/payments/users/:id/adjust
// 管理员余额调整（补偿/扣错）。body：
//
//	{ "amount_micro": -500000, "idempotency_key": "<uuid>", "reason": "..." }
//
// amount_micro 可正可负（微元整数）；不允许把余额调到负。
func (h *Handler) AdjustAdminUserBalance(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || userID <= 0 {
		writeError(c, http.StatusBadRequest, "用户 ID 非法")
		return
	}
	var req struct {
		AmountMicro    int64  `json:"amount_micro"`
		IdempotencyKey string `json:"idempotency_key"`
		Reason         string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "管理员余额调整"
	}
	if req.IdempotencyKey == "" {
		writeError(c, http.StatusBadRequest, "缺少 idempotency_key（建议 UUID）")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	replayed, err := h.db.AdminAdjustWalletBalance(ctx, userID, req.AmountMicro, req.IdempotencyKey, reason, 0)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrInsufficientBalance):
			writeError(c, http.StatusConflict, "调整后余额将为负，操作被拒绝")
		default:
			writeInternalError(c, err)
		}
		return
	}
	security.SecurityAuditLog("ADMIN_PAYMENT_ADJUST",
		"user_id="+strconv.FormatInt(userID, 10)+" amount_micro="+strconv.FormatInt(req.AmountMicro, 10)+
			" key="+security.SanitizeLog(req.IdempotencyKey)+" reason="+security.SanitizeLog(reason)+
			" replayed="+strconv.FormatBool(replayed)+" ip="+security.SanitizeLog(c.ClientIP()))
	if replayed {
		writeMessage(c, http.StatusOK, "该幂等键已处理过（重复操作被拦截）")
		return
	}
	writeMessage(c, http.StatusOK, "余额调整成功")
}

// GetPaymentSummaryHandler GET /api/admin/payments/summary
// 对账看板聚合指标。
func (h *Handler) GetPaymentSummaryHandler(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	s, err := h.db.GetPaymentSummary(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, s)
}

// ReconcileAdminPayments POST /api/admin/payments/reconcile
// 账本重算：对比账本流水重算余额与钱包账户当前值，返回差异清单。
// body：{ "dry_run": true }（默认 true 只报告；dry_run=false 时自动修复差异）。
func (h *Handler) ReconcileAdminPayments(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	var req struct {
		DryRun *bool `json:"dry_run"`
	}
	_ = c.ShouldBindJSON(&req)
	dryRun := true
	if req.DryRun != nil {
		dryRun = *req.DryRun
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	drifts, err := h.db.ReconcileWalletBalances(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	fixed := 0
	if !dryRun {
		for i := range drifts {
			if err := h.db.FixWalletBalance(ctx, drifts[i].UserID, drifts[i].ExpectedMicro); err != nil {
				writeInternalError(c, err)
				return
			}
			fixed++
		}
	}
	security.SecurityAuditLog("ADMIN_PAYMENT_RECONCILE",
		"drifts="+strconv.Itoa(len(drifts))+" dry_run="+strconv.FormatBool(dryRun)+
			" fixed="+strconv.Itoa(fixed)+" ip="+security.SanitizeLog(c.ClientIP()))
	if drifts == nil {
		drifts = []database.BalanceDrift{}
	}
	c.JSON(http.StatusOK, gin.H{
		"dry_run": dryRun,
		"fixed":   fixed,
		"drifts":  drifts,
	})
}

// ==================== 小工具 ====================

// parsePositiveInt 解析正整数参数，非法/空返回 fallback。
func parsePositiveInt(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// parseNonNegativeInt 解析非负整数参数，非法/空返回 fallback。
func parseNonNegativeInt(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

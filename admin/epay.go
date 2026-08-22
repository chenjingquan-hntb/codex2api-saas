package admin

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// 易支付（epay）适配器：服务端创建订单 + 回调验签 + 幂等入账。
//
// 安全基线（PLAN.md P6）：
//   - 只有服务端校验商户号、订单号、金额并完成回调验签后才入账；
//   - 浏览器同步跳转（return）不是入账依据，仅跳转门户结果页供前端轮询；
//   - 用户 API 返回的表单参数不含商户密钥；签名只用于网关侧校验。

const (
	// epayOrderTTL 充值订单支付截止时间。
	epayOrderTTL = 30 * time.Minute

	// epayMinRechargeMicro / epayMaxRechargeMicro 充值金额边界（微元）。
	// 易支付只支持到分，因此充值金额必须是 1 分（100000 微元）的整数倍。
	epayMinRechargeMicro = int64(100000) // 0.01 元
	epayMaxRechargeMicro = int64(1e11)   // 10000 元

	epayChannelAlipay = "alipay"
	epayChannelWxpay  = "wxpay"

	// 只对失败回调按来源 IP 计数，避免合法支付高峰误伤。
	epayCallbackFailureLimit  = 30
	epayCallbackFailureWindow = 5 * time.Minute
)

// ==================== 易支付签名 ====================

// epaySign 计算易支付 MD5 签名（易支付标准算法）：
// 取除 sign/sign_type 外的全部参数，跳过空值，按键名升序拼接 k=v&k2=v2，
// 末尾追加 &key=<商户密钥>，整体 MD5 小写十六进制。
func epaySign(params map[string]string, merchantKey string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "sign" || k == "sign_type" {
			continue
		}
		if strings.TrimSpace(params[k]) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
	}
	sb.WriteString("&key=")
	sb.WriteString(merchantKey)
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// epayVerifySign 校验回调/回跳签名（大小写不敏感）。
func epayVerifySign(params map[string]string, merchantKey string) bool {
	sign, ok := params["sign"]
	if !ok || strings.TrimSpace(sign) == "" {
		return false
	}
	want := epaySign(params, merchantKey)
	return strings.EqualFold(strings.TrimSpace(sign), want)
}

// epayMoney 把微元格式化为易支付金额字符串（两位小数，如 "10.00"）。
// 金额必须是 1 分的整数倍（易支付不支持分以下精度）。
func epayMoney(micro int64) (string, error) {
	if micro <= 0 || micro%100000 != 0 {
		return "", fmt.Errorf("金额必须是 1 分（0.01 元）的整数倍")
	}
	fen := micro / 100000
	return fmt.Sprintf("%d.%02d", fen/100, fen%100), nil
}

// epayCallbackPayloadJSON 把回调参数原样归档（审计/对账用，不含密钥）。
func epayCallbackPayloadJSON(params map[string]string) string {
	clean := make(map[string]string, len(params))
	for k, v := range params {
		if k == "key" {
			continue
		}
		clean[k] = v
	}
	data, err := json.Marshal(clean)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// newEpayOrderNo 生成全局唯一订单号：EP + 时间戳 + 随机后缀。
func newEpayOrderNo(now time.Time) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("EP%d%x", now.UnixNano(), time.Now().UnixNano())
	}
	return "EP" + now.UTC().Format("20060102150405") + hex.EncodeToString(b)
}

// ==================== 用户侧 API ====================

// CreateEpayRechargeOrder POST /api/auth/wallet/recharge
// 请求：{"amount_micro": <正整数，1 分整数倍>, "channel": "alipay"|"wxpay"(可选)}
// 响应：订单信息 + 易支付提交表单参数（前端渲染表单 POST 到 gateway_url）。
func (h *Handler) CreateEpayRechargeOrder(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	var req struct {
		AmountMicro int64  `json:"amount_micro"`
		Channel     string `json:"channel"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.AmountMicro < epayMinRechargeMicro || req.AmountMicro > epayMaxRechargeMicro {
		writeError(c, http.StatusBadRequest, "充值金额必须在 0.01 元 ~ 10000 元之间")
		return
	}
	if req.AmountMicro%100000 != 0 {
		writeError(c, http.StatusBadRequest, "充值金额必须是 1 分（0.01 元）的整数倍")
		return
	}
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel == "" {
		channel = epayChannelAlipay
	}
	if channel != epayChannelAlipay && channel != epayChannelWxpay {
		writeError(c, http.StatusBadRequest, "channel 仅支持 alipay / wxpay")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 强制邮箱验证后才能充值（PLAN P5 验收项）。
	user, err := h.db.GetUserByID(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if !user.EmailVerified() {
		writeError(c, http.StatusForbidden, "请先完成邮箱验证后再充值")
		return
	}

	cfg, err := h.db.LoadEpayConfig(ctx)
	if err != nil {
		log.Printf("epay: load config: %v", err)
		writeError(c, http.StatusServiceUnavailable, "支付配置不可用，请稍后重试")
		return
	}
	if !cfg.Enabled {
		writeError(c, http.StatusServiceUnavailable, "支付通道未启用")
		return
	}

	now := time.Now().UTC()
	orderNo := newEpayOrderNo(now)
	expiresAt := now.Add(epayOrderTTL)
	order, err := h.db.CreateRechargeOrder(ctx, sess.UserID, orderNo, channel, req.AmountMicro, "", expiresAt)
	if err != nil {
		writeInternalError(c, err)
		return
	}

	money, err := epayMoney(order.AmountMicro)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	params := map[string]string{
		"pid":          strings.TrimSpace(cfg.MerchantID),
		"type":         channel,
		"out_trade_no": order.OrderNo,
		"notify_url":   joinBaseURL(cfg.CallbackBaseURL, cfg.NotifyPath),
		"return_url":   joinBaseURL(cfg.CallbackBaseURL, cfg.ReturnPath),
		"name":         "API 余额充值 " + money + " 元",
		"money":        money,
		"sitename":     "Codex2API",
		"sign_type":    "MD5",
	}
	params["sign"] = epaySign(params, cfg.Key)

	security.SecurityAuditLog("WALLET_EPAY_ORDER_CREATED",
		fmt.Sprintf("user_id=%d order_no=%s amount_micro=%d channel=%s",
			sess.UserID, order.OrderNo, order.AmountMicro, channel))

	c.JSON(http.StatusOK, gin.H{
		"order_no":     order.OrderNo,
		"channel":      channel,
		"amount_micro": order.AmountMicro,
		"status":       order.Status,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"gateway_url":  strings.TrimSpace(cfg.GatewayURL),
		"form":         params,
	})
}

// GetMyWallet GET /api/auth/wallet
func (h *Handler) GetMyWallet(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	acc, err := h.db.GetWalletAccount(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if acc == nil {
		c.JSON(http.StatusOK, gin.H{"currency": "CNY", "available_micro": int64(0), "reserved_micro": int64(0)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"currency":        acc.Currency,
		"available_micro": acc.AvailableMicro,
		"reserved_micro":  acc.ReservedMicro,
	})
}

// ListMyRechargeOrders GET /api/auth/wallet/orders?limit=&offset=
func (h *Handler) ListMyRechargeOrders(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(c.Query("offset")))
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	orders, err := h.db.ListRechargeOrders(ctx, sess.UserID, limit, offset)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	out := make([]gin.H, 0, len(orders))
	for _, o := range orders {
		out = append(out, rechargeOrderJSON(o))
	}
	c.JSON(http.StatusOK, gin.H{"orders": out})
}

// GetMyRechargeOrder GET /api/auth/wallet/orders/:order_no
func (h *Handler) GetMyRechargeOrder(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	orderNo := strings.TrimSpace(c.Param("order_no"))
	if orderNo == "" {
		writeError(c, http.StatusBadRequest, "order_no 必填")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	o, err := h.db.GetRechargeOrder(ctx, sess.UserID, orderNo)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if o == nil {
		writeError(c, http.StatusNotFound, "订单不存在")
		return
	}
	c.JSON(http.StatusOK, rechargeOrderJSON(*o))
}

func rechargeOrderJSON(o database.RechargeOrder) gin.H {
	expiresAt := ""
	if o.ExpiresAt != nil {
		expiresAt = o.ExpiresAt.UTC().Format(time.RFC3339)
	}
	verifiedAt := ""
	if o.VerifiedAt != nil {
		verifiedAt = o.VerifiedAt.UTC().Format(time.RFC3339)
	}
	return gin.H{
		"order_no":     o.OrderNo,
		"channel":      o.Channel,
		"amount_micro": o.AmountMicro,
		"status":       o.Status,
		"expires_at":   expiresAt,
		"verified_at":  verifiedAt,
		"created_at":   o.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// ==================== 支付回调（服务器到服务器，不信任前端跳转） ====================

// EpayNotify POST {NotifyPath}（默认 /api/pay/epay/notify）
// 网关回调：验签 → 校验商户号/订单/金额 → 幂等入账。
// 成功回复纯文本 "success"；任何失败回复非 success 让网关重试。
func (h *Handler) EpayNotify(c *gin.Context) {
	ip := c.ClientIP()
	if h != nil && h.epayCallbackFailureLimiter != nil && h.epayCallbackFailureLimiter.blocked(ip, time.Now()) {
		h.epayRateLimitedCount.Add(1)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_RATE_LIMITED", "ip="+security.SanitizeLog(ip))
		c.String(http.StatusTooManyRequests, "fail")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	cfg, err := h.db.LoadEpayConfig(ctx)
	if err != nil || !cfg.Enabled {
		log.Printf("epay: notify ignored, config unavailable or disabled: %v", err)
		c.String(http.StatusServiceUnavailable, "fail")
		return
	}

	params := formParams(c)
	if !epayVerifySign(params, cfg.Key) {
		h.recordEpayCallbackFailure(ip, true)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_BAD_SIGN",
			fmt.Sprintf("order_no=%s pid=%s", params["out_trade_no"], params["pid"]))
		c.String(http.StatusBadRequest, "fail")
		return
	}
	if strings.TrimSpace(params["pid"]) != strings.TrimSpace(cfg.MerchantID) {
		h.recordEpayCallbackFailure(ip, false)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_BAD_MERCHANT",
			fmt.Sprintf("order_no=%s pid=%s", params["out_trade_no"], params["pid"]))
		c.String(http.StatusBadRequest, "fail")
		return
	}
	tradeStatus := strings.ToUpper(strings.TrimSpace(params["trade_status"]))
	if tradeStatus != "TRADE_SUCCESS" {
		h.epayRejectedCount.Add(1)
		// 合法签名只证明消息来自网关，不代表交易已经支付成功。对 pending、
		// failed 或缺失状态统一确认接收但不入账，避免网关重试风暴。
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_NON_SUCCESS",
			fmt.Sprintf("order_no=%s trade_status=%s", params["out_trade_no"], tradeStatus))
		c.String(http.StatusOK, "success")
		return
	}
	orderNo := strings.TrimSpace(params["out_trade_no"])
	amount, err := database.ParseYuanToMicro(params["money"])
	if err != nil {
		h.recordEpayCallbackFailure(ip, false)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_BAD_MONEY",
			fmt.Sprintf("order_no=%s money=%q", orderNo, params["money"]))
		c.String(http.StatusBadRequest, "fail")
		return
	}

	replayed, err := h.db.CreditEpayCallback(ctx, orderNo, epayCallbackPayloadJSON(params), amount)
	switch {
	case err == nil:
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_CREDITED",
			fmt.Sprintf("order_no=%s amount_micro=%d replayed=%v", orderNo, amount, replayed))
		c.String(http.StatusOK, "success")
	case errors.Is(err, database.ErrEpayOrderNotFound):
		h.recordEpayCallbackFailure(ip, false)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_ORDER_NOT_FOUND",
			fmt.Sprintf("order_no=%s amount_micro=%d", orderNo, amount))
		c.String(http.StatusNotFound, "fail")
	case errors.Is(err, database.ErrEpayAmountMismatch):
		h.recordEpayCallbackFailure(ip, false)
		security.SecurityAuditLog("WALLET_EPAY_CALLBACK_AMOUNT_MISMATCH",
			fmt.Sprintf("order_no=%s callback_micro=%d", orderNo, amount))
		c.String(http.StatusBadRequest, "fail")
	case errors.Is(err, database.ErrEpayOrderClosed):
		// 订单已取消：不再接受入账，回复 success 停止网关重试。
		c.String(http.StatusOK, "success")
	default:
		log.Printf("epay: notify credit failed order_no=%s: %v", orderNo, err)
		c.String(http.StatusInternalServerError, "fail")
	}
}

func (h *Handler) recordEpayCallbackFailure(ip string, badSign bool) {
	if h == nil {
		return
	}
	h.epayRejectedCount.Add(1)
	if badSign {
		h.epayBadSignCount.Add(1)
	}
	if h.epayCallbackFailureLimiter != nil {
		_ = h.epayCallbackFailureLimiter.allow(ip, time.Now())
	}
}

// EpayReturn GET {ReturnPath}（默认 /portal/pay/result）
// 用户支付完成后浏览器同步跳转。不在此入账（不可信），仅校验签名后
// 重定向到门户结果页，前端轮询订单状态。
func (h *Handler) EpayReturn(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	cfg, err := h.db.LoadEpayConfig(ctx)
	if err != nil || !cfg.Enabled {
		c.Redirect(http.StatusFound, "/portal/pay/result")
		return
	}
	params := queryParams(c)
	if !epayVerifySign(params, cfg.Key) {
		writeError(c, http.StatusBadRequest, "回调签名校验失败")
		return
	}
	target := "/portal/pay/result"
	if strings.HasPrefix(cfg.ReturnPath, "/") {
		target = cfg.ReturnPath
	}
	if orderNo := strings.TrimSpace(params["out_trade_no"]); orderNo != "" {
		target += "?order_no=" + url.QueryEscape(orderNo)
	}
	c.Redirect(http.StatusFound, target)
}

// ==================== 工具 ====================

func formParams(c *gin.Context) map[string]string {
	if err := c.Request.ParseForm(); err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(c.Request.PostForm))
	for k, vs := range c.Request.PostForm {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func queryParams(c *gin.Context) map[string]string {
	out := make(map[string]string, len(c.Request.URL.Query()))
	for k, vs := range c.Request.URL.Query() {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

// joinBaseURL 把对外根地址与路径拼成完整 URL（容忍根地址带尾斜杠）。
func joinBaseURL(base, path string) string {
	base = strings.TrimSpace(base)
	path = strings.TrimSpace(path)
	if path == "" {
		return base
	}
	if base == "" {
		return path
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

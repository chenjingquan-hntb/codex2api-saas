package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// 控制面配置管理接口（P5/P6）。
//
// 配置段存储于 database.system_setting_values（JSON），读取缺省回落默认值；
// PUT 采用 patch 语义（请求体字段省略则保留当前值），写前做字段合法性校验。
// 配置段：billing（钱包计费）/ smtp（邮件）/ epay（易支付）/ turnstile / geoip。

const (
	controlSettingSectionBilling   = "billing"
	controlSettingSectionSMTP      = "smtp"
	controlSettingSectionEpay      = "epay"
	controlSettingSectionTurnstile = "turnstile"
	controlSettingSectionGeoIP     = "geoip"
)

// GetControlSettings GET /api/admin/control-settings
// 返回全部配置段当前值（含默认回落），供管理页渲染。
func (h *Handler) GetControlSettings(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	billing, err := h.db.LoadBillingConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	smtp, err := h.db.LoadSMTPConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	epay, err := h.db.LoadEpayConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	turnstile, err := h.db.LoadTurnstileConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	geoip, err := h.db.LoadGeoIPConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"billing":   billing,
		"smtp":      smtp,
		"epay":      epay,
		"turnstile": turnstile,
		"geoip":     geoip,
	})
}

// UpdateControlSettingsSection PUT /api/admin/control-settings/:section
// patch 语义更新单个配置段；返回更新后的完整配置段。
func (h *Handler) UpdateControlSettingsSection(c *gin.Context) {
	section := strings.TrimSpace(c.Param("section"))
	if section == "" {
		writeError(c, http.StatusBadRequest, "缺少配置段")
		return
	}
	var body json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		writeError(c, http.StatusBadRequest, "请求体必须是 JSON")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	switch section {
	case controlSettingSectionBilling:
		cur, err := h.db.LoadBillingConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			return
		}
		if err := json.Unmarshal(body, cur); err != nil {
			writeError(c, http.StatusBadRequest, "计费配置 JSON 解析失败")
			return
		}
		if msg := validateBillingConfig(cur); msg != "" {
			writeError(c, http.StatusBadRequest, msg)
			return
		}
		cur.Sanitize()
		if err := h.storeControlSetting(c, ctx, database.SettingKeyBilling, cur); err != nil {
			writeInternalError(c, err)
			return
		}
		// 数据面计费配置缓存立即失效（否则最多滞后 walletConfigCacheTTL）。
		h.invalidateBillingConfigCache()
		c.JSON(http.StatusOK, gin.H{"key": database.SettingKeyBilling, "value": cur})
		return
	case controlSettingSectionSMTP:
		cur, err := h.db.LoadSMTPConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			return
		}
		if err := json.Unmarshal(body, cur); err != nil {
			writeError(c, http.StatusBadRequest, "SMTP 配置 JSON 解析失败")
			return
		}
		cur.Sanitize()
		if msg := validateSMTPConfig(cur); msg != "" {
			writeError(c, http.StatusBadRequest, msg)
			return
		}
		if err := h.storeControlSetting(c, ctx, database.SettingKeySMTP, cur); err != nil {
			writeInternalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": database.SettingKeySMTP, "value": cur})
		return
	case controlSettingSectionEpay:
		cur, err := h.db.LoadEpayConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			return
		}
		if err := json.Unmarshal(body, cur); err != nil {
			writeError(c, http.StatusBadRequest, "易支付配置 JSON 解析失败")
			return
		}
		if msg := validateEpayConfig(cur); msg != "" {
			writeError(c, http.StatusBadRequest, msg)
			return
		}
		if err := h.storeControlSetting(c, ctx, database.SettingKeyEpay, cur); err != nil {
			writeInternalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": database.SettingKeyEpay, "value": cur})
		return
	case controlSettingSectionTurnstile:
		cur, err := h.db.LoadTurnstileConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			return
		}
		if err := json.Unmarshal(body, cur); err != nil {
			writeError(c, http.StatusBadRequest, "Turnstile 配置 JSON 解析失败")
			return
		}
		if msg := validateTurnstileConfig(cur); msg != "" {
			writeError(c, http.StatusBadRequest, msg)
			return
		}
		if err := h.storeControlSetting(c, ctx, database.SettingKeyTurnstile, cur); err != nil {
			writeInternalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": database.SettingKeyTurnstile, "value": cur})
		return
	case controlSettingSectionGeoIP:
		cur, err := h.db.LoadGeoIPConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			return
		}
		if err := json.Unmarshal(body, cur); err != nil {
			writeError(c, http.StatusBadRequest, "GeoIP 配置 JSON 解析失败")
			return
		}
		if msg := validateGeoIPConfig(cur); msg != "" {
			writeError(c, http.StatusBadRequest, msg)
			return
		}
		cur.Sanitize()
		if err := h.storeControlSetting(c, ctx, database.SettingKeyGeoIP, cur); err != nil {
			writeInternalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": database.SettingKeyGeoIP, "value": cur})
		return
	default:
		writeError(c, http.StatusBadRequest, "未知配置段: "+section)
		return
	}
}

// storeControlSetting 序列化并写入配置段；返回错误由调用方统一处理响应。
func (h *Handler) storeControlSetting(c *gin.Context, ctx context.Context, key string, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := h.db.SetSettingValue(ctx, key, string(raw), 0); err != nil {
		return err
	}
	return nil
}

// TestSMTPConnection POST /api/admin/control-settings/smtp/test
// 用当前（已保存的）SMTP 配置向指定邮箱发一封测试邮件。
type testSMTPRequest struct {
	To string `json:"to"`
}

func (h *Handler) TestSMTPConnection(c *gin.Context) {
	var req testSMTPRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.To) == "" {
		writeError(c, http.StatusBadRequest, "缺少收件邮箱")
		return
	}
	if _, ok := normalizeContactEmail(req.To); !ok {
		writeError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	cfg, err := h.db.LoadSMTPConfig(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if !cfg.Enabled || strings.TrimSpace(cfg.Host) == "" {
		writeError(c, http.StatusBadRequest, "SMTP 尚未启用，请先保存配置")
		return
	}
	from := strings.TrimSpace(cfg.From)
	if from == "" {
		from = strings.TrimSpace(cfg.Username)
	}
	if from == "" {
		writeError(c, http.StatusBadRequest, "发件人地址为空，请填写 from 或 username")
		return
	}
	if err := sendSMTPMail(ctx, cfg, from, strings.TrimSpace(req.To), "Codex2API 测试邮件", "这是一封来自 Codex2API 的 SMTP 测试邮件，收到即表示配置正确。"); err != nil {
		writeError(c, http.StatusBadRequest, "发送失败: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"sent": true, "to": req.To})
}

// ==================== 校验 ====================

func validateBillingConfig(cfg *database.BillingConfig) string {
	if cfg.DepositMicro <= 0 {
		return "deposit_micro 必须大于 0"
	}
	if cfg.MinChargeMicro < 0 {
		return "min_charge_micro 不能为负"
	}
	// 预留必须能覆盖最小扣费；否则结算兜底会把实扣封顶在预留额，用户实付低于预期最低价。
	if cfg.DepositMicro < cfg.MinChargeMicro {
		return "deposit_micro 不能小于 min_charge_micro"
	}
	if cfg.ChargeCapMicro != 0 && cfg.ChargeCapMicro < cfg.MinChargeMicro {
		return "charge_cap_micro 不能小于 min_charge_micro（0 表示不封顶）"
	}
	if cfg.CNYPerUSD <= 0 {
		return "cny_per_usd 必须大于 0"
	}
	return ""
}

func validateSMTPConfig(cfg *database.SMTPConfig) string {
	if !cfg.Enabled {
		return ""
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return "启用 SMTP 时 host 必填"
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return "port 必须在 1-65535 之间"
	}
	if strings.TrimSpace(cfg.From) == "" && strings.TrimSpace(cfg.Username) == "" {
		return "启用 SMTP 时 from 或 username 必填"
	}
	return ""
}

func validateEpayConfig(cfg *database.EpayConfig) string {
	if !cfg.Enabled {
		return ""
	}
	if strings.TrimSpace(cfg.MerchantID) == "" {
		return "启用易支付时 merchant_id 必填"
	}
	if strings.TrimSpace(cfg.Key) == "" {
		return "启用易支付时 key 必填"
	}
	if strings.TrimSpace(cfg.GatewayURL) == "" {
		return "启用易支付时 gateway_url 必填"
	}
	if strings.TrimSpace(cfg.CallbackBaseURL) == "" {
		return "启用易支付时 callback_base_url 必填（本站对外根地址）"
	}
	return ""
}

func validateTurnstileConfig(cfg *database.TurnstileConfig) string {
	if !cfg.Enabled {
		return ""
	}
	if strings.TrimSpace(cfg.SiteKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return "启用 Turnstile 时 site_key 与 secret_key 必填"
	}
	return ""
}

func validateGeoIPConfig(cfg *database.GeoIPConfig) string {
	if !cfg.Enabled {
		return ""
	}
	if strings.TrimSpace(cfg.Provider) == "" {
		return "启用 GeoIP 时 provider 必填（maxmind | ipinfo）"
	}
	if cfg.Mode != "block" && cfg.Mode != "allow" {
		return "mode 只能是 block 或 allow"
	}
	return ""
}

// normalizeControlSettingSection 归一配置段名（兼容前端传全名/简写）。
func normalizeControlSettingSection(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case controlSettingSectionBilling:
		return controlSettingSectionBilling
	case controlSettingSectionSMTP:
		return controlSettingSectionSMTP
	case controlSettingSectionEpay:
		return controlSettingSectionEpay
	case controlSettingSectionTurnstile:
		return controlSettingSectionTurnstile
	case controlSettingSectionGeoIP:
		return controlSettingSectionGeoIP
	}
	return ""
}

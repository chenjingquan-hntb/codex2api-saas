package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// 控制面 JSON 配置存储（P5/P6）。
//
// system_setting_values 与旧的单行 system_settings 标量列并存：标量列继续服务
// 既有管理页（连接池/调度/账号等），这里专门存「段落式 JSON 配置」：
//   - billing  钱包计费（预留额度/汇率倍率/最小扣费/封顶）
//   - smtp     邮件发送（验证/重置邮件）
//   - epay     易支付（下单/回调）
//   - turnstile Cloudflare Turnstile（注册/登录人机校验）
//   - geoip    GeoIP 国家/地区准入
//
// 所有配置「缺省回默认值」：读取时 JSON 反序列化到默认结构上，字段缺失保持默认，
// 管理员 PUT 采用 patch 语义（字段省略则保留当前值）。金额一律为整数微元，见 money.go。

// 配置段 key。
const (
	SettingKeyBilling   = "billing"
	SettingKeySMTP      = "smtp"
	SettingKeyEpay      = "epay"
	SettingKeyTurnstile = "turnstile"
	SettingKeyGeoIP     = "geoip"
)

var (
	// ErrSettingNotFound 表示配置段不存在（按默认值返回，读取时通常不视为错误）。
	ErrSettingNotFound = errors.New("settings: setting not found")
)

// GetSettingValue 读取配置段的原始 JSON；不存在时返回 ErrSettingNotFound。
func (db *DB) GetSettingValue(ctx context.Context, key string) (string, error) {
	var raw string
	err := db.conn.QueryRowContext(ctx,
		`SELECT value_json FROM system_setting_values WHERE key = $1`, key).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSettingNotFound
		}
		return "", err
	}
	return raw, nil
}

// SetSettingValue 整段 upsert 配置 JSON（patch 由调用方完成）。
func (db *DB) SetSettingValue(ctx context.Context, key, valueJSON string, updatedBy int64) error {
	if strings.TrimSpace(valueJSON) == "" {
		valueJSON = "{}"
	}
	if !json.Valid([]byte(valueJSON)) {
		return fmt.Errorf("settings: invalid JSON for %q", key)
	}
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO system_setting_values (key, value_json, updated_by, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET
			value_json = EXCLUDED.value_json,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`,
		key, valueJSON, updatedBy, db.timeArg(time.Now().UTC()))
	return err
}

// ListSettingValues 返回全部配置段（key → value_json）。
func (db *DB) ListSettingValues(ctx context.Context) (map[string]string, error) {
	rows, err := db.conn.QueryContext(ctx, `SELECT key, value_json FROM system_setting_values`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// loadSetting 把某配置段 JSON 反序列化到 target（调用方已用默认值初始化）。
// 存储为空/缺失/非法时保持默认值。
func (db *DB) loadSetting(ctx context.Context, key string, target interface{}) error {
	raw, err := db.GetSettingValue(ctx, key)
	if err != nil {
		if errors.Is(err, ErrSettingNotFound) {
			return nil
		}
		return err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return nil
	}
	if err := json.Unmarshal([]byte(trimmed), target); err != nil {
		return fmt.Errorf("settings: 解析 %s 失败: %w", key, err)
	}
	return nil
}

// ==================== billing（钱包计费） ====================

// BillingConfig 钱包计费配置。
// 金额单位为整数微元（1e-7 元，见 money.go）；汇率倍率用于把上游美元成本
// （database/billing.go 的 CalculateCost）换算成对用户收取的人民币。
type BillingConfig struct {
	Enabled        bool    `json:"enabled"`           // 总开关；关闭时数据面完全不走钱包
	DepositMicro   int64   `json:"deposit_micro"`     // 每个请求预扣的预留额度（默认 ¥1）
	MinChargeMicro int64   `json:"min_charge_micro"`  // 每请求最小扣费（默认 1 分）
	ChargeCapMicro int64   `json:"charge_cap_micro"`  // 每请求扣费封顶（默认 ¥50；0=不封顶）
	CNYPerUSD      float64 `json:"cny_per_usd"`       // 上游美元成本 → 人民币收费的倍率
}

// DefaultBillingConfig 返回计费默认值（关闭状态）。
func DefaultBillingConfig() *BillingConfig {
	return &BillingConfig{
		Enabled:        false,
		DepositMicro:   10_000_000, // ¥1
		MinChargeMicro: 100_000,    // 1 分
		ChargeCapMicro: 500_000_000, // ¥50
		CNYPerUSD:      12.0,
	}
}

// Sanitize 修正非法字段（负值/零值回落默认），保证数据面断言可用。
func (c *BillingConfig) Sanitize() {
	def := DefaultBillingConfig()
	if c.DepositMicro <= 0 {
		c.DepositMicro = def.DepositMicro
	}
	if c.MinChargeMicro < 0 {
		c.MinChargeMicro = def.MinChargeMicro
	}
	if c.ChargeCapMicro < 0 {
		c.ChargeCapMicro = def.ChargeCapMicro
	}
	if c.CNYPerUSD <= 0 {
		c.CNYPerUSD = def.CNYPerUSD
	}
}

// LoadBillingConfig 读取计费配置（缺省回落默认值，字段非法自动修正）。
func (db *DB) LoadBillingConfig(ctx context.Context) (*BillingConfig, error) {
	cfg := DefaultBillingConfig()
	if err := db.loadSetting(ctx, SettingKeyBilling, cfg); err != nil {
		return nil, err
	}
	cfg.Sanitize()
	return cfg, nil
}

// ComputeChargeMicro 把一条用量日志按计费配置换算成应扣微元（纯换算，不含
// 最小扣费/封顶——那在请求收尾按整请求累计后统一施加）。上游美元成本 ≤ 0 返回 0。
func ComputeChargeMicro(log *UsageLogInput, cfg *BillingConfig) int64 {
	if log == nil || cfg == nil || cfg.CNYPerUSD <= 0 {
		return 0
	}
	usd := UsageLogBilledCost(log)
	if usd <= 0 {
		return 0
	}
	micro := int64(math.Round(usd * cfg.CNYPerUSD * 1e7))
	if micro <= 0 {
		return 0
	}
	return micro
}

// ==================== smtp（邮件） ====================

// SMTPConfig 邮件发送配置。
// Security: starttls（默认，587）| ssl（隐式 TLS，465）| none（明文，仅内网调试）。
type SMTPConfig struct {
	Enabled            bool   `json:"enabled"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Security           string `json:"security"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	From               string `json:"from"`
	FromName           string `json:"from_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// DefaultSMTPConfig 返回 SMTP 默认值（关闭状态）。
func DefaultSMTPConfig() *SMTPConfig {
	return &SMTPConfig{
		Port:     587,
		Security: "starttls",
	}
}

// Sanitize 修正非法字段。
func (c *SMTPConfig) Sanitize() {
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = 587
	}
	switch c.Security {
	case "ssl", "none":
	default:
		c.Security = "starttls"
	}
}

// LoadSMTPConfig 读取邮件配置。
func (db *DB) LoadSMTPConfig(ctx context.Context) (*SMTPConfig, error) {
	cfg := DefaultSMTPConfig()
	if err := db.loadSetting(ctx, SettingKeySMTP, cfg); err != nil {
		return nil, err
	}
	cfg.Sanitize()
	return cfg, nil
}

// ==================== epay（易支付） ====================

// EpayConfig 易支付网关配置。
// GatewayURL 形如 https://pay.example.com/submit.php；
// CallbackBaseURL 是本站对外根地址，用于拼通知/回跳 URL。
type EpayConfig struct {
	Enabled          bool   `json:"enabled"`
	MerchantID       string `json:"merchant_id"`
	Key              string `json:"key"`
	GatewayURL       string `json:"gateway_url"`
	CallbackBaseURL  string `json:"callback_base_url"`
	NotifyPath       string `json:"notify_path"` // 默认 /api/pay/epay/notify
	ReturnPath       string `json:"return_path"` // 默认 /portal/pay/result
}

// DefaultEpayConfig 返回易支付默认值（关闭状态）。
func DefaultEpayConfig() *EpayConfig {
	return &EpayConfig{
		NotifyPath: "/api/pay/epay/notify",
		ReturnPath: "/portal/pay/result",
	}
}

// LoadEpayConfig 读取易支付配置。
func (db *DB) LoadEpayConfig(ctx context.Context) (*EpayConfig, error) {
	cfg := DefaultEpayConfig()
	if err := db.loadSetting(ctx, SettingKeyEpay, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ==================== turnstile（人机校验） ====================

// TurnstileConfig Cloudflare Turnstile 配置。
type TurnstileConfig struct {
	Enabled   bool   `json:"enabled"`
	SiteKey   string `json:"site_key"`
	SecretKey string `json:"secret_key"`
}

// DefaultTurnstileConfig 返回 Turnstile 默认值（关闭状态）。
func DefaultTurnstileConfig() *TurnstileConfig {
	return &TurnstileConfig{}
}

// LoadTurnstileConfig 读取 Turnstile 配置。
func (db *DB) LoadTurnstileConfig(ctx context.Context) (*TurnstileConfig, error) {
	cfg := DefaultTurnstileConfig()
	if err := db.loadSetting(ctx, SettingKeyTurnstile, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ==================== geoip（地理准入） ====================

// GeoIPConfig 地理准入配置。
// Mode: off | block（名单内拒绝） | allow（名单内放行，其余拒绝）。
type GeoIPConfig struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider"` // maxmind | ipinfo
	APIKey          string   `json:"api_key"`
	Mode            string   `json:"mode"`
	Countries       []string `json:"countries"` // 与 Mode 配合的 ISO 3166-1 alpha-2 列表
	CacheTTLMinutes int      `json:"cache_ttl_minutes"`
}

// DefaultGeoIPConfig 返回 GeoIP 默认值（关闭状态）。
func DefaultGeoIPConfig() *GeoIPConfig {
	return &GeoIPConfig{
		Mode:            "block",
		CacheTTLMinutes: 60,
	}
}

// Sanitize 修正非法字段。
func (c *GeoIPConfig) Sanitize() {
	switch c.Mode {
	case "allow", "block":
	default:
		c.Mode = "block"
	}
	if c.CacheTTLMinutes <= 0 {
		c.CacheTTLMinutes = 60
	}
	for i := range c.Countries {
		c.Countries[i] = strings.ToUpper(strings.TrimSpace(c.Countries[i]))
	}
}

// LoadGeoIPConfig 读取 GeoIP 配置。
func (db *DB) LoadGeoIPConfig(ctx context.Context) (*GeoIPConfig, error) {
	cfg := DefaultGeoIPConfig()
	if err := db.loadSetting(ctx, SettingKeyGeoIP, cfg); err != nil {
		return nil, err
	}
	cfg.Sanitize()
	return cfg, nil
}

// SettingSections 返回全部配置段（key → 当前原始 JSON）。用于管理页总览。
func (db *DB) SettingSections(ctx context.Context) (map[string]string, error) {
	return db.ListSettingValues(ctx)
}

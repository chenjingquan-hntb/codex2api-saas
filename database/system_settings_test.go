package database

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"testing"
)

func newSettingsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSettingValueRoundTrip(t *testing.T) {
	db := newSettingsTestDB(t)
	ctx := context.Background()

	if _, err := db.GetSettingValue(ctx, SettingKeyBilling); err != ErrSettingNotFound {
		t.Fatalf("expected ErrSettingNotFound, got %v", err)
	}

	if err := db.SetSettingValue(ctx, SettingKeyBilling, `{"enabled":true,"deposit_micro":5000000}`, 7); err != nil {
		t.Fatalf("set: %v", err)
	}
	raw, err := db.GetSettingValue(ctx, SettingKeyBilling)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["enabled"] != true {
		t.Fatalf("enabled = %v", got["enabled"])
	}
	if got["deposit_micro"].(float64) != 5000000 {
		t.Fatalf("deposit_micro = %v", got["deposit_micro"])
	}

	// upsert 覆盖
	if err := db.SetSettingValue(ctx, SettingKeyBilling, `{"enabled":false}`, 9); err != nil {
		t.Fatalf("set2: %v", err)
	}
	raw, _ = db.GetSettingValue(ctx, SettingKeyBilling)
	var got2 map[string]bool
	if err := json.Unmarshal([]byte(raw), &got2); err != nil {
		t.Fatalf("unmarshal2: %v", err)
	}
	if got2["enabled"] {
		t.Fatalf("expected enabled=false after upsert, raw=%s", raw)
	}

	// 非法 JSON 拒绝
	if err := db.SetSettingValue(ctx, SettingKeySMTP, `{bad`, 1); err == nil {
		t.Fatalf("expected invalid JSON error")
	}

	// list
	vals, err := db.ListSettingValues(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, ok := vals[SettingKeyBilling]; !ok {
		t.Fatalf("billing missing from list: %v", vals)
	}
}

func TestLoadBillingConfigDefaults(t *testing.T) {
	db := newSettingsTestDB(t)
	ctx := context.Background()

	cfg, err := db.LoadBillingConfig(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	def := DefaultBillingConfig()
	if cfg.Enabled || cfg.DepositMicro != def.DepositMicro || cfg.CNYPerUSD != def.CNYPerUSD {
		t.Fatalf("defaults mismatch: %+v", cfg)
	}
	if cfg.MinChargeMicro != def.MinChargeMicro || cfg.ChargeCapMicro != def.ChargeCapMicro {
		t.Fatalf("defaults mismatch: %+v", cfg)
	}
}

func TestLoadBillingConfigPartialPatch(t *testing.T) {
	db := newSettingsTestDB(t)
	ctx := context.Background()

	if err := db.SetSettingValue(ctx, SettingKeyBilling, `{"enabled":true,"deposit_micro":2500000}`, 1); err != nil {
		t.Fatalf("set: %v", err)
	}
	cfg, err := db.LoadBillingConfig(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Enabled || cfg.DepositMicro != 2500000 {
		t.Fatalf("patch fields not applied: %+v", cfg)
	}
	// 未提供的字段保持默认
	def := DefaultBillingConfig()
	if cfg.CNYPerUSD != def.CNYPerUSD || cfg.MinChargeMicro != def.MinChargeMicro {
		t.Fatalf("missing fields should keep defaults: %+v", cfg)
	}
}

func TestBillingConfigSanitize(t *testing.T) {
	cfg := &BillingConfig{DepositMicro: -5, MinChargeMicro: -1, ChargeCapMicro: -2, CNYPerUSD: 0}
	cfg.Sanitize()
	def := DefaultBillingConfig()
	if cfg.DepositMicro != def.DepositMicro || cfg.MinChargeMicro != def.MinChargeMicro ||
		cfg.ChargeCapMicro != def.ChargeCapMicro || cfg.CNYPerUSD != def.CNYPerUSD {
		t.Fatalf("sanitize failed: %+v", cfg)
	}

	cfg2 := &BillingConfig{DepositMicro: 123, CNYPerUSD: 8.5}
	cfg2.Sanitize()
	if cfg2.DepositMicro != 123 || cfg2.CNYPerUSD != 8.5 {
		t.Fatalf("sanitize must not clobber valid values: %+v", cfg2)
	}
}

func TestComputeChargeMicro(t *testing.T) {
	cfg := DefaultBillingConfig()
	cfg.CNYPerUSD = 10.0 // 方便心算：$1 = ¥10 = 1e8 微元

	cases := []struct {
		name   string
		log    *UsageLogInput
		expect int64
	}{
		{"nil log", nil, 0},
		{"zero tokens", &UsageLogInput{Model: "gpt-4o"}, 0},
		{"negative tokens", &UsageLogInput{Model: "gpt-4o", InputTokens: -1}, 0},
		{
			"normal charge",
			&UsageLogInput{Model: "gpt-4o", InputTokens: 1000, OutputTokens: 500, CachedTokens: 0},
			0, // 期望值由 CalculateCost 推导，见下
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeChargeMicro(tc.log, cfg)
			if tc.expect == 0 {
				if tc.log == nil || tc.log.InputTokens <= 0 {
					if got != 0 {
						t.Fatalf("expected 0, got %d", got)
					}
					return
				}
			}
			want := int64(math.Round(UsageLogBilledCost(tc.log) * cfg.CNYPerUSD * 1e7))
			if got != want {
				t.Fatalf("ComputeChargeMicro = %d, want %d", got, want)
			}
		})
	}

	// 无配置返回 0
	if got := ComputeChargeMicro(&UsageLogInput{Model: "gpt-4o", InputTokens: 100}, nil); got != 0 {
		t.Fatalf("nil cfg should yield 0, got %d", got)
	}
}

func TestLoadSMTPAndGeoIPConfigs(t *testing.T) {
	db := newSettingsTestDB(t)
	ctx := context.Background()

	smtp, err := db.LoadSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("smtp: %v", err)
	}
	if smtp.Enabled || smtp.Port != 587 || smtp.Security != "starttls" {
		t.Fatalf("smtp defaults: %+v", smtp)
	}

	if err := db.SetSettingValue(ctx, SettingKeySMTP, `{"enabled":true,"host":"smtp.example.com","port":465,"security":"ssl"}`, 1); err != nil {
		t.Fatalf("set smtp: %v", err)
	}
	smtp, err = db.LoadSMTPConfig(ctx)
	if err != nil {
		t.Fatalf("smtp reload: %v", err)
	}
	if !smtp.Enabled || smtp.Host != "smtp.example.com" || smtp.Port != 465 || smtp.Security != "ssl" {
		t.Fatalf("smtp loaded: %+v", smtp)
	}

	geo, err := db.LoadGeoIPConfig(ctx)
	if err != nil {
		t.Fatalf("geoip: %v", err)
	}
	if geo.Enabled || geo.Mode != "block" || geo.CacheTTLMinutes != 60 {
		t.Fatalf("geoip defaults: %+v", geo)
	}

	// 非法 mode 修正为 block
	if err := db.SetSettingValue(ctx, SettingKeyGeoIP, `{"enabled":true,"mode":"bogus","countries":["cn","US"]}`, 1); err != nil {
		t.Fatalf("set geoip: %v", err)
	}
	geo, err = db.LoadGeoIPConfig(ctx)
	if err != nil {
		t.Fatalf("geoip reload: %v", err)
	}
	if geo.Mode != "block" || geo.Countries[0] != "CN" || geo.Countries[1] != "US" {
		t.Fatalf("geoip sanitize: %+v", geo)
	}
}

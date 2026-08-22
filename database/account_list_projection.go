package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// ListAccountListProjection returns only non-secret fields needed to build the
// short-lived admin list snapshot. In particular it never selects or decodes
// the complete credentials document: all display/index attributes come from the
// dedicated projection columns (kept in sync by every credentials write and by
// the startup backfill), so the encrypted credentials blob is never parsed in
// this path.
func (db *DB) ListAccountListProjection(ctx context.Context, channel string) ([]*AccountRow, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	where := `status <> 'deleted' AND COALESCE(error_message, '') <> 'deleted'`
	upstreamExpr := `LOWER(COALESCE(upstream_type, ''))`
	credentialColumns := `
		COALESCE(upstream_type, ''),
		COALESCE(email, ''),
		COALESCE(base_url, ''),
		COALESCE(plan_type, ''),
		COALESCE(cred_models, '[]'),
		COALESCE(has_api_key, false),
		COALESCE(has_refresh_token, false),
		COALESCE(scheduler_priority, '')`
	if db.isSQLite() {
		credentialColumns = `
			COALESCE(upstream_type, ''),
			COALESCE(email, ''),
			COALESCE(base_url, ''),
			COALESCE(plan_type, ''),
			COALESCE(cred_models, '[]'),
			COALESCE(has_api_key, 0),
			COALESCE(has_refresh_token, 0),
			COALESCE(scheduler_priority, '')`
	}
	switch channel {
	case UpstreamChannelGrok:
		where += ` AND ` + upstreamExpr + ` = 'grok'`
	case UpstreamChannelAnthropic:
		where += ` AND ` + upstreamExpr + ` = 'anthropic'`
	case UpstreamChannelCodex:
		where += ` AND ` + upstreamExpr + ` NOT IN ('grok', 'anthropic')`
	}
	query := `SELECT id, name, type, proxy_url, status, cooldown_reason, cooldown_until,
		COALESCE(error_message, ''), COALESCE(enabled, true), COALESCE(locked, false),
		score_bias_override, base_concurrency_override, COALESCE(tags, '[]'), created_at, updated_at,
		COALESCE(credential_generation, 1), COALESCE(credential_family_id, ''),` + credentialColumns + `
		FROM accounts WHERE ` + where + ` ORDER BY id`
	rows, err := db.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("查询账号列表投影失败: %w", err)
	}
	defer rows.Close()
	result := make([]*AccountRow, 0)
	for rows.Next() {
		row, err := scanAccountListProjection(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

type accountProjectionScanner interface {
	Scan(dest ...interface{}) error
}

func scanAccountListProjection(scanner accountProjectionScanner) (*AccountRow, error) {
	row := &AccountRow{}
	var cooldownRaw, tagsRaw, createdRaw, updatedRaw interface{}
	var upstreamType, email, baseURL, planType, schedulerPriority string
	var modelsRaw interface{}
	var hasAPIKeyRaw, hasRefreshTokenRaw interface{}
	if err := scanner.Scan(
		&row.ID, &row.Name, &row.Type, &row.ProxyURL, &row.Status, &row.CooldownReason, &cooldownRaw,
		&row.ErrorMessage, &row.Enabled, &row.Locked, &row.ScoreBiasOverride, &row.BaseConcurrencyOverride,
		&tagsRaw, &createdRaw, &updatedRaw, &row.CredentialGeneration, &row.CredentialFamilyID,
		&upstreamType, &email, &baseURL, &planType, &modelsRaw,
		&hasAPIKeyRaw, &hasRefreshTokenRaw, &schedulerPriority,
	); err != nil {
		return nil, fmt.Errorf("扫描账号列表投影失败: %w", err)
	}
	row.Tags = decodeTagsValue(tagsRaw)
	var err error
	row.CooldownUntil, err = parseDBNullTimeValue(cooldownRaw)
	if err != nil {
		return nil, fmt.Errorf("解析 cooldown_until 失败: %w", err)
	}
	row.CreatedAt, err = parseDBTimeValue(createdRaw)
	if err != nil {
		return nil, fmt.Errorf("解析 created_at 失败: %w", err)
	}
	row.UpdatedAt, err = parseDBTimeValue(updatedRaw)
	if err != nil {
		return nil, fmt.Errorf("解析 updated_at 失败: %w", err)
	}
	row.Credentials = map[string]interface{}{
		"upstream_type": upstreamType,
		"email":         email,
		"base_url":      baseURL,
		"plan_type":     planType,
	}
	// 调度优先级参与列表排序(issue 截图反馈:排序不生效),投影缺了它会让
	// 快照全员按 0 打平、退化成 ID 序。以文本取出交给 GetCredentialInt64 解析。
	if trimmed := strings.TrimSpace(schedulerPriority); trimmed != "" {
		row.Credentials["scheduler_priority"] = trimmed
	}
	if models := decodeProjectionStringSlice(modelsRaw); len(models) > 0 {
		row.Credentials["models"] = models
	}
	if projectionBoolValue(hasAPIKeyRaw) {
		row.Credentials["api_key"] = "configured"
	}
	if projectionBoolValue(hasRefreshTokenRaw) {
		row.Credentials["refresh_token"] = "configured"
	}
	return row, nil
}

// projectionBoolValue 兼容 PostgreSQL BOOLEAN 与 SQLite 0/1 整数。
func projectionBoolValue(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case int64:
		return typed != 0
	case int:
		return typed != 0
	case float64:
		return typed != 0
	case []byte:
		return strings.TrimSpace(string(typed)) != "" && strings.TrimSpace(string(typed)) != "0" && !strings.EqualFold(strings.TrimSpace(string(typed)), "false")
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" || trimmed == "0" || strings.EqualFold(trimmed, "false") {
			return false
		}
		return true
	default:
		return false
	}
}

func decodeProjectionStringSlice(value interface{}) []string {
	var raw []byte
	switch typed := value.(type) {
	case string:
		raw = []byte(typed)
	case []byte:
		raw = typed
	case nil:
		return nil
	default:
		raw, _ = json.Marshal(typed)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	return values
}

// ListActiveByIDs fetches the complete base rows for one selected page in a
// single query. It is intentionally capped by the caller's page size (<=500).
// The credentials blob is read through the encryption-aware expression and
// decoded with db.decodeStoredCredentials.
func (db *DB) ListActiveByIDs(ctx context.Context, ids []int64) ([]*AccountRow, error) {
	ids = positiveUniqueIDs(ids)
	if len(ids) == 0 {
		return []*AccountRow{}, nil
	}
	args := make([]interface{}, 0, len(ids))
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	query := `SELECT id, name, platform, type, ` + storedCredentialsExpr() + `, proxy_url, status, cooldown_reason,
		cooldown_until, error_message, COALESCE(enabled, true), COALESCE(locked, false),
		COALESCE(credit_enabled, false), COALESCE(credit_skip_usage_window, false),
		COALESCE(skip_warm_tier, false), score_bias_override, base_concurrency_override,
		COALESCE(tags, '[]'), COALESCE(note, ''), created_at, updated_at,
		COALESCE(credential_generation, 1), COALESCE(credential_family_id, '')
		FROM accounts WHERE status <> 'deleted' AND COALESCE(error_message, '') <> 'deleted'
		AND id IN (` + strings.Join(placeholders, ",") + `) ORDER BY id`
	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("批量查询账号失败: %w", err)
	}
	defer rows.Close()
	result := make([]*AccountRow, 0, len(ids))
	for rows.Next() {
		row := &AccountRow{}
		var credentialsRaw, cooldownRaw, tagsRaw, createdRaw, updatedRaw interface{}
		if err := rows.Scan(
			&row.ID, &row.Name, &row.Platform, &row.Type, &credentialsRaw, &row.ProxyURL, &row.Status,
			&row.CooldownReason, &cooldownRaw, &row.ErrorMessage, &row.Enabled, &row.Locked,
			&row.CreditEnabled, &row.CreditSkipUsageWindow, &row.SkipWarmTier, &row.ScoreBiasOverride,
			&row.BaseConcurrencyOverride, &tagsRaw, &row.Note, &createdRaw, &updatedRaw,
			&row.CredentialGeneration, &row.CredentialFamilyID,
		); err != nil {
			return nil, fmt.Errorf("扫描账号行失败: %w", err)
		}
		row.Credentials = db.decodeStoredCredentials(credentialsRaw)
		row.Tags = decodeTagsValue(tagsRaw)
		row.CooldownUntil, err = parseDBNullTimeValue(cooldownRaw)
		if err != nil {
			return nil, err
		}
		row.CreatedAt, err = parseDBTimeValue(createdRaw)
		if err != nil {
			return nil, err
		}
		row.UpdatedAt, err = parseDBTimeValue(updatedRaw)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

var _ accountProjectionScanner = (*sql.Row)(nil)

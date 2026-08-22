package database

import (
	"context"
	"fmt"
	"time"
)

// 用户门户用量聚合（P5）：按 user_id 聚合其名下全部 API key 的用量。
// 与 APIKeySelfUsageReport 同构，前端可复用同一套渲染。

// UserUsageReport 用户维度用量报告（聚合该用户全部 active/历史 key）。
type UserUsageReport struct {
	Summary            APIKeySelfUsageSummary     `json:"summary"`
	Windows            APIKeySelfUsageWindows     `json:"windows"`
	Models             []APIKeySelfUsageBreakdown `json:"models"`
	Endpoints          []APIKeySelfUsageBreakdown `json:"endpoints"`
	RecentLogs         []APIKeySelfUsageLog       `json:"recent_logs"`
	RecentLogsTotal    int64                      `json:"recent_logs_total"`
	RecentLogsPage     int                        `json:"recent_logs_page"`
	RecentLogsPageSize int                        `json:"recent_logs_page_size"`
}

// GetUserUsageReport 聚合用户全部 key 的用量报告。
func (db *DB) GetUserUsageReport(ctx context.Context, userID int64, rangeStart, rangeEnd time.Time, recentPage, recentPageSize int) (*UserUsageReport, error) {
	recentPage, recentPageSize = normalizeAPIKeySelfRecentLogPagination(recentPage, recentPageSize)
	if userID <= 0 {
		return &UserUsageReport{
			Models:             []APIKeySelfUsageBreakdown{},
			Endpoints:          []APIKeySelfUsageBreakdown{},
			RecentLogs:         []APIKeySelfUsageLog{},
			RecentLogsPage:     recentPage,
			RecentLogsPageSize: recentPageSize,
		}, nil
	}

	report := &UserUsageReport{
		RecentLogsPage:     recentPage,
		RecentLogsPageSize: recentPageSize,
	}
	var err error
	if report.Summary, err = db.getUserUsageSummary(ctx, userID, rangeStart, rangeEnd); err != nil {
		return nil, err
	}
	if report.Windows.Today, err = db.getUserUsageDailyWindow(ctx, userID); err != nil {
		return nil, err
	}
	if report.Windows.Last5h, err = db.getUserUsageSlidingWindow(ctx, userID, 5*time.Hour); err != nil {
		return nil, err
	}
	if report.Windows.Last7d, err = db.getUserUsageSlidingWindow(ctx, userID, 7*24*time.Hour); err != nil {
		return nil, err
	}
	if report.Windows.Last30d, err = db.getUserUsageSlidingWindow(ctx, userID, 30*24*time.Hour); err != nil {
		return nil, err
	}
	if report.Models, err = db.listUserUsageBreakdown(ctx, userID, rangeStart, rangeEnd, "model", 8); err != nil {
		return nil, err
	}
	if report.Endpoints, err = db.listUserUsageBreakdown(ctx, userID, rangeStart, rangeEnd, "endpoint", 8); err != nil {
		return nil, err
	}
	report.RecentLogs, report.RecentLogsTotal, report.RecentLogsPage, report.RecentLogsPageSize, err =
		db.listUserUsageRecentLogs(ctx, userID, rangeStart, rangeEnd, recentPage, recentPageSize)
	if err != nil {
		return nil, err
	}
	return report, nil
}

// userUsageWhere 用户维度的 usage_logs WHERE 子句。
func (db *DB) userUsageWhere(userID int64, rangeStart, rangeEnd time.Time) (string, []interface{}) {
	where := "api_key_id IN (SELECT id FROM api_keys WHERE user_id = $1) AND status_code <> 499"
	args := []interface{}{userID}
	if !rangeStart.IsZero() {
		args = append(args, db.timeArg(rangeStart))
		where += fmt.Sprintf(" AND created_at >= $%d", len(args))
	}
	if !rangeEnd.IsZero() {
		args = append(args, db.timeArg(rangeEnd))
		where += fmt.Sprintf(" AND created_at < $%d", len(args))
	}
	return where, args
}

func (db *DB) getUserUsageSummary(ctx context.Context, userID int64, rangeStart, rangeEnd time.Time) (APIKeySelfUsageSummary, error) {
	where, args := db.userUsageWhere(userID, rangeStart, rangeEnd)
	minuteAgo := time.Now().Add(-1 * time.Minute)
	args = append(args, db.timeArg(minuteAgo))
	minuteArg := fmt.Sprintf("$%d", len(args))
	query := `
		SELECT
			COUNT(*),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(SUM(input_tokens), 0),
			COALESCE(SUM(output_tokens), 0),
			COALESCE(SUM(cached_tokens), 0),
			COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(user_billed), 0),
			COALESCE(AVG(NULLIF(duration_ms, 0)), 0),
			COALESCE(AVG(NULLIF(first_token_ms, 0)), 0),
			COALESCE(SUM(CASE WHEN created_at >= ` + minuteArg + ` THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= ` + minuteArg + ` THEN total_tokens ELSE 0 END), 0)
		FROM usage_logs
		WHERE ` + where
	var summary APIKeySelfUsageSummary
	err := db.conn.QueryRowContext(ctx, query, args...).Scan(
		&summary.Requests,
		&summary.Tokens,
		&summary.InputTokens,
		&summary.OutputTokens,
		&summary.CachedTokens,
		&summary.ErrorCount,
		&summary.UserBilled,
		&summary.AvgDurationMS,
		&summary.AvgFirstTokenMS,
		&summary.RPM,
		&summary.TPM,
	)
	return summary, err
}

func (db *DB) getUserUsageDailyWindow(ctx context.Context, userID int64) (APIKeySelfUsageWindow, error) {
	dayStart := StartOfDay(time.Now())
	resetAt := dayStart.AddDate(0, 0, 1)
	out := APIKeySelfUsageWindow{WindowKind: usageWindowKindFixed, ResetAt: &resetAt}
	usage, err := db.getUserUsageSince(ctx, userID, dayStart)
	if err != nil || usage == nil {
		return out, err
	}
	out.APIKeyWindowUsage = *usage
	return out, nil
}

func (db *DB) getUserUsageSlidingWindow(ctx context.Context, userID int64, window time.Duration) (APIKeySelfUsageWindow, error) {
	out := APIKeySelfUsageWindow{WindowKind: usageWindowKindSliding}
	usage, err := db.getUserUsageSince(ctx, userID, time.Now().Add(-window))
	if err != nil || usage == nil {
		return out, err
	}
	out.APIKeyWindowUsage = *usage
	return out, nil
}

func (db *DB) getUserUsageSince(ctx context.Context, userID int64, since time.Time) (*APIKeyWindowUsage, error) {
	if userID <= 0 || since.IsZero() {
		return &APIKeyWindowUsage{}, nil
	}
	usage := &APIKeyWindowUsage{}
	query := `
		SELECT
			COUNT(*),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(SUM(user_billed), 0),
			MIN(created_at)
		FROM usage_logs
		WHERE api_key_id IN (SELECT id FROM api_keys WHERE user_id = $1)
		  AND created_at >= $2
		  AND status_code <> 499`
	var oldestRaw interface{}
	err := db.conn.QueryRowContext(ctx, query, userID, db.timeArg(since)).Scan(
		&usage.Requests, &usage.Tokens, &usage.UserBilled, &oldestRaw,
	)
	if err != nil {
		return nil, err
	}
	if oldest, err := parseDBTimeValue(oldestRaw); err == nil && !oldest.IsZero() {
		usage.OldestAt = &oldest
	}
	return usage, nil
}

func (db *DB) listUserUsageBreakdown(ctx context.Context, userID int64, rangeStart, rangeEnd time.Time, kind string, limit int) ([]APIKeySelfUsageBreakdown, error) {
	if limit <= 0 {
		limit = 8
	}
	nameExpr := "COALESCE(NULLIF(effective_model, ''), NULLIF(model, ''), 'unknown')"
	if kind == "endpoint" {
		nameExpr = "COALESCE(NULLIF(inbound_endpoint, ''), NULLIF(endpoint, ''), 'unknown')"
	}
	where, args := db.userUsageWhere(userID, rangeStart, rangeEnd)
	args = append(args, limit)
	limitArg := fmt.Sprintf("$%d", len(args))
	query := `
		SELECT
			` + nameExpr + ` AS name,
			COUNT(*) AS requests,
			COALESCE(SUM(total_tokens), 0) AS tokens,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
			COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0) AS error_count,
			COALESCE(SUM(user_billed), 0) AS user_billed
		FROM usage_logs
		WHERE ` + where + `
		GROUP BY 1
		ORDER BY user_billed DESC, requests DESC, name ASC
		LIMIT ` + limitArg
	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]APIKeySelfUsageBreakdown, 0, limit)
	for rows.Next() {
		var item APIKeySelfUsageBreakdown
		if err := rows.Scan(
			&item.Name,
			&item.Requests,
			&item.Tokens,
			&item.InputTokens,
			&item.OutputTokens,
			&item.CachedTokens,
			&item.ErrorCount,
			&item.UserBilled,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if items == nil {
		items = []APIKeySelfUsageBreakdown{}
	}
	return items, nil
}

func (db *DB) listUserUsageRecentLogs(ctx context.Context, userID int64, rangeStart, rangeEnd time.Time, page, pageSize int) ([]APIKeySelfUsageLog, int64, int, int, error) {
	page, pageSize = normalizeAPIKeySelfRecentLogPagination(page, pageSize)
	where, args := db.userUsageWhere(userID, rangeStart, rangeEnd)

	var total int64
	countQuery := `SELECT COUNT(*) FROM usage_logs WHERE ` + where
	if err := db.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, page, pageSize, err
	}
	if total > 0 {
		totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
		if page > totalPages {
			page = totalPages
		}
	}

	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)
	limitArg := fmt.Sprintf("$%d", len(args)-1)
	offsetArg := fmt.Sprintf("$%d", len(args))
	query := `
		SELECT
			id,
			COALESCE(NULLIF(inbound_endpoint, ''), NULLIF(endpoint, ''), 'unknown') AS endpoint_name,
			COALESCE(model, ''),
			COALESCE(effective_model, ''),
			COALESCE(status_code, 0),
			COALESCE(duration_ms, 0),
			COALESCE(first_token_ms, 0),
			COALESCE(input_tokens, 0),
			COALESCE(output_tokens, 0),
			COALESCE(cached_tokens, 0),
			COALESCE(total_tokens, 0),
			COALESCE(user_billed, 0),
			COALESCE(NULLIF(billing_service_tier, ''), NULLIF(actual_service_tier, ''), NULLIF(service_tier, ''), ''),
			COALESCE(stream, false),
			COALESCE(compact, false),
			COALESCE(has_compaction_history, false),
			COALESCE(via_websocket, false),
			COALESCE(upstream_error_kind, ''),
			created_at
		FROM usage_logs
		WHERE ` + where + `
		ORDER BY id DESC
		LIMIT ` + limitArg + ` OFFSET ` + offsetArg
	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, page, pageSize, err
	}
	defer rows.Close()

	items := make([]APIKeySelfUsageLog, 0, pageSize)
	for rows.Next() {
		var item APIKeySelfUsageLog
		var createdAtRaw interface{}
		if err := rows.Scan(
			&item.ID,
			&item.Endpoint,
			&item.Model,
			&item.EffectiveModel,
			&item.StatusCode,
			&item.DurationMS,
			&item.FirstTokenMS,
			&item.InputTokens,
			&item.OutputTokens,
			&item.CachedTokens,
			&item.TotalTokens,
			&item.UserBilled,
			&item.ServiceTier,
			&item.Stream,
			&item.Compact,
			&item.HasCompactionHistory,
			&item.ViaWebsocket,
			&item.UpstreamErrorKind,
			&createdAtRaw,
		); err != nil {
			return nil, 0, page, pageSize, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, 0, page, pageSize, err
		}
		item.CreatedAt = createdAt
		item.populateBillingBreakdown()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, page, pageSize, err
	}
	if items == nil {
		items = []APIKeySelfUsageLog{}
	}
	return items, total, page, pageSize, nil
}

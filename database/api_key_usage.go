package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// APIKeyWindowUsage 表示一个 API Key 在某时间窗口内的累计使用量。
// 仅排除 499 客户端取消请求,保持与 GetUsageStats 一致的语义。
type APIKeyWindowUsage struct {
	Requests   int64   `json:"requests"`
	Tokens     int64   `json:"tokens"`
	UserBilled float64 `json:"user_billed"`
	// OldestAt 是窗口内最早一笔用量的时间,窗口内无用量时为空。滑动窗口下
	// OldestAt+窗口长度 即额度开始回落的时刻,供自助用量页展示(issue #460)。
	OldestAt *time.Time `json:"oldest_at,omitempty"`
}

// StartOfDay 返回 t 所在自然日的零点(保留 t 的时区)。自然日限额与
// key-usage 展示共用,保证判定与展示的日界一致。
func StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// GetAPIKeyWindowUsage 聚合指定 API Key 在 [now-window, now] 时间窗口内的使用情况。
// 用于 API Key 级别的滑动窗口限额校验(rpm/rpd/cost_5h/cost_7d/token_5h/token_7d)。
// 手动额度重置只截断 5h/7d 窗口，RPM/RPD/30d 与自然日窗口保持原有口径。
func (db *DB) GetAPIKeyWindowUsage(ctx context.Context, apiKeyID int64, window time.Duration) (*APIKeyWindowUsage, error) {
	if window <= 0 {
		return &APIKeyWindowUsage{}, nil
	}
	return db.getAPIKeyUsageSince(ctx, apiKeyID, time.Now().Add(-window), isResettableAPIKeyWindow(window))
}

func isResettableAPIKeyWindow(window time.Duration) bool {
	return window == 5*time.Hour || window == 7*24*time.Hour
}

// GetAPIKeyUsageSince 聚合指定 API Key 自 since 起的使用情况。自然日限额
// (issue #460)以当天零点为 since 复用同一条查询。
// 索引 idx_usage_logs_api_key_created_at 让该查询在数据量大时仍 O(log n)。
func (db *DB) GetAPIKeyUsageSince(ctx context.Context, apiKeyID int64, since time.Time) (*APIKeyWindowUsage, error) {
	return db.getAPIKeyUsageSince(ctx, apiKeyID, since, false)
}

func (db *DB) getAPIKeyUsageSince(ctx context.Context, apiKeyID int64, since time.Time, honorReset bool) (*APIKeyWindowUsage, error) {
	if apiKeyID <= 0 || since.IsZero() {
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
		WHERE api_key_id = $1
		  AND created_at >= $2
		  AND status_code <> 499
	`
	if honorReset {
		query = `
			SELECT
				COUNT(*),
				COALESCE(SUM(u.total_tokens), 0),
				COALESCE(SUM(u.user_billed), 0),
				MIN(u.created_at)
			FROM usage_logs u
			JOIN api_keys k ON k.id = u.api_key_id
			WHERE u.api_key_id = $1
			  AND u.created_at >= $2
			  AND (k.last_reset_at IS NULL OR u.created_at >= k.last_reset_at)
			  AND u.status_code <> 499
		`
	}
	var oldestRaw interface{}
	err := db.conn.QueryRowContext(ctx, query, apiKeyID, db.timeArg(since)).Scan(
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

// GetAPIKeyAccountWindowUsage 聚合指定 API Key 在窗口内**按账号拆分**的使用情况,
// 供 scope 维度限额(issue #439)判定。一次查询即可覆盖该 Key 的全部 scope 条目:
// 分组维度在调用方按账号当前所属分组折算,因此分组成员变动即时生效,无需在
// usage_logs 里冗余 group_id。
//
// 复用索引 idx_usage_logs_api_key_created_at,扫描量与同窗口的 Key 级 cost 聚合同级。
// 已从账号池删除的账号仍会出现在返回值里,但调用方无法把它折算到分组——这部分历史
// 用量在分组维度上会被忽略(账号维度仍准确)。
func (db *DB) GetAPIKeyAccountWindowUsage(ctx context.Context, apiKeyID int64, window time.Duration) (map[int64]APIKeyWindowUsage, error) {
	if apiKeyID <= 0 || window <= 0 {
		return map[int64]APIKeyWindowUsage{}, nil
	}
	since := time.Now().Add(-window)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT
			COALESCE(account_id, 0),
			COUNT(*),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(SUM(user_billed), 0)
		FROM usage_logs
		WHERE api_key_id = $1
		  AND created_at >= $2
		  AND status_code <> 499
		GROUP BY account_id
	`, apiKeyID, db.timeArg(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64]APIKeyWindowUsage)
	for rows.Next() {
		var accountID int64
		var usage APIKeyWindowUsage
		if err := rows.Scan(&accountID, &usage.Requests, &usage.Tokens, &usage.UserBilled); err != nil {
			return nil, err
		}
		if accountID <= 0 {
			continue
		}
		out[accountID] = usage
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetAPIKeyAccountWindowsUsage aggregates all supported scope windows in one
// index range scan. The previous caller issued one GROUP BY query per window,
// making the 30-day view scan the same rows up to four times.
func (db *DB) GetAPIKeyAccountWindowsUsage(ctx context.Context, apiKeyID int64) (map[string]map[int64]APIKeyWindowUsage, error) {
	out := make(map[string]map[int64]APIKeyWindowUsage, len(APIKeyScopeWindows))
	for _, window := range APIKeyScopeWindows {
		out[window.Label] = make(map[int64]APIKeyWindowUsage)
	}
	if apiKeyID <= 0 {
		return out, nil
	}

	now := time.Now()
	since5h := db.timeArg(now.Add(-5 * time.Hour))
	since1d := db.timeArg(now.Add(-24 * time.Hour))
	since7d := db.timeArg(now.Add(-7 * 24 * time.Hour))
	since30d := db.timeArg(now.Add(-30 * 24 * time.Hour))
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(account_id, 0),
			COALESCE(SUM(CASE WHEN created_at >= $2 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $2 THEN total_tokens ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $2 THEN user_billed ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $3 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $3 THEN total_tokens ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $3 THEN user_billed ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $4 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $4 THEN total_tokens ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN created_at >= $4 THEN user_billed ELSE 0 END), 0),
			COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(user_billed), 0)
		FROM usage_logs
		WHERE api_key_id = $1 AND created_at >= $5 AND status_code <> 499
		GROUP BY account_id
	`, apiKeyID, since5h, since1d, since7d, since30d)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var accountID int64
		var fiveHours, oneDay, sevenDays, thirtyDays APIKeyWindowUsage
		if err := rows.Scan(&accountID,
			&fiveHours.Requests, &fiveHours.Tokens, &fiveHours.UserBilled,
			&oneDay.Requests, &oneDay.Tokens, &oneDay.UserBilled,
			&sevenDays.Requests, &sevenDays.Tokens, &sevenDays.UserBilled,
			&thirtyDays.Requests, &thirtyDays.Tokens, &thirtyDays.UserBilled,
		); err != nil {
			return nil, err
		}
		if accountID <= 0 {
			continue
		}
		out["5h"][accountID] = fiveHours
		out["1d"][accountID] = oneDay
		out["7d"][accountID] = sevenDays
		out["30d"][accountID] = thirtyDays
	}
	return out, rows.Err()
}

// GetAPIKeysAccountWindowUsage 是 GetAPIKeyAccountWindowUsage 的批量版本:一次查询拿到
// 多个 API Key 在同一窗口内、按账号拆分的用量,供列表页展示 scope 预算进度(issue #439)。
// apiKeyIDs 为空时返回空表(刻意不退化成全表聚合,避免列表页误触发大查询)。
func (db *DB) GetAPIKeysAccountWindowUsage(ctx context.Context, apiKeyIDs []int64, window time.Duration) (map[int64]map[int64]APIKeyWindowUsage, error) {
	out := make(map[int64]map[int64]APIKeyWindowUsage)
	if len(apiKeyIDs) == 0 || window <= 0 {
		return out, nil
	}
	placeholders := make([]string, 0, len(apiKeyIDs))
	args := make([]interface{}, 0, len(apiKeyIDs)+1)
	for i, id := range apiKeyIDs {
		if db.isSQLite() {
			placeholders = append(placeholders, "?")
		} else {
			placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		}
		args = append(args, id)
	}
	sincePlaceholder := "?"
	if !db.isSQLite() {
		sincePlaceholder = fmt.Sprintf("$%d", len(apiKeyIDs)+1)
	}
	args = append(args, db.timeArg(time.Now().Add(-window)))

	query := fmt.Sprintf(`
		SELECT
			api_key_id,
			COALESCE(account_id, 0),
			COUNT(*),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(SUM(user_billed), 0)
		FROM usage_logs
		WHERE api_key_id IN (%s)
		  AND created_at >= %s
		  AND status_code <> 499
		GROUP BY api_key_id, account_id
	`, strings.Join(placeholders, ","), sincePlaceholder)

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var apiKeyID, accountID int64
		var usage APIKeyWindowUsage
		if err := rows.Scan(&apiKeyID, &accountID, &usage.Requests, &usage.Tokens, &usage.UserBilled); err != nil {
			return nil, err
		}
		if apiKeyID <= 0 || accountID <= 0 {
			continue
		}
		if out[apiKeyID] == nil {
			out[apiKeyID] = make(map[int64]APIKeyWindowUsage)
		}
		out[apiKeyID][accountID] = usage
	}
	return out, rows.Err()
}

// APIKeyTokenStat 是 API Key 在某时间区间内的 token 使用排行项。
// 比 UsageAPIKeyStat 更细——分列 input / output / cached token，便于 UI 单独排序。
type APIKeyTokenStat struct {
	APIKeyID     int64   `json:"api_key_id"`
	APIKeyName   string  `json:"api_key_name"`
	APIKeyMasked string  `json:"api_key_masked"`
	Label        string  `json:"label"`
	Requests     int64   `json:"requests"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CachedTokens int64   `json:"cached_tokens"`
	TotalTokens  int64   `json:"total_tokens"`
	ErrorCount   int64   `json:"error_count"`
	UserBilled   float64 `json:"user_billed"`
}

// ListAPIKeyTokenStats 返回 [rangeStart, rangeEnd) 区间内按 API Key 聚合的 token 用量。
// 两个时间都可零值；rangeStart 零值表示"今日 0 点"，rangeEnd 零值表示"至今"。
// 返回结果**不限条数**，与 issue #162 一致；前端负责排序 / 搜索 / 分页。
func (db *DB) ListAPIKeyTokenStats(ctx context.Context, rangeStart, rangeEnd time.Time) ([]APIKeyTokenStat, error) {
	now := time.Now()
	if rangeStart.IsZero() {
		rangeStart = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	}

	query := `
		SELECT
			COALESCE(api_key_id, 0) AS api_key_id,
			COALESCE(api_key_name, '') AS api_key_name,
			COALESCE(api_key_masked, '') AS api_key_masked,
			COUNT(*) AS requests,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
			COALESCE(SUM(total_tokens), 0) AS total_tokens,
			COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0) AS error_count,
			COALESCE(SUM(user_billed), 0) AS user_billed
		FROM usage_logs
		WHERE status_code <> 499
		  AND created_at >= $1
	`
	args := []interface{}{db.timeArg(rangeStart)}
	if !rangeEnd.IsZero() {
		query += " AND created_at < $2"
		args = append(args, db.timeArg(rangeEnd))
	}
	query += " GROUP BY 1, 2, 3 ORDER BY total_tokens DESC, requests DESC"

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]APIKeyTokenStat, 0, 16)
	for rows.Next() {
		var item APIKeyTokenStat
		if err := rows.Scan(
			&item.APIKeyID,
			&item.APIKeyName,
			&item.APIKeyMasked,
			&item.Requests,
			&item.InputTokens,
			&item.OutputTokens,
			&item.CachedTokens,
			&item.TotalTokens,
			&item.ErrorCount,
			&item.UserBilled,
		); err != nil {
			return nil, err
		}
		// 计算 label（前端可直接展示）：优先 name，其次 masked，否则 "unknown"
		switch {
		case item.APIKeyName != "":
			item.Label = item.APIKeyName
		case item.APIKeyMasked != "":
			item.Label = item.APIKeyMasked
		default:
			item.Label = "unknown"
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// APIKeyAccountGroup 是上游账号所属分组的精简展示项（Token 用量明细用）。
type APIKeyAccountGroup struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// APIKeyAccountStat 是单个 API Key 在某时间区间内、按上游账号拆分的用量项。
// 与 AccountKeyStat（账号 → 各 Key）互为转置：这里是 Key → 各账号。
type APIKeyAccountStat struct {
	AccountID      int64                `json:"account_id"`
	AccountName    string               `json:"account_name"`
	AccountEmail   string               `json:"account_email"`
	AccountDeleted bool                 `json:"account_deleted"`
	Groups         []APIKeyAccountGroup `json:"groups,omitempty"`
	Requests       int64                `json:"requests"`
	InputTokens    int64                `json:"input_tokens"`
	OutputTokens   int64                `json:"output_tokens"`
	CachedTokens   int64                `json:"cached_tokens"`
	TotalTokens    int64                `json:"total_tokens"`
	ErrorCount     int64                `json:"error_count"`
	AccountBilled  float64              `json:"account_billed"`
	UserBilled     float64              `json:"user_billed"`
}

// ListAPIKeyAccountStats 返回某个 API Key 在 [rangeStart, rangeEnd) 内按上游账号聚合的用量。
// rangeStart 零值表示"今日 0 点"，rangeEnd 零值表示"至今"，与 ListAPIKeyTokenStats 语义一致。
// account 标签(name/email)从 accounts 表 JOIN 得到；email 存在 credentials JSON 中，在 Go 侧解析。
func (db *DB) ListAPIKeyAccountStats(ctx context.Context, apiKeyID int64, rangeStart, rangeEnd time.Time) ([]APIKeyAccountStat, error) {
	now := time.Now()
	if rangeStart.IsZero() {
		rangeStart = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	}

	query := `
		WITH aggregated AS (
			SELECT
				account_id,
				COUNT(*) AS requests,
				COALESCE(SUM(input_tokens), 0) AS input_tokens,
				COALESCE(SUM(output_tokens), 0) AS output_tokens,
				COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
				COALESCE(SUM(total_tokens), 0) AS total_tokens,
				COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0) AS error_count,
				COALESCE(SUM(account_billed), 0) AS account_billed,
				COALESCE(SUM(user_billed), 0) AS user_billed
			FROM usage_logs
			WHERE api_key_id = $1 AND status_code <> 499 AND created_at >= $2
	`
	args := []interface{}{apiKeyID, db.timeArg(rangeStart)}
	if !rangeEnd.IsZero() {
		query += " AND created_at < $3"
		args = append(args, db.timeArg(rangeEnd))
	}
	query += `
			GROUP BY account_id
		)
		SELECT
			u.account_id,
			COALESCE(a.name, '') AS account_name,
			COALESCE(a.email, '') AS account_email,
			COALESCE(a.status, '') AS account_status,
			COALESCE(a.error_message, '') AS account_error,
			u.requests, u.input_tokens, u.output_tokens, u.cached_tokens,
			u.total_tokens, u.error_count, u.account_billed, u.user_billed
		FROM aggregated u
		LEFT JOIN accounts a ON u.account_id = a.id
	`
	query += " ORDER BY u.requests DESC, u.total_tokens DESC"

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]APIKeyAccountStat, 0, 16)
	for rows.Next() {
		var item APIKeyAccountStat
		var accountEmail string
		var accountStatus string
		var accountError string
		if err := rows.Scan(
			&item.AccountID,
			&item.AccountName,
			&accountEmail,
			&accountStatus,
			&accountError,
			&item.Requests,
			&item.InputTokens,
			&item.OutputTokens,
			&item.CachedTokens,
			&item.TotalTokens,
			&item.ErrorCount,
			&item.AccountBilled,
			&item.UserBilled,
		); err != nil {
			return nil, err
		}
		item.AccountEmail = accountEmail
		item.AccountDeleted = strings.EqualFold(strings.TrimSpace(accountStatus), "deleted") ||
			strings.EqualFold(strings.TrimSpace(accountError), "deleted")
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := db.attachAPIKeyAccountGroups(ctx, items); err != nil {
		return nil, err
	}
	return items, nil
}

// attachAPIKeyAccountGroups 批量补齐上游账号的分组标签，避免 N+1。
// account_group_members 保留回收站账号软删除前的最后归属，因此这里不按
// accounts.status 过滤；统计历史用量时必须能看见该快照。
func (db *DB) attachAPIKeyAccountGroups(ctx context.Context, items []APIKeyAccountStat) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(items))
	seen := make(map[int64]struct{}, len(items))
	for _, item := range items {
		if item.AccountID <= 0 {
			continue
		}
		if _, ok := seen[item.AccountID]; ok {
			continue
		}
		seen[item.AccountID] = struct{}{}
		ids = append(ids, item.AccountID)
	}
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		if db.isSQLite() {
			placeholders[i] = "?"
		} else {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT m.account_id, g.id, g.name, COALESCE(g.color, '')
		FROM account_group_members m
		INNER JOIN account_groups g ON g.id = m.group_id
		WHERE m.account_id IN (%s)
		ORDER BY m.account_id, g.sort_order, g.name`, strings.Join(placeholders, ","))

	groupRows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer groupRows.Close()

	byAccount := make(map[int64][]APIKeyAccountGroup, len(ids))
	for groupRows.Next() {
		var accountID int64
		var group APIKeyAccountGroup
		if err := groupRows.Scan(&accountID, &group.ID, &group.Name, &group.Color); err != nil {
			return err
		}
		byAccount[accountID] = append(byAccount[accountID], group)
	}
	if err := groupRows.Err(); err != nil {
		return err
	}

	for i := range items {
		if groups := byAccount[items[i].AccountID]; len(groups) > 0 {
			items[i].Groups = groups
		}
	}
	return nil
}

// emailFromCredentialsJSON 从账号 credentials JSON 文本里取展示用邮箱；
// email 缺省时回落到 base_url（覆盖 openai_responses 直连账号的展示需要）。
func emailFromCredentialsJSON(raw string) string {
	if raw == "" {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return ""
	}
	if s, ok := m["email"].(string); ok && s != "" {
		return s
	}
	if s, ok := m["base_url"].(string); ok {
		return s
	}
	return ""
}

// ListAPIKeyLastUsedAt 返回每个 API Key 最近一次请求时间（来自 usage_logs）。
// 仅包含有调用记录的 key；索引 idx_usage_logs_api_key_created_at 支撑该聚合。
func (db *DB) ListAPIKeyLastUsedAt(ctx context.Context) (map[int64]time.Time, error) {
	query := `
		SELECT api_key_id, MAX(created_at)
		FROM usage_logs
		WHERE api_key_id > 0
		  AND status_code <> 499
		GROUP BY api_key_id
	`
	rows, err := db.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64]time.Time)
	for rows.Next() {
		var id int64
		var lastUsedRaw interface{}
		if err := rows.Scan(&id, &lastUsedRaw); err != nil {
			return nil, err
		}
		t, err := parseDBTimeValue(lastUsedRaw)
		if err != nil {
			return nil, err
		}
		if !t.IsZero() {
			result[id] = t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAllAPIKeysWindowCost 批量聚合所有 API Key 在 [now-window, now] 窗口内的 user_billed。
// 返回 map[apiKeyID] → cost。仅包含有使用记录的 key。
func (db *DB) GetAllAPIKeysWindowCost(ctx context.Context, window time.Duration) (map[int64]float64, error) {
	if window <= 0 {
		return make(map[int64]float64), nil
	}
	return db.getAllAPIKeysCostSince(ctx, time.Now().Add(-window), isResettableAPIKeyWindow(window))
}

// GetAllAPIKeysCostSince 批量聚合所有 API Key 自 since 起的 user_billed。
// 自然日限额(issue #460)以当天零点为 since 复用该查询。
func (db *DB) GetAllAPIKeysCostSince(ctx context.Context, since time.Time) (map[int64]float64, error) {
	return db.getAllAPIKeysCostSince(ctx, since, false)
}

func (db *DB) getAllAPIKeysCostSince(ctx context.Context, since time.Time, honorReset bool) (map[int64]float64, error) {
	if since.IsZero() {
		return make(map[int64]float64), nil
	}
	query := `
		SELECT api_key_id, COALESCE(SUM(user_billed), 0)
		FROM usage_logs
		WHERE api_key_id > 0
		  AND created_at >= $1
		  AND status_code <> 499
		GROUP BY api_key_id
	`
	if honorReset {
		query = `
			SELECT u.api_key_id, COALESCE(SUM(u.user_billed), 0)
			FROM usage_logs u
			JOIN api_keys k ON k.id = u.api_key_id
			WHERE u.api_key_id > 0
			  AND u.created_at >= $1
			  AND (k.last_reset_at IS NULL OR u.created_at >= k.last_reset_at)
			  AND u.status_code <> 499
			GROUP BY u.api_key_id
		`
	}
	rows, err := db.conn.QueryContext(ctx, query, db.timeArg(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64]float64)
	for rows.Next() {
		var id int64
		var cost float64
		if err := rows.Scan(&id, &cost); err != nil {
			return nil, err
		}
		result[id] = cost
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// APIKeySelfUsageReport 是 API Key 自助统计页使用的只读聚合结果。
// 只包含当前 key 自己的 usage_logs 数据,不返回账号池、客户端 IP、raw key 等后台字段。
type APIKeySelfUsageReport struct {
	Summary            APIKeySelfUsageSummary     `json:"summary"`
	Windows            APIKeySelfUsageWindows     `json:"windows"`
	Models             []APIKeySelfUsageBreakdown `json:"models"`
	Endpoints          []APIKeySelfUsageBreakdown `json:"endpoints"`
	RecentLogs         []APIKeySelfUsageLog       `json:"recent_logs"`
	RecentLogsTotal    int64                      `json:"recent_logs_total"`
	RecentLogsPage     int                        `json:"recent_logs_page"`
	RecentLogsPageSize int                        `json:"recent_logs_page_size"`
}

type APIKeySelfUsageSummary struct {
	Requests        int64   `json:"requests"`
	Tokens          int64   `json:"tokens"`
	InputTokens     int64   `json:"input_tokens"`
	OutputTokens    int64   `json:"output_tokens"`
	CachedTokens    int64   `json:"cached_tokens"`
	ErrorCount      int64   `json:"error_count"`
	UserBilled      float64 `json:"user_billed"`
	AvgDurationMS   float64 `json:"avg_duration_ms"`
	AvgFirstTokenMS float64 `json:"avg_first_token_ms"`
	RPM             int64   `json:"rpm"`
	TPM             int64   `json:"tpm"`
}

// APIKeySelfUsageWindow 是自助页的窗口条目:原始聚合之上附带窗口语义与重置/回落
// 时刻(issue #460),由服务端计算,前端不做本地推算。
type APIKeySelfUsageWindow struct {
	APIKeyWindowUsage
	// WindowKind: fixed=自然日固定窗口,到 ResetAt 全额清零;
	// sliding=滑动窗口,没有单一重置时刻,DecayAt 是最早一笔用量滚出窗口、
	// 额度开始回落的时间(窗口内无用量时为空)。
	WindowKind string     `json:"window_kind"`
	ResetAt    *time.Time `json:"reset_at,omitempty"`
	DecayAt    *time.Time `json:"decay_at,omitempty"`
}

type APIKeySelfUsageWindows struct {
	Today   APIKeySelfUsageWindow `json:"today"`
	Last5h  APIKeySelfUsageWindow `json:"last_5h"`
	Last7d  APIKeySelfUsageWindow `json:"last_7d"`
	Last30d APIKeySelfUsageWindow `json:"last_30d"`
}

type APIKeySelfUsageBreakdown struct {
	Name         string  `json:"name"`
	Requests     int64   `json:"requests"`
	Tokens       int64   `json:"tokens"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CachedTokens int64   `json:"cached_tokens"`
	ErrorCount   int64   `json:"error_count"`
	UserBilled   float64 `json:"user_billed"`
}

type APIKeySelfUsageLog struct {
	ID                   int64     `json:"id"`
	Endpoint             string    `json:"endpoint"`
	Model                string    `json:"model"`
	EffectiveModel       string    `json:"effective_model"`
	StatusCode           int       `json:"status_code"`
	DurationMS           int       `json:"duration_ms"`
	FirstTokenMS         int       `json:"first_token_ms"`
	InputTokens          int       `json:"input_tokens"`
	OutputTokens         int       `json:"output_tokens"`
	CachedTokens         int       `json:"cached_tokens"`
	TotalTokens          int       `json:"total_tokens"`
	UserBilled           float64   `json:"user_billed"`
	InputCost            float64   `json:"input_cost"`
	OutputCost           float64   `json:"output_cost"`
	CacheReadCost        float64   `json:"cache_read_cost"`
	TotalCost            float64   `json:"total_cost"`
	InputPrice           float64   `json:"input_price_per_mtoken"`
	OutputPrice          float64   `json:"output_price_per_mtoken"`
	CacheReadPrice       float64   `json:"cache_read_price_per_mtoken"`
	RateMultiplier       float64   `json:"rate_multiplier"`
	LongContext          bool      `json:"long_context"`
	ServiceTier          string    `json:"service_tier"`
	Stream               bool      `json:"stream"`
	Compact              bool      `json:"compact"`
	HasCompactionHistory bool      `json:"has_compaction_history"`
	ViaWebsocket         bool      `json:"via_websocket"`
	UpstreamErrorKind    string    `json:"upstream_error_kind"`
	CreatedAt            time.Time `json:"created_at"`
}

// populateBillingBreakdown 复用与管理端一致的计费拆解逻辑，按 effective_model + 计费档位
// 还原输入/输出/缓存读取的费用与单价，并在与实际计费总额不一致时等比缩放对齐。
func (l *APIKeySelfUsageLog) populateBillingBreakdown() {
	billingModel := l.EffectiveModel
	if billingModel == "" {
		billingModel = l.Model
	}
	breakdown := calculateCostBreakdown(l.InputTokens, l.OutputTokens, l.CachedTokens, billingModel, l.ServiceTier)
	l.InputCost = breakdown.InputCost
	l.OutputCost = breakdown.OutputCost
	l.CacheReadCost = breakdown.CacheReadCost
	l.TotalCost = breakdown.TotalCost
	l.InputPrice = breakdown.InputPricePerMToken
	l.OutputPrice = breakdown.OutputPricePerMToken
	l.CacheReadPrice = breakdown.CacheReadPricePerMToken
	l.RateMultiplier = breakdown.ServiceTierCostMultiplier
	l.LongContext = breakdown.LongContext

	if l.UserBilled > 0 && breakdown.TotalCost > 0 && l.UserBilled != breakdown.TotalCost {
		scale := l.UserBilled / breakdown.TotalCost
		l.InputCost *= scale
		l.OutputCost *= scale
		l.CacheReadCost *= scale
		l.TotalCost = l.UserBilled
		l.InputPrice *= scale
		l.OutputPrice *= scale
		l.CacheReadPrice *= scale
	}
}

func (db *DB) GetAPIKeySelfUsageReport(ctx context.Context, apiKeyID int64, rangeStart, rangeEnd time.Time, recentPage, recentPageSize int) (*APIKeySelfUsageReport, error) {
	recentPage, recentPageSize = normalizeAPIKeySelfRecentLogPagination(recentPage, recentPageSize)
	if apiKeyID <= 0 {
		return &APIKeySelfUsageReport{
			Models:             []APIKeySelfUsageBreakdown{},
			Endpoints:          []APIKeySelfUsageBreakdown{},
			RecentLogs:         []APIKeySelfUsageLog{},
			RecentLogsPage:     recentPage,
			RecentLogsPageSize: recentPageSize,
		}, nil
	}

	report := &APIKeySelfUsageReport{
		RecentLogsPage:     recentPage,
		RecentLogsPageSize: recentPageSize,
	}
	var err error
	if report.Summary, err = db.getAPIKeySelfUsageSummary(ctx, apiKeyID, rangeStart, rangeEnd); err != nil {
		return nil, err
	}
	if report.Windows.Today, err = db.getAPIKeySelfDailyWindow(ctx, apiKeyID); err != nil {
		return nil, err
	}
	if report.Windows.Last5h, err = db.getAPIKeySelfSlidingWindow(ctx, apiKeyID, 5*time.Hour); err != nil {
		return nil, err
	}
	if report.Windows.Last7d, err = db.getAPIKeySelfSlidingWindow(ctx, apiKeyID, 7*24*time.Hour); err != nil {
		return nil, err
	}
	if report.Windows.Last30d, err = db.getAPIKeySelfSlidingWindow(ctx, apiKeyID, 30*24*time.Hour); err != nil {
		return nil, err
	}
	if report.Models, err = db.listAPIKeySelfUsageBreakdown(ctx, apiKeyID, rangeStart, rangeEnd, "model", 8); err != nil {
		return nil, err
	}
	if report.Endpoints, err = db.listAPIKeySelfUsageBreakdown(ctx, apiKeyID, rangeStart, rangeEnd, "endpoint", 8); err != nil {
		return nil, err
	}
	report.RecentLogs, report.RecentLogsTotal, report.RecentLogsPage, report.RecentLogsPageSize, err = db.listAPIKeySelfRecentLogs(ctx, apiKeyID, rangeStart, rangeEnd, recentPage, recentPageSize)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func normalizeAPIKeySelfRecentLogPagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// 窗口语义取值(APIKeySelfUsageWindow.WindowKind)。
const (
	usageWindowKindFixed   = "fixed"
	usageWindowKindSliding = "sliding"
)

func (db *DB) getAPIKeySelfSlidingWindow(ctx context.Context, apiKeyID int64, window time.Duration) (APIKeySelfUsageWindow, error) {
	out := APIKeySelfUsageWindow{WindowKind: usageWindowKindSliding}
	usage, err := db.GetAPIKeyWindowUsage(ctx, apiKeyID, window)
	if err != nil || usage == nil {
		return out, err
	}
	out.APIKeyWindowUsage = *usage
	if usage.OldestAt != nil {
		decay := usage.OldestAt.Add(window)
		out.DecayAt = &decay
	}
	return out, nil
}

func (db *DB) getAPIKeySelfDailyWindow(ctx context.Context, apiKeyID int64) (APIKeySelfUsageWindow, error) {
	dayStart := StartOfDay(time.Now())
	resetAt := dayStart.AddDate(0, 0, 1)
	out := APIKeySelfUsageWindow{WindowKind: usageWindowKindFixed, ResetAt: &resetAt}
	usage, err := db.GetAPIKeyUsageSince(ctx, apiKeyID, dayStart)
	if err != nil || usage == nil {
		return out, err
	}
	out.APIKeyWindowUsage = *usage
	return out, nil
}

func (db *DB) apiKeySelfUsageWhere(apiKeyID int64, rangeStart, rangeEnd time.Time) (string, []interface{}) {
	where := "api_key_id = $1 AND status_code <> 499"
	args := []interface{}{apiKeyID}
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

func (db *DB) getAPIKeySelfUsageSummary(ctx context.Context, apiKeyID int64, rangeStart, rangeEnd time.Time) (APIKeySelfUsageSummary, error) {
	where, args := db.apiKeySelfUsageWhere(apiKeyID, rangeStart, rangeEnd)
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

func (db *DB) listAPIKeySelfUsageBreakdown(ctx context.Context, apiKeyID int64, rangeStart, rangeEnd time.Time, kind string, limit int) ([]APIKeySelfUsageBreakdown, error) {
	if limit <= 0 {
		limit = 8
	}
	nameExpr := "COALESCE(NULLIF(effective_model, ''), NULLIF(model, ''), 'unknown')"
	if kind == "endpoint" {
		nameExpr = "COALESCE(NULLIF(inbound_endpoint, ''), NULLIF(endpoint, ''), 'unknown')"
	}
	where, args := db.apiKeySelfUsageWhere(apiKeyID, rangeStart, rangeEnd)
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

func (db *DB) listAPIKeySelfRecentLogs(ctx context.Context, apiKeyID int64, rangeStart, rangeEnd time.Time, page, pageSize int) ([]APIKeySelfUsageLog, int64, int, int, error) {
	page, pageSize = normalizeAPIKeySelfRecentLogPagination(page, pageSize)
	where, args := db.apiKeySelfUsageWhere(apiKeyID, rangeStart, rangeEnd)

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

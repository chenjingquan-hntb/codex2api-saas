package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// P7.3 端点授权：account_groups.endpoint_ids 声明"该分组允许被哪些端点使用"。
// 空数组/NULL = 全端点可见；非空 = 仅列出的端点可加载该分组下的账号。
// 数据面节点在加载账号池时按本节点 endpoint_id 过滤（见
// ListActiveByChannelForEndpoint），实现凭证/账号的按端点授权隔离。

// EndpointGroupBinding 是端点↔分组绑定视图（管理 API 展示用）。
type EndpointGroupBinding struct {
	EndpointID string   `json:"endpoint_id"`
	GroupID    int64    `json:"group_id"`
	GroupName  string   `json:"group_name"`
	AccountCnt int64    `json:"account_cnt"`
}

// SetGroupEndpointIDs 设置分组的允许端点列表（空 = 全端点可见）。
// endpointIDs 会规范化：去空白、去重、排序。
func (db *DB) SetGroupEndpointIDs(ctx context.Context, groupID int64, endpointIDs []string) error {
	normalized := normalizeEndpointIDs(endpointIDs)
	payload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("endpoint-groups: marshal: %w", err)
	}
	if db.isSQLite() {
		res, err := db.conn.ExecContext(ctx,
			`UPDATE account_groups SET endpoint_ids = ? WHERE id = ?`, string(payload), groupID)
		if err != nil {
			return fmt.Errorf("endpoint-groups: set (sqlite): %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrGroupNotFound
		}
		return nil
	}
	res, err := db.conn.ExecContext(ctx,
		`UPDATE account_groups SET endpoint_ids = $1::jsonb WHERE id = $2`, string(payload), groupID)
	if err != nil {
		return fmt.Errorf("endpoint-groups: set: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// GetGroupEndpointIDs 读取分组的允许端点列表。
func (db *DB) GetGroupEndpointIDs(ctx context.Context, groupID int64) ([]string, error) {
	var raw string
	err := db.conn.QueryRowContext(ctx,
		`SELECT COALESCE(endpoint_ids, '[]') FROM account_groups WHERE id = $1`, groupID).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("endpoint-groups: get: %w", err)
	}
	return parseEndpointIDs(raw)
}

// ListEndpointGroupBindings 返回全部端点↔分组绑定（按端点分组）。
func (db *DB) ListEndpointGroupBindings(ctx context.Context) ([]EndpointGroupBinding, error) {
	query := `
		SELECT ep.value AS endpoint_id, g.id, g.name,
		       (SELECT COUNT(*) FROM account_group_members m WHERE m.group_id = g.id) AS account_cnt
		FROM account_groups g, json_each(g.endpoint_ids) AS ep
		ORDER BY ep.value, g.id`
	if !db.isSQLite() {
		query = `
			SELECT ep.endpoint_id, g.id, g.name,
			       (SELECT COUNT(*) FROM account_group_members m WHERE m.group_id = g.id) AS account_cnt
			FROM account_groups g
			JOIN jsonb_array_elements_text(g.endpoint_ids) AS ep(endpoint_id)
			ORDER BY ep.endpoint_id, g.id`
	}
	rows, err := db.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("endpoint-groups: list: %w", err)
	}
	defer rows.Close()
	var out []EndpointGroupBinding
	for rows.Next() {
		var b EndpointGroupBinding
		if err := rows.Scan(&b.EndpointID, &b.GroupID, &b.GroupName, &b.AccountCnt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListGroupsForEndpoint 返回允许指定端点使用的分组列表。
func (db *DB) ListGroupsForEndpoint(ctx context.Context, endpointID string) ([]int64, error) {
	endpointID = strings.TrimSpace(endpointID)
	if endpointID == "" {
		return nil, nil
	}
	var query string
	var args []interface{}
	if db.isSQLite() {
		query = `
			SELECT id FROM account_groups
			WHERE COALESCE(endpoint_ids, '[]') = '[]'
			   OR EXISTS (SELECT 1 FROM json_each(COALESCE(endpoint_ids, '[]')) WHERE json_each.value = ?)
			ORDER BY id`
		args = append(args, endpointID)
	} else {
		query = `
			SELECT id FROM account_groups
			WHERE COALESCE(endpoint_ids, '[]'::jsonb) = '[]'::jsonb
			   OR endpoint_ids ? $1
			ORDER BY id`
		args = append(args, endpointID)
	}
	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("endpoint-groups: list groups: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// endpointFilterClauseForEndpoint 生成账号加载的端点过滤子句。
// 语义：账号所属任一分组对该端点可见（endpoint_ids 为空或包含该端点）即可加载。
// 无任何分组归属的账号视为全端点可见（历史数据兜底）。
func endpointFilterClauseForEndpoint(endpointID string, isSQLite bool) string {
	if strings.TrimSpace(endpointID) == "" {
		return ""
	}
	if isSQLite {
		return fmt.Sprintf(` AND (
		NOT EXISTS (
			SELECT 1 FROM account_group_members m
			JOIN account_groups g ON g.id = m.group_id
			WHERE m.account_id = accounts.id
			  AND COALESCE(g.endpoint_ids, '[]') <> '[]'
			  AND NOT EXISTS (
				SELECT 1 FROM json_each(g.endpoint_ids) WHERE json_each.value = '%s'
			  )
		)
	)`, endpointID)
	}
	return fmt.Sprintf(` AND (
		NOT EXISTS (
			SELECT 1 FROM account_group_members m
			JOIN account_groups g ON g.id = m.group_id
			WHERE m.account_id = accounts.id
			  AND COALESCE(g.endpoint_ids, '[]'::jsonb) <> '[]'::jsonb
			  AND NOT (g.endpoint_ids ? '%s')
		)
	)`, endpointID)
}

func normalizeEndpointIDs(ids []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func parseEndpointIDs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// 兼容旧格式（非 JSON 时按逗号拆分）。
		if !strings.HasPrefix(raw, "[") {
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
			return out, nil
		}
		return nil, fmt.Errorf("endpoint-groups: parse %q: %w", raw, err)
	}
	return normalizeEndpointIDs(out), nil
}

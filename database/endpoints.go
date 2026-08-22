package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// P7 多端点控制面：节点注册/心跳/Drain/offline 判定/单节点吊销。
//
// 状态模型（DB status 落库 + 展示时动态判定）：
//   - offline：初始/心跳超时（动态判定或 ExpireStaleEndpoints 落库）
//   - active：注册或心跳恢复
//   - draining：管理员手动置 drain（CDN/GSLB 摘除信号；心跳仍允许，保持 draining）
//   - revoked：管理员单节点吊销（心跳被拒，不可恢复，除非管理员重新 activate）
//
// 心跳超时判定：展示状态优先 revoked > draining >（last_seen_at 超时 → offline）> active，
// 列表接口动态计算，无需依赖落库频率；ExpireStaleEndpoints 仅作为后台清理落库。

// 端点状态常量。
const (
	EndpointStatusOffline  = "offline"
	EndpointStatusActive   = "active"
	EndpointStatusDraining = "draining"
	EndpointStatusRevoked  = "revoked"
)

// 端点错误。
var (
	ErrEndpointNotFound = errors.New("endpoints: not found")
	ErrEndpointRevoked  = errors.New("endpoints: revoked")
	ErrGroupNotFound    = errors.New("account groups: not found")
)

// ServiceEndpoint 是 P7 多端点控制面的节点记录。
type ServiceEndpoint struct {
	ID          int64      `json:"id"`
	EndpointID  string     `json:"endpoint_id"` // 节点唯一标识（env CODEX_ENDPOINT_ID）
	Name        string     `json:"name"`
	Region      string     `json:"region"`   // hk / sg / tokyo ...
	BaseURL     string     `json:"base_url"` // 对外公开地址
	Role        string     `json:"role"`     // control / data / mixed
	Status      string     `json:"status"`   // 展示状态（已含超时动态判定）
	DBStatus    string     `json:"db_status"` // 数据库落库状态（draining/revoked 为准）
	Version     string     `json:"version"`
	Capacity    int        `json:"capacity"`
	HeartbeatAt *time.Time `json:"heartbeat_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	DrainedAt   *time.Time `json:"drained_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	// P7.3/P7.5 管理视图：绑定分组（列表接口填充，不作为持久化字段）。
	BoundGroups     []EndpointGroupSummary `json:"bound_groups,omitempty"`
	BoundGroupCount int                    `json:"bound_group_count,omitempty"`
}

// heartbeatTimeout 心跳超时阈值：超过该时长未心跳视为 offline（展示判定）。
const heartbeatTimeout = 3 * time.Minute

// RegisterServiceEndpoint 注册或更新节点（按 endpoint_id 唯一 upsert）。
// 新节点初始 status=offline（首次心跳转 active）；显式传递的 status 仅接受
// offline/active/draining，revoked 必须经 RevokeServiceEndpoint。
func (db *DB) RegisterServiceEndpoint(ctx context.Context, ep ServiceEndpoint) (*ServiceEndpoint, error) {
	if ep.EndpointID == "" {
		return nil, fmt.Errorf("endpoints: endpoint_id is required")
	}
	if ep.Role == "" {
		ep.Role = "data"
	}
	if ep.Status == "" || ep.Status == EndpointStatusRevoked {
		ep.Status = EndpointStatusOffline
	}
	now := time.Now().UTC()
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO service_endpoints
			(endpoint_id, name, region, base_url, role, status, version, capacity,
			 started_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT (endpoint_id) DO UPDATE SET
			name = EXCLUDED.name,
			region = EXCLUDED.region,
			base_url = EXCLUDED.base_url,
			role = EXCLUDED.role,
			version = EXCLUDED.version,
			capacity = EXCLUDED.capacity,
			updated_at = EXCLUDED.updated_at`,
		ep.EndpointID, ep.Name, ep.Region, ep.BaseURL, ep.Role, ep.Status,
		ep.Version, ep.Capacity, db.timeArg(now), db.timeArg(now))
	if err != nil {
		return nil, fmt.Errorf("endpoints: register: %w", err)
	}
	return db.GetServiceEndpoint(ctx, ep.EndpointID)
}

// HeartbeatServiceEndpoint 节点心跳：更新 heartbeat_at/last_seen_at；
// offline 恢复为 active；revoked 拒绝（单节点吊销即时生效）；draining 保持。
// 返回 (当前落库状态, error)。
func (db *DB) HeartbeatServiceEndpoint(ctx context.Context, endpointID, version string, capacity int) (string, error) {
	if endpointID == "" {
		return "", fmt.Errorf("endpoints: endpoint_id is required")
	}
	now := time.Now().UTC()
	var status string
	err := db.conn.QueryRowContext(ctx, `
		UPDATE service_endpoints
		SET heartbeat_at = $1,
		    last_seen_at = $1,
		    version      = CASE WHEN $2 = '' THEN version ELSE $2 END,
		    capacity     = CASE WHEN $3 > 0 THEN $3 ELSE capacity END,
		    status       = CASE WHEN status = 'offline' THEN 'active' ELSE status END,
		    updated_at   = $1
		WHERE endpoint_id = $4
		RETURNING status`,
		db.timeArg(now), version, capacity, endpointID).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrEndpointNotFound
		}
		return "", fmt.Errorf("endpoints: heartbeat: %w", err)
	}
	if status == EndpointStatusRevoked {
		return status, ErrEndpointRevoked
	}
	return status, nil
}

// SetEndpointDraining 置 drain：CDN/GSLB 应摘除该节点；心跳保持 draining。
func (db *DB) SetEndpointDraining(ctx context.Context, endpointID string) error {
	return db.setEndpointStatus(ctx, endpointID, EndpointStatusDraining)
}

// SetEndpointActive 恢复 active（含 revoked → active 的重启用）。
func (db *DB) SetEndpointActive(ctx context.Context, endpointID string) error {
	return db.setEndpointStatus(ctx, endpointID, EndpointStatusActive)
}

// RevokeServiceEndpoint 单节点吊销：心跳被拒，不可自我恢复。
func (db *DB) RevokeServiceEndpoint(ctx context.Context, endpointID string) error {
	return db.setEndpointStatus(ctx, endpointID, EndpointStatusRevoked)
}

func (db *DB) setEndpointStatus(ctx context.Context, endpointID, status string) error {
	if endpointID == "" {
		return fmt.Errorf("endpoints: endpoint_id is required")
	}
	now := time.Now().UTC()
	var id int64
	err := db.conn.QueryRowContext(ctx, `
		UPDATE service_endpoints
		SET status = $1,
		    drained_at = CASE WHEN $1 = 'draining' THEN $2 ELSE drained_at END,
		    revoked_at = CASE WHEN $1 = 'revoked' THEN $2 ELSE revoked_at END,
		    updated_at = $2
		WHERE endpoint_id = $3
		RETURNING id`,
		status, db.timeArg(now), endpointID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEndpointNotFound
		}
		return fmt.Errorf("endpoints: set status: %w", err)
	}
	return nil
}

// GetServiceEndpoint 按 endpoint_id 查询，返回含动态离线判定的展示状态。
func (db *DB) GetServiceEndpoint(ctx context.Context, endpointID string) (*ServiceEndpoint, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, endpoint_id, name, region, base_url, role, status, version, capacity,
		       heartbeat_at, last_seen_at, started_at, drained_at, revoked_at, created_at, updated_at
		FROM service_endpoints
		WHERE endpoint_id = $1`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("endpoints: get: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrEndpointNotFound
	}
	ep, err := scanServiceEndpoint(rows, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return ep, nil
}

// ListServiceEndpoints 列出全部节点（含动态离线判定）。endpointID 非空时按 ID 过滤。
func (db *DB) ListServiceEndpoints(ctx context.Context, endpointID string) ([]ServiceEndpoint, error) {
	q := `
		SELECT id, endpoint_id, name, region, base_url, role, status, version, capacity,
		       heartbeat_at, last_seen_at, started_at, drained_at, revoked_at, created_at, updated_at
		FROM service_endpoints`
	args := []interface{}{}
	if endpointID != "" {
		q += ` WHERE endpoint_id = $1`
		args = append(args, endpointID)
	}
	q += ` ORDER BY id`
	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("endpoints: list: %w", err)
	}
	defer rows.Close()
	now := time.Now().UTC()
	var out []ServiceEndpoint
	for rows.Next() {
		ep, err := scanServiceEndpoint(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, *ep)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// EndpointGroupSummary 是端点绑定分组摘要（P7.3/P7.5 管理视图）。
type EndpointGroupSummary struct {
	GroupID    int64  `json:"group_id"`
	GroupName  string `json:"group_name"`
	AccountCnt int64  `json:"account_cnt"`
}

// ExpireStaleEndpoints 把心跳超时的 active 节点落库为 offline（后台清理，
// 展示判定不依赖它）。返回处理条数。
func (db *DB) ExpireStaleEndpoints(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if grace <= 0 {
		grace = heartbeatTimeout
	}
	if limit <= 0 {
		limit = 200
	}
	cutoff := time.Now().UTC().Add(-grace)
	res, err := db.conn.ExecContext(ctx, `
		UPDATE service_endpoints
		SET status = 'offline', updated_at = $1
		WHERE status = 'active'
		  AND (last_seen_at IS NULL OR last_seen_at < $2)
		  AND id IN (
			SELECT id FROM service_endpoints
			WHERE status = 'active'
			  AND (last_seen_at IS NULL OR last_seen_at < $2)
			LIMIT $3
		  )`,
		db.timeArg(time.Now().UTC()), db.timeArg(cutoff), limit)
	if err != nil {
		return 0, fmt.Errorf("endpoints: expire stale: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// scanServiceEndpoint 扫描一行并计算展示状态。
func scanServiceEndpoint(row interface{ Scan(...any) error }, now time.Time) (*ServiceEndpoint, error) {
	var ep ServiceEndpoint
	var heartbeatRaw, lastSeenRaw, startedRaw, drainedRaw, revokedRaw, createdRaw, updatedRaw interface{}
	if err := row.Scan(&ep.ID, &ep.EndpointID, &ep.Name, &ep.Region, &ep.BaseURL, &ep.Role,
		&ep.DBStatus, &ep.Version, &ep.Capacity,
		&heartbeatRaw, &lastSeenRaw, &startedRaw, &drainedRaw, &revokedRaw, &createdRaw, &updatedRaw); err != nil {
		return nil, err
	}
	if t, ok := optionalTimeValue(heartbeatRaw); ok {
		ep.HeartbeatAt = &t
	}
	if t, ok := optionalTimeValue(lastSeenRaw); ok {
		ep.LastSeenAt = &t
	}
	if t, ok := optionalTimeValue(startedRaw); ok {
		ep.StartedAt = &t
	}
	if t, ok := optionalTimeValue(drainedRaw); ok {
		ep.DrainedAt = &t
	}
	if t, ok := optionalTimeValue(revokedRaw); ok {
		ep.RevokedAt = &t
	}
	ep.CreatedAt = decodeTimeValue(createdRaw)
	ep.UpdatedAt = decodeTimeValue(updatedRaw)

	// 动态离线判定：revoked > draining > 超时 offline > active。
	ep.Status = ep.DBStatus
	if ep.Status == EndpointStatusActive && ep.LastSeenAt != nil &&
		now.Sub(*ep.LastSeenAt) > heartbeatTimeout {
		ep.Status = EndpointStatusOffline
	}
	return &ep, nil
}

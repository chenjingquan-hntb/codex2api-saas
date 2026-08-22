package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newEndpointsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "ep.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEndpointRegisterAndHeartbeat(t *testing.T) {
	db := newEndpointsTestDB(t)
	ctx := context.Background()

	// 注册 → offline。
	ep, err := db.RegisterServiceEndpoint(ctx, ServiceEndpoint{
		EndpointID: "hk-01", Name: "HK Primary", Region: "hk",
		BaseURL: "https://hk.codex2api.example", Role: "data", Version: "1.2.3", Capacity: 300,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if ep.Status != EndpointStatusOffline {
		t.Fatalf("initial status = %q, want offline", ep.Status)
	}

	// 首次心跳 → active。
	status, err := db.HeartbeatServiceEndpoint(ctx, "hk-01", "1.2.4", 400)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if status != EndpointStatusActive {
		t.Fatalf("after heartbeat status = %q, want active", status)
	}

	// 未注册节点心跳 → ErrEndpointNotFound。
	if _, err := db.HeartbeatServiceEndpoint(ctx, "nope", "", 0); !errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("heartbeat missing err = %v", err)
	}

	// 重复注册 upsert（改名字/容量）。
	ep, err = db.RegisterServiceEndpoint(ctx, ServiceEndpoint{
		EndpointID: "hk-01", Name: "HK Renamed", Region: "hk", BaseURL: "https://hk2.example",
		Role: "data", Version: "1.2.4", Capacity: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Name != "HK Renamed" || ep.Capacity != 500 {
		t.Fatalf("upsert = %+v", ep)
	}
}

func TestEndpointDynamicOffline(t *testing.T) {
	db := newEndpointsTestDB(t)
	ctx := context.Background()

	_, err := db.RegisterServiceEndpoint(ctx, ServiceEndpoint{EndpointID: "sg-01", Region: "sg"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.HeartbeatServiceEndpoint(ctx, "sg-01", "", 0); err != nil {
		t.Fatal(err)
	}

	// 最近心跳 → active。
	ep, _ := db.GetServiceEndpoint(ctx, "sg-01")
	if ep.Status != EndpointStatusActive {
		t.Fatalf("status = %q, want active", ep.Status)
	}

	// 伪造旧心跳（直接改库）→ 动态判定 offline。
	if _, err := db.conn.ExecContext(ctx,
		`UPDATE service_endpoints SET last_seen_at = $1 WHERE endpoint_id = $2`,
		db.timeArg(time.Now().UTC().Add(-10*time.Minute)), "sg-01"); err != nil {
		t.Fatal(err)
	}
	ep, _ = db.GetServiceEndpoint(ctx, "sg-01")
	if ep.Status != EndpointStatusOffline {
		t.Fatalf("stale status = %q, want offline", ep.Status)
	}

	// ExpireStaleEndpoints 落库。
	n, err := db.ExpireStaleEndpoints(ctx, 3*time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired = %d, want 1", n)
	}
	ep, _ = db.GetServiceEndpoint(ctx, "sg-01")
	if ep.DBStatus != EndpointStatusOffline {
		t.Fatalf("db status = %q, want offline", ep.DBStatus)
	}
}

func TestEndpointDrainActivateRevoke(t *testing.T) {
	db := newEndpointsTestDB(t)
	ctx := context.Background()

	if _, err := db.RegisterServiceEndpoint(ctx, ServiceEndpoint{EndpointID: "tk-01", Region: "tokyo"}); err != nil {
		t.Fatal(err)
	}

	// drain：状态 draining，心跳保持 draining。
	if err := db.SetEndpointDraining(ctx, "tk-01"); err != nil {
		t.Fatal(err)
	}
	ep, _ := db.GetServiceEndpoint(ctx, "tk-01")
	if ep.Status != EndpointStatusDraining {
		t.Fatalf("drain status = %q", ep.Status)
	}
	status, err := db.HeartbeatServiceEndpoint(ctx, "tk-01", "", 0)
	if err != nil {
		t.Fatalf("heartbeat while draining: %v", err)
	}
	if status != EndpointStatusDraining {
		t.Fatalf("heartbeat during drain = %q", status)
	}

	// revoke：心跳被拒。
	if err := db.RevokeServiceEndpoint(ctx, "tk-01"); err != nil {
		t.Fatal(err)
	}
	ep, _ = db.GetServiceEndpoint(ctx, "tk-01")
	if ep.Status != EndpointStatusRevoked {
		t.Fatalf("revoke status = %q", ep.Status)
	}
	if _, err := db.HeartbeatServiceEndpoint(ctx, "tk-01", "", 0); !errors.Is(err, ErrEndpointRevoked) {
		t.Fatalf("heartbeat revoked err = %v", err)
	}

	// activate：revoked → active 重启用。
	if err := db.SetEndpointActive(ctx, "tk-01"); err != nil {
		t.Fatal(err)
	}
	status, err = db.HeartbeatServiceEndpoint(ctx, "tk-01", "", 0)
	if err != nil || status != EndpointStatusActive {
		t.Fatalf("reactivate heartbeat = %q err=%v", status, err)
	}

	// 操作不存在的节点 → ErrEndpointNotFound。
	if err := db.SetEndpointDraining(ctx, "missing"); !errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("drain missing err = %v", err)
	}
	if err := db.RevokeServiceEndpoint(ctx, "missing"); !errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("revoke missing err = %v", err)
	}
}

func TestEndpointListFilter(t *testing.T) {
	db := newEndpointsTestDB(t)
	ctx := context.Background()

	for _, id := range []string{"a-01", "b-02", "c-03"} {
		if _, err := db.RegisterServiceEndpoint(ctx, ServiceEndpoint{EndpointID: id}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.ListServiceEndpoints(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("list = %d, want 3", len(all))
	}
	one, err := db.ListServiceEndpoints(ctx, "b-02")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].EndpointID != "b-02" {
		t.Fatalf("filter = %+v", one)
	}
}

package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func newEndpointGroupsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", filepath.Join(t.TempDir(), "epg.db"))
	if err != nil {
		t.Fatalf("New(sqlite): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustCreateGroup(t *testing.T, db *DB, name string) int64 {
	t.Helper()
	id, err := db.CreateAccountGroup(context.Background(), name, "", "", 0, 0, sql.NullInt64{})
	if err != nil {
		t.Fatalf("CreateAccountGroup(%s): %v", name, err)
	}
	return id
}

func mustCreateAccount(t *testing.T, db *DB, name string) int64 {
	t.Helper()
	id, err := db.InsertAccountWithCredentials(context.Background(), name, map[string]interface{}{
		"access_token": "sk-" + name,
		"upstream_type": "codex",
	}, "")
	if err != nil {
		t.Fatalf("InsertAccountWithCredentials(%s): %v", name, err)
	}
	return id
}

func TestEndpointGroupBindingRoundTrip(t *testing.T) {
	db := newEndpointGroupsTestDB(t)
	ctx := context.Background()
	gid := mustCreateGroup(t, db, "Bound")

	// 默认空 = 全端点。
	ids, err := db.GetGroupEndpointIDs(ctx, gid)
	if err != nil || len(ids) != 0 {
		t.Fatalf("initial ids = %v err=%v", ids, err)
	}

	// 设置两个端点（含重复/空白，应去重）。
	if err := db.SetGroupEndpointIDs(ctx, gid, []string{" hk-01 ", "sg-02", "hk-01", "", "sg-02"}); err != nil {
		t.Fatal(err)
	}
	ids, err = db.GetGroupEndpointIDs(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "hk-01" || ids[1] != "sg-02" {
		t.Fatalf("ids = %v", ids)
	}

	// 清空 = 全端点。
	if err := db.SetGroupEndpointIDs(ctx, gid, nil); err != nil {
		t.Fatal(err)
	}
	ids, _ = db.GetGroupEndpointIDs(ctx, gid)
	if len(ids) != 0 {
		t.Fatalf("cleared ids = %v", ids)
	}

	// 不存在的组 → ErrGroupNotFound。
	if err := db.SetGroupEndpointIDs(ctx, 99999, []string{"x"}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("missing group err = %v", err)
	}
}

func TestListGroupsForEndpoint(t *testing.T) {
	db := newEndpointGroupsTestDB(t)
	ctx := context.Background()

	open := mustCreateGroup(t, db, "Open")           // 全端点
	hkOnly := mustCreateGroup(t, db, "HK Only")      // 仅 hk-01
	sgOnly := mustCreateGroup(t, db, "SG Only")      // 仅 sg-02
	multi := mustCreateGroup(t, db, "HK+SG")         // hk-01 + sg-02

	if err := db.SetGroupEndpointIDs(ctx, hkOnly, []string{"hk-01"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupEndpointIDs(ctx, sgOnly, []string{"sg-02"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupEndpointIDs(ctx, multi, []string{"hk-01", "sg-02"}); err != nil {
		t.Fatal(err)
	}

	hk, err := db.ListGroupsForEndpoint(ctx, "hk-01")
	if err != nil {
		t.Fatal(err)
	}
	contains := func(list []int64, id int64) bool {
		for _, v := range list {
			if v == id {
				return true
			}
		}
		return false
	}
	if !contains(hk, open) || !contains(hk, hkOnly) || !contains(hk, multi) {
		t.Fatalf("hk groups = %v (want %d,%d,%d)", hk, open, hkOnly, multi)
	}
	if contains(hk, sgOnly) {
		t.Fatalf("hk groups must not contain sgOnly: %v", hk)
	}
}

func TestListActiveByChannelForEndpoint(t *testing.T) {
	db := newEndpointGroupsTestDB(t)
	ctx := context.Background()

	accA := mustCreateAccount(t, db, "acc-a") // 组 HK
	accB := mustCreateAccount(t, db, "acc-b") // 组 SG
	accC := mustCreateAccount(t, db, "acc-c") // 无组（全端点兜底）

	hkGroup := mustCreateGroup(t, db, "HK")
	sgGroup := mustCreateGroup(t, db, "SG")
	if err := db.SetGroupEndpointIDs(ctx, hkGroup, []string{"hk-01"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupEndpointIDs(ctx, sgGroup, []string{"sg-02"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountGroups(ctx, accA, []int64{hkGroup}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountGroups(ctx, accB, []int64{sgGroup}); err != nil {
		t.Fatal(err)
	}

	// 空 endpointID = 全量。
	all, err := db.ListActiveByChannelForEndpoint(ctx, "", "")
	if err != nil || len(all) != 3 {
		t.Fatalf("no-filter = %d err=%v", len(all), err)
	}

	// hk-01 只见 acc-a + 无组 acc-c。
	hk, err := db.ListActiveByChannelForEndpoint(ctx, "", "hk-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(hk) != 2 {
		t.Fatalf("hk-01 accounts = %d, want 2 (a + c)", len(hk))
	}
	ids := map[int64]bool{}
	for _, a := range hk {
		ids[a.ID] = true
	}
	if !ids[accA] || !ids[accC] || ids[accB] {
		t.Fatalf("hk-01 ids = %v (accA=%d accB=%d accC=%d)", ids, accA, accB, accC)
	}

	// sg-02 只见 acc-b + acc-c。
	sg, err := db.ListActiveByChannelForEndpoint(ctx, "", "sg-02")
	if err != nil {
		t.Fatal(err)
	}
	if len(sg) != 2 {
		t.Fatalf("sg-02 accounts = %d, want 2", len(sg))
	}
}

func TestListEndpointGroupBindings(t *testing.T) {
	db := newEndpointGroupsTestDB(t)
	ctx := context.Background()
	gid := mustCreateGroup(t, db, "Bound")
	acc := mustCreateAccount(t, db, "acc")
	if err := db.SetAccountGroups(ctx, acc, []int64{gid}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupEndpointIDs(ctx, gid, []string{"hk-01", "sg-02"}); err != nil {
		t.Fatal(err)
	}
	bindings, err := db.ListEndpointGroupBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("bindings = %d, want 2", len(bindings))
	}
	if bindings[0].GroupID != gid || bindings[0].AccountCnt != 1 {
		t.Fatalf("binding[0] = %+v", bindings[0])
	}
}

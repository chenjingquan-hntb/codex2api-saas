package version

import "testing"

func TestRuntimeDefaults(t *testing.T) {
	info := Runtime()

	if info.Version == "" {
		t.Fatal("Runtime().Version 不应为空")
	}
	if info.Commit == "" {
		t.Fatal("Runtime().Commit 不应为空（至少为 \"unknown\"）")
	}
	if info.GoVersion == "" {
		t.Fatal("Runtime().GoVersion 不应为空")
	}
	// 默认构建不应携带意外内容。
	if info.Version != "dev" && info.Version != Version {
		t.Fatalf("Runtime().Version = %q 与 Current() = %q 不一致", info.Version, Version)
	}
	if Current() != Version {
		t.Fatalf("Current() = %q, want %q", Current(), Version)
	}
}

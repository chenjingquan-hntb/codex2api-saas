package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeReflectsBuildVariables(t *testing.T) {
	info := Runtime()

	if info.Version != Version {
		t.Fatalf("Runtime().Version = %q, want %q", info.Version, Version)
	}
	if info.Commit != Commit {
		t.Fatalf("Runtime().Commit = %q, want %q", info.Commit, Commit)
	}
	if info.BuildTime != BuildTime {
		t.Fatalf("Runtime().BuildTime = %q, want %q", info.BuildTime, BuildTime)
	}
	if info.GoVersion == "" {
		t.Fatal("Runtime().GoVersion 不应为空")
	}
	if Current() != Version {
		t.Fatalf("Current() = %q, want %q", Current(), Version)
	}
}

func TestRuntimeDefaultsAreSafe(t *testing.T) {
	// 开发构建至少要有非空占位，避免下游把空值当错误。
	if Version == "" {
		t.Fatal("Version 不应为空（开发构建应为 \"dev\"）")
	}
	if Commit == "" {
		t.Fatal("Commit 不应为空（开发构建应为 \"unknown\"）")
	}
}

func TestInfoJSONOmitsEmptyBuildTime(t *testing.T) {
	// BuildTime 为空时应省略 build_time 键（omitempty 语义）。
	empty, err := json.Marshal(Info{Version: "dev", Commit: "unknown", GoVersion: "go1.27"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(empty), "build_time") {
		t.Fatalf("空 BuildTime 仍被序列化: %s", empty)
	}

	// BuildTime 非空时应出现在输出中。
	withTime, err := json.Marshal(Info{Version: "v1", Commit: "abc", BuildTime: "2026-08-22T00:00:00Z", GoVersion: "go1.27"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(withTime), `"build_time":"2026-08-22T00:00:00Z"`) {
		t.Fatalf("BuildTime 未被正确序列化: %s", withTime)
	}
}

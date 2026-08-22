// Package version 汇总构建期与运行期的版本信息，供启动日志、更新检查和
// /version 状态接口使用。构建期变量由 release/Docker 构建通过 ldflags 注入，
// 开发构建保持默认值。
package version

import "runtime"

// Version 是发布构建注入的语义化版本号；开发构建保持 "dev"。
var Version = "dev"

// Commit 是发布构建注入的 Git commit（短哈希或完整哈希均可）；开发构建为
// "unknown"。仅用于运维定位与回滚追踪，不参与任何业务鉴权。
var Commit = "unknown"

// BuildTime 是发布构建注入的 RFC3339 时间戳；开发构建为空字符串。
var BuildTime = ""

// Current 返回当前版本号。
func Current() string {
	return Version
}

// Info 是 /version 接口返回的运行期版本摘要。字段刻意只含非敏感信息：
// 不含数据库/Redis 凭据、上游账号、密钥或任何内部拓扑。
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version"`
}

// Runtime 返回运行期版本摘要。
func Runtime() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}
}

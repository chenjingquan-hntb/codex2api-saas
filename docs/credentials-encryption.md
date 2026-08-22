# 账号凭证加密（B0 整改）

> 状态：已实现并通过全量测试（2026-08-22）。本文件是运维/安全操作手册。
>
> 目标：`accounts.credentials` 中的 refresh/access/session token、上游 API Key、
> 私钥等高敏感凭证不再以明文 JSON 落库；展示/索引所需的非敏感属性拆为投影列，
> SQL 不再对密文做 JSON 表达式查询。

## 1. 原理

- **算法**：AES-256-GCM（带随机 nonce 与认证标签，篡改即解密失败）。
- **存储格式**：单条自描述密文 `enc:v1:<key_version>:<base64(nonce||ciphertext)>`。
  - 密钥版本内嵌于密文，恢复备份、跨节点滚动升级都不需要额外元数据。
  - 密文写入新增列 `accounts.credentials_enc`；原 `credentials` 列在加密模式下
    恒为 `{}`（明文不再留存）。未配置密钥时保持明文模式并输出启动警告。
- **投影列**：`upstream_type / email / base_url / plan_type / cred_models /
  has_api_key / has_refresh_token / scheduler_priority` 由每次凭证写入与启动回填
  维护；渠道过滤、账号列表、邮箱查重等 SQL 全部改用投影列，不解析密文。
- **密钥管理**：密钥来自进程环境，**严禁**写入数据库、源码、日志或备份。
  - `CREDENTIALS_ENCRYPTION_KEY`：当前写入密钥（64 位十六进制 = 32 字节）。
  - `CREDENTIALS_ENCRYPTION_PREVIOUS_KEY`：上一代密钥（仅解密，轮换双读）。

## 2. 启用步骤（首次部署 / 存量数据迁移）

```bash
# 1) 生成密钥（切勿提交到 Git / 写入 .env 仓库副本之外的任何明文载体）
openssl rand -hex 32
#   例如: 1a2b...（64 个十六进制字符）

# 2) 写入 .env
CREDENTIALS_ENCRYPTION_KEY=<上面生成的 64 位十六进制>
```

启动时（`database.New` → `migrate` → `ensureCredentialsEncryption`）自动完成：

1. `ALTER TABLE accounts ADD COLUMN ...`（PostgreSQL / SQLite 双驱动，幂等）。
2. **投影列回填**：旧二进制写入的行补齐投影列（`credentials_projection_version`）。
3. **存量加密**：已配置密钥时，把 `credentials_enc='' 且 credentials<>'{}'` 的
   明文行加密迁移到 `credentials_enc` 并清空明文列；分批（每批 500）执行，
   中途失败会在下次启动继续。

迁移完成后可用 SQL 自检（应返回 0 行明文）：

```sql
-- PostgreSQL
SELECT count(*) FROM accounts WHERE credentials_enc = '' AND credentials <> '{}';
-- SQLite
SELECT count(*) FROM accounts WHERE credentials_enc = '' AND credentials <> '{}';
```

> **回滚预案**：加密迁移只改写 `accounts` 两列，业务表不受影响。如需回滚，
> 从迁移前的备份恢复 accounts 表即可（明文仍可被新代码读取——`decodeStoredCredentials`
> 对无 `enc:` 前缀的值按明文 JSON 兼容解析）。

## 3. 密钥轮换

轮换只支持保留上一代密钥（环境变量只能携带两代）。流程：

1. 生成新密钥 `openssl rand -hex 32`。
2. 把旧密钥写入 `CREDENTIALS_ENCRYPTION_PREVIOUS_KEY`，新密钥写入
   `CREDENTIALS_ENCRYPTION_KEY`，滚动发布。
3. 新版本启动时：
   - 旧密文（版本 1）通过 PREVIOUS_KEY 双读可解密；
   - 所有新写入使用新密钥（版本 2）；
   - `encryptCredentialsAtRest` 会把存量明文行直接以新密钥加密（版本 2）。
4. 若轮换跨度超过一代（旧密文同时存在版本 1、2），需要先以中间版本逐个滚动，
   或一次性重写所有行到当前版本（分批执行 `ensureCredentialsEncryption` 的
   加密例程；后续版本会提供运维命令入口）。

> 注意：错误地把 PREVIOUS_KEY 配成与 CURRENT 无关的值，会导致旧密文解密失败。
> 读取失败不会崩溃——`decodeStoredCredentials` 返回空凭证并记录日志；但上游调用
> 会因缺少 token 而失败，等价于该账号不可用。部署后应立即抽查 `/api/admin/accounts`
> 列表与一次真实上游调用。

## 4. 丢失密钥的后果

密钥丢失 = 已有密文永久不可解。届时只能：
- 让用户重新授权 / 重新导入全部账号（token 会刷新覆盖）；
- 或从加密前的备份恢复（明文行仍兼容读取），并立即重新执行加密迁移。

因此密钥备份应纳入组织的密钥管理体系（KMS / 保险库），而不是仅存在服务器磁盘。

## 5. 常见问题

| 现象 | 原因与处理 |
|---|---|
| 启动日志出现“警告: 未配置 CREDENTIALS_ENCRYPTION_KEY，账号凭证将以明文存储” | 明文模式。本地开发可接受；生产必须配置密钥，否则审计不通过。 |
| 日志出现“凭证解密失败: ... unknown key version” | 密文由更早版本的密钥写入且未带 PREVIOUS_KEY。按第 3 节补配上一代密钥并重发。 |
| 日志出现“凭证解密失败: cipher: message authentication failed” | 密文被篡改或密钥不匹配。检查备份/恢复来源与密钥配置；按事件流程人工介入。 |
| 后台账号列表邮箱/渠道显示为空 | 投影列缺失（旧数据未回填）。重启一次触发启动回填；或检查迁移日志。 |

## 6. 性能影响评估（2026-08-22 实测）

基准：`database/credentials_benchmark_test.go`（`go test ./database -bench BenchmarkCredentials`），
AMD Ryzen 9 7940H（带 AES-NI），2KB / 8KB 凭证文档。

| 操作 | 实测耗时 | 说明 |
|---|---|---|
| 加密 2KB 文档 | ~6 µs | AES-256-GCM + base64 |
| 解密 2KB 文档 | ~4.6 µs | |
| 加密 8KB 文档（Grok 完整凭证） | ~44 µs | |
| 解密 8KB 文档 | ~34 µs | |
| 单账号完整写入（SQL+加密+投影） | ~179 µs | 其中加密仅占 ~6 µs，大头是 SQLite UPDATE |
| 单账号完整读取（SQL+解密+解析） | ~45 µs | 明文对照 ~39 µs，加密增量 <7 µs |
| 账号池全量加载 500 个 | ~10 ms | 每 2 分钟后台刷新一次 |

**运行负载结论：**

- **请求热路径增量 ≈ 0**：数据面在启动与每 2 分钟后台刷新时一次性加载全部账号并解密，
  解密后的凭证常驻内存；单次上游请求不执行加解密。
- **VPS CPU 影响 < 0.1%**：典型部署（数百账号、每 2 分钟全量加载 + 每分钟几十次 token
  刷新）累计加解密耗时约每秒 <1 ms；即使把加解密放大 10 倍也远低于一次上游 HTTP 调用
  （100–500 ms）。
- **数据库负载下降**：渠道过滤/邮箱查重从 JSON 表达式（`json_extract` / `->>`）改为
  投影列 + 普通 B-tree 索引，查询更快；写入从 1 列变为 12 列（多几个小文本列，可忽略）。
- **内存**：常驻内存不变（解密后凭证本就驻留）；加载期瞬时分配每账号约 8–15 KB，随即释放。
- 无 AES-NI 的旧 CPU 加解密慢 10–30 倍（单次 ≤ 500 µs），仍远低于网络与数据库开销，
  不影响结论；如遇极端场景可用 `BenchmarkCredentials` 在目标机上复测。

## 7. 安全审计复核点

- [ ] 数据库备份/导出中不包含 token 明文（`credentials` 列全为 `{}`，`credentials_enc` 为密文）。
- [ ] 应用日志、错误返回、管理 API 不回显 token 原文。
- [ ] 密钥未出现在源码、Git 历史、.env 仓库副本、日志或监控快照。
- [ ] 轮换演练通过：旧密文可读 → 新写入用新版本 → 存量重写完成。
- [ ] `go test ./... -count=1`、`go vet ./...`、`go build ./...` 在发布前通过。

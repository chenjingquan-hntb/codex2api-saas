package database

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
)

// 账号凭证加密（B0 上线阻断项整改）。
//
// 设计约束：
//   - 敏感凭证（refresh_token / access_token / session_token / api_key / 私钥等）
//     只允许以 AES-256-GCM 密文落库，密钥来自进程环境
//     CREDENTIALS_ENCRYPTION_KEY（轮换时配合 CREDENTIALS_ENCRYPTION_PREVIOUS_KEY
//     双读），严禁写入数据库、源码、日志或备份。
//   - 单条密文自描述（enc:v1:<key_version>:<base64(nonce||ciphertext)>），因此
//     恢复备份、跨节点滚动升级时不需要额外元数据即可解密。
//   - 展示/索引所需的非敏感属性（upstream_type / email / base_url / plan_type /
//     models / scheduler_priority / 是否配置了 api_key / refresh_token）拆为
//     accounts 上的受控投影列，SQL 不再对密文做 JSON 表达式查询。
//   - 未配置密钥时保持明文模式并输出启动告警：仅用于本地开发与存量数据迁移前
//     的兼容读取；生产环境必须配置密钥（见 docs/credentials-encryption.md）。

const (
	// credentialsEncryptionMagicPrefix 标记 AES-GCM 加密的凭证密文。
	credentialsEncryptionMagicPrefix = "enc:v1:"

	// credentialsPlainKeyVersion 明文模式的密钥版本哨兵值。
	credentialsPlainKeyVersion = 0

	// credentialsProjectionVersion 投影列由新写入路径维护的版本哨兵值；
	// 旧二进制写入的行该值为 0，启动回填会补齐。
	credentialsProjectionVersion = 1

	// credentialsEncryptionEnv 当前加密密钥（64 位十六进制 = 32 字节 AES-256）。
	credentialsEncryptionEnv = "CREDENTIALS_ENCRYPTION_KEY"
	// credentialsEncryptionPreviousEnv 上一代密钥（仅解密，用于轮换双读）。
	credentialsEncryptionPreviousEnv = "CREDENTIALS_ENCRYPTION_PREVIOUS_KEY"
	// credentialsEncryptionRequiredEnv 置 1 时强制启用加密，未配置密钥则拒绝启动（fail-closed）。
	credentialsEncryptionRequiredEnv = "CREDENTIALS_ENCRYPTION_REQUIRED"

	// credentialsBackfillBatchSize 凭证加密/投影回填的批大小。
	credentialsBackfillBatchSize = 500
)

var (
	ErrCredentialsKeyInvalid    = errors.New("CREDENTIALS_ENCRYPTION_KEY 必须是 64 位十六进制字符串（32 字节 AES-256 密钥）")
	ErrCredentialsEncryptFailed = errors.New("credentials 加密失败")
	ErrCredentialsDecryptFailed = errors.New("credentials 解密失败")
	ErrCredentialsKeyUnknown    = errors.New("credentials 密文引用了未知密钥版本")
	ErrCredentialsKeyCollision  = errors.New("credentials 密钥版本指纹冲突")
)

// credentialsKey 单个 AES-256 密钥及版本。
type credentialsKey struct {
	version int
	key     []byte
}

// credentialsCipher 持有当前写入密钥与上一代解密密钥，支持轮换双读。
type credentialsCipher struct {
	mu      sync.RWMutex
	current int
	keys    map[int]credentialsKey
}

func parseCredentialsKeyHex(keyHex string) ([]byte, error) {
	keyHex = strings.TrimSpace(keyHex)
	if keyHex == "" {
		return nil, ErrCredentialsKeyInvalid
	}
	decoded, err := hex.DecodeString(keyHex)
	if err != nil || len(decoded) != 32 {
		return nil, ErrCredentialsKeyInvalid
	}
	return decoded, nil
}

// credentialsKeyVersion derives a stable, non-secret 31-bit identifier from the
// key. Unlike process-local ordinal versions, the identifier survives restarts
// and supports repeated rotations without extra version environment variables.
func credentialsKeyVersion(key []byte) int {
	sum := sha256.Sum256(append([]byte("codex2api:credentials-key-version:v1:"), key...))
	version := int(binary.BigEndian.Uint32(sum[:4]) & math.MaxInt32)
	if version == 0 {
		return 1
	}
	return version
}

// NewCredentialsCipher 从十六进制密钥构造加密器。keyHex 为空返回 nil（明文模式）。
// 密钥版本由密钥指纹稳定派生；轮换场景请使用 setCredentialsEncryptionKeys
// 显式传入上一代密钥以保持旧密文可读。
func NewCredentialsCipher(keyHex string) (*credentialsCipher, error) {
	key, err := parseCredentialsKeyHex(keyHex)
	if err != nil {
		return nil, err
	}
	version := credentialsKeyVersion(key)
	return &credentialsCipher{
		current: version,
		keys:    map[int]credentialsKey{version: {version: version, key: key}},
	}, nil
}

// AddCurrentKey switches the write key while retaining already registered keys
// for decryption. The stable key identifier makes repeated rotations safe.
func (c *credentialsCipher) AddCurrentKey(keyHex string) error {
	key, err := parseCredentialsKeyHex(keyHex)
	if err != nil {
		return err
	}
	version := credentialsKeyVersion(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.keys[version]; ok && !bytes.Equal(existing.key, key) {
		return fmt.Errorf("%w: %d", ErrCredentialsKeyCollision, version)
	}
	c.keys[version] = credentialsKey{version: version, key: key}
	c.current = version
	return nil
}

// AddPreviousKey registers a read-only historical key. Its stable identifier is
// derived from the key itself, so ciphertext remains readable after restarts.
func (c *credentialsCipher) AddPreviousKey(keyHex string) error {
	keyHex = strings.TrimSpace(keyHex)
	if keyHex == "" {
		return nil
	}
	key, err := parseCredentialsKeyHex(keyHex)
	if err != nil {
		return err
	}
	version := credentialsKeyVersion(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.keys[version]; ok && !bytes.Equal(existing.key, key) {
		return fmt.Errorf("%w: %d", ErrCredentialsKeyCollision, version)
	}
	c.keys[version] = credentialsKey{version: version, key: key}
	return nil
}

// Enabled 是否启用了加密。
func (c *credentialsCipher) Enabled() bool {
	return c != nil && c.current > 0
}

// CurrentVersion 当前写入密钥版本。
func (c *credentialsCipher) CurrentVersion() int {
	if c == nil {
		return credentialsPlainKeyVersion
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Encrypt 用当前密钥加密明文，返回 enc:v1:<version>:<base64(nonce||ct)>。
func (c *credentialsCipher) Encrypt(plaintext []byte) (string, error) {
	if c == nil {
		return "", ErrCredentialsEncryptFailed
	}
	c.mu.RLock()
	key, ok := c.keys[c.current]
	version := c.current
	c.mu.RUnlock()
	if !ok {
		return "", ErrCredentialsKeyUnknown
	}
	block, err := aes.NewCipher(key.key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialsEncryptFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialsEncryptFailed, err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialsEncryptFailed, err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	payload := append(nonce, sealed...)
	return credentialsEncryptionMagicPrefix + fmt.Sprintf("%d:", version) + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt 解密 enc:v1:<version>:<b64> 格式的密文。版本未知时返回
// ErrCredentialsKeyUnknown（轮换窗口内旧密文需要 PREVIOUS_KEY 才能读取）。
func (c *credentialsCipher) Decrypt(blob string) ([]byte, error) {
	if c == nil {
		return nil, ErrCredentialsDecryptFailed
	}
	rest, ok := strings.CutPrefix(blob, credentialsEncryptionMagicPrefix)
	if !ok {
		return nil, ErrCredentialsDecryptFailed
	}
	versionText, encoded, ok := strings.Cut(rest, ":")
	if !ok {
		return nil, ErrCredentialsDecryptFailed
	}
	var version int
	if _, err := fmt.Sscanf(versionText, "%d", &version); err != nil || version <= 0 {
		return nil, ErrCredentialsDecryptFailed
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialsDecryptFailed, err)
	}

	c.mu.RLock()
	key, exists := c.keys[version]
	c.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("%w: %d", ErrCredentialsKeyUnknown, version)
	}
	block, err := aes.NewCipher(key.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialsDecryptFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialsDecryptFailed, err)
	}
	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return nil, ErrCredentialsDecryptFailed
	}
	plaintext, err := gcm.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialsDecryptFailed, err)
	}
	return plaintext, nil
}

// credentialsEncryptionEnvKeys 返回 (current, previous) 环境变量密钥。
func credentialsEncryptionEnvKeys() (string, string) {
	return strings.TrimSpace(os.Getenv(credentialsEncryptionEnv)),
		strings.TrimSpace(os.Getenv(credentialsEncryptionPreviousEnv))
}

// credentialsEncryptionRequired 是否强制要求启用凭证加密（fail-closed）。
func credentialsEncryptionRequired() bool {
	v := strings.TrimSpace(os.Getenv(credentialsEncryptionRequiredEnv))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// ==================== DB 集成 ====================

// credentialsCipherEnabled 是否启用了凭证加密。
func (db *DB) credentialsCipherEnabled() bool {
	return db != nil && db.credentialsCipher != nil && db.credentialsCipher.Enabled()
}

// credentialsEncryptionVersion 当前凭证加密密钥版本（明文模式为 0）。
func (db *DB) credentialsEncryptionVersion() int {
	if db == nil || db.credentialsCipher == nil {
		return credentialsPlainKeyVersion
	}
	return db.credentialsCipher.CurrentVersion()
}

// setCredentialsEncryptionKeys injects the current write key and one historical
// read key. Key versions are deterministic fingerprints, not restart-local
// ordinals, so repeated rotations remain readable.
func (db *DB) setCredentialsEncryptionKeys(currentHex, previousHex string) error {
	currentHex = strings.TrimSpace(currentHex)
	previousHex = strings.TrimSpace(previousHex)
	if currentHex == "" {
		db.credentialsCipher = nil
		return nil
	}
	c, err := NewCredentialsCipher(currentHex)
	if err != nil {
		return err
	}
	if err := c.AddPreviousKey(previousHex); err != nil {
		return err
	}
	db.credentialsCipher = c
	return nil
}

// SetCredentialsEncryptionKey 运行时注入/轮换凭证加密密钥。已在数据库中的旧密文
// 仍可通过上一代密钥读取；调用方负责在轮换后尽快将存量行重写为新密钥
// （重启时会由启动回填自动完成）。
func (db *DB) SetCredentialsEncryptionKey(keyHex string) error {
	if db == nil {
		return errors.New("database is not initialized")
	}
	return db.setCredentialsEncryptionKeys(keyHex, "")
}

// CredentialsEncryptionEnabled 凭证加密是否已启用（供 /healthz 与运维观测）。
func (db *DB) CredentialsEncryptionEnabled() bool {
	return db != nil && db.credentialsCipherEnabled()
}

// CredentialsEncryptionVersion 当前密钥版本（未启用返回 0）。
func (db *DB) CredentialsEncryptionVersion() int {
	return db.credentialsEncryptionVersion()
}

// credentialsProjection 非敏感展示/索引投影列。
type credentialsProjection struct {
	UpstreamType      string
	Email             string
	BaseURL           string
	PlanType          string
	ModelsJSON        string
	HasAPIKey         bool
	HasRefreshToken   bool
	SchedulerPriority string
}

// deriveCredentialsProjection 从明文凭证推导投影列。永不读取敏感 token 原文。
func deriveCredentialsProjection(creds map[string]any) credentialsProjection {
	upstreamType := strings.ToLower(strings.TrimSpace(credentialStringFromMap(creds, "upstream_type")))
	email := strings.TrimSpace(credentialStringFromMap(creds, "email"))
	baseURL := strings.TrimSpace(credentialStringFromMap(creds, "base_url"))
	planType := strings.TrimSpace(credentialStringFromMap(creds, "plan_type"))
	// scheduler_priority 历史上以整数（int64/float64/json.Number）写入，投影列需
	// 归一化为文本以便 GetCredentialInt64 解析。
	schedulerPriority := credentialNumericString(creds, "scheduler_priority")

	var models []string
	if raw, ok := creds["models"]; ok && raw != nil {
		models = stringSliceFromValue(raw)
	}
	modelsJSON := encodeTagsJSON(models) // []string -> JSON 数组文本

	hasAPIKey := strings.TrimSpace(credentialStringFromMap(creds, "api_key")) != ""
	hasRefreshToken := strings.TrimSpace(credentialStringFromMap(creds, "refresh_token")) != ""

	return credentialsProjection{
		UpstreamType:      upstreamType,
		Email:             email,
		BaseURL:           baseURL,
		PlanType:          planType,
		ModelsJSON:        modelsJSON,
		HasAPIKey:         hasAPIKey,
		HasRefreshToken:   hasRefreshToken,
		SchedulerPriority: schedulerPriority,
	}
}

// credentialNumericString 返回凭证中可表示为整数的字段的文本形式：
// 字符串原样、整型/浮点（整数）转十进制、json.Number 原样。
func credentialNumericString(creds map[string]any, key string) string {
	if creds == nil {
		return ""
	}
	value, ok := creds[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.FormatInt(int64(typed), 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		if math.Trunc(typed) != typed {
			return ""
		}
		return strconv.FormatInt(int64(typed), 10)
	case float32:
		if math.Trunc(float64(typed)) != float64(typed) {
			return ""
		}
		return strconv.FormatInt(int64(typed), 10)
	case json.Number:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}

// credentialsWriteFields 一次凭证写入的全部持久化值（密文/明文 + 投影列）。
type credentialsWriteFields struct {
	Ciphertext string // credentials_enc 值（加密模式）；明文模式为 ""
	PlainJSON  string // credentials 值（明文模式为 JSON；加密模式为 "{}"）
	KeyVersion int
	Projection credentialsProjection
}

// buildCredentialsWriteFields 编码一次凭证写入并推导投影列。
func (db *DB) buildCredentialsWriteFields(creds map[string]any) (credentialsWriteFields, error) {
	plainJSON, err := json.Marshal(creds)
	if err != nil {
		return credentialsWriteFields{}, fmt.Errorf("序列化 credentials 失败: %w", err)
	}
	fields := credentialsWriteFields{
		PlainJSON:  string(plainJSON),
		KeyVersion: credentialsPlainKeyVersion,
		Projection: deriveCredentialsProjection(creds),
	}
	if db.credentialsCipherEnabled() {
		ciphertext, encryptErr := db.credentialsCipher.Encrypt(plainJSON)
		if encryptErr != nil {
			return credentialsWriteFields{}, encryptErr
		}
		fields.Ciphertext = ciphertext
		fields.PlainJSON = "{}"
		fields.KeyVersion = db.credentialsEncryptionVersion()
	}
	return fields, nil
}

// credentialsProjectionColumns 投影列名（不含凭证明文/密文两列）。
var credentialsProjectionColumns = []string{
	"upstream_type", "email", "base_url", "plan_type", "cred_models",
	"has_api_key", "has_refresh_token", "scheduler_priority",
}

// dbBool 返回 SQLite 可用的布尔表示（SQLite 无原生 BOOLEAN，用 0/1）。
func (db *DB) dbBool(value bool) any {
	if db.isSQLite() {
		if value {
			return int64(1)
		}
		return int64(0)
	}
	return value
}

// credentialsStoreSet 生成 UPDATE 的 SET 片段与参数（不含调用方自增/WHERE）。
// PostgreSQL 使用 $N 编号；SQLite 使用 ?。返回的 args 与片段按列序一一对应。
func (db *DB) credentialsStoreSet(fields credentialsWriteFields) (string, []any) {
	columns := []struct {
		name      string
		value     any
		castJSONB bool
	}{
		{"credentials_enc", fields.Ciphertext, false},
		{"credentials", fields.PlainJSON, true},
		{"cred_key_version", fields.KeyVersion, false},
		{"upstream_type", fields.Projection.UpstreamType, false},
		{"email", fields.Projection.Email, false},
		{"base_url", fields.Projection.BaseURL, false},
		{"plan_type", fields.Projection.PlanType, false},
		{"cred_models", fields.Projection.ModelsJSON, false},
		{"has_api_key", db.dbBool(fields.Projection.HasAPIKey), false},
		{"has_refresh_token", db.dbBool(fields.Projection.HasRefreshToken), false},
		{"scheduler_priority", fields.Projection.SchedulerPriority, false},
	}
	sets := make([]string, 0, len(columns))
	args := make([]any, 0, len(columns))
	for _, col := range columns {
		if db.isSQLite() {
			sets = append(sets, col.name+" = ?")
		} else {
			ph := fmt.Sprintf("$%d", len(args)+1)
			if col.castJSONB {
				ph += "::jsonb"
			}
			sets = append(sets, col.name+" = "+ph)
		}
		args = append(args, col.value)
	}
	return strings.Join(sets, ", "), args
}

// credentialsInsertFragment 生成 INSERT 的列清单、占位符与参数。
// start 是 PostgreSQL 编号的起始参数（前面已有 name=$1 时传 2）。
func (db *DB) credentialsInsertFragment(start int, fields credentialsWriteFields) (columns string, placeholders string, args []any) {
	allColumns := []string{"credentials_enc", "credentials", "cred_key_version"}
	allColumns = append(allColumns, credentialsProjectionColumns...)
	values := []any{
		fields.Ciphertext, fields.PlainJSON, fields.KeyVersion,
		fields.Projection.UpstreamType, fields.Projection.Email, fields.Projection.BaseURL,
		fields.Projection.PlanType, fields.Projection.ModelsJSON,
		db.dbBool(fields.Projection.HasAPIKey), db.dbBool(fields.Projection.HasRefreshToken),
		fields.Projection.SchedulerPriority,
	}
	columns = strings.Join(allColumns, ", ")
	if db.isSQLite() {
		placeholders = strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
		return columns, placeholders, values
	}
	phs := make([]string, 0, len(values))
	for i := range values {
		ph := fmt.Sprintf("$%d", start+i)
		// credentials 列为 JSONB，需显式文本→jsonb 赋值转换。
		if i == 1 {
			ph += "::jsonb"
		}
		phs = append(phs, ph)
	}
	return columns, strings.Join(phs, ", "), values
}

// ==================== 读取 ====================

// decodeStoredCredentialsStrict 从数据库原始值解码凭证。启动迁移、投影回填和
// 完整性校验必须使用严格版本，避免错误密钥或损坏密文被误当作空凭证后继续写库。
func (db *DB) decodeStoredCredentialsStrict(raw any) (map[string]any, error) {
	data := bytesFromDBValue(raw)
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	text := string(data)
	if strings.HasPrefix(text, credentialsEncryptionMagicPrefix) {
		if db == nil || db.credentialsCipher == nil {
			return nil, fmt.Errorf("发现加密凭证但未配置 %s", credentialsEncryptionEnv)
		}
		plaintext, err := db.credentialsCipher.Decrypt(text)
		if err != nil {
			return nil, err
		}
		data = plaintext
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("credentials JSON 解析失败: %w", err)
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

// decodeStoredCredentials 是业务读取的兼容包装。失败时记录日志并返回空 map；启动
// 路径会另外执行严格校验并 fail-closed，因此错误密钥不会进入可服务状态。
func (db *DB) decodeStoredCredentials(raw any) map[string]any {
	out, err := db.decodeStoredCredentialsStrict(raw)
	if err != nil {
		log.Printf("[credentials] 凭证解密/解析失败: %v（请检查 %s / %s 是否与写入时一致）", err, credentialsEncryptionEnv, credentialsEncryptionPreviousEnv)
		return map[string]any{}
	}
	return out
}

// storedCredentialsExpr 返回 SELECT 时读取账号凭证的表达式：优先密文，空时回落
// 明文存量。CAST(... AS TEXT) 同时兼容 PostgreSQL JSONB 与 SQLite TEXT，避免
// PostgreSQL 的 COALESCE(TEXT, JSONB) 类型不匹配。
func storedCredentialsExpr() string {
	return `COALESCE(NULLIF(credentials_enc, ''), CAST(credentials AS TEXT))`
}

func storedCredentialsExprAliased(alias string) string {
	return `COALESCE(NULLIF(` + alias + `.credentials_enc, ''), CAST(` + alias + `.credentials AS TEXT))`
}

// ==================== 启动回填 ====================

// ensureCredentialsEncryption 在迁移完成后调用：
//  1. 无条件回填存量行的投影列（明文模式也执行，保证 SQL 过滤可用）。
//  2. 已配置密钥时，把存量明文 credentials 加密迁移到 credentials_enc 并清空明文。
func (db *DB) ensureCredentialsEncryption(ctx context.Context) error {
	if !db.credentialsCipherEnabled() {
		return db.backfillCredentialsProjections(ctx)
	}
	// 在任何写迁移前先认证全部存量密文。错误或缺失密钥必须 fail-closed，
	// 不能先写入空投影或产生部分轮换。
	if err := db.validateEncryptedCredentials(ctx); err != nil {
		return err
	}
	if err := db.reencryptCredentialsAtRest(ctx); err != nil {
		return err
	}
	if err := db.encryptCredentialsAtRest(ctx); err != nil {
		return err
	}
	// 同时校验本次新写入/重加密结果，再确认明文残留为零。
	if err := db.validateEncryptedCredentials(ctx); err != nil {
		return err
	}
	plaintextRows, err := db.CountPlaintextCredentials(ctx)
	if err != nil {
		return fmt.Errorf("检查明文凭证残留失败: %w", err)
	}
	if plaintextRows != 0 {
		return fmt.Errorf("凭证加密迁移后仍有 %d 行明文凭证，按 fail-closed 策略拒绝启动", plaintextRows)
	}
	return db.backfillCredentialsProjections(ctx)
}

// backfillCredentialsProjections 为旧二进制写入的行补齐投影列（幂等）。
func (db *DB) backfillCredentialsProjections(ctx context.Context) error {
	limit := credentialsBackfillBatchSize
	for {
		updated, err := db.backfillCredentialsProjectionsBatch(ctx, limit)
		if err != nil {
			return err
		}
		if updated < limit {
			break
		}
	}
	return nil
}

func (db *DB) backfillCredentialsProjectionsBatch(ctx context.Context, limit int) (int, error) {
	query := `SELECT id, ` + storedCredentialsExpr() + `
		FROM accounts
		WHERE credentials_projection_version < $1
		ORDER BY id LIMIT $2`
	if db.isSQLite() {
		query = `SELECT id, ` + storedCredentialsExpr() + `
			FROM accounts
			WHERE credentials_projection_version < ?
			ORDER BY id LIMIT ?`
	}
	rows, err := db.conn.QueryContext(ctx, query, credentialsProjectionVersion, limit)
	if err != nil {
		return 0, fmt.Errorf("查询待回填投影的账号失败: %w", err)
	}
	type pending struct {
		id  int64
		raw any
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.raw); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}
	stmt, err := db.conn.PrepareContext(ctx, db.projectionBackfillUpdateSQL())
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	updated := 0
	for _, p := range batch {
		creds, decodeErr := db.decodeStoredCredentialsStrict(p.raw)
		if decodeErr != nil {
			return updated, fmt.Errorf("解码账号 %d 凭证以回填投影失败: %w", p.id, decodeErr)
		}
		proj := deriveCredentialsProjection(creds)
		rawSnapshot := string(bytesFromDBValue(p.raw))
		res, err := stmt.ExecContext(ctx,
			proj.UpstreamType, proj.Email, proj.BaseURL, proj.PlanType, proj.ModelsJSON,
			db.dbBool(proj.HasAPIKey), db.dbBool(proj.HasRefreshToken), proj.SchedulerPriority,
			credentialsProjectionVersion, p.id, credentialsProjectionVersion, rawSnapshot,
		)
		if err != nil {
			return updated, err
		}
		if n, err := res.RowsAffected(); err == nil && n > 0 {
			updated++
		}
	}
	return updated, nil
}

func (db *DB) projectionBackfillUpdateSQL() string {
	if db.isSQLite() {
		return `UPDATE accounts SET upstream_type=?, email=?, base_url=?, plan_type=?, cred_models=?,
			has_api_key=?, has_refresh_token=?, scheduler_priority=?, credentials_projection_version=?
			WHERE id=? AND credentials_projection_version < ? AND ` + storedCredentialsExpr() + ` = ?`
	}
	return `UPDATE accounts SET upstream_type=$1, email=$2, base_url=$3, plan_type=$4, cred_models=$5,
		has_api_key=$6, has_refresh_token=$7, scheduler_priority=$8, credentials_projection_version=$9
		WHERE id=$10 AND credentials_projection_version < $11 AND ` + storedCredentialsExpr() + ` = $12`
}

// encryptCredentialsAtRest 把存量明文凭证加密迁移到 credentials_enc，成功后清空
// credentials 明文列（避免明文继续留在备份/导出的可读字段中）。幂等：
// 已加密行 credentials_enc 非空即跳过。
func (db *DB) encryptCredentialsAtRest(ctx context.Context) error {
	limit := credentialsBackfillBatchSize
	for {
		updated, err := db.encryptCredentialsAtRestBatch(ctx, limit)
		if err != nil {
			return err
		}
		if updated < limit {
			break
		}
	}
	return nil
}

func (db *DB) encryptCredentialsAtRestBatch(ctx context.Context, limit int) (int, error) {
	query := `SELECT id, credentials FROM accounts
		WHERE credentials_enc = '' AND credentials <> '{}'
		ORDER BY id LIMIT $1`
	if db.isSQLite() {
		query = `SELECT id, credentials FROM accounts
			WHERE credentials_enc = '' AND credentials <> '{}'
			ORDER BY id LIMIT ?`
	}
	rows, err := db.conn.QueryContext(ctx, query, limit)
	if err != nil {
		return 0, fmt.Errorf("查询待加密明文凭证失败: %w", err)
	}
	type pending struct {
		id       int64
		plainRaw any
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.plainRaw); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, db.encryptAtRestUpdateSQL())
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	updated := 0
	for _, p := range batch {
		plaintext := bytesFromDBValue(p.plainRaw)
		ciphertext, encryptErr := db.credentialsCipher.Encrypt(plaintext)
		if encryptErr != nil {
			return updated, fmt.Errorf("加密账号 %d 凭证失败: %w", p.id, encryptErr)
		}
		version := db.credentialsEncryptionVersion()
		plainSnapshot := string(plaintext)
		res, execErr := stmt.ExecContext(ctx, ciphertext, "{}", version, p.id, plainSnapshot)
		if execErr != nil {
			return updated, execErr
		}
		if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
			updated++
		}
	}
	if err := tx.Commit(); err != nil {
		return updated, err
	}
	if updated > 0 {
		log.Printf("[credentials] 已加密 %d 个账号的存量凭证（密钥版本 %d）", updated, db.credentialsEncryptionVersion())
	}
	return updated, nil
}

func (db *DB) encryptAtRestUpdateSQL() string {
	if db.isSQLite() {
		return `UPDATE accounts SET credentials_enc=?, credentials=?, cred_key_version=?
			WHERE id=? AND credentials_enc='' AND CAST(credentials AS TEXT)=?`
	}
	return `UPDATE accounts SET credentials_enc=$1, credentials=$2::jsonb, cred_key_version=$3
		WHERE id=$4 AND credentials_enc='' AND credentials=$5::jsonb`
}

// reencryptCredentialsAtRest rewrites ciphertext created by a historical key to
// the current key. This is required before retiring CREDENTIALS_ENCRYPTION_PREVIOUS_KEY
// and makes repeated key rotations safe across process restarts.
func (db *DB) reencryptCredentialsAtRest(ctx context.Context) error {
	limit := credentialsBackfillBatchSize
	for {
		updated, err := db.reencryptCredentialsAtRestBatch(ctx, limit)
		if err != nil {
			return err
		}
		if updated < limit {
			remaining, countErr := db.countCredentialsRequiringRotation(ctx)
			if countErr != nil {
				return countErr
			}
			if remaining != 0 {
				return fmt.Errorf("凭证密钥轮换后仍有 %d 行旧版本密文，可能存在并发写入，按 fail-closed 策略拒绝启动", remaining)
			}
			return nil
		}
	}
}

func (db *DB) reencryptCredentialsAtRestBatch(ctx context.Context, limit int) (int, error) {
	if !db.credentialsCipherEnabled() {
		return 0, nil
	}
	currentVersion := db.credentialsEncryptionVersion()
	currentPrefix := credentialsEncryptionMagicPrefix + strconv.Itoa(currentVersion) + ":%"
	query := `SELECT id, credentials_enc FROM accounts
		WHERE credentials_enc <> '' AND (cred_key_version <> $1 OR credentials_enc NOT LIKE $2)
		ORDER BY id LIMIT $3`
	if db.isSQLite() {
		query = `SELECT id, credentials_enc FROM accounts
			WHERE credentials_enc <> '' AND (cred_key_version <> ? OR credentials_enc NOT LIKE ?)
			ORDER BY id LIMIT ?`
	}
	rows, err := db.conn.QueryContext(ctx, query, currentVersion, currentPrefix, limit)
	if err != nil {
		return 0, fmt.Errorf("查询待轮换凭证失败: %w", err)
	}
	type pending struct {
		id         int64
		ciphertext string
	}
	batch := make([]pending, 0, limit)
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.ciphertext); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}

	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	updateSQL := `UPDATE accounts SET credentials_enc=$1, cred_key_version=$2 WHERE id=$3 AND credentials_enc=$4`
	if db.isSQLite() {
		updateSQL = `UPDATE accounts SET credentials_enc=?, cred_key_version=? WHERE id=? AND credentials_enc=?`
	}
	stmt, err := tx.PrepareContext(ctx, updateSQL)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	updated := 0
	for _, item := range batch {
		plaintext, decryptErr := db.credentialsCipher.Decrypt(item.ciphertext)
		if decryptErr != nil {
			return updated, fmt.Errorf("解密账号 %d 的历史凭证失败: %w", item.id, decryptErr)
		}
		ciphertext, encryptErr := db.credentialsCipher.Encrypt(plaintext)
		if encryptErr != nil {
			return updated, fmt.Errorf("使用当前密钥重加密账号 %d 凭证失败: %w", item.id, encryptErr)
		}
		res, execErr := stmt.ExecContext(ctx, ciphertext, currentVersion, item.id, item.ciphertext)
		if execErr != nil {
			return updated, execErr
		}
		if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 1 {
			updated++
		}
	}
	if err := tx.Commit(); err != nil {
		return updated, err
	}
	if updated > 0 {
		log.Printf("[credentials] 已将 %d 个账号凭证轮换到密钥版本 %d", updated, currentVersion)
	}
	return updated, nil
}

// CountPlaintextCredentials 返回仍以明文 JSON 持久化的账号行数。供启动
// fail-closed 校验与 /healthz 运维观测使用。
func (db *DB) CountPlaintextCredentials(ctx context.Context) (int64, error) {
	if db == nil || db.conn == nil {
		return 0, errors.New("database is not initialized")
	}
	var count int64
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts
		WHERE COALESCE(credentials_enc, '') = ''
		  AND COALESCE(CAST(credentials AS TEXT), '') NOT IN ('', '{}', 'null')`).Scan(&count)
	return count, err
}

func (db *DB) countCredentialsRequiringRotation(ctx context.Context) (int64, error) {
	if !db.credentialsCipherEnabled() {
		return 0, nil
	}
	currentVersion := db.credentialsEncryptionVersion()
	currentPrefix := credentialsEncryptionMagicPrefix + strconv.Itoa(currentVersion) + ":%"
	query := `SELECT COUNT(*) FROM accounts
		WHERE credentials_enc <> '' AND (cred_key_version <> $1 OR credentials_enc NOT LIKE $2)`
	if db.isSQLite() {
		query = `SELECT COUNT(*) FROM accounts
			WHERE credentials_enc <> '' AND (cred_key_version <> ? OR credentials_enc NOT LIKE ?)`
	}
	var count int64
	if err := db.conn.QueryRowContext(ctx, query, currentVersion, currentPrefix).Scan(&count); err != nil {
		return 0, fmt.Errorf("检查旧版本凭证密文失败: %w", err)
	}
	return count, nil
}

// validateEncryptedCredentials 对所有密文执行认证解密和 JSON 解析。错误密钥、未知
// 版本或 GCM 篡改必须在服务接流量前被发现，而不能降级为空凭证继续启动。
func (db *DB) validateEncryptedCredentials(ctx context.Context) error {
	if !db.credentialsCipherEnabled() {
		return nil
	}
	var lastID int64
	for {
		query := `SELECT id, credentials_enc FROM accounts
			WHERE id > $1 AND credentials_enc <> '' ORDER BY id LIMIT $2`
		if db.isSQLite() {
			query = `SELECT id, credentials_enc FROM accounts
				WHERE id > ? AND credentials_enc <> '' ORDER BY id LIMIT ?`
		}
		rows, err := db.conn.QueryContext(ctx, query, lastID, credentialsBackfillBatchSize)
		if err != nil {
			return fmt.Errorf("查询待校验凭证密文失败: %w", err)
		}
		checked := 0
		for rows.Next() {
			var id int64
			var ciphertext string
			if err := rows.Scan(&id, &ciphertext); err != nil {
				rows.Close()
				return err
			}
			if _, err := db.decodeStoredCredentialsStrict(ciphertext); err != nil {
				rows.Close()
				return fmt.Errorf("账号 %d 凭证完整性校验失败: %w", id, err)
			}
			lastID = id
			checked++
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if checked < credentialsBackfillBatchSize {
			return nil
		}
	}
}

// ==================== 迁移期写入辅助（tx 内） ====================

// accountSetField 一条 UPDATE SET 赋值（value 为 nil 时表示纯 SQL 片段，不占参数）。
type accountSetField struct {
	column    string // 列名或纯 SQL 片段（无参数）
	value     any    // 绑定的值
	castJSONB bool   // PostgreSQL 下追加 ::jsonb 转换
}

// accountWhereField 一条 WHERE 相等条件。
type accountWhereField struct {
	column string
	value  any
}

// buildAccountUpdateSQL 按位置生成 UPDATE accounts 语句与参数，PostgreSQL 使用
// $N 顺延编号，SQLite 使用 ?。setRaw / whereRaw 为不含占位符的纯 SQL 片段。
func (db *DB) buildAccountUpdateSQL(creds map[string]any, setFields []accountSetField, setRaw string, whereFields []accountWhereField, whereRaw string) (string, []any, error) {
	fields, err := db.buildCredentialsWriteFields(creds)
	if err != nil {
		return "", nil, err
	}
	credSet, credArgs := db.credentialsStoreSet(fields)
	args := append([]any{}, credArgs...)

	place := func(n int) string {
		if db.isSQLite() {
			return "?"
		}
		return fmt.Sprintf("$%d", n)
	}
	argIndex := len(args)
	setParts := []string{credSet}
	for _, f := range setFields {
		argIndex++
		ph := place(argIndex)
		if f.castJSONB && !db.isSQLite() {
			ph += "::jsonb"
		}
		setParts = append(setParts, f.column+" = "+ph)
		args = append(args, f.value)
	}
	if strings.TrimSpace(setRaw) != "" {
		setParts = append(setParts, setRaw)
	}

	query := "UPDATE accounts SET " + strings.Join(setParts, ", ")
	var wheres []string
	for _, f := range whereFields {
		argIndex++
		wheres = append(wheres, f.column+" = "+place(argIndex))
		args = append(args, f.value)
	}
	if strings.TrimSpace(whereRaw) != "" {
		wheres = append(wheres, strings.TrimSpace(whereRaw))
	}
	if len(wheres) > 0 {
		query += " WHERE " + strings.Join(wheres, " AND ")
	}
	return query, args, nil
}

// buildCredentialsSetForUpdate 供少数保留原 SQL 结构的调用点使用：返回凭证 SET
// 片段与参数，调用方自行拼接剩余 SQL（占位符需从 len(args)+1 续排）。
func (db *DB) buildCredentialsSetForUpdate(creds map[string]any) (string, []any, error) {
	fields, err := db.buildCredentialsWriteFields(creds)
	if err != nil {
		return "", nil, err
	}
	setClause, args := db.credentialsStoreSet(fields)
	return setClause, args, nil
}

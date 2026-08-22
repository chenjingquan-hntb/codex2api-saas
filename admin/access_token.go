package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// Access Token 分层（P5）：短寿命无状态访问令牌 + HttpOnly 刷新 Cookie。
//
//   - Access Token：HMAC-SHA256 签名自包含（uid/sid/role/email/iat/exp），TTL 15 分钟，
//     放在前端内存、经 `Authorization: Bearer` 头携带；本地验签零 DB 查询，无状态可水平扩展。
//   - Refresh Token：即现有会话 Cookie（`codex2api_session`），仅用于 POST /api/auth/refresh
//     换新 Access Token；存 DB 摘要、可吊销、HttpOnly，JS 不可读。
//
// 签名密钥：
//   - 环境变量 ACCESS_TOKEN_SECRET 优先（多端点部署必须在所有节点配置相同值，否则节点间
//     签发的 token 互不认领；见 PLAN.md P7）。
//   - 未配置时使用进程内随机密钥（重启后所有存量 Access Token 失效——前端会静默 refresh，
//     用数据库里的刷新 Cookie 自动恢复，无需用户重新登录）。
//
// 安全权衡：Access Token 是无状态的，因此「封禁用户 / 改密 / 吊销会话」经 refresh 路径
// （查 DB）即时生效，存量 Access Token 最长存在 TTL（15 分钟）的滞后窗口，可接受。

const (
	accessTokenTTL    = 15 * time.Minute
	accessTokenPrefix = "v1."
)

var (
	errAccessTokenInvalid = errors.New("access token: invalid signature or format")
	errAccessTokenExpired = errors.New("access token: expired")

	accessTokenSecretOnce sync.Once
	accessTokenSecretVal  []byte
)

// accessClaims 是 Access Token 的自包含载荷。
type accessClaims struct {
	UID   int64  `json:"uid"`
	SID   int64  `json:"sid"`
	Role  string `json:"role"`
	Email string `json:"email"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// accessTokenSecret 返回 HMAC 签名密钥（进程内解析一次）。
func accessTokenSecret() []byte {
	accessTokenSecretOnce.Do(func() {
		if s := strings.TrimSpace(os.Getenv("ACCESS_TOKEN_SECRET")); s != "" {
			accessTokenSecretVal = []byte(s)
			log.Printf("access token: 使用环境变量 ACCESS_TOKEN_SECRET 作为签名密钥（长度 %d）", len(s))
			return
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			// 无法生成安全密钥时拒绝启动而非降级。
			panic(fmt.Sprintf("access token: 生成随机签名密钥失败: %v", err))
		}
		accessTokenSecretVal = buf
		log.Printf("access token: 未配置 ACCESS_TOKEN_SECRET，使用进程内随机密钥（重启后存量 token 失效，由前端 refresh 自动恢复）")
	})
	return accessTokenSecretVal
}

// issueAccessToken 为已通过认证的用户签发短寿命 Access Token。
// 返回 token 与有效秒数（expires_in）。
func issueAccessToken(userID, sessionID int64, role, email string, now time.Time) (string, int64, error) {
	if userID <= 0 {
		return "", 0, errors.New("issue access token: invalid user")
	}
	cl := accessClaims{
		UID:   userID,
		SID:   sessionID,
		Role:  role,
		Email: email,
		Iat:   now.Unix(),
		Exp:   now.Add(accessTokenTTL).Unix(),
	}
	payload, err := json.Marshal(cl)
	if err != nil {
		return "", 0, fmt.Errorf("issue access token: %w", err)
	}
	sig := signAccessTokenPayload(payload)
	return accessTokenPrefix + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), int64(accessTokenTTL.Seconds()), nil
}

func signAccessTokenPayload(payload []byte) []byte {
	mac := hmac.New(sha256.New, accessTokenSecret())
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

// verifyAccessToken 验签并解析 Access Token；过期/篡改/格式错误返回错误。
func verifyAccessToken(token string, now time.Time) (*accessClaims, error) {
	if !strings.HasPrefix(token, accessTokenPrefix) {
		return nil, errAccessTokenInvalid
	}
	rest := token[len(accessTokenPrefix):]
	dot := strings.LastIndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return nil, errAccessTokenInvalid
	}
	payloadB64, sigB64 := rest[:dot], rest[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errAccessTokenInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errAccessTokenInvalid
	}
	if !hmac.Equal(sig, signAccessTokenPayload(payload)) {
		return nil, errAccessTokenInvalid
	}
	var cl accessClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, errAccessTokenInvalid
	}
	if cl.UID <= 0 || cl.Exp <= cl.Iat {
		return nil, errAccessTokenInvalid
	}
	if cl.Exp < now.Unix() {
		return nil, errAccessTokenExpired
	}
	return &cl, nil
}

// bearerAccessToken 从 Authorization: Bearer <token> 头解析 Access Token。
func bearerAccessToken(c *gin.Context) string {
	h := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// accessClaimsToSession 把 Access Token 载荷构造为会话视图（供 sessionFromGin 使用）。
// 无状态路径不查 DB：封禁/改密以 Access Token TTL 为滞后窗口，见文件头说明。
func accessClaimsToSession(cl *accessClaims) *database.UserSession {
	return &database.UserSession{
		ID:              cl.SID,
		UserID:          cl.UID,
		Email:           cl.Email,
		Role:            cl.Role,
		Status:          database.UserStatusActive,
		EmailVerifiedAt: time.Now(), // 签发链路（登录/refresh）已强制邮箱验证
		ExpiresAt:       time.Unix(cl.Exp, 0),
	}
}

// accessTokenResponseBody 统一登录/refresh 的响应体。
func accessTokenResponseBody(user *database.User, token string, expiresIn int64) gin.H {
	return gin.H{
		"user_id":      user.ID,
		"email":        user.Email,
		"role":         user.Role,
		"verified":     true,
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   expiresIn,
	}
}

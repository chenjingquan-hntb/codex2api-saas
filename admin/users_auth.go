package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// 门户认证（P5/P6 控制面）。
//
// 会话模型（用户已确认）：HttpOnly 刷新 Cookie + 短时 Access Token。
// 本步骤落地 Cookie 会话基础设施；数据面 /v1/* 仍走用户 API Key，
// Access Token 分层在后续门户步骤叠加。
//
// 邮件发送：本步骤为 log-only stub（验证/重置链接打印到日志并在响应中返回
// dev URL），SMTP 配置接口在下一步接入，届时 userMailer 替换为真实实现。

const (
	userSessionCookieName = "codex2api_session"
	userSessionTTL        = 30 * 24 * time.Hour
	userTokenTTL          = 24 * time.Hour

	userPasswordMinLen = 8
	userPasswordMaxLen = 128
	userEmailMaxLen    = 254
)

// 端点限流（内存滑动窗口；够用即可，后续可上 Redis 计数）。
const (
	userRegisterRateLimit    = 5
	userRegisterRateWin      = time.Hour
	userLoginRateLimit       = 30
	userLoginEmailRateLimit  = 10
	userLoginRateWin         = 15 * time.Minute
	userResendRateLimit      = 3
	userResendRateWin        = time.Hour
	userResetReqRateLimit    = 3
	userResetReqRateWin      = time.Hour
)

var (
	// 各端点限流器实例挂在 Handler 上（NewHandler 初始化），避免包级共享状态污染测试。
)

// userMailer 邮件发送抽象；SMTP 实现在下一步接入。
type userMailer interface {
	SendVerificationEmail(ctx context.Context, to, verifyURL string) error
	SendPasswordResetEmail(ctx context.Context, to, resetURL string) error
}

// logOnlyUserMailer 开发态实现：仅打印日志，不真正发信。
type logOnlyUserMailer struct{}

func (logOnlyUserMailer) SendVerificationEmail(_ context.Context, to, verifyURL string) error {
	log.Printf("[user-mailer] 验证邮件(未配置 SMTP，仅日志): to=%s url=%s", security.SanitizeLog(to), verifyURL)
	return ErrMailerNotConfigured
}

func (logOnlyUserMailer) SendPasswordResetEmail(_ context.Context, to, resetURL string) error {
	log.Printf("[user-mailer] 重置邮件(未配置 SMTP，仅日志): to=%s url=%s", security.SanitizeLog(to), resetURL)
	return ErrMailerNotConfigured
}

// keyedRateLimiter 按 key（IP/邮箱）的滑动窗口计数限流。
type keyedRateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	win    time.Duration
	lastGC time.Time
}

func newKeyedRateLimiter(limit int, win time.Duration) *keyedRateLimiter {
	return &keyedRateLimiter{hits: make(map[string][]time.Time), limit: limit, win: win}
}

// allow 报告 key 在窗口内是否仍有配额；有则记一次。now 由调用方传入以便测试。
func (l *keyedRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcIfDue(now)
	cutoff := now.Add(-l.win)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// gcIfDue 每经过一个窗口周期清扫一次：删除已无记录的 key，防止长运行下 map 无界增长。
func (l *keyedRateLimiter) gcIfDue(now time.Time) {
	if l.lastGC.IsZero() {
		l.lastGC = now
		return
	}
	if now.Sub(l.lastGC) < l.win {
		return
	}
	l.lastGC = now
	cutoff := now.Add(-l.win)
	for k, ts := range l.hits {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.hits, k)
			continue
		}
		l.hits[k] = kept
	}
}

// ==================== 请求上下文 ====================

type userContextKey string

const (
	ctxKeyUserSession userContextKey = "admin.userSession"
)

// sessionFromGin 从上下文取出当前用户会话（由 requireUserSession 注入）。
func sessionFromGin(c *gin.Context) *database.UserSession {
	v, ok := c.Get(string(ctxKeyUserSession))
	if !ok {
		return nil
	}
	s, _ := v.(*database.UserSession)
	return s
}

// requireUserSession 校验用户会话并注入用户会话到上下文。
// 双路径：
//  1. Authorization: Bearer <access_token>（无状态本地验签，零 DB 查询；新前端首选）
//  2. 兼容路径：HttpOnly 会话 Cookie（查 DB，测试与旧前端继续可用）
// 若带 Bearer 但无效，直接 401 不回落 Cookie，避免过期 token 被 Cookie 路径放行。
func (h *Handler) requireUserSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || h.db == nil {
			writeError(c, http.StatusServiceUnavailable, "服务未就绪")
			c.Abort()
			return
		}
		// 路径 1：Bearer Access Token（无状态）。
		if tok := bearerAccessToken(c); tok != "" {
			claims, err := verifyAccessToken(tok, time.Now())
			if err != nil {
				writeError(c, http.StatusUnauthorized, "会话已过期，请重新登录")
				c.Abort()
				return
			}
			c.Set(string(ctxKeyUserSession), accessClaimsToSession(claims))
			c.Next()
			return
		}
		// 路径 2：兼容 HttpOnly 会话 Cookie（查 DB）。
		raw, err := c.Cookie(userSessionCookieName)
		if err != nil || strings.TrimSpace(raw) == "" {
			writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
			c.Abort()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		sess, err := h.db.GetUserSessionByTokenHash(ctx, database.HashSessionToken(raw))
		if err != nil || !sess.Valid(time.Now()) {
			writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
			c.Abort()
			return
		}
		c.Set(string(ctxKeyUserSession), sess)
		c.Next()
	}
}

// ==================== 工具 ====================

// newOpaqueToken 生成 32 字节随机 token（hex 编码），数据库只存 SHA-256 摘要。
func newOpaqueToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

var (
	dummyHashOnce sync.Once
	dummyHashVal  string
)

// dummyArgon2Hash 返回一个预计算的 Argon2id 哈希（惰性生成一次），用于未知邮箱
// 登录时做等开销校验，抹平「邮箱已注册/未注册」的响应时长差异（防时序枚举）。
func dummyArgon2Hash() string {
	dummyHashOnce.Do(func() {
		if h, err := database.HashPassword("codex2api-timing-dummy-password"); err == nil {
			dummyHashVal = h
		}
	})
	return dummyHashVal
}

// portalBaseURLFromEnv 读取 PUBLIC_BASE_URL 环境变量（可选）。
func portalBaseURLFromEnv() string {
	return os.Getenv("PUBLIC_BASE_URL")
}

// portalBaseURL 拼接邮件链接基础地址：优先 PUBLIC_BASE_URL，否则用请求的 scheme+host。
func portalBaseURL(c *gin.Context) string {
	if base := strings.TrimSpace(portalBaseURLFromEnv()); base != "" {
		return strings.TrimSuffix(base, "/")
	}
	scheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

func (h *Handler) setUserSessionCookie(c *gin.Context, token string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     userSessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(userSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"),
	})
}

func (h *Handler) clearUserSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     userSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ==================== 注册 / 邮箱验证 ====================

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterUser POST /api/auth/register
func (h *Handler) RegisterUser(c *gin.Context) {
	ip := c.ClientIP()
	if !h.registerLimiter.allow(ip, time.Now()) {
		security.SecurityAuditLog("USER_REGISTER_RATE_LIMITED", "ip="+security.SanitizeLog(ip))
		writeError(c, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	email, ok := normalizeContactEmail(req.Email)
	if !ok {
		writeError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	if msg := validateUserPassword(req.Password); msg != "" {
		writeError(c, http.StatusBadRequest, msg)
		return
	}
	passwordHash, err := database.HashPassword(req.Password)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	user, err := h.db.CreateUser(c.Request.Context(), email, passwordHash)
	if err != nil {
		if errors.Is(err, database.ErrEmailTaken) {
			writeError(c, http.StatusConflict, "该邮箱已被注册")
			return
		}
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("USER_REGISTERED", "user_id="+strconv.FormatInt(user.ID, 10)+" email="+security.SanitizeLog(email)+" ip="+security.SanitizeLog(ip))

	h.issueVerification(c, user.ID, email, http.StatusCreated)
}

// issueVerification 签发邮箱验证 token 并（尝试）发送邮件。
// 仅当邮件实际未配置（dev 模式）时响应才携带 dev_verify_url；SMTP 已配置并发出时
// 不再把一次性 token 泄漏到响应/日志/浏览器历史。
func (h *Handler) issueVerification(c *gin.Context, userID int64, email string, statusCode int) {
	token, err := newOpaqueToken()
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.CreateEmailVerificationToken(c.Request.Context(), userID, database.HashSessionToken(token), time.Now().Add(userTokenTTL)); err != nil {
		writeInternalError(c, err)
		return
	}
	base := portalBaseURL(c)
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", base, token)
	emailSent := false
	mailErr := h.userMailer.SendVerificationEmail(c.Request.Context(), email, verifyURL)
	if mailErr != nil {
		if !errors.Is(mailErr, ErrMailerNotConfigured) {
			log.Printf("发送验证邮件失败: email=%s err=%v", security.SanitizeLog(email), mailErr)
		}
	} else {
		emailSent = true
	}
	resp := gin.H{
		"user_id":    userID,
		"email":      email,
		"email_sent": emailSent,
		"message":    "注册成功，请查收邮件完成邮箱验证",
	}
	if errors.Is(mailErr, ErrMailerNotConfigured) {
		resp["dev_verify_url"] = verifyURL
	}
	c.JSON(statusCode, resp)
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmail POST /api/auth/verify-email
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req verifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		writeError(c, http.StatusBadRequest, "缺少验证 token")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	userID, err := h.db.ConsumeEmailVerificationToken(ctx, database.HashSessionToken(strings.TrimSpace(req.Token)))
	if err != nil {
		switch {
		case errors.Is(err, database.ErrTokenNotFound):
			writeError(c, http.StatusBadRequest, "验证链接无效")
		case errors.Is(err, database.ErrTokenExpired):
			writeError(c, http.StatusBadRequest, "验证链接已过期，请重新发送")
		case errors.Is(err, database.ErrTokenUsed):
			writeError(c, http.StatusBadRequest, "验证链接已被使用")
		default:
			writeInternalError(c, err)
		}
		return
	}
	// 封禁用户不可通过验证自解封（token 已消费，不再可用）。
	user, err := h.db.GetUserByID(ctx, userID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if user.IsBanned() {
		security.SecurityAuditLog("USER_EMAIL_VERIFY_BANNED", "user_id="+strconv.FormatInt(userID, 10))
		writeError(c, http.StatusForbidden, "账号已被封禁，无法验证邮箱")
		return
	}
	if err := h.db.SetUserEmailVerified(ctx, userID); err != nil {
		writeInternalError(c, err)
		return
	}
	security.SecurityAuditLog("USER_EMAIL_VERIFIED", "user_id="+strconv.FormatInt(userID, 10))
	writeMessage(c, http.StatusOK, "邮箱验证成功")
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

// ResendVerification POST /api/auth/resend-verification
func (h *Handler) ResendVerification(c *gin.Context) {
	var req resendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	email, ok := normalizeContactEmail(req.Email)
	if !ok {
		writeError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	ip := c.ClientIP()
	key := email + "|" + ip
	if !h.resendLimiter.allow(key, time.Now()) {
		security.SecurityAuditLog("USER_RESEND_RATE_LIMITED", "email="+security.SanitizeLog(email))
		writeError(c, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}
	// 防枚举：无论用户是否存在都返回 200。
	user, err := h.db.GetUserByEmail(c.Request.Context(), email)
	if err != nil || user.EmailVerified() {
		writeMessage(c, http.StatusOK, "如果该邮箱已注册且未验证，验证邮件已重新发送")
		return
	}
	h.issueVerification(c, user.ID, email, http.StatusOK)
}

// ==================== 登录 / 登出 ====================

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginUser POST /api/auth/login
func (h *Handler) LoginUser(c *gin.Context) {
	ip := c.ClientIP()
	if !h.loginIPLimiter.allow(ip, time.Now()) {
		security.SecurityAuditLog("USER_LOGIN_IP_RATE_LIMITED", "ip="+security.SanitizeLog(ip))
		writeError(c, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	email, ok := normalizeContactEmail(req.Email)
	if !ok {
		writeError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	if !h.loginEmailLimiter.allow(email, time.Now()) {
		security.SecurityAuditLog("USER_LOGIN_EMAIL_RATE_LIMITED", "email="+security.SanitizeLog(email))
		writeError(c, http.StatusTooManyRequests, "尝试次数过多，请 15 分钟后再试")
		return
	}

	user, err := h.db.GetUserByEmail(c.Request.Context(), email)
	if err != nil || user == nil {
		// 统一口径防枚举 + 时序均衡：未知邮箱也执行一次等开销的 Argon2 校验，
		// 避免攻击者以响应时长区分「邮箱已注册」与「未注册」。
		if hash := dummyArgon2Hash(); hash != "" {
			_, _ = database.VerifyPassword(hash, req.Password)
		}
		writeError(c, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	ok, err = database.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		writeInternalError(c, fmt.Errorf("校验密码失败: %w", err))
		return
	}
	if !ok {
		security.SecurityAuditLog("USER_LOGIN_FAILED", "user_id="+strconv.FormatInt(user.ID, 10)+" ip="+security.SanitizeLog(ip))
		writeError(c, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	if user.IsBanned() {
		security.SecurityAuditLog("USER_LOGIN_BANNED", "user_id="+strconv.FormatInt(user.ID, 10)+" ip="+security.SanitizeLog(ip))
		writeError(c, http.StatusForbidden, "账号已被封禁")
		return
	}
	if !user.EmailVerified() {
		writeError(c, http.StatusForbidden, "邮箱尚未验证，请先验证邮箱后再登录")
		return
	}

	token, err := newOpaqueToken()
	if err != nil {
		writeInternalError(c, err)
		return
	}
	sessionID, err := h.db.CreateUserSession(c.Request.Context(), user.ID, database.HashSessionToken(token),
		"", ip, c.Request.UserAgent(), time.Now().Add(userSessionTTL))
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.UpdateUserLastLogin(c.Request.Context(), user.ID); err != nil {
		log.Printf("更新登录时间失败: user_id=%d err=%v", user.ID, err)
	}
	h.setUserSessionCookie(c, token)
	security.SecurityAuditLog("USER_LOGIN_OK", "user_id="+strconv.FormatInt(user.ID, 10)+" session_id="+strconv.FormatInt(sessionID, 10)+" ip="+security.SanitizeLog(ip))
	accessToken, expiresIn, err := issueAccessToken(user.ID, sessionID, user.Role, user.Email, time.Now())
	if err != nil {
		// 会话已建立，仅 access token 签发失败不阻断登录（前端可 refresh 重取）。
		log.Printf("签发 access token 失败: user_id=%d err=%v", user.ID, err)
		accessToken, expiresIn = "", 0
	}
	c.JSON(http.StatusOK, accessTokenResponseBody(user, accessToken, expiresIn))
}

// RefreshUserSession POST /api/auth/refresh
// 刷新 Cookie → 校验会话（DB）→ 滑动过期 + 记录活动 → 签发新 Access Token。
// 不做 token 轮换：Cookie 值不变、仅重置 MaxAge，避免多标签页并发 refresh 竞争；
// 防重放由 DB 会话吊销兜底（logout/改密/封禁即吊销）。
func (h *Handler) RefreshUserSession(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "服务未就绪")
		return
	}
	raw, err := c.Cookie(userSessionCookieName)
	if err != nil || strings.TrimSpace(raw) == "" {
		writeError(c, http.StatusUnauthorized, "会话已过期，请重新登录")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	sess, err := h.db.GetUserSessionByTokenHash(ctx, database.HashSessionToken(raw))
	if err != nil || !sess.Valid(time.Now()) {
		security.SecurityAuditLog("USER_REFRESH_REJECTED", "ip="+security.SanitizeLog(c.ClientIP()))
		writeError(c, http.StatusUnauthorized, "会话已过期，请重新登录")
		return
	}
	newExpiresAt := time.Now().Add(userSessionTTL)
	if err := h.db.TouchUserSession(ctx, sess.ID, newExpiresAt); err != nil {
		writeInternalError(c, err)
		return
	}
	accessToken, expiresIn, err := issueAccessToken(sess.UserID, sess.ID, sess.Role, sess.Email, time.Now())
	if err != nil {
		writeInternalError(c, err)
		return
	}
	// 重设 Cookie（MaxAge 重置为完整 TTL），前端无需感知。
	h.setUserSessionCookie(c, raw)
	user := &database.User{ID: sess.UserID, Email: sess.Email, Role: sess.Role}
	security.SecurityAuditLog("USER_REFRESH_OK", "user_id="+strconv.FormatInt(sess.UserID, 10)+" session_id="+strconv.FormatInt(sess.ID, 10)+" ip="+security.SanitizeLog(c.ClientIP()))
	c.JSON(http.StatusOK, accessTokenResponseBody(user, accessToken, expiresIn))
}

// LogoutUser POST /api/auth/logout
func (h *Handler) LogoutUser(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		if err := h.db.RevokeUserSession(ctx, sess.UserID, sess.ID); err != nil {
			log.Printf("吊销会话失败: session_id=%d err=%v", sess.ID, err)
		}
	}
	h.clearUserSessionCookie(c)
	writeMessage(c, http.StatusOK, "已退出登录")
}

// GetCurrentUser GET /api/auth/me
func (h *Handler) GetCurrentUser(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	user, err := h.db.GetUserByID(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			writeError(c, http.StatusUnauthorized, "账号不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":     user.ID,
		"email":       user.Email,
		"role":        user.Role,
		"status":      user.Status,
		"verified":    user.EmailVerified(),
		"created_at":  user.CreatedAt.UTC().Format(time.RFC3339),
		"last_login":  formatOptionalTime(user.LastLoginAt),
		"session_id":  sess.ID,
	})
}

// ==================== 修改密码 / 重置密码 ====================

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword POST /api/auth/password（需登录）
func (h *Handler) ChangePassword(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if msg := validateUserPassword(req.NewPassword); msg != "" {
		writeError(c, http.StatusBadRequest, msg)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	user, err := h.db.GetUserByID(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	ok, err := database.VerifyPassword(user.PasswordHash, req.CurrentPassword)
	if err != nil {
		writeInternalError(c, fmt.Errorf("校验密码失败: %w", err))
		return
	}
	if !ok {
		writeError(c, http.StatusBadRequest, "当前密码不正确")
		return
	}
	newHash, err := database.HashPassword(req.NewPassword)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.SetUserPasswordHash(ctx, user.ID, newHash); err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.RevokeUserSessionsExcept(ctx, user.ID, sess.ID); err != nil {
		log.Printf("改密后吊销其他会话失败: user_id=%d err=%v", user.ID, err)
	}
	security.SecurityAuditLog("USER_PASSWORD_CHANGED", "user_id="+strconv.FormatInt(user.ID, 10)+" ip="+security.SanitizeLog(c.ClientIP()))
	writeMessage(c, http.StatusOK, "密码已更新")
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

// RequestPasswordReset POST /api/auth/password-reset-request
func (h *Handler) RequestPasswordReset(c *gin.Context) {
	var req passwordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	email, ok := normalizeContactEmail(req.Email)
	if !ok {
		writeError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	ip := c.ClientIP()
	key := email + "|" + ip
	if !h.resetReqLimiter.allow(key, time.Now()) {
		writeError(c, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}
	// 防枚举：用户不存在也返回 200。
	user, err := h.db.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		writeMessage(c, http.StatusOK, "如果该邮箱已注册，重置邮件已发送")
		return
	}
	token, err := newOpaqueToken()
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.CreatePasswordResetToken(c.Request.Context(), user.ID, database.HashSessionToken(token), time.Now().Add(userTokenTTL)); err != nil {
		writeInternalError(c, err)
		return
	}
	base := portalBaseURL(c)
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", base, token)
	emailSent := false
	mailErr := h.userMailer.SendPasswordResetEmail(c.Request.Context(), email, resetURL)
	if mailErr != nil {
		if !errors.Is(mailErr, ErrMailerNotConfigured) {
			log.Printf("发送重置邮件失败: email=%s err=%v", security.SanitizeLog(email), mailErr)
		}
	} else {
		emailSent = true
	}
	security.SecurityAuditLog("USER_PASSWORD_RESET_REQUESTED", "user_id="+strconv.FormatInt(user.ID, 10)+" ip="+security.SanitizeLog(ip))
	resp := gin.H{
		"email_sent": emailSent,
		"message":    "如果该邮箱已注册，重置邮件已发送",
	}
	// 仅未配置 SMTP（dev 模式）时回传一次性重置链接，避免生产环境 token 泄漏。
	if errors.Is(mailErr, ErrMailerNotConfigured) {
		resp["dev_reset_url"] = resetURL
	}
	c.JSON(http.StatusOK, resp)
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPassword POST /api/auth/password-reset
func (h *Handler) ResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		writeError(c, http.StatusBadRequest, "缺少重置 token")
		return
	}
	if msg := validateUserPassword(req.NewPassword); msg != "" {
		writeError(c, http.StatusBadRequest, msg)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	userID, err := h.db.ConsumePasswordResetToken(ctx, database.HashSessionToken(strings.TrimSpace(req.Token)))
	if err != nil {
		switch {
		case errors.Is(err, database.ErrTokenNotFound):
			writeError(c, http.StatusBadRequest, "重置链接无效")
		case errors.Is(err, database.ErrTokenExpired):
			writeError(c, http.StatusBadRequest, "重置链接已过期，请重新申请")
		case errors.Is(err, database.ErrTokenUsed):
			writeError(c, http.StatusBadRequest, "重置链接已被使用")
		default:
			writeInternalError(c, err)
		}
		return
	}
	newHash, err := database.HashPassword(req.NewPassword)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.SetUserPasswordHash(ctx, userID, newHash); err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.db.RevokeAllUserSessions(ctx, userID); err != nil {
		log.Printf("重置后吊销会话失败: user_id=%d err=%v", userID, err)
	}
	security.SecurityAuditLog("USER_PASSWORD_RESET_OK", "user_id="+strconv.FormatInt(userID, 10)+" ip="+security.SanitizeLog(c.ClientIP()))
	writeMessage(c, http.StatusOK, "密码已重置，请使用新密码登录")
}

// ==================== 会话管理 ====================

// ListMySessions GET /api/auth/sessions
func (h *Handler) ListMySessions(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	sessions, err := h.db.ListUserSessions(ctx, sess.UserID)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	now := time.Now()
	items := make([]gin.H, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, gin.H{
			"session_id": s.ID,
			"current":    s.ID == sess.ID,
			"ip":         s.IP,
			"user_agent": s.UserAgent,
			"created_at": s.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": s.ExpiresAt.UTC().Format(time.RFC3339),
			"active":     s.Valid(now),
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": items})
}

// RevokeSession POST /api/auth/sessions/:id/revoke
func (h *Handler) RevokeSession(c *gin.Context) {
	sess := sessionFromGin(c)
	if sess == nil {
		writeError(c, http.StatusUnauthorized, "未登录或会话已过期")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(c, http.StatusBadRequest, "无效的会话 ID")
		return
	}
	if id == sess.ID {
		writeError(c, http.StatusBadRequest, "不能吊销当前会话，请使用退出登录")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	if err := h.db.RevokeUserSession(ctx, sess.UserID, id); err != nil {
		writeInternalError(c, err)
		return
	}
	writeMessage(c, http.StatusOK, "会话已吊销")
}

// ==================== 校验 ====================

// validateUserPassword 校验密码强度；合法返回空串。
func validateUserPassword(password string) string {
	if len(password) < userPasswordMinLen {
		return fmt.Sprintf("密码长度至少 %d 位", userPasswordMinLen)
	}
	if len(password) > userPasswordMaxLen {
		return fmt.Sprintf("密码长度不能超过 %d 位", userPasswordMaxLen)
	}
	return ""
}

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

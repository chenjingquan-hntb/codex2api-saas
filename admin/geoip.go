package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// GeoIP 地区准入执行（P5 安全闸门）。
//
// 真实 IP 解析：统一走 gin 的 c.ClientIP()——它只在连接来自可信代理
// （CODEX_TRUSTED_PROXIES，见 main.go configureTrustedProxies）时才信任
// X-Forwarded-For 链，公网直连时伪造 XFF 无效，杜绝 IP 欺骗。
//
// 国家判定：Provider 为 maxmind（GeoIP2 Web Service，api_key 填
// `accountid:licensekey`）或 ipinfo（HTTP API）。结果按
// cache_ttl_minutes 内存缓存，避免每个请求打上游。
//
// 策略（fail-closed）：
//   - 未启用或 provider 为空：放行。
//   - 启用但 provider/api_key 缺失或解析失败：拒绝并记审计（安全优先，
//     管理员修正配置后自动恢复）。
//   - block 模式：国家在名单内 → 拒绝；allow 模式：国家不在名单内 → 拒绝。
//   - 内网/回环 IP 不适用地区策略，一律放行（开发与同机部署场景）。
//
// 覆盖范围：全部 /api/auth/* 门户端点（注册/登录/验证/重置/会话/密钥/钱包/用量）。

const (
	geoIPProviderMaxMind = "maxmind"
	geoIPProviderIPInfo  = "ipinfo"

	geoIPCacheMaxEntries = 50000
	geoIPResolveTimeout  = 8 * time.Second
)

var (
	maxMindCountryURLFmt = "https://geoip.maxmind.com/geoip/v2.1/country/%s"
	ipinfoCountryURLFmt  = "https://ipinfo.io/%s/json"
)

// geoipResolver 查询 IP 所属国家（ISO 3166-1 alpha-2，大写）；测试注入 stub。
type geoipResolver interface {
	CountryCode(ctx context.Context, provider, apiKey, ip string, cacheTTL time.Duration) (string, error)
}

// geoIPCacheEntry 单个 IP 的缓存条目。
type geoIPCacheEntry struct {
	code      string
	expiresAt time.Time
}

// geoIPCache 简单的 TTL 内存缓存；条目超限时整体重置（防无界增长）。
type geoIPCache struct {
	mu sync.Mutex
	m  map[string]geoIPCacheEntry
}

func newGeoIPCache() *geoIPCache {
	return &geoIPCache{m: make(map[string]geoIPCacheEntry)}
}

func (c *geoIPCache) get(ip string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ip]
	if !ok {
		return "", false
	}
	if now.After(e.expiresAt) {
		delete(c.m, ip)
		return "", false
	}
	return e.code, true
}

func (c *geoIPCache) set(ip, code string, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= geoIPCacheMaxEntries {
		c.m = make(map[string]geoIPCacheEntry)
	}
	c.m[ip] = geoIPCacheEntry{code: code, expiresAt: now.Add(ttl)}
}

// httpGeoIPResolver 生产实现：maxmind / ipinfo HTTP API + 共享缓存。
type httpGeoIPResolver struct {
	client *http.Client
	cache  *geoIPCache
}

func newHTTPGeoIPResolver() *httpGeoIPResolver {
	return &httpGeoIPResolver{
		client: &http.Client{Timeout: geoIPResolveTimeout},
		cache:  newGeoIPCache(),
	}
}

func (r *httpGeoIPResolver) CountryCode(ctx context.Context, provider, apiKey, ip string, cacheTTL time.Duration) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", errors.New("geoip: 空 IP")
	}
	now := time.Now()
	if code, ok := r.cache.get(ip, now); ok {
		return code, nil
	}
	var (
		code string
		err  error
	)
	switch provider {
	case geoIPProviderMaxMind:
		code, err = r.maxMindCountry(ctx, apiKey, ip)
	case geoIPProviderIPInfo:
		code, err = r.ipInfoCountry(ctx, apiKey, ip)
	default:
		return "", fmt.Errorf("geoip: 未知 provider %q", provider)
	}
	if err != nil {
		return "", err
	}
	r.cache.set(ip, code, cacheTTL, now)
	return code, nil
}

// maxMindCountry 调 GeoIP2 Web Service country 端点；
// api_key 格式为 `accountid:licensekey`（Basic Auth）。
func (r *httpGeoIPResolver) maxMindCountry(ctx context.Context, apiKey, ip string) (string, error) {
	acc, lic, ok := strings.Cut(strings.TrimSpace(apiKey), ":")
	if !ok || acc == "" || lic == "" {
		return "", errors.New("geoip: maxmind api_key 需为 accountid:licensekey 格式")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(maxMindCountryURLFmt, url.PathEscape(ip)), nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(acc, lic)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("geoip maxmind: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("geoip maxmind: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Country struct {
			ISOCode string `json:"iso_code"`
		} `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("geoip maxmind: 解析响应失败: %w", err)
	}
	return strings.ToUpper(strings.TrimSpace(out.Country.ISOCode)), nil
}

// ipInfoCountry 调 IPinfo country 端点；api_key 可选（无 key 有配额限制）。
func (r *httpGeoIPResolver) ipInfoCountry(ctx context.Context, apiKey, ip string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(ipinfoCountryURLFmt, url.PathEscape(ip)), nil)
	if err != nil {
		return "", err
	}
	if key := strings.TrimSpace(apiKey); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("geoip ipinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("geoip ipinfo: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("geoip ipinfo: 解析响应失败: %w", err)
	}
	return strings.ToUpper(strings.TrimSpace(out.Country)), nil
}

// isPrivateOrLoopback 报告 IP 是否为内网/回环地址（这些地址不适用地区策略）。
func isPrivateOrLoopback(ip string) bool {
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" ||
		strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.") || strings.HasPrefix(host, "169.254.")
}

// geoIPGate 返回一个中间件：GeoIP 启用时按配置执行地区准入。
func (h *Handler) geoIPGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || h.db == nil {
			writeError(c, http.StatusServiceUnavailable, "服务未就绪")
			c.Abort()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), geoIPResolveTimeout)
		defer cancel()
		cfg, err := h.db.LoadGeoIPConfig(ctx)
		if err != nil {
			writeInternalError(c, err)
			c.Abort()
			return
		}
		if !cfg.Enabled {
			c.Next()
			return
		}
		provider := strings.TrimSpace(cfg.Provider)
		if provider == "" {
			// 启用但未配置 provider：配置不完整视为不可用，拒绝（fail-closed）。
			security.SecurityAuditLog("GEOIP_NOT_CONFIGURED", "ip="+security.SanitizeLog(c.ClientIP()))
			writeError(c, http.StatusForbidden, "地区风控未完成配置，请联系管理员")
			c.Abort()
			return
		}
		ip := c.ClientIP()
		if isPrivateOrLoopback(ip) {
			c.Next() // 内网/回环不适用地区策略
			return
		}
		ttl := time.Duration(cfg.CacheTTLMinutes) * time.Minute
		code, err := h.geoipResolver.CountryCode(ctx, provider, cfg.APIKey, ip, ttl)
		if err != nil {
			security.SecurityAuditLog("GEOIP_RESOLVE_FAILED",
				"ip="+security.SanitizeLog(ip)+" provider="+provider+" err="+security.SanitizeLog(err.Error()))
			writeError(c, http.StatusServiceUnavailable, "地区校验服务暂不可用，请稍后再试")
			c.Abort()
			return
		}
		inList := false
		for _, cc := range cfg.Countries {
			if strings.EqualFold(strings.TrimSpace(cc), code) {
				inList = true
				break
			}
		}
		blocked := (cfg.Mode == "allow" && !inList) || (cfg.Mode != "allow" && inList)
		if blocked {
			security.SecurityAuditLog("GEOIP_BLOCKED",
				"ip="+security.SanitizeLog(ip)+" country="+code+" mode="+cfg.Mode+
					" path="+security.SanitizeLog(c.Request.URL.Path))
			writeError(c, http.StatusForbidden, "当前地区暂不提供服务")
			c.Abort()
			return
		}
		c.Next()
	}
}

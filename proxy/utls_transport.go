package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	xproxy "golang.org/x/net/proxy"

	"github.com/codex2api/security"
)

// ==================== utls RoundTripper（Chrome 指纹 + HTTP/2） ====================
//
// 设计要点：
//   - 使用 HelloChrome_Auto 模拟 Chrome 浏览器的 TLS 指纹
//   - 支持 HTTP/2 协议（与 OpenAI/Anthropic API 兼容）
//   - 连接池 + pending 管理：防止同一 host 重复创建连接
//   - 代理支持：HTTP(S) 和 SOCKS5

// 连接生命周期参数（issue #446）。
//
// 该 transport 自管 HTTP/2 连接池，不经标准库 *http.Transport，因此标准库的
// IdleConnTimeout 一概不生效——必须显式配到 http2.Transport 上，否则
// NewClientConn 不会安装空闲定时器（idleConnTimeout()==0 时直接跳过），
// 连接的 readLoop goroutine 会永久持有 socket 与缓冲区，既不关闭也无法 GC。
const (
	// codexUTLSIdleConnTimeout 是自管 HTTP/2 连接的空闲存活上限，
	// 与标准 transport 的 IdleConnTimeout 对齐。到点由 h2 自身的空闲定时器
	// 调用 closeIfIdle 回收，是所有回收路径的最终兜底。
	codexUTLSIdleConnTimeout = 90 * time.Second

	// utlsCloseIdleGrace 是 CloseIdleConnections 的保护窗口：连接从池中取出到
	// 真正发起 RoundTrip 之间存在无锁窗口，此时 h2 侧尚无任何 stream，看起来
	// 「空闲」。用最后交付时间兜住这个窗口，避免关掉刚被取走待用的连接。
	utlsCloseIdleGrace = 5 * time.Second
)

// utlsShutdownTimeout 返回优雅关闭时等待在途 stream 收尾的上限。
//
// 可在系统设置里调（utls_shutdown_timeout_minutes，默认 30 分钟）：流式回答
// 单回合可超过 10 分钟（issue #287），默认给足余量；超时才强制关闭，
// 保证异常挂死的 stream 不会把连接永久留住。
func utlsShutdownTimeout() time.Duration {
	return CurrentRuntimeSettings().UTLSShutdownTimeout()
}

// utlsConn 包装一条自管 HTTP/2 连接，并记录最后一次「交付给请求」的时间。
// h2 的 State() 只能反映当前 stream 数，无法区分「刚取出还没发请求」与
// 「已彻底空闲」，故额外记录时间戳做空闲判定。
type utlsConn struct {
	conn     *http2.ClientConn
	lastUsed atomic.Int64 // UnixNano
}

func (c *utlsConn) touch() {
	c.lastUsed.Store(time.Now().UnixNano())
}

// busy 报告连接上是否有在途请求（含已预留与排队等待的 stream）。
// 流式响应在 body 关闭前始终计入 StreamsActive，因此长回答不会被误判为空闲。
func (c *utlsConn) busy() bool {
	st := c.conn.State()
	return st.StreamsActive > 0 || st.StreamsReserved > 0 || st.StreamsPending > 0
}

// reclaimable 报告该连接可否安全关闭：无在途请求，且已过交付保护窗口。
func (c *utlsConn) reclaimable(now time.Time, grace time.Duration) bool {
	if c.busy() {
		return false
	}
	return now.Sub(time.Unix(0, c.lastUsed.Load())) >= grace
}

// utlsRoundTripper 实现 http.RoundTripper 接口
// 使用 utls 模拟 Chrome 浏览器的 TLS 指纹以绕过 TLS 指纹检测
type utlsRoundTripper struct {
	mu          sync.Mutex
	connections map[string]*utlsConn  // HTTP/2 连接池，按 host 索引
	pending     map[string]*sync.Cond // 防止重复连接创建
	dialer      xproxy.Dialer         // 底层拨号器（支持代理）
}

// utlsSessionCache 在所有 uTLS 连接间共享 TLS 会话缓存，让重连走 TLS resumption。
// 必须实例级共享（而非每次 new），否则缓存无法命中。
var utlsSessionCache = utls.NewLRUClientSessionCache(256)

// NewUTLSTransport 创建使用 Chrome TLS 指纹的 RoundTripper
// 支持 HTTP(S) 和 SOCKS5 代理
func NewUTLSTransport(proxyURL string) http.RoundTripper {
	var dialer xproxy.Dialer = xproxy.Direct

	if proxyURL != "" {
		d, err := buildProxyDialer(proxyURL)
		if err != nil {
			log.Printf("[UTLS] 代理配置失败，回退直连: proxy=%s err=%v", proxyURL, err)
			dialer = xproxy.Direct
		} else {
			dialer = d
		}
	}

	return &utlsRoundTripper{
		connections: make(map[string]*utlsConn),
		pending:     make(map[string]*sync.Cond),
		dialer:      dialer,
	}
}

// NewUTLSHttpClient 创建使用 Chrome TLS 指纹的 HTTP 客户端
func NewUTLSHttpClient(proxyURL string) *http.Client {
	return &http.Client{
		Transport: NewUTLSTransport(proxyURL),
		Timeout:   0, // 不设置全局超时，由请求上下文控制
	}
}

// buildProxyDialer 根据代理 URL 创建拨号器
func buildProxyDialer(proxyURL string) (xproxy.Dialer, error) {
	u, err := security.ParseProxyURL(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("解析代理 URL 失败: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return buildHTTPProxyDialer(u)
	case "socks5", "socks5h":
		return buildSOCKS5Dialer(u)
	default:
		return nil, fmt.Errorf("不支持的代理协议: %s", u.Scheme)
	}
}

// httpConnectDialer 通过 HTTP CONNECT 方法建立隧道的拨号器
type httpConnectDialer struct {
	proxyAddr  string // 代理服务器地址（host:port）
	authHeader string // Proxy-Authorization 头（可选）
}

// Dial 通过 HTTP CONNECT 隧道连接到目标地址
func (d *httpConnectDialer) Dial(network, addr string) (net.Conn, error) {
	// 1. 建立到代理服务器的 TCP 连接
	conn, err := net.DialTimeout("tcp", d.proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接代理服务器失败: %w", err)
	}

	// 2. 发送 CONNECT 请求建立隧道
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if d.authHeader != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: %s\r\n", d.authHeader)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %w", err)
	}

	// 3. 读取代理响应
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取代理响应失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("代理 CONNECT 失败 (status %d)", resp.StatusCode)
	}

	// bufio.Reader 可能缓冲了响应之后的字节，需要包装确保后续读取不丢失
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}

// bufferedConn 包装 net.Conn，优先读取 bufio.Reader 中的缓冲数据
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// buildHTTPProxyDialer 创建 HTTP CONNECT 代理拨号器
func buildHTTPProxyDialer(u *url.URL) (xproxy.Dialer, error) {
	addr := u.Host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	d := &httpConnectDialer{proxyAddr: addr}

	// 处理代理认证
	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		d.authHeader = "Basic " + credentials
	}

	return d, nil
}

// buildSOCKS5Dialer 创建 SOCKS5 代理拨号器
func buildSOCKS5Dialer(u *url.URL) (xproxy.Dialer, error) {
	var auth *xproxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &xproxy.Auth{
			User:     u.User.Username(),
			Password: password,
		}
	}

	return xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
}

// getOrCreateConnection 获取或创建 HTTP/2 连接
// 使用 sync.Cond 防止同一 host 的重复连接创建
//
// 返回前会 touch() 命中的连接：该时间戳是 CloseIdleConnections 的保护窗口依据，
// 防止连接在“已取出、尚未发 stream”的窗口里被当成空闲连接关掉。
func (t *utlsRoundTripper) getOrCreateConnection(host, addr string) (*utlsConn, error) {
	t.mu.Lock()

	// 检查是否已有可用连接
	if entry, ok := t.connections[host]; ok && entry.conn.CanTakeNewRequest() {
		entry.touch()
		t.mu.Unlock()
		return entry, nil
	}

	// 检查是否有其他 goroutine 正在创建连接
	if cond, ok := t.pending[host]; ok {
		// 等待其他 goroutine 完成（循环重试，避免虚假唤醒）
		for {
			cond.Wait()
			// 再次检查连接是否可用
			if entry, ok := t.connections[host]; ok && entry.conn.CanTakeNewRequest() {
				entry.touch()
				t.mu.Unlock()
				return entry, nil
			}
			// 如果 pending 已移除，说明创建完成（可能失败），跳出循环自己创建
			if _, still := t.pending[host]; !still {
				break
			}
		}
	}

	// 标记此 host 正在创建连接
	cond := sync.NewCond(&t.mu)
	t.pending[host] = cond
	t.mu.Unlock()

	// 在锁外创建连接
	h2Conn, err := t.createConnection(host, addr)

	t.mu.Lock()
	defer t.mu.Unlock()

	// 移除 pending 标记并唤醒一个等待者（Signal 而非 Broadcast，避免惊群）
	delete(t.pending, host)
	cond.Broadcast()

	if err != nil {
		return nil, err
	}

	// 旧连接已不可用（走到这里说明 CanTakeNewRequest()==false），但可能仍有
	// 在途 stream（例如已收 GOAWAY 但旧请求未完）。用 graceful shutdown 等它们
	// 收尾再关，不能直接 Close 掉——否则会把进行中的流式回答直接截断。
	if oldEntry, ok := t.connections[host]; ok {
		shutdownUTLSConn(oldEntry.conn)
	}

	// 存储新连接
	entry := &utlsConn{conn: h2Conn}
	entry.touch()
	t.connections[host] = entry
	return entry, nil
}

// shutdownUTLSConn 异步优雅关闭一条连接：先发 GOAWAY 并等在途 stream 收尾，
// 超时（或异常）后强制关闭。两路径都保证底层 socket 与 readLoop goroutine
// 最终被释放，不会像修复前那样泄漏（issue #446）。
func shutdownUTLSConn(conn *http2.ClientConn) {
	if conn == nil {
		return
	}
	timeout := utlsShutdownTimeout()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := conn.Shutdown(ctx); err != nil {
			// 超时/失败均强制关闭，宁可截断挂死请求也不能泄漏连接。
			_ = conn.Close()
		}
	}()
}

// createConnection 创建新的 HTTP/2 连接
// 使用 utls 的 HelloChrome_Auto 模拟 Chrome 浏览器的 TLS 指纹
func (t *utlsRoundTripper) createConnection(host, addr string) (*http2.ClientConn, error) {
	// 1. 建立 TCP 连接（通过代理或直连）
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP 连接失败: %w", err)
	}

	// 2. 配置 TLS（共享会话缓存，握手走 resumption 降低重连成本）
	tlsConfig := &utls.Config{
		ServerName:         host,
		ClientSessionCache: utlsSessionCache,
	}

	// 3. 使用 utls 握手（Chrome 指纹）
	tlsConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

	// 设置握手超时
	handshakeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS 握手失败: %w", err)
	}

	// 4. 创建 HTTP/2 连接
	// 启用保活 PING（ReadIdleTimeout/PingTimeout）：uTLS 自管连接池，池化连接
	// 被代理/NAT 静默掐断后无法被感知，请求会挂到 TCP 重传超时。开启后空闲连接
	// 主动发 PING，探测失败即在读循环里报错，触发上层从池中剔除并重建。
	//
	// IdleConnTimeout 必须显式设置：NewClientConn 仅在 idleConnTimeout()!=0 时安装
	// 空闲定时器（closeIfIdle）。缺失时连接永不自动回收，readLoop goroutine 与
	// socket 常驻，是 issue #446 万级连接/goroutine 泄漏的根因。
	//
	// Go 1.27 起 x/net/http2 将 http2.Transport 改为包裹 net/http.Transport，
	// NewClientConn 会经内部 t1 走标准库 NewClientConn；直接用 &http2.Transport{}
	// 时 t1 为 nil，会触发 nil pointer panic。必须通过 http2.ConfigureTransports
	// 拿到与底层 *http.Transport 绑定的实例（与 enableCodexHTTP2KeepAlive 同款）。
	t1 := &http.Transport{}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 配置失败: %w", err)
	}
	tr.ReadIdleTimeout = codexHTTP2ReadIdleTimeout
	tr.PingTimeout = codexHTTP2PingTimeout
	tr.IdleConnTimeout = codexUTLSIdleConnTimeout
	h2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 连接创建失败: %w", err)
	}

	return h2Conn, nil
}

// RoundTrip 实现 http.RoundTripper 接口
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// 获取主机名（不含端口）用于 TLS ServerName
	hostname := req.URL.Hostname()

	entry, err := t.getOrCreateConnection(hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := entry.conn.RoundTrip(req)
	if err != nil {
		// 连接失败，从缓存中移除并关闭连接
		t.mu.Lock()
		if cached, ok := t.connections[hostname]; ok && cached == entry {
			delete(t.connections, hostname)
		}
		t.mu.Unlock()
		// 关闭失败的连接，避免资源泄漏。已摘出池，同一连接上可能还有
		// 其他并发 stream（h2 多路复用），故走优雅关闭而非直接 Close，
		// 避免误杀邻居请求；超时后仍会强制关闭。
		shutdownUTLSConn(entry.conn)
		return nil, err
	}

	// 响应头已到，body 可能还在流式传输（stream 仍计入 StreamsActive）；
	// 刷新时间戳使空闲判定以“最后一次使用”为基准。
	entry.touch()
	return resp, nil
}

// CloseIdleConnections 关闭所有空闲连接。
//
// 判据是“连接上无在途 stream”，而不能用 CanTakeNewRequest()：后者对健康空闲
// 连接恒为 true，修复前的 !CanTakeNewRequest() 条件恰好把真正需要回收的空闲
// 连接全部跳过，导致上层 TTL 淘汰路径彻底失效（issue #446）。
func (t *utlsRoundTripper) CloseIdleConnections() {
	t.closeIdleConnections(utlsCloseIdleGrace)
}

func (t *utlsRoundTripper) closeIdleConnections(grace time.Duration) {
	now := time.Now()

	// 先在锁内摘除，再在锁外关闭：Close 会触发 h2 内部锁与回调，持锁关闭
	// 有自身与 RoundTrip 互锁的风险。
	var reclaimed []*http2.ClientConn
	t.mu.Lock()
	for host, entry := range t.connections {
		if entry.reclaimable(now, grace) {
			delete(t.connections, host)
			reclaimed = append(reclaimed, entry.conn)
		}
	}
	t.mu.Unlock()

	for _, conn := range reclaimed {
		_ = conn.Close()
	}
}

// CloseAllConnections 摘除并关闭该 transport 持有的全部连接。
//
// 给“这个 transport 不再被持有”的场景用（一次性 Client 用完、连接池 TTL 淘汰），
// 确保不留下无人回收的连接。在途 stream 走优雅关闭（等收尾），不截断正在
// 传输的响应体。
//
// 调用后 transport 仍可用（后续请求会重新拨号）：故意不做“永久毒化”，否则与
// 连接池淘汰存在竞争——刚被取走的 client 会直接报错。漏网的掉队请求新建的
// 连接由 IdleConnTimeout 兜底回收，不会无限积累。
func (t *utlsRoundTripper) CloseAllConnections() {
	t.mu.Lock()
	entries := make([]*utlsConn, 0, len(t.connections))
	for host, entry := range t.connections {
		entries = append(entries, entry)
		delete(t.connections, host)
	}
	t.mu.Unlock()

	for _, entry := range entries {
		if entry.busy() {
			shutdownUTLSConn(entry.conn)
			continue
		}
		_ = entry.conn.Close()
	}
}

// connCountForTest 返回当前池内连接数，仅测试断言用。
func (t *utlsRoundTripper) connCountForTest() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.connections)
}

// ==================== 兼容现有代码的封装 ====================

// uTLSHTTPClientWrapper 包装 utlsRoundTripper 以兼容现有的 http.Client 接口
type uTLSHTTPClientWrapper struct {
	transport *utlsRoundTripper
}

// NewUTLSClient 创建使用 Chrome TLS 指纹的 HTTP 客户端
// 返回包装后的客户端，支持 CloseIdleConnections
func NewUTLSClient(proxyURL string) *uTLSHTTPClientWrapper {
	rt := NewUTLSTransport(proxyURL).(*utlsRoundTripper)
	return &uTLSHTTPClientWrapper{
		transport: rt,
	}
}

// Do 执行 HTTP 请求
func (c *uTLSHTTPClientWrapper) Do(req *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(req)
}

// CloseIdleConnections 关闭空闲连接
func (c *uTLSHTTPClientWrapper) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

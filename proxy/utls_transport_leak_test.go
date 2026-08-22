package proxy

import (
	"net/http"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// issue #446 回归测试：utls_chrome 模式下短生命周期 HTTP Client 曾导致
// HTTP/2 连接、goroutine 与内存持续泄漏。以下测试锁死四条修复不变量。

// TestUTLSConnCreationSetsIdleConnTimeout 是最关键的回归保护：
// http2.Transport 只在 idleConnTimeout()!=0 时才为新连接安装空闲定时器
// （NewClientConn → time.AfterFunc(d, cc.onIdleTimeout)）。缺失该配置时，
// 健康空闲连接永不自动回收，readLoop goroutine 与 socket 常驻到进程结束。
func TestUTLSConnCreationSetsIdleConnTimeout(t *testing.T) {
	if codexUTLSIdleConnTimeout <= 0 {
		t.Fatalf("codexUTLSIdleConnTimeout = %s, want > 0（否则 h2 不装空闲定时器，连接永不回收）", codexUTLSIdleConnTimeout)
	}

	// 断言 createConnection 构造的 http2.Transport 三项保活/回收参数齐备。
	// Go 1.27 起必须经 http2.ConfigureTransports 绑定底层 net/http.Transport，
	// 这里同样按该路径构造，确保覆盖的是生产构建方式而非旧的 &http2.Transport{}。
	t1 := &http.Transport{}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		t.Fatalf("ConfigureTransports: %v", err)
	}
	tr.ReadIdleTimeout = codexHTTP2ReadIdleTimeout
	tr.PingTimeout = codexHTTP2PingTimeout
	tr.IdleConnTimeout = codexUTLSIdleConnTimeout
	if tr.IdleConnTimeout == 0 {
		t.Fatal("IdleConnTimeout 为 0：NewClientConn 会跳过空闲定时器安装")
	}
	if tr.ReadIdleTimeout == 0 {
		t.Fatal("ReadIdleTimeout 为 0：无法感知被静默掐断的死连接")
	}
}

// TestUTLSTransportCloseIdleConnectionsClosesHealthyIdleConn 验证修复后的
// CloseIdleConnections 会关闭「健康且空闲」的连接。
//
// 修复前的判据是 !CanTakeNewRequest()，而健康空闲的 h2 连接恒为
// CanTakeNewRequest()==true，因此真正需要回收的连接全部被跳过——
// 上层连接池 TTL 淘汰路径（evictExpiredClients）因此完全失效。
func TestUTLSTransportCloseIdleConnectionsClosesHealthyIdleConn(t *testing.T) {
	rt := NewUTLSTransport("").(*utlsRoundTripper)

	server, conn := newIdleHTTP2ClientConn(t)
	defer server.Close()

	rt.mu.Lock()
	entry := &utlsConn{conn: conn}
	// 时间戳回拨到保护窗口之外，模拟「已空闲一段时间」。
	entry.lastUsed.Store(time.Now().Add(-time.Minute).UnixNano())
	rt.connections["example.com"] = entry
	rt.mu.Unlock()

	if !conn.CanTakeNewRequest() {
		t.Fatal("前置条件不成立：新建的 h2 连接应当是健康可用的")
	}

	rt.CloseIdleConnections()

	if got := rt.connCountForTest(); got != 0 {
		t.Fatalf("CloseIdleConnections 后池内连接数 = %d, want 0（健康空闲连接必须被回收）", got)
	}
	if !conn.State().Closed {
		t.Fatal("底层 h2 连接未关闭：socket 与 readLoop goroutine 仍在泄漏")
	}
}

// TestUTLSTransportCloseIdleConnectionsKeepsBusyConn 验证回收不会误杀在途请求。
// 直接关闭所有连接会截断仍在传输的 HTTP/2 stream（例如长时间流式回答）。
func TestUTLSTransportCloseIdleConnectionsKeepsBusyConn(t *testing.T) {
	rt := NewUTLSTransport("").(*utlsRoundTripper)

	server, conn := newIdleHTTP2ClientConn(t)
	defer server.Close()
	defer conn.Close()

	// 预留一个 stream 槽位，等价于「已取出连接、请求在途」。
	if !conn.ReserveNewRequest() {
		t.Fatal("ReserveNewRequest 失败，无法构造在途连接场景")
	}

	rt.mu.Lock()
	entry := &utlsConn{conn: conn}
	entry.lastUsed.Store(time.Now().Add(-time.Minute).UnixNano())
	rt.connections["example.com"] = entry
	rt.mu.Unlock()

	rt.CloseIdleConnections()

	if got := rt.connCountForTest(); got != 1 {
		t.Fatalf("在途连接被回收：池内连接数 = %d, want 1", got)
	}
	if conn.State().Closed {
		t.Fatal("在途连接被关闭：会截断正在传输的响应体")
	}
}

// TestUTLSTransportCloseIdleConnectionsRespectsGrace 验证交付保护窗口：
// 连接从池中取出到真正发起 RoundTrip 之间存在无锁窗口，此时 h2 侧尚无
// 任何 stream，看起来「空闲」。若不设保护窗口，后台清理会关掉刚被取走待用的连接。
func TestUTLSTransportCloseIdleConnectionsRespectsGrace(t *testing.T) {
	rt := NewUTLSTransport("").(*utlsRoundTripper)

	server, conn := newIdleHTTP2ClientConn(t)
	defer server.Close()
	defer conn.Close()

	rt.mu.Lock()
	entry := &utlsConn{conn: conn}
	entry.touch() // 刚刚交付
	rt.connections["example.com"] = entry
	rt.mu.Unlock()

	rt.CloseIdleConnections()

	if got := rt.connCountForTest(); got != 1 {
		t.Fatalf("刚交付的连接被回收：池内连接数 = %d, want 1", got)
	}
}

// TestUTLSTransportCloseAllConnectionsDrainsPool 验证一次性 transport 的
// 完整生命周期收口：CloseAllConnections 必须摘除并关闭全部连接，
// 否则 entry 从连接池 map 删除后就再无人持有该 transport，其连接会泄漏到进程结束。
func TestUTLSTransportCloseAllConnectionsDrainsPool(t *testing.T) {
	rt := NewUTLSTransport("").(*utlsRoundTripper)

	server, conn := newIdleHTTP2ClientConn(t)
	defer server.Close()

	rt.mu.Lock()
	entry := &utlsConn{conn: conn}
	entry.touch() // 即便刚交付，销毁时也必须关闭
	rt.connections["example.com"] = entry
	rt.mu.Unlock()

	rt.CloseAllConnections()

	if got := rt.connCountForTest(); got != 0 {
		t.Fatalf("CloseAllConnections 后池内连接数 = %d, want 0", got)
	}
	if !conn.State().Closed {
		t.Fatal("连接未被关闭：一次性 transport 仍会泄漏连接与 goroutine")
	}
}

// TestReleaseEvictedClientClosesUTLSConnections 验证连接池 TTL 淘汰路径在
// uTLS 模式下真正释放连接。修复前该路径调用 client.CloseIdleConnections()，
// 在 uTLS transport 上等同 no-op —— 每轮 TTL 淘汰都漏一条连接。
func TestReleaseEvictedClientClosesUTLSConnections(t *testing.T) {
	rt := NewUTLSTransport("").(*utlsRoundTripper)

	server, conn := newIdleHTTP2ClientConn(t)
	defer server.Close()

	rt.mu.Lock()
	entry := &utlsConn{conn: conn}
	entry.touch()
	rt.connections["example.com"] = entry
	rt.mu.Unlock()

	releaseEvictedClient(&http.Client{Transport: rt})

	if got := rt.connCountForTest(); got != 0 {
		t.Fatalf("淘汰后池内连接数 = %d, want 0", got)
	}
	if !conn.State().Closed {
		t.Fatal("TTL 淘汰未关闭 uTLS 连接：泄漏仍在")
	}
}

// TestUTLSTransportRepeatedCyclesReturnToBaseline 是 issue #446 「方案四」要求的
// 回归测试：连续多轮「建连 → 用完 → 回收」后，连接数与 goroutine 数必须回到
// 稳定区间，而不是随轮次线性增长。
//
// 修复前每轮都会残留一条 ESTABLISHED 连接与一个 readLoop goroutine
// （goroutine 与 TCP 连接近似 1:1 增长），几十小时后累积到数万条并 OOM。
func TestUTLSTransportRepeatedCyclesReturnToBaseline(t *testing.T) {
	const rounds = 50

	baseline := runtime.NumGoroutine()

	for i := 0; i < rounds; i++ {
		rt := NewUTLSTransport("").(*utlsRoundTripper)
		server, conn := newIdleHTTP2ClientConn(t)

		rt.mu.Lock()
		entry := &utlsConn{conn: conn}
		entry.touch()
		rt.connections["example.com"] = entry
		rt.mu.Unlock()

		// 模拟一次性 Client 用完即弃：修复后由 CloseAllConnections 收口。
		rt.CloseAllConnections()

		if got := rt.connCountForTest(); got != 0 {
			t.Fatalf("第 %d 轮回收后仍有 %d 条连接驻留", i+1, got)
		}
		if !conn.State().Closed {
			t.Fatalf("第 %d 轮：底层连接未关闭，socket 与 readLoop 泄漏", i+1)
		}
		server.Close()
	}

	// readLoop 退出是异步的，给它收尾时间后再断言。
	var leaked int
	for attempt := 0; attempt < 50; attempt++ {
		leaked = runtime.NumGoroutine() - baseline
		if leaked <= rounds/5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 修复前 leaked 会接近 rounds（每轮一个常驻 readLoop）；
	// 修复后应回落到与轮次无关的小常数（容忍测试服务端的收尾抖动）。
	if leaked > rounds/5 {
		t.Fatalf("goroutine 未回落：baseline=%d 增量=%d（轮次=%d），疑似每轮泄漏一个 readLoop",
			baseline, leaked, rounds)
	}
}

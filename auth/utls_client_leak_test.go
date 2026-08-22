package auth

import (
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func newIdleAuthHTTP2ClientConn(t *testing.T) (*http.Server, net.Listener, *http2.ClientConn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), &http2.Server{}),
	}
	go func() { _ = server.Serve(listener) }()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = server.Close()
		_ = listener.Close()
		t.Fatalf("dial: %v", err)
	}

	// Go 1.27 起 http2.Transport 包裹 net/http.Transport，NewClientConn 经内部
	// t1 走标准库；直接 &http2.Transport{} 会因 t1 为 nil 而 panic，需先
	// ConfigureTransports 绑定底层 transport。
	t1 := &http.Transport{}
	transport, err := http2.ConfigureTransports(t1)
	if err != nil {
		_ = rawConn.Close()
		_ = server.Close()
		_ = listener.Close()
		t.Fatalf("ConfigureTransports: %v", err)
	}
	transport.AllowHTTP = true
	clientConn, err := transport.NewClientConn(rawConn)
	if err != nil {
		_ = rawConn.Close()
		_ = server.Close()
		_ = listener.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	return server, listener, clientConn
}

func TestEvictExpiredUTLSAuthClientClosesHealthyIdleConnection(t *testing.T) {
	const poolKey = "test://expired-auth-client"
	defer utlsAuthClientPool.Delete(poolKey)

	server, listener, conn := newIdleAuthHTTP2ClientConn(t)
	defer server.Close()
	defer listener.Close()
	defer conn.Close()

	transport := newUTLSAuthTransport("").(*utlsAuthRoundTripper)
	transport.mu.Lock()
	transport.connections["example.test"] = conn
	transport.mu.Unlock()

	if !conn.CanTakeNewRequest() {
		t.Fatal("前置条件不成立：新建的 HTTP/2 连接应为健康空闲状态")
	}

	entry := &utlsAuthPoolEntry{
		client: &http.Client{Transport: transport},
	}
	entry.lastUsed.Store(time.Now().Add(-utlsAuthClientPoolTTL - time.Minute).UnixNano())
	utlsAuthClientPool.Store(poolKey, entry)

	evictExpiredUTLSAuthClients()

	if _, ok := utlsAuthClientPool.Load(poolKey); ok {
		t.Fatal("过期认证客户端仍在连接池中")
	}
	if !conn.State().Closed {
		t.Fatal("健康空闲 HTTP/2 连接未关闭：socket、readLoop goroutine 和缓冲区会继续驻留")
	}
}

func TestUTLSAuthCloseIdleConnectionsKeepsBusyConnection(t *testing.T) {
	server, listener, conn := newIdleAuthHTTP2ClientConn(t)
	defer server.Close()
	defer listener.Close()
	defer conn.Close()

	if !conn.ReserveNewRequest() {
		t.Fatal("ReserveNewRequest failed")
	}

	transport := newUTLSAuthTransport("").(*utlsAuthRoundTripper)
	transport.mu.Lock()
	transport.connections["example.test"] = conn
	transport.mu.Unlock()

	transport.CloseIdleConnections()

	transport.mu.Lock()
	_, exists := transport.connections["example.test"]
	transport.mu.Unlock()
	if !exists {
		t.Fatal("在途 HTTP/2 连接被当成空闲连接移除")
	}
	if conn.State().Closed {
		t.Fatal("在途 HTTP/2 连接被关闭")
	}
}

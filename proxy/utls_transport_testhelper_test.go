package proxy

import (
	"net"
	"net/http"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// h2TestServer 是一个明文 HTTP/2（h2c）测试服务端，用于构造真实的
// *http2.ClientConn —— 连接生命周期的断言必须打在真连接上，
// mock 无法复现 readLoop / 空闲定时器 / stream 计数等关键行为。
type h2TestServer struct {
	listener net.Listener
	server   *http.Server
}

func (s *h2TestServer) Close() {
	_ = s.server.Close()
	_ = s.listener.Close()
}

// newIdleHTTP2ClientConn 起一个本地 h2c 服务端并返回一条已完成握手、
// 当前处于空闲状态（无任何 stream）的客户端连接。
//
// 连接由调用方负责关闭（或交给被测代码关闭后断言其状态）。
func newIdleHTTP2ClientConn(t *testing.T) (*h2TestServer, *http2.ClientConn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h2s := &http2.Server{}
	handler := h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), h2s)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(listener) }()

	server := &h2TestServer{listener: listener, server: srv}

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("dial: %v", err)
	}

	// 与 createConnection 保持同款配置，确保测试覆盖的是生产路径的参数。
	// 注意：Go 1.27 起 http2.Transport 包裹 net/http.Transport，必须经
	// http2.ConfigureTransports 绑定底层 transport，否则 NewClientConn 会
	// 因内部 t1 为 nil 而 panic。
	t1 := &http.Transport{}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		_ = rawConn.Close()
		server.Close()
		t.Fatalf("ConfigureTransports: %v", err)
	}
	tr.ReadIdleTimeout = codexHTTP2ReadIdleTimeout
	tr.PingTimeout = codexHTTP2PingTimeout
	tr.IdleConnTimeout = codexUTLSIdleConnTimeout
	tr.AllowHTTP = true
	clientConn, err := tr.NewClientConn(rawConn)
	if err != nil {
		_ = rawConn.Close()
		server.Close()
		t.Fatalf("NewClientConn: %v", err)
	}

	return server, clientConn
}

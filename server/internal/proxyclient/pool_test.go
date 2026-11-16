// Pool / PoolSet 单测（后端架构 §15.4 连接生命周期表）：惰性建连、Transport
// 恒同与超时独立、Dialer 按 scheme 分流、池级空闲常量、PoolSet 同 key 同池 /
// 配置变更换池并排空旧池 / 并发安全，以及池层统一兜底（死连接换连重放、新拨
// 失败不重试）。
package proxyclient

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// closerListener 计数 accept 并立即断开的桩：模拟「代理不可达」——每次拨号
// 恰好产生一次 accept，握手即失败。
type closerListener struct {
	mu      sync.Mutex
	ln      net.Listener
	accepts int
	done    chan struct{}
}

func newCloserListener(t *testing.T) *closerListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &closerListener{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(cl.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cl.mu.Lock()
			cl.accepts++
			cl.mu.Unlock()
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-cl.done })
	return cl
}

func (l *closerListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accepts
}

func (l *closerListener) addr() (string, int32) {
	return splitAddr(l.ln.Addr().String())
}

// splitAddr "host:port" → (host, int32 port)。
func splitAddr(addr string) (string, int32) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(p)
	return h, int32(port)
}

// waitFor 轮询等待异步事件（对端建连 / 观测连接关闭），超时判失败。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// TestPoolLazyConnect 池创建（经 PoolSet.Get）只建 Transport 不拨号：构造后
// 与取 client / dialer 后桩 accept 数恒为 0，首个请求才建连。
func TestPoolLazyConnect(t *testing.T) {
	cl := newCloserListener(t)
	host, port := cl.addr()
	cfg, err := NewConfig("socks5", host, port, "", "")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPoolSet().Get("k", cfg)
	if n := cl.count(); n != 0 {
		t.Fatalf("池创建即拨号：accept = %d", n)
	}
	_ = p.HTTPClient(time.Second)
	_ = p.Dialer()
	if n := cl.count(); n != 0 {
		t.Fatalf("构造 client / dialer 即拨号：accept = %d", n)
	}
	if _, err := p.HTTPClient(time.Second).Get("http://example.invalid/probe"); err == nil {
		t.Fatal("代理桩 accept 即断，请求应失败")
	}
	waitFor(t, "首请求建连", func() bool { return cl.count() >= 1 })
}

// TestPoolHTTPClientSharedTransport 同池多次取 client：Transport 恒同（连接
// 复用）、Client 实例独立、timeout 按调用方各自生效；池级空闲常量唯一定义
// 在池上；直连池 Transport 为 nil（沿用默认 Transport，不另建池）。
func TestPoolHTTPClientSharedTransport(t *testing.T) {
	cfg, err := NewConfig("http", "127.0.0.1", 8080, "", "")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPoolSet().Get("k", cfg)
	c1 := p.HTTPClient(time.Second)
	c2 := p.HTTPClient(3 * time.Second)
	if c1 == c2 {
		t.Fatal("client 实例应独立")
	}
	tr, ok := c1.Transport.(*http.Transport)
	if !ok || tr != c2.Transport {
		t.Fatalf("Transport 应恒同且为 *http.Transport：c1=%T c2=%T", c1.Transport, c2.Transport)
	}
	if c1.Timeout != time.Second || c2.Timeout != 3*time.Second {
		t.Fatalf("timeout = %v / %v, want 1s / 3s", c1.Timeout, c2.Timeout)
	}
	if tr.IdleConnTimeout != poolIdleConnTimeout ||
		tr.MaxIdleConnsPerHost != poolMaxIdleConnsPerHost ||
		tr.MaxIdleConns != poolMaxIdleConns {
		t.Fatalf("池级常量不符: idle=%v perHost=%d max=%d",
			tr.IdleConnTimeout, tr.MaxIdleConnsPerHost, tr.MaxIdleConns)
	}
	dc := NewPoolSet().Get("direct", Config{}).HTTPClient(time.Second)
	if dc.Transport != nil {
		t.Fatalf("直连池 Transport = %T, want nil（默认 Transport）", dc.Transport)
	}
}

// TestPoolDialerSchemeDispatch SMTP 拨号器按 scheme 分流：socks5 返回代理
// 拨号器；http/https 与直连（零值配置）按静默失效口径返回 net.Dialer。
func TestPoolDialerSchemeDispatch(t *testing.T) {
	socksCfg, _ := NewConfig("socks5", "127.0.0.1", 1080, "u", "p")
	httpCfg, _ := NewConfig("http", "127.0.0.1", 8080, "", "")
	httpsCfg, _ := NewConfig("https", "127.0.0.1", 8443, "", "")
	ps := NewPoolSet()
	socks := ps.Get("s", socksCfg).Dialer()
	if socks == nil {
		t.Fatal("socks5 拨号器为空")
	}
	if _, ok := socks.(*net.Dialer); ok {
		t.Fatal("socks5 池不应返回 net.Dialer")
	}
	for name, cfg := range map[string]Config{"http": httpCfg, "https": httpsCfg, "直连": {}} {
		d := ps.Get(name, cfg).Dialer()
		if nd, ok := d.(*net.Dialer); !ok || nd == nil {
			t.Fatalf("%s 池应返回 net.Dialer, got %T", name, d)
		}
	}
}

// TestPoolSetGet 同 key 同 cfg 命中同池；cfg 变更换新池；换池后旧配置再次
// 请求得到新池；不同 key 互不共享。
func TestPoolSetGet(t *testing.T) {
	ps := NewPoolSet()
	c1, _ := NewConfig("socks5", "127.0.0.1", 1080, "", "")
	c2, _ := NewConfig("socks5", "127.0.0.1", 1081, "", "")
	p1 := ps.Get("k", c1)
	if p2 := ps.Get("k", c1); p1 != p2 {
		t.Fatal("同 key 同 cfg 应命中同池")
	}
	if !p1.Config().Equal(c1) {
		t.Fatalf("池应持有其配置: %+v", p1.Config())
	}
	p2 := ps.Get("k", c2)
	if p2 == p1 {
		t.Fatal("cfg 变更应换池")
	}
	if p3 := ps.Get("k", c1); p3 == p1 || p3 == p2 {
		t.Fatal("换池后旧配置再次请求应得到新池")
	}
	a := ps.Get("a", c1)
	b := ps.Get("b", c1)
	if a == b {
		t.Fatal("不同 key 互不共享")
	}
}

// drainableOrigin 恒应答源（兼作 http 代理桩）：记录 accept 数与对端观测到
// 的连接关闭数，供「换池排空旧池」断言。
type drainableOrigin struct {
	ln       net.Listener
	srv      *http.Server
	mu       sync.Mutex
	accepted int
	closed   int
}

func newDrainableOrigin(t *testing.T) *drainableOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &drainableOrigin{ln: ln}
	o.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "OK")
		}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			o.mu.Lock()
			defer o.mu.Unlock()
			switch s {
			case http.StateNew:
				o.accepted++
			case http.StateClosed:
				o.closed++
			}
		},
	}
	go func() { _ = o.srv.Serve(ln) }()
	t.Cleanup(func() { _ = o.srv.Close() })
	return o
}

func (o *drainableOrigin) stats() (accepted, closed int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.accepted, o.closed
}

func (o *drainableOrigin) addr() (string, int32) {
	return splitAddr(o.ln.Addr().String())
}

// TestPoolSetSwapDrainsOldPool cfg 变更换池：旧池空闲连接被排空（对端观测到
// 连接关闭，在途请求自然收尾），新池下一次构造即生效。
func TestPoolSetSwapDrainsOldPool(t *testing.T) {
	o := newDrainableOrigin(t)
	host, port := o.addr()
	c1, err := NewConfig("http", host, port, "", "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewConfig("http", host, port+1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPoolSet()
	old := ps.Get("k", c1)
	resp, err := old.HTTPClient(3 * time.Second).Get("http://example.invalid/probe")
	if err != nil {
		t.Fatalf("经代理桩 GET: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	waitFor(t, "空闲连接进入旧池", func() bool { a, _ := o.stats(); return a >= 1 })

	ps.Get("k", c2) // 换池：旧池 closeIdle
	waitFor(t, "旧池空闲连接被排空", func() bool { _, c := o.stats(); return c >= 1 })
}

// TestPoolSetConcurrent 并发 Get：同 key 并发取池全部命中同一实例（-race 下
// 验证锁正确），不同 key 并发建池互不串扰。
func TestPoolSetConcurrent(t *testing.T) {
	ps := NewPoolSet()
	cfg, _ := NewConfig("socks5", "127.0.0.1", 1080, "", "")
	const n = 64
	same := make([]*Pool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			same[i] = ps.Get("k", cfg)
		}(i)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ps.Get(strconv.Itoa(i), cfg)
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if same[i] != same[0] {
			t.Fatalf("并发 Get 同 key 得到不同池: %d", i)
		}
	}
}

// TestPoolReplayAfterDeadIdleConn 死连接换连重放（池层统一兜底，§15.4）：
// 空闲连接被对端关闭后，可重放请求（GET）自动废弃死连接并新拨重放成功，
// 业务方无需自带重试。
func TestPoolReplayAfterDeadIdleConn(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK")
	}))
	t.Cleanup(proxy.Close)

	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port := u.Hostname(), u.Port()
	portNum, _ := strconv.Atoi(port)
	cfg, err := NewConfig("http", host, int32(portNum), "", "")
	if err != nil {
		t.Fatal(err)
	}
	cl := NewPoolSet().Get("k", cfg).HTTPClient(3 * time.Second)

	for i := 0; i < 2; i++ {
		if i == 1 {
			proxy.CloseClientConnections() // 排空对端：池内空闲连接变死连接
		}
		resp, err := cl.Get("http://example.invalid/probe")
		if err != nil {
			t.Fatalf("第 %d 次请求: %v", i+1, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	// 两次请求均到达桩：第一次建连，第二次在死连接上换连重放（新连接）。
}

// TestPoolNoRetryOnNewDialFailure 新拨失败不重试（fail-fast，§15.4）：代理桩
// accept 即断，一次请求恰好一次拨号，不因失败产生第二次 accept；错误一次
// 上抛，池层不掩盖代理故障。
func TestPoolNoRetryOnNewDialFailure(t *testing.T) {
	cl := newCloserListener(t)
	host, port := cl.addr()
	cfg, err := NewConfig("socks5", host, port, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPoolSet().Get("k", cfg)
	if _, err := p.HTTPClient(3 * time.Second).Get("http://example.invalid/probe"); err == nil {
		t.Fatal("代理不可达应失败")
	}
	if n := cl.count(); n != 1 {
		t.Fatalf("新拨失败被重试：accept = %d, want 1", n)
	}
}

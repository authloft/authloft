// Package proxyclient 是 Provider 出站代理的单一包边界（docs/后端架构.md §15.4）：
// 解析、校验与 client 构造都收口在这里，golang.org/x/net/proxy 只在本文件 import。
// 适配器 / Sender / service / handler 只消费 Parse / HTTPClient / Dialer，不直接
// 依赖具体代理库、不各自拼装 http.Transport，也不改写 http.DefaultTransport /
// 设包级单例 client / 注入全局。
package proxyclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/proxy"
)

const (
	// maxRawLen 拼串长度上限（字节，UTF-8）：Parse 原串与 NewConfig 拼串共用，
	// 抑制日志 / 错误串膨胀（接口文档 §5.3 代理提供商与出站代理引用约定）。
	maxRawLen = 512
)

// 可判别错误：错误串只报错误类别，绝不含完整 URL 或 userinfo 凭据（脱敏，
// 接口文档 §5.3 / 后端架构 §15.4 / CODE_GUIDE §3.7）。
var (
	ErrMalformedURL      = errors.New("proxyclient: malformed URL")
	ErrUnsupportedScheme = errors.New("proxyclient: unsupported scheme")
	ErrMissingHost       = errors.New("proxyclient: missing host")
	ErrInvalidPort       = errors.New("proxyclient: invalid port")
	ErrUnexpectedPath    = errors.New("proxyclient: path/query/fragment not allowed")
	ErrInvalidUserinfo   = errors.New("proxyclient: invalid userinfo")
	ErrTooLong           = errors.New("proxyclient: URL too long")
	ErrDialerBuild       = errors.New("proxyclient: build dialer failed")
)

// Config 一条已校验的代理配置。Scheme 为空串表示直连（唯一的「不代理」表示），
// 其余字段为零值；Host / Port / User / Password 是解码后的语义值，u 为原始解析
// 结果（保留百分号编码），供 FromURL / ProxyURL 直接复用。
type Config struct {
	Scheme   string
	Host     string
	Port     int
	User     string
	Password string
	HasAuth  bool
	u        *url.URL
}

// Direct 报告配置是否为「直连」（空串 / 纯空白）。
func (c Config) Direct() bool { return c.Scheme == "" }

// Parse 按接口文档 §5.3 代理字段约定解析并校验 `<scheme>://[USER:PASSWORD@]HOST:PORT`：
// 空串（trim 后）返回直连 Config；scheme 封闭 socks5/http/https 且全小写；
// 禁 path/query/fragment；HOST 必填、PORT 十进制 1..65535；userinfo 可选且 USER
// 非空、PASSWORD 可空；整串 ≤512 字节。错误可判别、不含完整 URL 与凭据。
func Parse(raw string) (Config, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Config{}, nil
	}
	if len(s) > maxRawLen {
		return Config{}, ErrTooLong
	}
	sep := strings.Index(s, "://")
	if sep <= 0 {
		return Config{}, ErrMalformedURL
	}
	scheme := s[:sep]
	if scheme != strings.ToLower(scheme) {
		return Config{}, ErrUnsupportedScheme // 封闭集全小写
	}
	switch scheme {
	case "socks5", "http", "https":
	default:
		return Config{}, ErrUnsupportedScheme
	}

	u, err := url.Parse(s)
	if err != nil {
		return Config{}, ErrMalformedURL
	}
	// url.Parse 对尾部孤立 '#' / '?' 不设 Fragment / RawQuery，再按原始串拦一道；
	// 百分号编码的保留字符（如 userinfo 的 %2F）是字面量、不构成分隔符，不误伤。
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.RawFragment != "" || u.ForceQuery || strings.ContainsAny(s[sep+3:], "/?#") {
		return Config{}, ErrUnexpectedPath
	}

	host := u.Hostname()
	if host == "" {
		return Config{}, ErrMissingHost
	}
	portStr := u.Port()
	if portStr == "" {
		return Config{}, ErrInvalidPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, ErrInvalidPort
	}

	cfg := Config{Scheme: scheme, Host: host, Port: port, u: u}
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		if user == "" {
			return Config{}, ErrInvalidUserinfo
		}
		cfg.User, cfg.Password, cfg.HasAuth = user, pass, true
	}
	return cfg, nil
}

// ContextDialer 与 http.Transport.DialContext / SMTP Sender.dialContext 同形态的
// 拨号器；本包不向调用方泄漏 x/net/proxy 的具体类型（单一依赖点，§15.4）。
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// HTTPClient 按 scheme 构造出站 client：socks5 走 x/net/proxy 取 ContextDialer
// 赋给 Transport.DialContext；http/https 走标准库 http.ProxyURL；空串返回直连
// client（沿用 http.DefaultTransport、不构造代理 Transport）。timeout 由调用方
// 传其既有默认值，代理配置不引入新的超时来源（§15.4）。
func HTTPClient(raw string, timeout time.Duration) (*http.Client, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if cfg.Direct() {
		return &http.Client{Timeout: timeout}, nil
	}
	tr := &http.Transport{}
	switch cfg.Scheme {
	case "socks5":
		d, err := Dialer(raw)
		if err != nil {
			return nil, err
		}
		tr.DialContext = d.DialContext
	case "http", "https":
		tr.Proxy = http.ProxyURL(cfg.u)
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// Dialer 供 SMTP（socks5）拨号复用：socks5 取 x/net/proxy 的 ContextDialer；
// http/https 与空串按 §15.4「http/https 对 SMTP 静默失效、按直连拨号」返回
// net.Dialer（不报错、不降级提示）。构造失败返回 ErrDialerBuild，不含 URL。
func Dialer(raw string) (ContextDialer, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if cfg.Direct() || cfg.Scheme != "socks5" {
		return &net.Dialer{}, nil
	}
	d, err := proxy.FromURL(cfg.u, proxy.Direct)
	if err != nil {
		return nil, ErrDialerBuild
	}
	cd, ok := d.(ContextDialer)
	if !ok {
		return nil, ErrDialerBuild
	}
	return cd, nil
}

// 编译期断言：标准库直连拨号器满足本包对外接口。
var _ ContextDialer = (*net.Dialer)(nil)

// NewConfig 从结构化字段构造并校验代理配置（后端架构 §15.4 单一规则源）：
// scheme 封闭 socks5/http/https 全小写；host trim 后必填、禁空白与 /?#@[]
// 任一字符（IPv6 直接写 ::1 形态，含 : 由本函数按 IPv6 字面量补 []）；port
// 1..65535；password 非空而 user 为空拒绝；user 非空时按 RFC 3986 编码为
// userinfo（管理员原文输入，无需手工编码）；拼串 ≤512B。admin 保存期组合
// 校验与运行期引用解析共用本函数，无第二套规则。NewConfig 不产生直连配置
// （proxy 行五字段必填齐全，直连只存在于引用侧 key 为空）；零值 Config 仍
// 表示直连，仅类型零值场景使用。错误可判别、不含字段值与凭据。
func NewConfig(scheme, host string, port int32, user, password string) (Config, error) {
	switch scheme {
	case "socks5", "http", "https":
	default:
		return Config{}, ErrUnsupportedScheme
	}
	h := strings.TrimSpace(host)
	if h == "" {
		return Config{}, ErrMissingHost
	}
	if strings.ContainsFunc(h, unicode.IsSpace) || strings.ContainsAny(h, "/?#@[]") {
		return Config{}, ErrMalformedURL
	}
	if port < 1 || port > 65535 {
		return Config{}, ErrInvalidPort
	}
	if user == "" && password != "" {
		return Config{}, ErrInvalidUserinfo
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(h, strconv.Itoa(int(port))), // 含 : 的 IPv6 字面量在此补 []
	}
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	if len(u.String()) > maxRawLen {
		return Config{}, ErrTooLong
	}
	return Config{
		Scheme:   scheme,
		Host:     h,
		Port:     int(port),
		User:     user,
		Password: password,
		HasAuth:  user != "",
		u:        u,
	}, nil
}

// Equal 按语义字段比对两份配置（不比解析出的 u），供 PoolSet 判定配置是否
// 变更（换池依据，§15.4）。
func (c Config) Equal(o Config) bool {
	return c.Scheme == o.Scheme && c.Host == o.Host && c.Port == o.Port &&
		c.User == o.User && c.Password == o.Password && c.HasAuth == o.HasAuth
}

// 池级空闲回收常量（§15.4 连接生命周期表）：空闲连接 5 分钟回收，每 host
// 最多留存 4 条、全池上限 64 条。不改变请求级超时口径——调用方 timeout
// 原样传入，不引入新的超时来源。
const (
	poolIdleConnTimeout     = 5 * time.Minute
	poolMaxIdleConnsPerHost = 4
	poolMaxIdleConns        = 64
)

// Pool 一个出站连接池：一份已校验配置 + 配套共享 Transport（§15.4）。
//
// 连接生命周期：惰性建连——构造只建 Transport 不拨号，首个请求才建连，无
// 后台连接协程；断开不自动重连——无健康检查 / 保活探测 / 重连循环，空闲
// 连接被对端关闭后原样留存，使用时由标准库对可重放请求透明换连重放（新拨
// 失败 fail-fast 不重试，不掩盖代理故障）；空闲连接经 IdleConnTimeout 回收。
//
// 零值配置 = 直连池：Transport 为 nil，沿用 http.DefaultTransport 的进程级
// 复用，不另建连接池。机制不限 proxy，非 proxy provider 可经同一入口持池。
type Pool struct {
	cfg    Config
	tr     *http.Transport // nil = 直连池
	dialer ContextDialer   // socks5 代理拨号器；直连与 http/https 恒 nil
}

// newPool 构造池（PoolSet 内部入口）：cfg 恒为 NewConfig 产物或零值。
func newPool(cfg Config) *Pool {
	p := &Pool{cfg: cfg}
	if cfg.Direct() {
		return p
	}
	tr := &http.Transport{
		IdleConnTimeout:     poolIdleConnTimeout,
		MaxIdleConnsPerHost: poolMaxIdleConnsPerHost,
		MaxIdleConns:        poolMaxIdleConns,
	}
	switch cfg.Scheme {
	case "socks5":
		d, err := proxy.FromURL(cfg.u, proxy.Direct)
		// 不可达分支：cfg 恒经 NewConfig 校验且 scheme 恒 socks5，FromURL 仅
		// 对未注册 scheme 报错。构造失败若按直连兜底会静默绕过代理，故
		// fail-fast 暴露装配缺陷，不做静默降级。
		if err != nil {
			panic("proxyclient: build socks5 dialer: " + err.Error())
		}
		cd, ok := d.(ContextDialer)
		if !ok {
			panic("proxyclient: socks5 dialer not ContextDialer")
		}
		p.dialer = cd
		tr.DialContext = cd.DialContext
	case "http", "https":
		tr.Proxy = http.ProxyURL(cfg.u)
	}
	p.tr = tr
	return p
}

// HTTPClient 取共享 Transport 的 client：Transport 恒同（连接复用），请求级
// 超时由调用方按既有口径传入（Client 壳按请求构造，代价可忽略）。直连池
// 返回默认 Transport 的 client。
func (p *Pool) HTTPClient(timeout time.Duration) *http.Client {
	if p.tr == nil {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{Transport: p.tr, Timeout: timeout}
}

// Dialer 供 SMTP 拨号（一连接一邮件，SMTP 连接不池化）：socks5 返回
// x/net/proxy 的 ContextDialer；http/https 与直连按 §15.4「http/https 对
// SMTP 静默失效、按直连拨号」返回 net.Dialer（不报错、不降级提示）。
func (p *Pool) Dialer() ContextDialer {
	if p.dialer == nil {
		return &net.Dialer{}
	}
	return p.dialer
}

// Config 返回池的配置快照（供 PoolSet 比对与测试断言）。
func (p *Pool) Config() Config { return p.cfg }

// closeIdle 排空池内空闲连接（配置变更换池时由 PoolSet 调用，在途请求跑完
// 自然收尾）；直连池无自有 Transport，无池可排。
func (p *Pool) closeIdle() {
	if p.tr != nil {
		p.tr.CloseIdleConnections()
	}
}

// PoolSet 进程级池注册表：按逻辑键（provider_key）惰性取 / 建池（§15.4）。
// 显式构造、显式注入（bootstrap 构造一次），非包级单例、非全局默认 client；
// 禁止改写 http.DefaultTransport、禁止把代理配置注入全局默认 client。
type PoolSet struct {
	mu    sync.Mutex
	pools map[string]*Pool
}

// NewPoolSet 构造空池注册表。
func NewPoolSet() *PoolSet {
	return &PoolSet{pools: make(map[string]*Pool)}
}

// Get 按键取池：现池 cfg 与请求 cfg 语义一致（Equal）→ 复用同一池（同一
// proxy 的全部引用方共享连接）；不一致 → 建新池替换并排空旧池（在途请求
// 自然收尾，下一次工厂构造即走新配置）——代理行改动经既有缓存失效链触发
// 重解析后由本函数换池生效，无需重启。不同 key 互不共享。
func (s *PoolSet) Get(key string, cfg Config) *Pool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.pools[key]; ok {
		if old.cfg.Equal(cfg) {
			return old
		}
		old.closeIdle()
	}
	p := newPool(cfg)
	s.pools[key] = p
	return p
}

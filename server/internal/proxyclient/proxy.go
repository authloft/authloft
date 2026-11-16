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
	"time"

	"golang.org/x/net/proxy"
)

const (
	// maxRawLen 整串长度上限（字节，UTF-8），抑制日志 / 错误串膨胀（§5.3 代理字段约定）。
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

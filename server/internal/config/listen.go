// listen.go server 段 → http.Server 监听字段的映射（docs/后端架构.md
// §3.1「启动与监听口径」行 241-247）。生产装配（bootstrap.go）与 setup
// 模式（internal/setup）共用本映射，保证 setup 的监听 / TLS 模式与生产
// 同口径（§3.15）；监听运行（ListenAndServe*）留在各装配层。
package config

import (
	"crypto/tls"
	"net/http"
)

// ConfigureHTTPServer 把 server 段写进 http.Server 的监听字段
// （§3.1 行 244-245，Go 1.26 标准库原生 http.Server.Protocols）：
//   - 未配置 cert_file + key_file：同端口 HTTP/1.1 + H2C（明文 HTTP/2）
//     ——Protocols = SetHTTP1 + SetUnencryptedHTTP2，min_tls_version 不生效；
//   - 已配置：同端口 HTTP/1.1(TLS) + H2(TLS)——Protocols = SetHTTP1 +
//     SetHTTP2，TLSConfig.MinVersion 按 min_tls_version 映射（"1.2" /
//     "1.3"，空 = 不设、标准库默认；非法取值返回 error 供装配层 fail-fast）；
//   - TLSNextProto 保持 nil、不手写 NextProtos——ALPN 由标准库按 Protocols
//     协商；不引 golang.org/x/net（http2/h2c 全由标准库承担）。
//
// srv 上既有的 TLSConfig 在 h2c 模式下清空（防止上一态残留干扰）。
func (s ServerConfig) ConfigureHTTPServer(srv *http.Server) error {
	srv.Addr = s.Listen
	proto := &http.Protocols{}
	if !s.TLSEnabled() {
		proto.SetHTTP1(true)
		proto.SetUnencryptedHTTP2(true)
		srv.Protocols = proto
		srv.TLSConfig = nil
		return nil
	}
	min, err := s.TLSMinVersion()
	if err != nil {
		return err
	}
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	srv.Protocols = proto
	if min != 0 {
		srv.TLSConfig = &tls.Config{MinVersion: min}
	} else {
		srv.TLSConfig = nil
	}
	return nil
}

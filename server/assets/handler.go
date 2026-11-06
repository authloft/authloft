package assets

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// prefix 默认 URL 前缀（§3.13 行 486：Go 路由恒挂 /assets/**——settings 的
// static_base 只影响 HTML 输出前缀，配 CDN 时 Go 侧仍供回源与内网直连；
// setup 模式无 settings 可读，同为该常量）。
const prefix = "/assets"

// cacheControl 命中响应的缓存头（§3.13 行 487：入驻文件名均带 contenthash，
// 一年期不可变缓存；壳层 HTML 仍 no-store，见 internal/pages）。
const cacheControl = "public, max-age=31536000, immutable"

// NewHandler 构造静态资源 handler：f 为资源子树（FS() 返回形态），base 为
// URL 前缀（如 "/assets"），请求路径剥离 base 后映射 f 内文件。
//
// 行为契约（§3.13 行 484-487）：
//   - 仅 GET / HEAD，其余 405 + Allow: GET, HEAD；
//   - 命中：Cache-Control 一年不可变 + Content-Type 按扩展名（.js →
//     text/javascript; charset=utf-8、.css → text/css; charset=utf-8、
//     .woff2 → font/woff2、.svg → image/svg+xml，其余回落
//     application/octet-stream）；
//   - 未命中 / 目录请求一律统一 404（不回退壳层页、不泄露文件存在性、
//     不 panic、禁止目录列举）；
//   - 目录穿越由 fs.FS 语义天然拒绝：fs.ValidPath 是「path.Clean 后与原串
//     一致」的强形式（空元素 / . / .. / 绝对形态 / 反斜杠一律拒，
//     §3.13 行 485），URL 解码后的 ../ 与编码变体（%2e%2e%2f）同落空；
//     embed 以嵌入子树为物理边界，无从逃出 dist。
func NewHandler(f fs.FS, base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// r.URL.Path 已过 URL 解码（%2e%2e%2f → ../）。剥离 base 后必须是
		// 合法 fs.FS 名（fs.ValidPath：清洁、无 .. 元素、非绝对形态）。
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, base), "/")
		if name == "" || !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		st, err := fs.Stat(f, name)
		if err != nil || st.IsDir() {
			// 目录请求（/assets/、/assets/static/css/ 等）一律 404。
			http.NotFound(w, r)
			return
		}
		file, err := f.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		var content io.ReadSeeker
		if rs, ok := file.(io.ReadSeeker); ok {
			content = rs
		} else {
			// embed.FS / fstest.MapFS 文件均实现 io.ReadSeeker；仅对旁路
			// 传入的其他 fs.FS 实现兜底整体读入，仍走 ServeContent。
			data, err := io.ReadAll(file)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			content = bytes.NewReader(data)
		}
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("Content-Type", contentTypeFor(name))
		// ServeContent 自动处理 HEAD（只写头不写 body）与 Range，并尊重
		// 已设置的 Content-Type（不再 sniff）；embed / MapFS 的 modtime 为
		// 零值 → 不落 Last-Modified（内容寻址资源无需协商缓存）。
		http.ServeContent(w, r, name, time.Time{}, content)
	})
}

// Register 把 /assets/** 挂顶层 ServeMux（§3.13 行 484：正常 / setup 两模式
// 恒在；无鉴权、不进 gin 全局链与 session / Origin / admin 中间件，也不套
// Connect 前缀中间件链；与 API 前缀不冲突）。装配点两处：bootstrap
// buildHandlerWithSSO 与 internal/setup.NewServer 的 mux 构造处。pattern 带
// 尾斜杠（子树匹配 "/assets/**"），base 供 handler 剥离（无尾斜杠）。
func Register(mux *http.ServeMux) {
	mux.Handle(prefix+"/", NewHandler(FS(), prefix))
}

// contentTypeFor 按扩展名映射响应 Content-Type（§3.13 行 483 入驻产物形态：
// 根级 js 与 static/** 下的 css / 字体 / 图片；.LICENSE.txt 等其余形态回落
// octet-stream）。不用 mime.TypeByExtension——其映射平台相关且无此四项的
// 稳定保证。
func contentTypeFor(name string) string {
	switch path.Ext(name) {
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".woff2":
		return "font/woff2"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

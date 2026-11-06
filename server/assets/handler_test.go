// assets 包 handler 行为测试（§3.13 行 484-487 施工口径）：
// Content-Type 与缓存头矩阵、404 / 405 语义、目录穿越拒绝（含编码变体，
// 实证 fs.FS 边界）、HEAD 无 body、Register 挂载可达性与真实 embed 子树
// （空仓 .gitkeep 形态）。
package assets

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// mapFS 四扩展各一（§3.13 行 481 产物布局：根级 js + static/** 下的 css /
// 字体 / 图片）+ LICENSE.txt 回落对照。
func mapFS() fstest.MapFS {
	return fstest.MapFS{
		"login.a1b2c3.js":             &fstest.MapFile{Data: []byte("console.log('login')")},
		"static/css/login.d4e5f6.css": &fstest.MapFile{Data: []byte("body{color:#000}")},
		"static/font/main.789a.woff2": &fstest.MapFile{Data: []byte("w2data")},
		"static/img/logo.svg":         &fstest.MapFile{Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
		"chunk.0f1e2d.LICENSE.txt":    &fstest.MapFile{Data: []byte("/*! license */")},
	}
}

// TestNewHandlerContentTypes 命中 → 200 + 一年不可变缓存头 + 按扩展名的
// Content-Type（§3.13 行 487），其余形态回落 octet-stream。
func TestNewHandlerContentTypes(t *testing.T) {
	h := NewHandler(mapFS(), prefix)
	cases := []struct {
		path, ctype string
	}{
		{"/assets/login.a1b2c3.js", "text/javascript; charset=utf-8"},
		{"/assets/static/css/login.d4e5f6.css", "text/css; charset=utf-8"},
		{"/assets/static/font/main.789a.woff2", "font/woff2"},
		{"/assets/static/img/logo.svg", "image/svg+xml"},
		{"/assets/chunk.0f1e2d.LICENSE.txt", "application/octet-stream"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, w.Code)
			continue
		}
		if got := w.Header().Get("Content-Type"); got != tc.ctype {
			t.Errorf("%s Content-Type = %q, want %q", tc.path, got, tc.ctype)
		}
		if got := w.Header().Get("Cache-Control"); got != cacheControl {
			t.Errorf("%s Cache-Control = %q, want %q", tc.path, got, cacheControl)
		}
	}
}

// TestNewHandlerNotFound 未命中与目录请求一律统一 404（§3.13 行 485：不回退
// 壳层、不泄露存在性、不 panic、禁止目录列举）；空 FS 同样 404 不 panic。
func TestNewHandlerNotFound(t *testing.T) {
	h := NewHandler(mapFS(), prefix)
	missPaths := []string{
		"/assets/missing.abc.js",
		"/assets/",          // 根目录
		"/assets/static",    // 目录（无尾斜杠）
		"/assets/static/",   // 目录
		"/assets/static/css",
	}
	for _, p := range missPaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
	}
	empty := NewHandler(fstest.MapFS{}, prefix)
	req := httptest.NewRequest(http.MethodGet, "/assets/whatever.js", nil)
	w := httptest.NewRecorder()
	empty.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("GET on empty FS = %d, want 404 (and no panic)", w.Code)
	}
}

// TestNewHandlerMethodNotAllowed 仅 GET / HEAD（§3.13 行 484 施工口径），
// 其余 405 + Allow: GET, HEAD。
func TestNewHandlerMethodNotAllowed(t *testing.T) {
	h := NewHandler(mapFS(), prefix)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/assets/login.a1b2c3.js", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /assets/login.a1b2c3.js = %d, want 405", m, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s Allow = %q, want %q", m, got, "GET, HEAD")
		}
	}
}

// TestNewHandlerTraversalBlocked 目录穿越实证（§3.13 行 485）：URL 解码后的
// ../ 与编码变体（%2e%2e%2f / ..%2f）、非清洁双斜杠一律 404，且响应体与
// 普通 miss 完全一致（统一 404，不泄露差异）。
func TestNewHandlerTraversalBlocked(t *testing.T) {
	h := NewHandler(mapFS(), prefix)

	// 普通 miss 响应体作为统一性基准。
	base := httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil)
	bw := httptest.NewRecorder()
	h.ServeHTTP(bw, base)
	missBody := bw.Body.String()

	paths := []string{
		"/assets/../secret",
		"/assets/static/../secret",
		"/assets/a/../../secret",
		"/assets/%2e%2e%2fsecret",
		"/assets/..%2fsecret",
		"/assets/a//b.js",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
		if w.Body.String() != missBody {
			t.Errorf("GET %s body = %q, want uniform miss body %q", p, w.Body.String(), missBody)
		}
	}
}

// TestNewHandlerHeadNoBody HEAD → 200、头与 GET 一致、无 body
// （§3.13 行 484 施工口径）。
func TestNewHandlerHeadNoBody(t *testing.T) {
	h := NewHandler(mapFS(), prefix)
	req := httptest.NewRequest(http.MethodHead, "/assets/login.a1b2c3.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HEAD /assets/login.a1b2c3.js = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript", got)
	}
	if got := w.Header().Get("Cache-Control"); got != cacheControl {
		t.Errorf("Cache-Control = %q, want %q", got, cacheControl)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD body len = %d, want 0", w.Body.Len())
	}
}

// TestNewHandlerRealEmbedTraversal 真实 embed 子树的穿越边界实证：dist 上层
// 物理存在本包源文件 embed.go，穿越请求仍 404——embed 以嵌入子树为边界，
// 无从逃逸（§3.13 行 485）。
func TestNewHandlerRealEmbedTraversal(t *testing.T) {
	h := NewHandler(FS(), prefix)
	for _, p := range []string{"/assets/../embed.go", "/assets/%2e%2e%2fembed.go", "/assets/../../go.mod"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s on real embed = %d, want 404", p, w.Code)
		}
	}
}

// TestRegisterMountsPrefix Register 挂载后 /assets/** 经真实 ServeMux 可达
// （§3.13 行 484；setup / bootstrap 两装配点同用此形态）。空仓形态下以入库
// 占位 .gitkeep 200 印证；穿越请求经 mux 后无论被 ServeMux clean 重定向
// 还是直达 handler，最终均 404、拿不到 dist 上层文件。
func TestRegisterMountsPrefix(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/assets/.gitkeep")
	if err != nil {
		t.Fatalf("GET /assets/.gitkeep: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /assets/.gitkeep = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != cacheControl {
		t.Errorf("Cache-Control = %q, want %q", got, cacheControl)
	}

	resp, err = http.Get(srv.URL + "/assets/missing.abc.js")
	if err != nil {
		t.Fatalf("GET /assets/missing.abc.js: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /assets/missing.abc.js = %d, want 404", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/assets/../embed.go")
	if err != nil {
		t.Fatalf("GET /assets/../embed.go: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /assets/../embed.go = %d, want 404 (must not escape dist)", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/assets/anything.js", nil)
	if err != nil {
		t.Fatalf("POST /assets/anything.js: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /assets/anything.js: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /assets/anything.js = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
}

// TestNewHandlerServesFromSubtreeFS NewHandler 对 fs.Sub 形态子树（FS() 返回
// 形态）映射正确：剥离 base 后文件名扁平直达（§3.13 行 481）。
func TestNewHandlerServesFromSubtreeFS(t *testing.T) {
	sub, err := fs.Sub(fstest.MapFS{
		"dist/login.abc.js":          &fstest.MapFile{Data: []byte("ok")},
		"dist/static/css/x.y.css":     &fstest.MapFile{Data: []byte("c")},
	}, "dist")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	h := NewHandler(sub, prefix)
	req := httptest.NewRequest(http.MethodGet, "/assets/static/css/x.y.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "c" {
		t.Errorf("GET nested = %d %q, want 200 %q", w.Code, w.Body.String(), "c")
	}
	if got := w.Header().Get("Content-Type"); got != "text/css; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/css", got)
	}
}

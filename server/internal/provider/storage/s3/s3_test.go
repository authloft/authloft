// s3_test.go S3 实现行为：注册形态、Ext 构造校验、URL 拼接、HTTP 往返
// （httptest 服务端断言请求形态，不依赖真实 S3）、错误面与 key 自守。
// 签名正确性由 sigv4_test.go 权威矢量锁定，此处只验装配与请求形态。
package s3

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authloft/internal/provider"

	providerpb "authloft/gen/go/provider"
)

// 接口满足编译期断言：*S3 实现 provider.Storage（§15.1 逐字接口）。
var _ provider.Storage = (*S3)(nil)

func TestRegistryRegistration(t *testing.T) {
	meta, ok := provider.LookupTypeMeta(Type)
	if !ok {
		t.Fatal("s3 未注册（本包 init 未生效）")
	}
	if meta.Category != provider.CategoryStorage {
		t.Errorf("category = %q, want %q", meta.Category, provider.CategoryStorage)
	}
	st, err := provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{Endpoint: "http://minio.internal:9000", Bucket: "b", ClientId: "ak", ClientSecret: "sk"},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if _, ok := st.(*S3); !ok {
		t.Errorf("NewStorage 返回 %T, want *S3（factory 等价）", st)
	}
	for _, typ := range provider.AdapterTypes() {
		if typ == Type {
			t.Error("AdapterTypes 混入 storage 类型（登录快照被污染）")
		}
	}
}

func TestNewS3NotConfigured(t *testing.T) {
	for _, ext := range []*providerpb.Ext{
		nil,
		{Bucket: "b", ClientId: "ak", ClientSecret: "sk"},                                           // 缺 endpoint
		{Endpoint: "http://minio.internal:9000", ClientId: "ak", ClientSecret: "sk"},                // 缺 bucket
		{Endpoint: "http://minio.internal:9000", Bucket: "b", ClientSecret: "sk"},                   // 缺 access key
		{Endpoint: "http://minio.internal:9000", Bucket: "b", ClientId: "ak"},                       // 缺 secret key
		{Endpoint: "http://minio.internal:9000", Bucket: "b/x", ClientId: "ak", ClientSecret: "sk"}, // bucket 带分隔符
	} {
		if _, err := NewS3(ext); !errors.Is(err, provider.ErrNotConfigured) {
			t.Errorf("NewS3(%+v) err = %v, want ErrNotConfigured", ext, err)
		}
	}
}

func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		in           string
		scheme, host string
	}{
		{"minio.internal:9000", "https", "minio.internal:9000"},
		{"http://minio.internal:9000", "http", "minio.internal:9000"},
		{"https://s3.amazonaws.com/", "https", "s3.amazonaws.com"},
		{"https://s3.amazonaws.com:443", "https", "s3.amazonaws.com"}, // 默认端口剥离，保 Host 头逐字节一致
		{"http://minio.internal:80", "http", "minio.internal"},
	}
	for _, c := range cases {
		scheme, host, err := splitEndpoint(c.in)
		if err != nil || scheme != c.scheme || host != c.host {
			t.Errorf("splitEndpoint(%q) = (%q, %q, %v), want (%q, %q, nil)",
				c.in, scheme, host, err, c.scheme, c.host)
		}
	}
	for _, bad := range []string{"", "ftp://minio.internal:9000", "://host"} {
		if _, _, err := splitEndpoint(bad); err == nil {
			t.Errorf("splitEndpoint(%q) 应拒绝", bad)
		}
	}
}

func TestNormalizeTTL(t *testing.T) {
	cases := []struct {
		in   int32
		want int64
	}{
		{0, presignTTLDefault},
		{-5, presignTTLDefault},
		{600, 600},
		{999999, presignTTLMax}, // 超 S3 协议上限收敛到 7 天
	}
	for _, c := range cases {
		if got := normalizeTTL(c.in); got != c.want {
			t.Errorf("normalizeTTL(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestS3URL(t *testing.T) {
	// domain 优先（同 local 口径）。
	s := &S3{scheme: "https", host: "s3.amazonaws.com", bucket: "b", prefix: "qr", domain: "https://cdn.example.com"}
	if got, want := s.URL("k.jpg"), "https://cdn.example.com/qr/k.jpg"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	// 无 domain 按 endpoint + 寻址风格派生；path_style 桶名入路径。
	s.domain = ""
	s.pathStyle = true
	if got, want := s.URL("k.jpg"), "https://s3.amazonaws.com/b/qr/k.jpg"; got != want {
		t.Errorf("URL path-style = %q, want %q", got, want)
	}
	s.pathStyle = false
	if got, want := s.URL("k.jpg"), "https://b.s3.amazonaws.com/qr/k.jpg"; got != want {
		t.Errorf("URL virtual-host = %q, want %q", got, want)
	}
}

// TestS3KeyGuard key 自守：与渲染侧 / local 同一规则。
func TestS3KeyGuard(t *testing.T) {
	s := &S3{scheme: "http", host: "h:9000", bucket: "b", region: "r", accessKey: "ak", secretKey: "sk"}
	for _, key := range []string{"", "/abs.jpg", "../escape.jpg", "a/../../b.jpg", `a\b.jpg`, "C:ev.jpg"} {
		if _, _, err := s.PresignPut(context.Background(), key, "image/jpeg", 1); err == nil {
			t.Errorf("PresignPut(%q) 应被拒绝", key)
		}
		if _, err := s.Get(context.Background(), key); err == nil {
			t.Errorf("Get(%q) 应被拒绝", key)
		}
		if err := s.Delete(context.Background(), key); err == nil {
			t.Errorf("Delete(%q) 应被拒绝", key)
		}
		if _, err := s.Put(context.Background(), key, []byte("x"), "image/jpeg"); err == nil {
			t.Errorf("Put(%q) 应被拒绝", key)
		}
	}
}

// TestS3PutGetDeleteRoundTrip httptest 往返：服务端断言请求形态（方法 / 路径 /
// 签名头 / ACL），客户端断言返回值；Delete 幂等（404 亦成功）。
func TestS3PutGetDeleteRoundTrip(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/authloft/qr/k1.bin":
			gotBody, _ = io.ReadAll(r.Body)
			if got := r.Header.Get("x-amz-content-sha256"); got != "" && len(got) != 64 {
				t.Errorf("x-amz-content-sha256 = %q, want 64 位 hex", got)
			}
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=") {
				t.Errorf("Authorization = %q", got)
			}
			if got := r.Header.Get("X-Amz-Acl"); got != "public-read" {
				t.Errorf("X-Amz-Acl = %q, want public-read", got)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/authloft/qr/k1.bin":
			w.Write([]byte("jpeg-bytes"))
		case r.Method == http.MethodDelete && r.URL.Path == "/authloft/qr/k1.bin":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/authloft/qr/gone.bin":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	s, err := NewS3(&providerpb.Ext{
		Endpoint: srv.URL, Bucket: "authloft", PathPrefix: "qr", PathStyle: true,
		ClientId: "ak", ClientSecret: "sk", PublicRead: true, RegionId: "us-east-1",
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if got, want := s.scheme, "http"; got != want {
		t.Errorf("scheme = %q, want %q", got, want)
	}
	url, err := s.Put(context.Background(), "k1.bin", []byte("jpeg-bytes"), "image/jpeg")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if url != srv.URL+"/authloft/qr/k1.bin" {
		t.Errorf("Put url = %q", url)
	}
	if string(gotBody) != "jpeg-bytes" {
		t.Errorf("服务端收到的 body = %q", gotBody)
	}
	body, err := s.Get(context.Background(), "k1.bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "jpeg-bytes" {
		t.Errorf("Get body = %q", body)
	}
	if err := s.Delete(context.Background(), "k1.bin"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := s.Delete(context.Background(), "gone.bin"); err != nil {
		t.Errorf("Delete 404 应幂等成功: %v", err)
	}
}

// TestS3HTTPErrorSurface 非 2xx 包装状态码与响应片段，且不泄漏凭证。
func TestS3HTTPErrorSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<Error><Code>InvalidAccessKeyId</Code></Error>`))
	}))
	defer srv.Close()
	s, err := NewS3(&providerpb.Ext{
		Endpoint: srv.URL, Bucket: "b", PathStyle: true,
		ClientId: "AKIDEXAMPLE", ClientSecret: "SUPERSECRET",
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	_, err = s.Put(context.Background(), "k.bin", []byte("x"), "application/octet-stream")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Errorf("Put err = %v, want 含 403 与 S3 错误码", err)
	}
	if strings.Contains(err.Error(), "SUPERSECRET") {
		t.Error("错误面泄漏 secret key")
	}
}

// TestSchemaExtKinds Schema 声明形态：表列基线落 column、Ext 字段落 ext
// （§5.3：键恒等于表列名或 Ext 字段名）。
func TestSchemaExtKinds(t *testing.T) {
	fields := storageS3Schema()
	extKeys := map[string]bool{
		"endpoint": true, "bucket": true, "region_id": true, "path_style": true,
		"client_id": true, "client_secret": true, "path_prefix": true, "domain": true,
		"public_read": true, "upload_mode": true, "presign_ttl": true,
		"max_size": true, "allowed_types": true,
	}
	columnKeys := map[string]bool{
		"provider_key": true, "display_name": true, "icon_url": true,
		"ui_group": true, "sort_order": true, "remark": true, "is_enabled": true,
	}
	seen := map[string]int{}
	for _, f := range fields {
		seen[f.Key]++
		want := provider.StorageExt
		if columnKeys[f.Key] {
			want = provider.StorageColumn
		}
		if (extKeys[f.Key] || columnKeys[f.Key]) && f.Storage != want {
			t.Errorf("field %q storage = %q, want %q", f.Key, f.Storage, want)
		}
		if f.Label == "" || f.Type == "" || f.Section == "" {
			t.Errorf("field %q 声明残缺: %+v", f.Key, f)
		}
	}
	for k := range extKeys {
		if seen[k] != 1 {
			t.Errorf("ext 字段 %q 声明 %d 次, want 1", k, seen[k])
		}
	}
	for k := range columnKeys {
		if seen[k] != 1 {
			t.Errorf("表列 %q 声明 %d 次, want 1", k, seen[k])
		}
	}
	if len(seen) != len(fields) {
		t.Errorf("Schema 出现未声明键: %+v", fields)
	}
}

// cos_test.go COS 薄封装行为：注册形态、region → endpoint 派生、path_style
// 固化 false、region_id / 凭证缺失 fail-closed、bucket APPID pattern 与
// Schema 收窄。传输与签名正确性由 storage/s3 基座测试锁定（httptest 往返 +
// botocore 权威矢量），此处只验派生与装配判定，不触网（URL / PresignPut
// 均为纯派生值探针）。
package cos

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"authloft/internal/provider"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider/storage/s3"
)

func TestRegistryRegistration(t *testing.T) {
	meta, ok := provider.LookupTypeMeta(Type)
	if !ok {
		t.Fatal("cos 未注册（本包 init 未生效）")
	}
	if meta.Category != provider.CategoryStorage {
		t.Errorf("category = %q, want %q", meta.Category, provider.CategoryStorage)
	}
	st, err := provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{RegionId: "ap-guangzhou", Bucket: "b", ClientId: "ak", ClientSecret: "sk"},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if _, ok := st.(*s3.S3); !ok {
		t.Errorf("NewStorage 返回 %T, want *s3.S3（工厂委托基座）", st)
	}
	for _, typ := range provider.AdapterTypes() {
		if typ == Type {
			t.Error("AdapterTypes 混入 storage 类型（登录快照被污染）")
		}
	}
}

func TestEndpointDerivedFromRegion(t *testing.T) {
	// 虚拟托管寻址 host = bucket + "." + 派生 host，URL 即派生结果的逐字节探针。
	st, err := provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{RegionId: "ap-guangzhou", Bucket: "examplebucket-1250000000", ClientId: "ak", ClientSecret: "sk"},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if got, want := st.URL("k.jpg"), "https://examplebucket-1250000000.cos.ap-guangzhou.myqcloud.com/k.jpg"; got != want {
		t.Errorf("URL = %q, want %q（region → endpoint 派生失真）", got, want)
	}
	// PresignPut 直传 URL 同源派生（不触网）。
	url, _, err := st.PresignPut(context.Background(), "k.jpg", "image/jpeg", 1)
	if err != nil {
		t.Fatalf("PresignPut: %v", err)
	}
	if !strings.HasPrefix(url, "https://examplebucket-1250000000.cos.ap-guangzhou.myqcloud.com/") {
		t.Errorf("PresignPut url = %q, want 派生 host", url)
	}
	// region 两端留白容忍（TrimSpace 口径与基座一致）。
	st, err = provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{RegionId: " ap-guangzhou ", Bucket: "examplebucket-1250000000", ClientId: "ak", ClientSecret: "sk"},
	})
	if err != nil {
		t.Fatalf("NewStorage(带空白 region): %v", err)
	}
	if got, want := st.URL("k.jpg"), "https://examplebucket-1250000000.cos.ap-guangzhou.myqcloud.com/k.jpg"; got != want {
		t.Errorf("URL = %q, want %q（region 未归一）", got, want)
	}
}

// TestPathStyleForcedFalse path_style 固化 false：2024-01-01 后新建桶不支持
// path-style，Ext 声明 true 也必须覆写为虚拟托管寻址（可证伪点）。
func TestPathStyleForcedFalse(t *testing.T) {
	st, err := provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{RegionId: "ap-guangzhou", Bucket: "examplebucket-1250000000", PathStyle: true, ClientId: "ak", ClientSecret: "sk"},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if got, want := st.URL("k.jpg"), "https://examplebucket-1250000000.cos.ap-guangzhou.myqcloud.com/k.jpg"; got != want {
		t.Errorf("URL = %q, want %q（path_style 未固化 false）", got, want)
	}
}

// TestNotConfigured fail-closed 判定：region_id 缺失即拒绝（基座自身会回退
// us-east-1「成功」，此处必须装配期拦下——可证伪点）；凭证 / bucket 缺失
// 由基座同口径拒绝。
func TestNotConfigured(t *testing.T) {
	for _, tt := range []struct {
		name string
		ext  *providerpb.Ext
	}{
		{"nil ext", nil},
		{"region_id 缺失", &providerpb.Ext{Bucket: "b", ClientId: "ak", ClientSecret: "sk"}},
		{"region_id 空白", &providerpb.Ext{RegionId: "  ", Bucket: "b", ClientId: "ak", ClientSecret: "sk"}},
		{"凭证缺失", &providerpb.Ext{RegionId: "ap-guangzhou", Bucket: "b"}},
		{"bucket 缺失", &providerpb.Ext{RegionId: "ap-guangzhou", ClientId: "ak", ClientSecret: "sk"}},
	} {
		_, err := provider.NewStorage(&provider.Provider{Type: Type, Ext: tt.ext})
		if !errors.Is(err, provider.ErrNotConfigured) {
			t.Errorf("%s: NewStorage err = %v, want ErrNotConfigured（fail-closed）", tt.name, err)
		}
	}
}

// TestBucketPattern APPID 后缀提示：BucketName-APPID 形态接受，缺后缀 /
// 大写 / 非数字后缀拒绝（pattern 仅表单提示，构造器不强制——bucket 无 APPID
// 仍可构造，判定以 COS 侧实际校验为准）。
func TestBucketPattern(t *testing.T) {
	re := regexp.MustCompile(bucketPattern)
	for _, bucket := range []string{"examplebucket-1250000000", "a0-1"} {
		if !re.MatchString(bucket) {
			t.Errorf("bucket %q 应匹配 APPID pattern", bucket)
		}
	}
	for _, bucket := range []string{"examplebucket", "Examplebucket-1250000000", "examplebucket-125a", "examplebucket-1250000000-x"} {
		if re.MatchString(bucket) {
			t.Errorf("bucket %q 不应匹配 APPID pattern", bucket)
		}
	}
	if _, err := provider.NewStorage(&provider.Provider{
		Type: Type,
		Ext:  &providerpb.Ext{RegionId: "ap-guangzhou", Bucket: "noappid", ClientId: "ak", ClientSecret: "sk"},
	}); err != nil {
		t.Errorf("NewStorage(bucket 无 APPID): %v——构造器不强制 pattern", err)
	}
}

// TestSchemaNarrowed Schema 收窄边界：固化参数（endpoint / path_style）不
// 声明，is_enabled 不声明（storage 恒可用）；bucket 携带 APPID pattern；
// 其余键各声明一次，region_id 必填。
func TestSchemaNarrowed(t *testing.T) {
	fields := schema()
	seen := map[string]int{}
	required := map[string]bool{}
	var bucket *provider.FieldMeta
	for i := range fields {
		f := fields[i]
		seen[f.Key]++
		if f.Required {
			required[f.Key] = true
		}
		if f.Label == "" || f.Type == "" || f.Section == "" {
			t.Errorf("field %q 声明残缺: %+v", f.Key, f)
		}
		if f.Key == "bucket" {
			bucket = &fields[i]
		}
	}
	for _, key := range []string{"endpoint", "path_style", "intranet_endpoint", "is_enabled"} {
		if seen[key] != 0 {
			t.Errorf("字段 %q 不应声明（固化参数 / 不保留键 / storage 恒可用）", key)
		}
	}
	for _, key := range []string{
		"provider_key", "display_name", "bucket", "region_id",
		"client_id", "client_secret", "path_prefix", "domain", "public_read",
		"upload_mode", "presign_ttl", "max_size", "allowed_types",
		"icon_url", "sort_order", "remark",
	} {
		if seen[key] != 1 {
			t.Errorf("字段 %q 声明 %d 次, want 1", key, seen[key])
		}
	}
	if len(seen) != len(fields) {
		t.Errorf("Schema 出现未声明键: %+v", fields)
	}
	if !required["region_id"] {
		t.Error("region_id 应声明必填（实质必填，缺失装配期即拒绝）")
	}
	if bucket == nil || bucket.Pattern != bucketPattern {
		t.Errorf("bucket pattern = %+v, want bucketPattern（APPID 后缀提示）", bucket)
	}
}

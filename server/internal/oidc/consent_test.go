// consent.go 纯工具测试：双口径解析（逗号与空格）、空 token 容错、去重
// 保序、规范化、缺省补值、子集与并集。
package oidc

import (
	"reflect"
	"slices"
	"testing"
)

func TestParseScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"空串", "", nil},
		{"纯分隔符", " , , ", nil},
		{"空格口径", "openid profile email", []string{"openid", "profile", "email"}},
		{"逗号口径", "openid,profile,email", []string{"openid", "profile", "email"}},
		{"双口径混排", "openid, profile\temail", []string{"openid", "profile", "email"}},
		{"空首元素容错", ",openid", []string{"openid"}},
		{"连续分隔符", "openid,,, ,profile", []string{"openid", "profile"}},
		{"去重保序", "email openid email profile openid", []string{"email", "openid", "profile"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseScopes(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseScopes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeScope(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"", ""},
		{" , ", ""},
		{"openid,profile,email", "openid profile email"},
		{"openid  profile    email", "openid profile email"},
		{"email openid email", "email openid"},
	} {
		if got := NormalizeScope(tc.in); got != tc.want {
			t.Errorf("NormalizeScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEffectiveScope(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"", DefaultScope},
		{" , ", DefaultScope},
		{"openid", "openid"},
		{"openid,profile", "openid profile"},
		{"profile openid profile", "profile openid"},
	} {
		if got := EffectiveScope(tc.in); got != tc.want {
			t.Errorf("EffectiveScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if !ScopeSubset(ScopeOpenID, EffectiveScope("")) {
		t.Errorf("缺省补值 %q 应含 openid", EffectiveScope(""))
	}
}

func TestScopeSubset(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sub, sup string
		want     bool
	}{
		{"空集是任意集合子集", "", "openid", true},
		{"双方为空", "", "", true},
		{"全集对空集非子集", "openid", "", false},
		{"真子集（空格口径）", "openid profile", "openid profile email", true},
		{"相等集合", "openid profile", "profile openid", true},
		{"超集非子集", "openid profile email", "openid profile", false},
		{"单元素缺失", "phone", "openid profile email", false},
		{"双口径混判", "openid,profile", "openid profile email", true},
		{"注册侧逗号口径", "openid profile", "openid,profile,email", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScopeSubset(tc.sub, tc.sup); got != tc.want {
				t.Errorf("ScopeSubset(%q, %q) = %v, want %v", tc.sub, tc.sup, got, tc.want)
			}
		})
	}
}

func TestScopeUnion(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		want string
	}{
		{"双方为空", "", "", ""},
		{"单侧为空", "", "openid profile", "openid profile"},
		{"不相交并集（先 a 后 b）", "openid", "profile email", "openid profile email"},
		{"相交去重", "openid profile", "email openid", "openid profile email"},
		{"双口径混算", "openid,profile", "profile email", "openid profile email"},
		{"保序不重排", "email openid", "openid", "email openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScopeUnion(tc.a, tc.b); got != tc.want {
				t.Errorf("ScopeUnion(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
	// 只扩不缩：并集结果对两参均为超集或相等。
	for _, a := range []string{"", "openid", "openid profile", "openid,profile,email"} {
		for _, b := range []string{"", "email", "profile email", "openid,phone"} {
			merged := ParseScopes(ScopeUnion(a, b))
			for _, s := range ParseScopes(a) {
				if !slices.Contains(merged, s) {
					t.Errorf("ScopeUnion(%q, %q) 丢失 a 侧 %q", a, b, s)
				}
			}
			for _, s := range ParseScopes(b) {
				if !slices.Contains(merged, s) {
					t.Errorf("ScopeUnion(%q, %q) 丢失 b 侧 %q", a, b, s)
				}
			}
		}
	}
}

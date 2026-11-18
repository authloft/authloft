package uriutil

import "testing"

// 断言值等价构造：原三处实现（service/admin、internal/pages、internal/oidc）
// 均无独立单测，本表覆盖以下维度——精确匹配 / 单 * / 多 * / 无 * /
// 前缀 / 中段 / 后缀边界，含大小写敏感与连续 * 空段等原算法边界行为。
func TestMatchWildcardURI(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		target  string
		want    bool
	}{
		// 精确匹配（无通配）
		{"精确相等", "https://app.example.com/callback", "https://app.example.com/callback", true},
		{"无星不等", "https://app.example.com/callback", "https://app.example.com/other", false},
		{"无星大小写敏感", "https://App.example.com/cb", "https://app.example.com/cb", false},
		{"空 pattern 非空 target", "", "x", false},
		{"空对空字面相等", "", "", true},

		// 单 * 前缀形态
		{"前缀通配命中", "https://app.example.com/*", "https://app.example.com/callback/x", true},
		{"前缀通配任意后缀", "https://app.example.com/*", "https://app.example.com/other", true},
		{"前缀不命中防子域陷阱", "https://app.example.com/*", "https://evil.example.com/x", false},

		// 单 * 后缀形态与后缀边界
		{"后缀通配命中", "*.example.com/callback", "https://app.example.com/callback", true},
		{"后缀 rest 短于末段", "*.example.com/callback", "app.example.com/cb", false},
		{"后缀长度不足", "a*abc", "abc", false},
		{"后缀前缀段吞尽 target", "aba*ba", "aba", false},
		{"中置单星", "https://*.example.com/cb", "https://app.example.com/cb", true},

		// 多 *：中段依序匹配
		{"中段依序命中", "https://*.example.com/*/cb", "https://app.example.com/foo/cb", true},
		{"中段不命中", "https://*.example.com/*/cb", "https://app.example.org/foo/cb", false},
		{"多段顺序命中", "a*b*c", "axbxc", true},
		{"多段顺序耗尽不命中", "a*b*c", "axcxb", false},

		// 边界：连续 * 与裸 *
		{"连续星星空段平凡命中", "https://app.example.com/**", "https://app.example.com/a/b", true},
		{"裸星万能", "*", "anything://whatever", true},
		{"裸星对空串", "*", "", true},

		// 通配也不折叠大小写
		{"通配大小写敏感", "https://*.EXAMPLE.com/*", "https://app.example.com/x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchWildcardURI(tt.pattern, tt.target); got != tt.want {
				t.Fatalf("MatchWildcardURI(%q, %q) = %v, want %v", tt.pattern, tt.target, got, tt.want)
			}
		})
	}
}

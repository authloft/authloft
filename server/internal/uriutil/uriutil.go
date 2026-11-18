// Package uriutil 回调 URI 白名单通配匹配的唯一公共实现（接口文档
// §12.3：redirect_uris 支持 * 通配、整段匹配防子域名陷阱）。纯函数
// 叶子包：service/admin、internal/pages、internal/oidc 共用，改匹配
// 规则只改此处；不 import 项目内其他包，不产生依赖方向环。
package uriutil

import "strings"

// MatchWildcardURI 回调白名单条目整段匹配：字面相等，或按 * 切段后
// 前缀 / 中段 / 后缀依序匹配。算法自 service/admin、internal/pages、
// internal/oidc 三处原实现原样收敛，行为逐字节不变（大小写敏感、
// 连续 * 产出的空段平凡命中）。
func MatchWildcardURI(pattern, target string) bool {
	if pattern == target {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(target, parts[0]) {
		return false
	}
	rest := target[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 {
			if len(rest) < len(parts[i]) || !strings.HasSuffix(rest, parts[i]) {
				return false
			}
		} else {
			idx := strings.Index(rest, parts[i])
			if idx < 0 {
				return false
			}
			rest = rest[idx+len(parts[i]):]
		}
	}
	return true
}

// consent.go scope 纯工具（后端架构 §4.5「两套解析统一收进授权参数校验
// 工具、不散落调用点」的集合运算层）：oidc_client.scopes 为逗号分隔、
// oidc_consent.scopes / oidc_refresh_token.scopes 为空格分隔（RFC 6749），
// 两套口径在本包统一为「先解析成集合、再运算」。只做纯集合运算，无加密
// / token 逻辑、无 IO；openid 的强制校验归 authz_validate.go（Authorize
// 入口与同意 RPC），本层不做静默补值、不扩值。
package oidc

import (
	"slices"
	"strings"
	"unicode"
)

// ScopeOpenID openid：ID Token 签发与 sub 派生的前提，授权链路全强制
// （接口文档 §4.2 / §5.5 / §3.10）。
const ScopeOpenID = "openid"

// ParseScopes 双口径统一解析：逗号与空白均视为分隔符，丢弃空 token
// （存量 scopes 行经迁移补齐后可能含空首元素，如 ",openid"，§4.5）、
// 去重保序（取首次出现位置）。空串 / 纯分隔符返回 nil。
func ParseScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	if len(fields) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

// NormalizeScope 规范化为空格分隔口径（RFC 6749 / §4.5）：双口径解析 +
// 去重后以单空格连接。空串返回空串；是否含 openid 由校验层判定，
// 本函数不补值。
func NormalizeScope(raw string) string {
	return strings.Join(ParseScopes(raw), " ")
}

// EffectiveScope 缺省补值后的有效 scope（接口文档 §4.2：scope 缺省
// openid profile email，空 scope 按缺省补值判定）：空串 / 纯分隔符返回
// DefaultScope，其余返回规范化结果。授权记录判定、签码与同意校验统一以
// 有效 scope 为准——authorize 入口注入与 authorize 三态判定均以此为准入。
func EffectiveScope(raw string) string {
	if normalized := NormalizeScope(raw); normalized != "" {
		return normalized
	}
	return DefaultScope
}

// ScopeSubset 报告 sub 的每个取值都在 sup 中（两参各经 ParseScopes 统一
// 解析，逗号 / 空格口径均可）。空集是任意集合的子集——「从未同意 = 空集」
// 口径下空请求 scope 对任意记录免同意，请求 scope 的缺省补值由调用方先做
// （EffectiveScope，§4.2）。
func ScopeSubset(sub, sup string) bool {
	super := ParseScopes(sup)
	for _, s := range ParseScopes(sub) {
		if !slices.Contains(super, s) {
			return false
		}
	}
	return true
}

// ScopeUnion 并集（授权记录「只扩不缩」的落库口径，§4.5 / 接口文档
// §4.2）：两参各经 ParseScopes 统一解析，去重保序（先 a 的既有项、后 b
// 的新增项），空格分隔返回。任一参为空 / 纯分隔符时返回另一参的规范化
// 结果。
func ScopeUnion(a, b string) string {
	seen := make(map[string]struct{})
	var merged []string
	for _, s := range append(ParseScopes(a), ParseScopes(b)...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		merged = append(merged, s)
	}
	return strings.Join(merged, " ")
}

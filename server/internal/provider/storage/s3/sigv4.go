// sigv4.go AWS Signature Version 4 签名核心（零第三方依赖，stdlib 自实现）。
// 选型依据：storage 域未授权新 SDK 依赖（internal/storage 包注释既定口径），
// 而 PresignPut / Put / Get / Delete 所需仅为确定性签名计算 + 单对象 HTTP
// 往返，SDK 的 multipart / 分页 / 重试等重能力对本项目使用面（码图、≤2MB
// 头像）无增益，反增二进制体积。正确性以 AWS 官方 SigV4 实装（botocore）
// 固定时间产出的完整 URL 矢量锁定（sigv4_test.go），非自证。
//
// 实现覆盖面：头签名请求（x-amz-content-sha256 恒在 SignedHeaders 内）与
// 查询串预签名（UNSIGNED-PAYLOAD）。canonical 细节按 S3 规范：路径逐段
// RFC3986 编码但斜杠保留（不二次编码）、查询按 key 排序全量编码、签名头
// 名小写排序每行 name:value\n。
package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	sigAlgorithm    = "AWS4-HMAC-SHA256"
	emptyPayloadSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedPayload = "UNSIGNED-PAYLOAD"
	amzTimeFormat   = "20060102T150405Z"
	amzDateFormat   = "20060102"
)

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signingKey SigV4 派生链 kDate → kRegion → kService → kSigning。
func signingKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// uriEncode RFC3986 百分号编码（非保留字 A-Z a-z 0-9 - _ . ~ 原样透传）；
// encodeSlash=false 时斜杠保留——S3 规范要求 canonical URI 逐段编码、
// 斜杠不编码不二次编码。
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// signedHeaders 参与签名的头集合：名一律小写 → 值原样。S3 场景全部为单值
// 简单头，不做多值折叠与空白规整。
type signedHeaders map[string]string

// canonical 产出规范化头块（每行 name:value\n）与签名头清单（小写分号连接）。
func (h signedHeaders) canonical() (block, list string) {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(h[name])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// canonicalQuery 规范化查询串：按 key 排序、key 与 value 全量 RFC3986 编码。
// S3 预签名键全部单值，map 形态足够。
func canonicalQuery(q map[string]string) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(uriEncode(k, true))
		b.WriteByte('=')
		b.WriteString(uriEncode(q[k], true))
	}
	return b.String()
}

// stringToSign 组装 string-to-sign（算法 / 时间 / scope / 规范化请求哈希）。
func stringToSign(amzDate, scope, canonicalRequest string) string {
	return strings.Join([]string{
		sigAlgorithm, amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")
}

// signature 由 string-to-sign 求签名 hex（密钥按 date/region/service 派生）。
func signature(stringToSignVal, secret, date, region, service string) string {
	return hex.EncodeToString(hmacSHA256(
		signingKey(secret, date, region, service), []byte(stringToSignVal)))
}

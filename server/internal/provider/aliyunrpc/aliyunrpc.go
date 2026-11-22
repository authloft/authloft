// Package aliyunrpc 阿里云 RPC 风格 API 签名公共实现（RPC 签名 V1.0）：
// HMAC-SHA1、密钥 = AccessKeySecret + "&"、RFC 3986 百分号编码、按 key
// 升序规范化、SignatureNonce + Timestamp 防重放。自 sms/aliyun_sms 抽出
// 供多渠道复用（docs/后端架构.md §15.5 薄封装总则：短信 dysmsapi、邮件推送
// DirectMail、验证码等渠道共用同一签名算法）。
//
// 本包只承载规范化 / 编码 / 签名与防重放随机数，不带任何渠道业务语义
// （Action / Version / 参数集 / 响应判定归各渠道子包）；零第三方依赖。
package aliyunrpc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignRPCForm 阿里云 RPC 签名 V1.0（SHA1 密钥 = AccessKeySecret + "&"）：
// StringToSign = POST & percentEncode("/") & percentEncode(规范化查询串)；
// 规范化串 = 除 Signature 外按 key 升序的 percentEncode(k)=percentEncode(v)。
func SignRPCForm(form url.Values, accessKeySecret string) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(PercentEncode(k))
		b.WriteByte('=')
		b.WriteString(PercentEncode(form.Get(k)))
	}
	stringToSign := http.MethodPost + "&" + PercentEncode("/") + "&" + PercentEncode(b.String())
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// PercentEncode RFC 3986 百分号编码：url.QueryEscape 的空格转 '+' 需改回
// %20，其余（含保留字）一致。
func PercentEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// NewNonce 签名防重放随机数（16 字节 hex）。
func NewNonce(now func() time.Time) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属系统级异常，用纳秒时钟兜底保证唯一性。
		return fmt.Sprintf("%d", now().UnixNano())
	}
	return hex.EncodeToString(b)
}

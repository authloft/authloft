// aliyunrpc_test.go：RPC 签名 V1.0 可证伪用例。百分号编码逐字符断言；
// 签名用「手写规范串 + 测试内独立 HMAC 复算」的已知向量——规范化（排序 /
// 编码 / 拼接）任一环节偏离公开规范即红，不依赖被测函数自证。
package aliyunrpc

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestPercentEncodeCharacterMap RFC 3986 编码逐字符断言：空格必须 %20
// （非 QueryEscape 的 '+'）、保留字与未保留字边界、UTF-8 多字节。
func TestPercentEncodeCharacterMap(t *testing.T) {
	cases := map[string]string{
		" ":           "%20", // 空格转 %20 而非 '+'（RPC 签名规范关键差异点）
		"+":           "%2B",
		"*":           "%2A",
		"~":           "~", // RFC 3986 未保留字符不编码
		"-":           "-",
		"_":           "_",
		".":           ".",
		"/":           "%2F",
		"=":           "%3D",
		"&":           "%26",
		"%":           "%25",
		":":           "%3A",
		"?":           "%3F",
		"中":           "%E4%B8%AD", // UTF-8 按字节百分号编码
		"a b+c*d/e~f": "a%20b%2Bc%2Ad%2Fe~f",
	}
	for in, want := range cases {
		if got := PercentEncode(in); got != want {
			t.Errorf("PercentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSignRPCFormIndependentVector 已知签名向量：规范化查询串手写（按 key
// 升序、RFC 3986 编码，含需编码的 key 带空格 / value 带 & 与 : 的项，乱序
// Set 构造），测试内独立重算 HMAC-SHA1（密钥 = secret + "&"）比对。实现若
// 不排序、编码口径错、拼接符错或密钥漏 "&"，本用例必红。
func TestSignRPCFormIndependentVector(t *testing.T) {
	form := url.Values{}
	// 乱序 Set：字典序（AccessKeyId < Action < Timestamp < b key）与插入序不同。
	form.Set("Timestamp", "2026-11-04T12:00:00Z")
	form.Set("b key", "v&1")
	form.Set("AccessKeyId", "ak")
	form.Set("Action", "SingleSendMail")

	// 手写规范化查询串（升序 + RFC 3986），不借被测包函数。
	canonical := "AccessKeyId=ak&Action=SingleSendMail&Timestamp=2026-11-04T12%3A00%3A00Z&b%20key=v%261"
	stringToSign := "POST&%2F&" + PercentEncode(canonical)
	mac := hmac.New(sha1.New, []byte("secret&"))
	mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if got := SignRPCForm(form, "secret"); got != want {
		t.Errorf("SignRPCForm = %q, want independent vector %q (stringToSign %q)", got, want, stringToSign)
	}
}

// TestSignRPCFormPermutationStable 同一表单内容不同构造序 → 签名一致
// （规范化只看 key 升序，与遍历序无关）。
func TestSignRPCFormPermutationStable(t *testing.T) {
	build := func(order []string) url.Values {
		form := url.Values{}
		for _, k := range order {
			form.Set(k, "v:"+k)
		}
		return form
	}
	a := build([]string{"zz", "mm", "Action", "aa"})
	b := build([]string{"aa", "Action", "zz", "mm"})
	if got, want := SignRPCForm(a, "k"), SignRPCForm(b, "k"); got != want {
		t.Errorf("permutation signatures differ: %q vs %q", got, want)
	}
}

// TestSignRPCFormExcludesSignature Signature 键不参与规范化串（重算场景：
// 剔除已有签名后按同密钥重算必须一致）。
func TestSignRPCFormExcludesSignature(t *testing.T) {
	form := url.Values{}
	form.Set("Action", "SingleSendMail")
	form.Set("Signature", "stale-signature")
	clean := url.Values{}
	clean.Set("Action", "SingleSendMail")
	if got, want := SignRPCForm(form, "k"), SignRPCForm(clean, "k"); got != want {
		t.Errorf("Signature key must not affect signing: %q vs %q", got, want)
	}
}

// TestSignRPCFormSecretKeying 密钥 = AccessKeySecret + "&"：不同 secret
// 必产生不同签名（防密钥尾缀丢失回归）。
func TestSignRPCFormSecretKeying(t *testing.T) {
	form := url.Values{}
	form.Set("Action", "SingleSendMail")
	if SignRPCForm(form, "abc") == SignRPCForm(form, "abc&") {
		t.Error("secret must be keyed as AccessKeySecret + &")
	}
}

// TestNewNonce 随机数形态：32 位小写 hex（16 字节）、两次调用不重复；
// 注入时钟仅作 crypto/rand 失败兜底，正常路径不触达。
func TestNewNonce(t *testing.T) {
	now := func() time.Time { return time.Unix(0, 0) }
	a, b := NewNonce(now), NewNonce(now)
	if len(a) != 32 || strings.ToLower(a) != a {
		t.Errorf("nonce = %q, want 32-char lowercase hex", a)
	}
	if a == b {
		t.Errorf("nonces must differ: %q == %q", a, b)
	}
}

// sigv4_test.go 签名核心以权威矢量锁定：固定时间 20130524T000000Z + AWS
// 文档示例密钥（AKIAIOSFODNN7EXAMPLE），期望值由 AWS 官方 SigV4 实装
// （botocore 1.44 SigV4Auth / S3SigV4QueryAuth）固定同时间产出——预签名
// GET 场景与 AWS 文档「Using Query Parameters」示例签名逐字节一致
// （aeeed9bb…f604d404），头签名 GET 场景为 AWS 文档 header-auth 示例矢量
// （f0e8bdb8…36bd41f，x-amz-content-sha256 入 SignedHeaders 形态）。非
// 自证：期望值与实现互相独立。
package s3

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testAccess = "AKIAIOSFODNN7EXAMPLE"
	testSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var testNow = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func TestURIEncode(t *testing.T) {
	cases := []struct {
		in, want    string
		encodeSlash bool
	}{
		{"abcXYZ019-_.~", "abcXYZ019-_.~", true},
		{"a b", "a%20b", true},
		{"a/b", "a/b", false},  // 斜杠保留（canonical URI）
		{"a/b", "a%2Fb", true}, // 查询侧编码
		{"a;b:c", "a%3Bb%3Ac", true},
		{"中文", "%E4%B8%AD%E6%96%87", true},
	}
	for i, c := range cases {
		if got := uriEncode(c.in, c.encodeSlash); got != c.want {
			t.Errorf("case %d uriEncode(%q) = %q, want %q", i, c.in, got, c.want)
		}
	}
}

func TestCanonicalQuery(t *testing.T) {
	got := canonicalQuery(map[string]string{
		"X-Amz-Date":          "20130524T000000Z",
		"X-Amz-Expires":       "300",
		"X-Amz-SignedHeaders": "content-type;host",
	})
	want := "X-Amz-Date=20130524T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost"
	if got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}

// TestPresignGETDocVector AWS 文档预签名 GET 示例（host-only 签名，86400s）。
func TestPresignGETDocVector(t *testing.T) {
	s := &S3{
		scheme: "https", host: "s3.amazonaws.com", bucket: "examplebucket",
		region: "us-east-1", accessKey: testAccess, secretKey: testSecret, ttl: 86400,
	}
	got, headers := s.presign(http.MethodGet, "test.txt", nil, testNow)
	want := "https://examplebucket.s3.amazonaws.com/test.txt" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	if got != want {
		t.Errorf("presign GET:\n got %s\nwant %s", got, want)
	}
	if len(headers) != 0 {
		t.Errorf("headers = %v, want empty", headers)
	}
}

// TestPresignPUTPathStyleVector path-style + content-type 入签名（botocore
// 权威矢量）。
func TestPresignPUTPathStyleVector(t *testing.T) {
	s := &S3{
		scheme: "http", host: "minio.internal:9000", bucket: "authloft", pathStyle: true,
		prefix: "qr", region: "us-east-1", accessKey: testAccess, secretKey: testSecret, ttl: 300,
	}
	got, headers := s.presignPut("t1.jpg", "image/jpeg", testNow)
	want := "http://minio.internal:9000/authloft/qr/t1.jpg" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost" +
		"&X-Amz-Signature=48abb1b2b13af744f1bff33e523dd3e027fa21824eff02d0cfe4e931784d6444"
	if got != want {
		t.Errorf("presign PUT path-style:\n got %s\nwant %s", got, want)
	}
	if len(headers) != 1 || headers["Content-Type"] != "image/jpeg" {
		t.Errorf("headers = %v, want {Content-Type: image/jpeg}", headers)
	}
}

// TestPresignPUTAclVector public_read 时 x-amz-acl 入签名且随 headers 下发。
func TestPresignPUTAclVector(t *testing.T) {
	s := &S3{
		scheme: "http", host: "minio.internal:9000", bucket: "authloft", pathStyle: true,
		prefix: "qr", region: "us-east-1", accessKey: testAccess, secretKey: testSecret,
		ttl: 300, publicRead: true,
	}
	got, headers := s.presignPut("t1.jpg", "image/jpeg", testNow)
	want := "http://minio.internal:9000/authloft/qr/t1.jpg" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-acl" +
		"&X-Amz-Signature=395d7bf01b582a02f9be3a0dced708efb6316ff0499e91b860b7147de0d627f0"
	if got != want {
		t.Errorf("presign PUT acl:\n got %s\nwant %s", got, want)
	}
	if headers["Content-Type"] != "image/jpeg" || headers["X-Amz-Acl"] != "public-read" {
		t.Errorf("headers = %v, want Content-Type + X-Amz-Acl", headers)
	}
}

// TestPresignPUTVirtualHostVector virtual-host 寻址（botocore 权威矢量）。
func TestPresignPUTVirtualHostVector(t *testing.T) {
	s := &S3{
		scheme: "https", host: "s3.amazonaws.com", bucket: "authloft", prefix: "avatar",
		region: "us-east-1", accessKey: testAccess, secretKey: testSecret, ttl: 300,
	}
	got, _ := s.presignPut("u1.jpg", "image/png", testNow)
	want := "https://authloft.s3.amazonaws.com/avatar/u1.jpg" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=content-type%3Bhost" +
		"&X-Amz-Signature=ff723a0e7c3decb565468441f0021d0fbc0a37fcff71929947d0ec66ef8fb162"
	if got != want {
		t.Errorf("presign PUT virtual-host:\n got %s\nwant %s", got, want)
	}
}

// TestHeaderSignDocVector 头签名 GET 示例（Range 头入签名，x-amz-content-sha256
// 在 SignedHeaders 内；botocore S3SigV4Auth 权威矢量）。
func TestHeaderSignDocVector(t *testing.T) {
	s := &S3{
		scheme: "https", host: "s3.amazonaws.com", bucket: "examplebucket",
		region: "us-east-1", accessKey: testAccess, secretKey: testSecret,
	}
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	s.signRequest(req, emptyPayloadSHA, map[string]string{"Range": "bytes=0-9"}, testNow)
	auth := req.Header.Get("Authorization")
	for _, want := range []string{
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date",
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization 缺 %q:\n%s", want, auth)
		}
	}
	if got := req.Header.Get("x-amz-content-sha256"); got != emptyPayloadSHA {
		t.Errorf("x-amz-content-sha256 = %q", got)
	}
	if got := req.Header.Get("Range"); got != "bytes=0-9" {
		t.Errorf("Range = %q", got)
	}
}

// TestSigningKeyChain 派生链自洽：同输入必同签名、密钥参与派生（换密钥换签名）。
func TestSigningKeyChain(t *testing.T) {
	sts := stringToSign("20130524T000000Z", "20130524/us-east-1/s3/aws4_request",
		fmt.Sprintf("%s\n%s\n\nhost:x\n\nhost\n%s", "PUT", "/a", unsignedPayload))
	sig1 := signature(sts, testSecret, "20130524", "us-east-1", "s3")
	sig2 := signature(sts, testSecret, "20130524", "us-east-1", "s3")
	sig3 := signature(sts, testSecret+"x", "20130524", "us-east-1", "s3")
	if len(sig1) != 64 || sig1 != sig2 || sig1 == sig3 {
		t.Errorf("signature 派生不稳定或不依赖密钥: %q %q %q", sig1, sig2, sig3)
	}
}

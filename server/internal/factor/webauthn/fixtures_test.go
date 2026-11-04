package webauthn

// fixtures_test.go 用 github.com/go-webauthn/webauthn 的 COSE / CBOR 组件
// （webauthncose、webauthncbor）与标准库 P-256 生成合法的注册 / 断言响应
// 夹具，使测试可逐项篡改 challenge / origin / rpId / signature / signCount。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"google.golang.org/protobuf/types/known/structpb"
)

// COSE_Key 公共参数（EC2 / ES256 / P-256）。
const (
	coseKeyTypeEC2 = int64(2)
	coseAlgES256   = int64(-7)
	coseCurveP256  = int64(1)
)

// testAuthenticator 一台模拟认证器：持有私钥、COSE 公钥、credential_id 与
// userHandle，可签发任意 challenge / origin / rpId / counter 的响应。
type testAuthenticator struct {
	priv       *ecdsa.PrivateKey
	pubCOSE    []byte
	credID     []byte
	userHandle []byte
}

func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubCOSE, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   coseKeyTypeEC2,
			Algorithm: coseAlgES256,
		},
		Curve:  coseCurveP256,
		XCoord: priv.X.FillBytes(make([]byte, 32)),
		YCoord: priv.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("credID: %v", err)
	}
	userHandle := make([]byte, 16)
	if _, err := rand.Read(userHandle); err != nil {
		t.Fatalf("userHandle: %v", err)
	}
	return &testAuthenticator{priv: priv, pubCOSE: pubCOSE, credID: credID, userHandle: userHandle}
}

// ceremonyFixture 一次 ceremony 的可调参数（用于逐项破坏四项固定校验）。
type ceremonyFixture struct {
	challenge string
	origin    string
	rpID      string
	counter   uint32
	// signKey 非 nil 时用「另一把私钥」签名，用于构造签名校验失败。
	signKey *ecdsa.PrivateKey
}

// assertion 构造一条合法的 navigator.credentials.get() 断言对象（Struct）。
func (a *testAuthenticator) assertion(t *testing.T, f ceremonyFixture) *structpb.Struct {
	t.Helper()
	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   f.challenge,
		"origin":      f.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	authData := authDataBytes(f.rpID, 0x01, f.counter, nil) // UP
	clientDataHash := sha256.Sum256(clientDataJSON)
	sigData := append(append([]byte(nil), authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	key := a.priv
	if f.signKey != nil {
		key = f.signKey
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return mustStruct(t, map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": b64(authData),
			"clientDataJSON":    b64(clientDataJSON),
			"signature":         b64(sig),
			"userHandle":        b64(a.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}

// attestation 构造一条合法的 navigator.credentials.create() 注册对象
// （fmt="none" 自证明，便于不引入证书链即可覆盖注册路径）。
func (a *testAuthenticator) attestation(t *testing.T, f ceremonyFixture) *structpb.Struct {
	t.Helper()
	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   f.challenge,
		"origin":      f.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	// attestedCredentialData = aaguid(16) || credIdLen(2) || credId || COSE pubkey
	extra := make([]byte, 0, 16+2+len(a.credID)+len(a.pubCOSE))
	extra = append(extra, make([]byte, 16)...)
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(a.credID)))
	extra = append(extra, credLen...)
	extra = append(extra, a.credID...)
	extra = append(extra, a.pubCOSE...)
	authData := authDataBytes(f.rpID, 0x41, f.counter, extra) // UP | AT
	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	return mustStruct(t, map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientDataJSON),
			"attestationObject": b64(attObj),
		},
		"clientExtensionResults": map[string]any{},
	})
}

// authDataBytes = sha256(rpID) || flags || counter || extra。
func authDataBytes(rpID string, flags byte, counter uint32, extra []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37+len(extra))
	buf = append(buf, rpHash[:]...)
	buf = append(buf, flags)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, counter)
	buf = append(buf, c...)
	buf = append(buf, extra...)
	return buf
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	return s
}

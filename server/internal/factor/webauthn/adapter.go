package webauthn

// adapter.go 是 github.com/go-webauthn/webauthn 的唯一引用点（§1.5 行 78
// 「可替换性」）：库类型只出现在本文件内部，factor 对外接口、装配方与
// service 都不接触该库类型，替换实现只改本适配层。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	libwa "github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// RPConfig 服务端 WebAuthn 口径（§8.3 行 1047：rpId 固定 Authloft 根域名
// 配置项、origin 服务端强校验）。
type RPConfig struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	Timeout       time.Duration
}

// ValidRPID 判定字符串是否为库启动期接受的 RP ID 域名字符串（localhost
// 或多 label 域名；拒绝 IP、scheme、端口、路径等，W3C RP ID 语义）。
// 供安装域源头校验复用（接口文档 §13.3：安装期接受的 rp_id 集合必须 ⊆
// 启动期库接受集合，避免装出装完即降级的 config，D6）；仍经本文件转出，
// 不破坏「go-webauthn 唯一引用点」约定（§1.5 行 78）。
func ValidRPID(rpID string) bool {
	return protocol.ValidateRPID(rpID) == nil
}

// ceremony 封装库实例；库类型不越出本文件。
type ceremony struct {
	rp RPConfig
	wa *libwa.WebAuthn
}

func newCeremony(rp RPConfig) (*ceremony, error) {
	wa, err := libwa.New(&libwa.Config{
		RPID:          rp.RPID,
		RPDisplayName: rp.RPDisplayName,
		RPOrigins:     rp.RPOrigins,
		Timeouts: libwa.TimeoutsConfig{
			Login:        libwa.TimeoutConfig{Timeout: rp.Timeout},
			Registration: libwa.TimeoutConfig{Timeout: rp.Timeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: init ceremony: %w", err)
	}
	return &ceremony{rp: rp, wa: wa}, nil
}

// adapterUser 实现库的 webauthn.User 接口，用于注册场景构造 options.user：
// id 固定为不透明的 uid 字节串（W3C：user.id 须稳定且不得含可识别信息），
// name / displayName 取服务端查得的 username——用户在通行密钥注册弹窗与
// 凭据管理界面看到的是自己的账号名，而不是一串数字 ID。username 变更不
// 影响已注册凭据（认证始终按 user.id 匹配）。
type adapterUser struct {
	id   []byte
	name string
}

func (u adapterUser) WebAuthnID() []byte                      { return u.id }
func (u adapterUser) WebAuthnName() string                    { return u.name }
func (u adapterUser) WebAuthnDisplayName() string             { return u.name }
func (u adapterUser) WebAuthnCredentials() []libwa.Credential { return nil }

// requestOptions 生成登录 / 断言场景的完整 PublicKeyCredentialRequestOptions
// （接口文档 §2.6 行 547、§8.3 行 1045）：固定 usernameless，allowCredentials
// 恒为空；challenge 由调用方生成并绑定 login_token（§8.3 行 1046）。
func (c *ceremony) requestOptions(challenge []byte) (*structpb.Struct, error) {
	assertion, _, err := c.wa.BeginDiscoverableLogin(libwa.WithChallenge(challenge))
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin assertion: %w", err)
	}
	m, err := marshalOptions(assertion.Response)
	if err != nil {
		return nil, err
	}
	// BeginDiscoverableLogin 的 allowCredentials 为 nil、JSON 会省略；§8.3
	// 要求「恒为空」，显式下发空数组，避免前端把它当作未提供。
	m["allowCredentials"] = []any{}
	return structpb.NewStruct(m)
}

// creationOptions 生成账号域注册场景的完整 PublicKeyCredentialCreationOptions
// （接口文档 §3.6 行 926、§8.3 行 1045）。要求 resident key / 可发现凭据
// （§8.3 行 1048），challenge 改用与独立原子 token 绑定的同一份随机值。
// userID 为不透明 uid 字节串，username 由账号域从服务端用户表查得后传入，
// 同时作为 options.user.name 与 displayName。
func (c *ceremony) creationOptions(userID []byte, username string, challenge []byte) (*structpb.Struct, error) {
	creation, _, err := c.wa.BeginRegistration(
		adapterUser{id: userID, name: username},
		libwa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin registration: %w", err)
	}
	creation.Response.Challenge = protocol.URLEncodedBase64(challenge)
	return optionsToStruct(creation.Response)
}

// assertionResult 断言校验结果（标准类型）。
type assertionResult struct {
	CredentialID string
	SignCount    int64
}

// verifyAssertion 校验 §8.3 行 1046/1049 的四项固定：challenge 匹配、origin、
// rpId hash、断言签名（均由 protocol.ParsedCredentialAssertionData.Verify
// 完成）；signCount 递增由调用方比对存储值。pubKey 为
// user_credential_webauthn.public_key（COSE 编码公钥）。
func (c *ceremony) verifyAssertion(credential *structpb.Struct, storedChallenge string, pubKey []byte) (*assertionResult, error) {
	b, err := structToBytes(credential)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(b)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse assertion: %w", err)
	}
	if err := parsed.Verify(
		storedChallenge,
		c.rp.RPID,
		"", // appID：usernameless 不使用 FIDO U2F AppID 扩展
		c.rp.RPOrigins,
		nil, nil,
		protocol.TopOriginExplicitVerificationMode,
		false, // 不允许跨源
		false, // UV 由展示类字段决定，不强制
		true,  // 要求用户存在位
		pubKey,
		protocol.SignaturePolicy{},
	); err != nil {
		return nil, fmt.Errorf("webauthn: verify assertion: %w", err)
	}
	return &assertionResult{
		CredentialID: base64.RawURLEncoding.EncodeToString(parsed.RawID),
		SignCount:    int64(parsed.Response.AuthenticatorData.Counter),
	}, nil
}

// attestationResult 注册校验结果（标准类型，交给账号域建库）。
// Transports / AAGUID 为展示类投影字段（§3.6 行 914 列表项）：取自注册
// 响应 response.transports 与 attestationObject.authData 的 AAGUID，
// 不参与四项固定校验。
type attestationResult struct {
	CredentialID string
	PublicKey    []byte
	SignCount    int64
	Transports   []string
	AAGUID       string
}

// verifyAttestation 校验账号域注册提交的 attestation 对象：challenge 匹配、
// origin、rpId hash、attestation 签名（注册路径的四项固定校验）。
func (c *ceremony) verifyAttestation(credential *structpb.Struct, storedChallenge string) (*attestationResult, error) {
	b, err := structToBytes(credential)
	if err != nil {
		return nil, err
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(b)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse attestation: %w", err)
	}
	if _, err := pcc.Verify(
		storedChallenge,
		c.rp.RPID,
		c.rp.RPOrigins, nil, nil,
		protocol.TopOriginExplicitVerificationMode,
		false, false, false,
		nil, // 本期不接 FIDO 元数据服务
		libwa.CredentialParametersDefault(),
		protocol.AttestationPolicy{},
		protocol.SignaturePolicy{},
	); err != nil {
		return nil, fmt.Errorf("webauthn: verify attestation: %w", err)
	}
	auth := pcc.Response.AttestationObject.AuthData
	transports := make([]string, 0, len(pcc.Response.Transports))
	for _, tr := range pcc.Response.Transports {
		transports = append(transports, string(tr))
	}
	return &attestationResult{
		CredentialID: base64.RawURLEncoding.EncodeToString(pcc.RawID),
		PublicKey:    auth.AttData.CredentialPublicKey,
		SignCount:    int64(auth.Counter),
		Transports:   transports,
		AAGUID:       formatAAGUID(auth.AttData.AAGUID),
	}, nil
}

// formatAAGUID AAGUID（16 字节）→ 标准 UUID 展示形 8-4-4-4-12 小写十六
// 进制（§3.6 行 914 aaguid 字段）；全零值 / 非 16 字节返回空串（认证器
// 未提供）。
func formatAAGUID(a []byte) string {
	if len(a) != 16 {
		return ""
	}
	for _, b := range a {
		if b != 0 {
			return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
		}
	}
	return ""
}

// marshalOptions 把库 options 结构经 JSON 转成 map[string]any（Struct 只解决
// 「结构随场景变化、前端不逐字段消费」的表达问题，§12.9 行 1779-1780）。
func marshalOptions(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal options: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("webauthn: decode options: %w", err)
	}
	return m, nil
}

func optionsToStruct(v any) (*structpb.Struct, error) {
	m, err := marshalOptions(v)
	if err != nil {
		return nil, err
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil, fmt.Errorf("webauthn: struct options: %w", err)
	}
	return s, nil
}

// structToBytes 把前端原样透传的断言 / 注册对象（google.protobuf.Struct）
// 还原成 JSON 字节，交给库解析器；前端不感知结构（§3.6 行 931）。
func structToBytes(s *structpb.Struct) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("webauthn: nil credential")
	}
	b, err := protojson.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal credential: %w", err)
	}
	return b, nil
}

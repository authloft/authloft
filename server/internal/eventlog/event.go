// Package eventlog 负责 event_log 的事件名、actor_type 与 detail 编码
// （docs/后端架构.md §3.12 行 447-448、§4.6 行 763-806；接口文档 §12.0
// 行 1626-1631）。detail 不固定 schema，按 §12.0 用 msgpack
// （map[string]any）序列化为 VARBINARY；本包只编码、不读写 DB。
package eventlog

import (
	"log/slog"

	"github.com/vmihailenco/msgpack/v5"

	"authloft/internal/logx"
)

// 事件名常量，与 §4.6 行 770 的 event 枚举一一对应；末尾
// oidc_authorize_no_state 是 §4.6 行 792 定义的 system 事件（接口文档
// §4.2）。事件名是落库值，改动需先更新文档（docs/ 为唯一真相）。
const (
	EventLoginSuccess       = "login_success"
	EventChangePassword     = "change_password"
	EventResetPassword      = "reset_password"
	EventBindPhone          = "bind_phone"
	EventBindEmail          = "bind_email"
	EventEnableMFA          = "enable_mfa"
	EventDisableMFA         = "disable_mfa"
	EventWebAuthnRegister   = "webauthn_register"
	EventWebAuthnDelete     = "webauthn_delete"
	EventThirdpartyBind     = "thirdparty_bind"
	EventThirdpartyUnbind   = "thirdparty_unbind"
	EventAdminDisableUser   = "admin_disable_user"
	EventAdminResetPassword = "admin_reset_password"
	EventAdminUpdateUser    = "admin_update_user"
	EventAdminUpdateContact = "admin_update_contact"
	// admin 用户管理族救援事件（§4.6 枚举、接口文档 §5.6）：detail 一律不记
	// 密码、TOTP 密钥、恢复码、联系方式明文。
	EventAdminDisableMFA         = "admin_disable_mfa"
	EventAdminUnbindTotp         = "admin_unbind_totp"
	EventAdminCredentialDelete   = "admin_credential_delete"
	EventAdminRecoveryCodesReset = "admin_recovery_codes_reset"
	EventProviderCreate          = "provider_create"
	EventProviderUpdate          = "provider_update"
	EventSettingsUpdate          = "settings_update"
	EventOIDCAuthorizeNoState    = "oidc_authorize_no_state"
)

// actor_type 取值（§4.6 行 771-772）：user=该用户 uid；admin=操作管理员
// uid；system=0。system 事件目前只有 oidc_authorize_no_state。
const (
	ActorTypeUser   = "user"
	ActorTypeAdmin  = "admin"
	ActorTypeSystem = "system"
)

// DetailLoginSuccess 编码 login_success 的 detail（§4.6 行 798）：
// {factor, mfa_factor, session_id, device_hint}。四个键恒定存在，调用方
// 无从推导的值填空串（键缺失会让管理后台视图字段漂移）。
func DetailLoginSuccess(factor, mfaFactor, sessionID, deviceHint string) []byte {
	return encodeDetail(map[string]any{
		"factor":      factor,
		"mfa_factor":  mfaFactor,
		"session_id":  sessionID,
		"device_hint": deviceHint,
	})
}

// DetailPwdEpoch 编码 change_password / reset_password 的 detail（§4.6
// 行 799）：{pwd_epoch}。
func DetailPwdEpoch(pwdEpoch int64) []byte {
	return encodeDetail(map[string]any{"pwd_epoch": pwdEpoch})
}

// DetailTargetMasked 编码 bind_phone / bind_email 的 detail（§4.6 行
// 800）：{target_masked}。
func DetailTargetMasked(targetMasked string) []byte {
	return encodeDetail(map[string]any{"target_masked": targetMasked})
}

// DetailThirdpartyBind 编码 thirdparty_bind / thirdparty_unbind 的 detail
// （§4.6 行 802）：{provider_key, open_id}。
func DetailThirdpartyBind(providerKey, openID string) []byte {
	return encodeDetail(map[string]any{
		"provider_key": providerKey,
		"open_id":      openID,
	})
}

// DetailProviderChanged 编码 provider_create / provider_update 的 detail
// （§4.6 行 803）：{provider_key, changed_fields:[...]}。nil 归一为空数组。
func DetailProviderChanged(providerKey string, changedFields []string) []byte {
	if changedFields == nil {
		changedFields = []string{}
	}
	return encodeDetail(map[string]any{
		"provider_key":   providerKey,
		"changed_fields": changedFields,
	})
}

// DetailSettingsUpdate 编码 settings_update 的 detail（§4.6 行 804）：
// {keys:[...], before:{...}, after:{...}}，只含变更项。nil 归一为空数组 /
// 空对象，保证键值类型稳定。
func DetailSettingsUpdate(keys []string, before, after map[string]any) []byte {
	if keys == nil {
		keys = []string{}
	}
	if before == nil {
		before = map[string]any{}
	}
	if after == nil {
		after = map[string]any{}
	}
	return encodeDetail(map[string]any{
		"keys":   keys,
		"before": before,
		"after":  after,
	})
}

// DetailChangedFields 编码 admin_update_user / admin_update_contact 的
// detail（《后端架构》§4.6）：{changed_fields:[...]}，只记变更字段名——
// admin_update_contact 不记手机号 / 邮箱明文。nil 归一为空数组。
func DetailChangedFields(changedFields []string) []byte {
	if changedFields == nil {
		changedFields = []string{}
	}
	return encodeDetail(map[string]any{"changed_fields": changedFields})
}

// DetailEnabled 编码 admin_disable_mfa 的 detail（《后端架构》§4.6：
// {enabled:false}，管理端关闭用户两步验证；与自助 enable_mfa / disable_mfa
// 的 {enabled:...} 同形）。
func DetailEnabled(enabled bool) []byte {
	return encodeDetail(map[string]any{"enabled": enabled})
}

// DetailCredentialDelete 编码 admin_credential_delete 的 detail
// （《后端架构》§4.6）：{credential_id, kind}，不记凭证 secret。
func DetailCredentialDelete(credentialID int64, kind string) []byte {
	return encodeDetail(map[string]any{
		"credential_id": credentialID,
		"kind":          kind,
	})
}

// DetailEmpty 编码契约明示 detail 为 {} 的事件（§4.6 admin_unbind_totp /
// admin_recovery_codes_reset 等：不记 TOTP 密钥 / 任何码值）：msgpack 空映射，
// 与「无 detail」（NULL 列）区分——字段存在但为空对象。
func DetailEmpty() []byte {
	return encodeDetail(map[string]any{})
}

// encodeDetail 是所有 detail 构造器的唯一编码出口（接口文档 §12.0 行
// 1631：msgpack 透传）。编码失败返回 nil（落 NULL）：附加信息缺失不能让
// 事件写入链路报错，呼应 §5.2 行 893「绝不因辅助写入失败影响主链路」。
func encodeDetail(detail map[string]any) []byte {
	b, err := msgpack.Marshal(detail)
	if err != nil {
		// 降级为 NULL 但不能无痕：不记 detail 内容（可能含敏感值），只记
		// 脱敏后的错误文本。本函数无 ctx，按 CODE_GUIDE §3.8 用包级 slog。
		slog.Warn("eventlog: encode detail failed, storing NULL",
			"error", logx.RedactText(err.Error()),
		)
		return nil
	}
	return b
}

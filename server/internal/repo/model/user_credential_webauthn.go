// user_credential_webauthn 表 bun model（后端架构 §4.2 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"github.com/uptrace/bun"
)

// UserCredentialWebauthn user_credential_webauthn 表映射（§4.2）：WebAuthn
// 额外凭据表。id 主键不自增、与 user_credential.id 保持一致（由
// WebauthnRepo.Create 在同一事务内先插 user_credential 行、以回填的自增
// 值作本表主键写入第二行）；kind 列恒 'webauthn'（DDL DEFAULT）；public_key
// 为 COSE 公钥字节；credential_id base64url 编码，uk_kind_credid 在
// (kind, credential_id) 上唯一；sign_count 防克隆计数（§8.3：断言校验通过
// 后经延迟队列按凭据同键合并取最大值落库）。本表无时间列，struct 不含
// created_at / updated_at。
type UserCredentialWebauthn struct {
	bun.BaseModel `bun:"table:user_credential_webauthn"`

	ID           int64  `bun:"column:id,pk"`
	UserID       int64  `bun:"column:user_id,notnull"`
	Kind         string `bun:"column:kind,notnull,default:'webauthn'"`
	PublicKey    []byte `bun:"column:public_key"`
	CredentialID string `bun:"column:credential_id,notnull,default:''"`
	SignCount    int64  `bun:"column:sign_count,notnull,default:0"`
}

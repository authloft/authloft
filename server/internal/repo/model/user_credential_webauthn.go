// user_credential_webauthn 表 GORM model（后端架构 §4.2 行 666-675 DDL）。
// 表结构由 migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

// UserCredentialWebauthn user_credential_webauthn 表映射（§4.2 行
// 666-675）：WebAuthn 额外凭据表。id 主键不自增、与 user_credential.id
// 保持一致（行 667：由 WebauthnRepo.Create 在同一事务内先插
// user_credential 行、以回填的自增值作本表主键写入第二行）；kind 列恒
// 'webauthn'（行 669，DDL DEFAULT）；public_key 为 COSE 公钥字节；
// credential_id base64url 编码，uk_kind_credid（行 673）在
// (kind, credential_id) 上唯一；sign_count 防克隆计数（§8.3 行 1047：
// 断言校验通过后经延迟队列按凭据同键合并取最大值落库）。本表无时间列，
// struct 不含 CreatedAt / UpdatedAt，GORM 不做自动填充。
type UserCredentialWebauthn struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	UserID       int64  `gorm:"column:user_id;not null"`
	Kind         string `gorm:"column:kind;size:32;not null;default:'webauthn'"`
	PublicKey    []byte `gorm:"column:public_key;type:varbinary(2048)"`
	CredentialID string `gorm:"column:credential_id;size:512;not null;default:''"`
	SignCount    int64  `gorm:"column:sign_count;not null;default:0"`
}

// TableName 固定表名 user_credential_webauthn（§4.2）。
func (UserCredentialWebauthn) TableName() string {
	return "user_credential_webauthn"
}

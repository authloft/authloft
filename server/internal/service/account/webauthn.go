// webauthn.go account 域通行密钥族业务层（docs/接口文档.md §3.6
// 行 927-947、docs/后端架构.md §8.3 行 1061-1077）。
//
// 职责边界（五方法实装，Delete 闭环）：
//   - GetWebauthnCredentials：{items:[{id,label,createdAt,lastUsedAt,
//     transports,aaguid}]}（行 931）。数据源 = WebauthnRepo.ListByUser
//     （user_credential_webauthn 行，id 倒序）与 CredentialRepo.ListByUser
//     （user_credential 行，label / meta / 时间列）按同值主键拼接；meta 解
//     credential.CredentialMeta 取 transports / aaguid；user_credential 行
//     缺失（脏数据）仅投影零值，不放大为错误（thirdparty 列表同口径）。
//   - RegisterWebauthn step=challenge：factor.BeginRegistration（factor 内核
//     ——独立原子 token purpose=webauthn + 完整
//     PublicKeyCredentialCreationOptions + resident key 要求 + expiresIn
//     120s），本层透传。
//   - RegisterWebauthn step=verify：factor.FinishRegistration 完成 token
//     解析（篡改 / 无效 → invalid_request，过期 → code_expired）与
//     attestation 四项固定校验；token 载荷 uid 与当前会话 uid 不一致 →
//     invalid_request（防串号，ThirdpartyOauth cookie uid 同口径）；同
//     credential_id 已注册 → already_exists；写库走 WebauthnRepo.Create
//     同事务两行（user_credential：label 落 label 列、transports / aaguid
//     落 meta 列；§4.2 DDL 行 675 label 列即「用户自定义名称」）；成功投
//     递 webauthn_register 审计（§4.6 行 790 事件枚举）。
//   - RenameWebauthnCredential：{id,label} 仅本人（行 934）。label 必填、
//     ≤128 字节（§4.2 label 列宽，超长拒绝防 DB 500）；目标行经
//     CredentialRepo.ListByUser 按 id+kind 定位（未命中 / 非本人 →
//     not_found，不泄露存在性）；更新走 CredentialRepo.Update（label 在
//     可变列更新集）。无审计（§4.6 事件枚举无 webauthn_rename，不自造）。
//   - DeleteWebauthnCredential：{id} 仅本人（行 935）。
//     定位 / 删除走 WebauthnRepo.Delete 单事务两行（id+uid+kind 不命中
//     即 not_found——不存在 / 属他人统一 not_found，不泄露存在性）；
//     审计需 credential_id，经 WebauthnRepo.ListByUser 预查目标行
//     （TOCTOU 无害：并发删除后 Delete 返回 not_found，一致性不破）；
//     成功投递 webauthn_delete 审计（eventlog.EventWebAuthnDelete，
//     §4.6 行 790 枚举既有成员）。
//
// fail-closed（§8.3 行 1071-1075 窗口期六要素，本实现即行 1073 注记的
// 「实装后必须带窗口期拒绝」落地）：webauthn 引擎启动初始化失败降级时
// bootstrap 注入 Factor=nil，本层五方法（含只读列表）一律拒绝
// method_disabled + 文案「通行密钥暂不可用，请联系管理员」（§1.6 行
// 250）+ 逐次 WARN；未启用账号与无关功能行为不变。
package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	credentialpb "authloft/gen/go/credential"
	"authloft/internal/eventlog"
	"authloft/internal/factor/webauthn"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// 域常量（字面量均为文档封闭集成员；跨包私有常量按后端架构 §3.5「各落
// 一份」先例——thirdparty.go / handler/account 同款）。
const (
	// registerStepChallenge / registerStepVerify RegisterWebauthn.step 取值
	//（§3.6 行 932-933）。
	registerStepChallenge = "challenge"
	registerStepVerify    = "verify"
	// kindWebauthn user_credential.kind 的 webauthn 取值（§4.2 行 673）。
	kindWebauthn = "webauthn"
	// webauthnLabelMaxBytes §4.2 行 675 label 列宽 VARCHAR(128)，按字节计。
	webauthnLabelMaxBytes = 128
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员；
// ErrWebauthnInternal 例外——映射 internal 无 ErrorInfo，§1.6 行 273）。
var (
	// ErrWebauthnUnauthenticated 无有效会话（401）。
	ErrWebauthnUnauthenticated = errors.New("account webauthn: authentication required")
	// ErrWebauthnDegraded 降级窗口 fail-closed（method_disabled + 固定文案）。
	ErrWebauthnDegraded = errors.New("account webauthn: method disabled (degraded)")
	// ErrWebauthnInvalidRequest 参数缺失 / step 非法 / token 篡改无效 / uid 串号。
	ErrWebauthnInvalidRequest = errors.New("account webauthn: invalid request")
	// ErrWebauthnCodeExpired 注册 token 过期（需重新走 step=challenge）。
	ErrWebauthnCodeExpired = errors.New("account webauthn: code expired")
	// ErrWebauthnDuplicate 同 credential_id 凭据已注册（uk_kind_credid）。
	ErrWebauthnDuplicate = errors.New("account webauthn: credential already exists")
	// ErrWebauthnInternal 基础设施故障（映射 internal）。
	ErrWebauthnInternal = errors.New("account webauthn: failed")
)

// WebauthnDegradedMessage 窗口期拒绝的固定文案（§1.6 行 250「文案明示
// 『通行密钥暂不可用，请联系管理员』语义」；与 orchestrator.WebauthnDegradedMessage
// 同一句——跨包导出常量按 §3.5 各落一份，此处随本域 handler ErrorInfo 下发）。
const WebauthnDegradedMessage = "通行密钥暂不可用，请联系管理员"

// WebauthnFactor 注册两态的因子内核窄接口（§20）：*webauthn.Factor 天然
// 满足（factor/webauthn 内核）；nil = 启动降级（fail-closed 判定源）。
type WebauthnFactor interface {
	BeginRegistration(uid int64) (*webauthn.RegistrationChallenge, error)
	FinishRegistration(tok string, credential *structpb.Struct) *webauthn.RegistrationVerify
}

// WebauthnStore user_credential_webauthn 表读写窄接口（§20）：*repo.WebauthnRepo
// 天然满足（列表 / 按凭据 ID 查重 / 同事务两行建库 / 同事务两行删除均既有，
// Delete 为本实现增量）。
type WebauthnStore interface {
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error)
	FindByCredentialID(ctx context.Context, credentialID string) (*model.UserCredentialWebauthn, error)
	Create(ctx context.Context, c *model.UserCredential, w *model.UserCredentialWebauthn) error
	Delete(ctx context.Context, id, userID int64) error
}

// WebauthnCredentialStore user_credential 表读写窄接口（§20）：*repo.CredentialRepo
// 天然满足（Rename 按 id+uid+kind 定位走 ListByUser，label 更新走 Update）。
type WebauthnCredentialStore interface {
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error)
	Update(ctx context.Context, c *model.UserCredential) error
}

// WebauthnDeps 依赖注入（§20）；装配层构造（bootstrap buildEngine）。
type WebauthnDeps struct {
	// Factor 注册内核；nil = 启动降级窗口（四方法一律 fail-closed 拒绝）。
	Factor WebauthnFactor
	// Webauthn user_credential_webauthn 读写。
	Webauthn WebauthnStore
	// Creds user_credential 读写（列表投影 / Rename）。
	Creds WebauthnCredentialStore
	// Audit webauthn_register 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// WebauthnService account 域通行密钥族业务层。
type WebauthnService struct {
	deps WebauthnDeps
	now  func() time.Time
}

// NewWebauthnService 构造。
func NewWebauthnService(d WebauthnDeps) *WebauthnService {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &WebauthnService{deps: d, now: now}
}

// compile 时断言生产实现满足各窄接口。
var (
	_ WebauthnFactor          = (*webauthn.Factor)(nil)
	_ WebauthnStore           = (*repo.WebauthnRepo)(nil)
	_ WebauthnCredentialStore = (*repo.CredentialRepo)(nil)
)

// WebauthnItem GetWebauthnCredentials 列表项（§3.6 行 931）。
type WebauthnItem struct {
	ID         int64
	Label      string
	CreatedAt  int64
	LastUsedAt int64
	Transports []string
	AAGUID     string
}

// failClosed 窗口期判定（§8.3 行 1071-1075）：Factor 未装配（启动初始化
// 失败降级）→ 逐次 WARN + ErrWebauthnDegraded（handler 映射 method_disabled
// + 固定文案）。五方法入口统一调用，含只读列表。
func (s *WebauthnService) failClosed() error {
	if s.deps.Factor == nil {
		slog.Warn("account webauthn: request rejected: webauthn engine degraded (fail-closed)")
		return ErrWebauthnDegraded
	}
	return nil
}

// ListCredentials 通行密钥列表（§3.6 行 931，OUTCOME ①）。
func (s *WebauthnService) ListCredentials(ctx context.Context, uid int64) ([]WebauthnItem, error) {
	if uid <= 0 {
		return nil, ErrWebauthnUnauthenticated
	}
	if err := s.failClosed(); err != nil {
		return nil, err
	}
	rows, err := s.deps.Webauthn.ListByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("%w: list webauthn rows: %v", ErrWebauthnInternal, err)
	}
	creds, err := s.deps.Creds.ListByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("%w: list credential rows: %v", ErrWebauthnInternal, err)
	}
	byID := make(map[int64]model.UserCredential, len(creds))
	for i := range creds {
		if creds[i].Kind == kindWebauthn {
			byID[creds[i].ID] = creds[i]
		}
	}

	items := make([]WebauthnItem, 0, len(rows))
	for i := range rows {
		it := WebauthnItem{ID: rows[i].ID}
		if c, ok := byID[rows[i].ID]; ok {
			it.Label = c.Label
			it.CreatedAt = c.CreatedAt.Unix()
			if c.LastUsedAt != nil {
				it.LastUsedAt = c.LastUsedAt.Unix()
			}
			if meta, err := repo.UnmarshalCredentialMeta(c.Meta); err == nil {
				it.Transports = meta.GetTransports()
				it.AAGUID = meta.GetAaguid()
			}
		}
		// user_credential 行缺失（脏数据）：仅投影 webauthn 行自带字段，
		// 不放大为错误（thirdparty 列表同口径）。
		items = append(items, it)
	}
	return items, nil
}

// BeginRegister step=challenge（§3.6 行 932、行 937-945 示例，OUTCOME ①）：
// 透传 factor 内核产物 {token, challengeData, expiresIn:120}。
func (s *WebauthnService) BeginRegister(ctx context.Context, uid int64) (*webauthn.RegistrationChallenge, error) {
	if uid <= 0 {
		return nil, ErrWebauthnUnauthenticated
	}
	if err := s.failClosed(); err != nil {
		return nil, err
	}
	ch, err := s.deps.Factor.BeginRegistration(uid)
	if err != nil {
		return nil, fmt.Errorf("%w: begin registration: %v", ErrWebauthnInternal, err)
	}
	return ch, nil
}

// FinishRegister step=verify（§3.6 行 933、行 947 token 契约，OUTCOME ①）：
// token 解析校验（篡改 / 无效 → invalid_request，过期 → code_expired）→
// uid 串号防御 → 凭据查重 → 同事务两行建库 → 审计投递。
func (s *WebauthnService) FinishRegister(ctx context.Context, uid int64, tok string, credential *structpb.Struct, label string) error {
	if uid <= 0 {
		return ErrWebauthnUnauthenticated
	}
	if err := s.failClosed(); err != nil {
		return err
	}
	if tok == "" || credential == nil {
		return fmt.Errorf("%w: empty token or credential", ErrWebauthnInvalidRequest)
	}
	if len(label) > webauthnLabelMaxBytes {
		return fmt.Errorf("%w: label too long", ErrWebauthnInvalidRequest)
	}

	res := s.deps.Factor.FinishRegistration(tok, credential)
	switch res.Status {
	case "":
		// Status 空即通过（factor.go RegistrationVerify 语义）。
	case webauthn.StatusInvalidRequest:
		return fmt.Errorf("%w: token invalid or attestation rejected", ErrWebauthnInvalidRequest)
	case webauthn.StatusCodeExpired:
		return ErrWebauthnCodeExpired
	default:
		// 因子层仅产出上述两态；未知态按内部故障防御。
		return fmt.Errorf("%w: unexpected verify status %q", ErrWebauthnInternal, res.Status)
	}
	// 串号防御（行 947「uid 为当前会话 uid」：token 是会话 A 签发的，
	// 换会话 B 提交即拒绝——ThirdpartyOauth cookie uid 同口径）。
	if res.UID != uid {
		return fmt.Errorf("%w: token uid mismatch", ErrWebauthnInvalidRequest)
	}
	// 查重：credential_id 全局唯一（uk_kind_credid，§4.2 行 690）。
	if _, err := s.deps.Webauthn.FindByCredentialID(ctx, res.CredentialID); err == nil {
		return fmt.Errorf("%w: credential id %q", ErrWebauthnDuplicate, res.CredentialID)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("%w: lookup credential id: %v", ErrWebauthnInternal, err)
	}

	meta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{
		Transports: res.Transports,
		Aaguid:     res.AAGUID,
	})
	if err != nil {
		return fmt.Errorf("%w: marshal meta: %v", ErrWebauthnInternal, err)
	}
	now := s.now()
	c := &model.UserCredential{
		UserID:    uid,
		Kind:      kindWebauthn,
		Secret:    []byte{}, // 公钥在 user_credential_webauthn 行，本列无 webauthn 语义（§4.2 行 674）
		Label:     label,    // §4.2 行 675：label 列即「用户自定义名称」
		Meta:      meta,     // transports / aaguid（credential.CredentialMeta，§12.2）
		IsEnabled: 1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	w := &model.UserCredentialWebauthn{
		UserID:       uid,
		Kind:         kindWebauthn,
		PublicKey:    res.PublicKey,
		CredentialID: res.CredentialID,
		SignCount:    res.SignCount,
	}
	if err := s.deps.Webauthn.Create(ctx, c, w); err != nil {
		if errors.Is(err, repo.ErrWebauthnDuplicate) {
			return fmt.Errorf("%w: credential id %q", ErrWebauthnDuplicate, res.CredentialID)
		}
		return fmt.Errorf("%w: create credential: %v", ErrWebauthnInternal, err)
	}
	// webauthn_register 审计（§4.6 行 790；detail={credential_id}，
	// thirdparty_bind 先例口径）。
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     eventlog.EventWebAuthnRegister,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Target:    res.CredentialID,
			Detail:    encodeDetailWebauthn(res.CredentialID),
			CreatedAt: now,
		})
	}
	return nil
}

// RenameCredential 重命名（§3.6 行 934，OUTCOME ①）：仅本人凭证——目标行
// 按 id+uid+kind 经 CredentialRepo.ListByUser 定位，未命中（不存在 / 非本
// 人 / 非 webauthn 行）统一 not_found，不泄露存在性。
func (s *WebauthnService) RenameCredential(ctx context.Context, uid int64, id int64, label string) error {
	if uid <= 0 {
		return ErrWebauthnUnauthenticated
	}
	if err := s.failClosed(); err != nil {
		return err
	}
	if label == "" {
		return fmt.Errorf("%w: empty label", ErrWebauthnInvalidRequest)
	}
	if len(label) > webauthnLabelMaxBytes {
		return fmt.Errorf("%w: label too long", ErrWebauthnInvalidRequest)
	}
	rows, err := s.deps.Creds.ListByUser(ctx, uid)
	if err != nil {
		return fmt.Errorf("%w: list credential rows: %v", ErrWebauthnInternal, err)
	}
	var target *model.UserCredential
	for i := range rows {
		if rows[i].ID == id && rows[i].Kind == kindWebauthn {
			target = &rows[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("account webauthn: rename: user %d has no webauthn credential %d: %w", uid, id, gorm.ErrRecordNotFound)
	}
	target.Label = label
	target.UpdatedAt = s.now()
	if err := s.deps.Creds.Update(ctx, target); err != nil {
		return fmt.Errorf("%w: rename credential: %v", ErrWebauthnInternal, err)
	}
	return nil
}

// DeleteCredential 删除（§3.6 行 935）：仅本人——定位 / 删除
// 走 WebauthnRepo.Delete 单事务两行（id+uid+kind 不命中即 not_found：不存在 /
// 属他人统一 not_found，不泄露存在性）；成功投递 webauthn_delete 审计
// （§4.6 行 790 枚举既有成员，detail={credential_id}——经 ListByUser 预查
// 目标行取值；TOCTOU 无害：并发删除后 Delete 返回 not_found，不投审计）。
func (s *WebauthnService) DeleteCredential(ctx context.Context, uid int64, id int64) error {
	if uid <= 0 {
		return ErrWebauthnUnauthenticated
	}
	if err := s.failClosed(); err != nil {
		return err
	}
	if id <= 0 {
		return fmt.Errorf("%w: empty id", ErrWebauthnInvalidRequest)
	}
	// 预查目标行取 credential_id（审计 detail）；未命中直接 not_found，
	// 不触碰删除路径（不存在 / 属他人同一结论，不泄露存在性）。
	rows, err := s.deps.Webauthn.ListByUser(ctx, uid)
	if err != nil {
		return fmt.Errorf("%w: list webauthn rows for delete: %v", ErrWebauthnInternal, err)
	}
	credentialID := ""
	for i := range rows {
		if rows[i].ID == id {
			credentialID = rows[i].CredentialID
			break
		}
	}
	if credentialID == "" {
		return fmt.Errorf("account webauthn: delete: user %d has no webauthn credential %d: %w", uid, id, gorm.ErrRecordNotFound)
	}
	if err := s.deps.Webauthn.Delete(ctx, id, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// TOCTOU：预查与删除之间行被并发删除——同一结论 not_found。
			return fmt.Errorf("account webauthn: delete: user %d credential %d: %w", uid, id, err)
		}
		return fmt.Errorf("%w: delete credential: %v", ErrWebauthnInternal, err)
	}
	// webauthn_delete 审计（§4.6 行 790；detail={credential_id}）。
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     eventlog.EventWebAuthnDelete,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Target:    credentialID,
			Detail:    encodeDetailWebauthn(credentialID),
			CreatedAt: s.now(),
		})
	}
	return nil
}

// encodeDetailWebauthn 编码 webauthn_register / webauthn_delete 的 detail
// （§4.6：{credential_id}，msgpack 透传——eventlog 包无 webauthn 构造器，
// 同包 thirdparty.go encodeExtra 同款私有实现）。编码失败返回 nil（落
// NULL），不影响主链路。
func encodeDetailWebauthn(credentialID string) []byte {
	b, err := msgpack.Marshal(map[string]any{"credential_id": credentialID})
	if err != nil {
		return nil
	}
	return b
}

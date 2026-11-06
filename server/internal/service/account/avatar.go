// avatar.go account 域头像直传两桩业务层（docs/接口文档.md §3.2 行
// 839-840、行 842、行 868、§1.6 行 261、§10.8 行 1711-1720；《后端架构》
// §15.1 行 1702-1737）。
//
// 职责：AccountService/PresignAvatar / CommitAvatar 编排——数据源链对齐
// handler avatarUpload 同口径：settings avatar_storage_provider →
// provider 表 storage 生效行 → ParseProviderExt → dto.AccountAvatarUpload
// 投影（mode / maxSize / allowedTypes 与 GetConfig 下发恒一致，local+direct
// 回退 proxy 在 dto 内折）；direct 模式校验 MIME 白名单 / size 上限后生成
// 服务端 key（avatars/{uid}/ 隔离 + crypto/rand 随机成分，行 839「key 由
// 服务端生成，前端无法覆盖」），Resolver → PresignPut 签发有时效 PUT URL
//（ExpiresIn = Ext.presign_ttl，0 → 300，§12.1 行 1704 注释默认）。
// CommitAvatar 仅以 Storage.URL(key) 回显地址，不回读校验（行 868 禁止
// Get/HEAD；§15.1 commit 要点——异步 HEAD 校验留待存储扩展，本层不做）。
// uid 由 handler 注入（service 不解析会话，profile.go 先例），存在性先判
// 404 优先（profile.go 先例）。未配置 / mode 非 direct 哨兵错误按行 842 由
// handler 映射 internal（不新增错误码），file_type_not_allowed /
// file_too_large 依 §1.6 行 261。
package account

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/internal/dto"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
	"authloft/internal/storage"
)

// 哨兵错误（handler 映射锚点，errors.Is 可辨；§1.6 行 261 封闭集，
// 不新增错误码）。
var (
	// ErrAvatarNotConfigured 头像存储未配置（行 842：settings 空串 / 查无
	// 该行 / is_enabled=0 / category≠storage）——被直调的上传接口按未知
	// 异常映射 internal。
	ErrAvatarNotConfigured = errors.New("account avatar: storage provider not configured")
	// ErrAvatarPresignUnavailable 当前配置不支持直传（mode≠direct，含
	// local 回退，行 842 / §15.1 表）——同按 internal 口径映射。
	ErrAvatarPresignUnavailable = errors.New("account avatar: presign unavailable")
	// ErrAvatarFileTypeNotAllowed MIME 不在 allowedTypes 内（行 868）→
	// file_type_not_allowed。
	ErrAvatarFileTypeNotAllowed = errors.New("account avatar: file type not allowed")
	// ErrAvatarFileTooLarge size 超 maxSize（行 868）→ file_too_large。
	ErrAvatarFileTooLarge = errors.New("account avatar: file too large")
	// ErrAvatarInvalidRequest 文档未覆盖边界的非法入参自决兜底（presign
	// size≤0、commit key 空 / 非本 uid 前缀）→ invalid_argument +
	// ErrorInfo(account, invalid_request)（ErrProfileInvalidRequest 同款）。
	ErrAvatarInvalidRequest = errors.New("account avatar: invalid request")
)

const (
	// avatarKeyRandLen key 随机成分长度（security.RandomString，crypto/rand
	// URL-safe，64^16 组合防猜测 / 防遍历，§3.11 禁 math/rand）。
	avatarKeyRandLen = 16
	// avatarPresignTTLDefault Ext.presign_ttl 零值兜底（§12.1 行 1704
	// 注释默认 300 秒）。
	avatarPresignTTLDefault = 300
)

// AvatarSettings 头像上传配置读取窄接口（§20 依赖注入）：*settings.Store
// 天然满足；nil / 键缺失按未配置处理（handler 同款防御读）。
type AvatarSettings interface {
	GetString(key string) (string, bool)
}

// AvatarProviderStore provider 表按 key 取行窄接口（§20）：*repo.ProviderRepo
// 天然满足（FindByKey 既有），数据源链用。
type AvatarProviderStore interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// AvatarUserStore 用户存在性窄接口（§20）：*repo.UserRepo 天然满足
//（profile.go ProfileStore 同源方法）。
type AvatarUserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// AvatarStorageResolver storage provider 解析窄接口（§15.1）：
// *storage.Resolver 天然满足。
type AvatarStorageResolver interface {
	Resolve(ctx context.Context, providerKey string) (storage.Storage, error)
}

// AvatarDeps 依赖注入（§20）；装配层构造（bootstrap 接线）。除 Settings（nil 按
// 未配置防御读）外均须非 nil。
type AvatarDeps struct {
	// Settings settings 表读取（avatar_storage_provider）。
	Settings AvatarSettings
	// Providers provider 表读取（数据源链）。
	Providers AvatarProviderStore
	// Users 用户存在性先判。
	Users AvatarUserStore
	// Resolver storage provider 解析（presign 签发 / commit URL 拼接）。
	Resolver AvatarStorageResolver
}

// AvatarService account 域头像直传两桩业务层。
type AvatarService struct {
	deps AvatarDeps
}

// NewAvatarService 构造。
func NewAvatarService(d AvatarDeps) *AvatarService {
	return &AvatarService{deps: d}
}

// compile 时断言生产实现满足各窄接口（webauthn.go 同款）。
var (
	_ AvatarSettings       = (*settings.Store)(nil)
	_ AvatarProviderStore   = (*repo.ProviderRepo)(nil)
	_ AvatarUserStore       = (*repo.UserRepo)(nil)
	_ AvatarStorageResolver = (*storage.Resolver)(nil)
)

// PresignAvatar（§3.2 行 839、§10.8 行 1717）：direct 模式头像直传第一步，
// 签发有时效的 PUT URL。链路：存在性先判（404 优先）→ 数据源链（mode /
// maxSize / allowedTypes）→ mode 必为 direct（local 回退已在 dto 折 proxy，
// 行 842）→ MIME 白名单 / size 上限（行 868）→ key 服务端生成 →
// Resolve → PresignPut 透传。ExpiresIn = Ext.presign_ttl（0 → 300）。
func (s *AvatarService) PresignAvatar(ctx context.Context, uid int64, in *accountv1.PresignAvatarRequest) (*accountv1.AvatarPresignResponse, error) {
	// 存在性先判：user 行不存在 → gorm.ErrRecordNotFound 透传（handler 转
	// not_found，口径同 profile.go）。
	if _, err := s.deps.Users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("account avatar: load user: %w", err)
	}

	providerKey := s.avatarStorageProviderKey()
	cfg, presignTTL, err := s.avatarUploadConfig(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	// mode≠direct（含 local 回退）：presign 不可用（行 842 internal 口径）。
	if cfg.GetMode() != "direct" {
		return nil, ErrAvatarPresignUnavailable
	}
	if !avatarAllowedType(cfg.GetAllowedTypes(), in.GetContentType()) {
		return nil, ErrAvatarFileTypeNotAllowed
	}
	// size≤0：文档未覆盖，自决拒绝（零 / 负 size 头像无意义，防零字节对象
	// 占坑）→ invalid_request。
	if in.GetSize() <= 0 {
		return nil, ErrAvatarInvalidRequest
	}
	if in.GetSize() > cfg.GetMaxSize() {
		return nil, ErrAvatarFileTooLarge
	}

	key, err := avatarObjectKey(uid, in.GetFilename())
	if err != nil {
		return nil, err
	}
	st, err := s.deps.Resolver.Resolve(ctx, providerKey)
	if err != nil {
		return nil, fmt.Errorf("account avatar: resolve storage: %w", err)
	}
	uploadURL, headers, err := st.PresignPut(ctx, key, in.GetContentType(), in.GetSize())
	if err != nil {
		return nil, fmt.Errorf("account avatar: presign put: %w", err)
	}
	return &accountv1.AvatarPresignResponse{
		Key:       key,
		UploadUrl: uploadURL,
		Headers:   headers,
		ExpiresIn: avatarNormalizeTTL(presignTTL),
	}, nil
}

// CommitAvatar（§3.2 行 840、§10.8 行 1719）：direct 模式第三步，仅记录
// 已上传并回显地址，不回读校验（行 868 禁止 Get/HEAD）。「记录」= 回显该
// key 的公开 URL 归 caller 消费；avatar_url 落库走 UpdateProfile（行 837），
// 本层不写 user 表。key 边界见 avatarCommitKeyOK（拒绝在 Resolve 前）。
func (s *AvatarService) CommitAvatar(ctx context.Context, uid int64, in *accountv1.CommitAvatarRequest) (*accountv1.AvatarResponse, error) {
	// 存在性先判（同 PresignAvatar，404 优先）。
	if _, err := s.deps.Users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("account avatar: load user: %w", err)
	}

	key := in.GetKey()
	if !avatarCommitKeyOK(uid, key) {
		return nil, ErrAvatarInvalidRequest
	}
	st, err := s.deps.Resolver.Resolve(ctx, s.avatarStorageProviderKey())
	if err != nil {
		return nil, fmt.Errorf("account avatar: resolve storage: %w", err)
	}
	return &accountv1.AvatarResponse{Url: st.URL(key)}, nil
}

// avatarStorageProviderKey 读 settings 键 avatar_storage_provider（行 842）。
// Settings 未装配 / 键缺失按空串（未配置）处理（handler 行 257-259
// 同款防御读）。
func (s *AvatarService) avatarStorageProviderKey() string {
	if s.deps.Settings == nil {
		return ""
	}
	key, _ := s.deps.Settings.GetString(settings.KeyAvatarStorageProvider)
	return key
}

// avatarUploadConfig 数据源链（handler.avatarUpload 行 249-278 同
// 口径，service 侧复判以保证 presign / commit 与 GetConfig 下发口径恒
// 一致）：settings 键空 / FindByKey 查无 / category≠storage /
// is_enabled≠1 → ErrAvatarNotConfigured（行 842）；查询故障 / ext 解析
// 失败属基础设施错误，包装上抛（行 842 按 internal 映射）。返回 dto 投影 +
// presign_ttl（dto 不透出，本层自用）。
func (s *AvatarService) avatarUploadConfig(ctx context.Context, providerKey string) (*accountv1.AvatarUploadConfig, int32, error) {
	if providerKey == "" {
		return nil, 0, ErrAvatarNotConfigured
	}
	row, err := s.deps.Providers.FindByKey(ctx, providerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrAvatarNotConfigured
		}
		return nil, 0, fmt.Errorf("account avatar: load storage provider: %w", err)
	}
	// category / 启用态与 handler 同判（行 842 封闭口径；字面量同
	// storage.Resolver / handler providerCategoryStorage，§15.1）。
	if row.Category != "storage" || row.IsEnabled != 1 {
		return nil, 0, ErrAvatarNotConfigured
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, 0, fmt.Errorf("account avatar: parse provider ext: %w", err)
	}
	return dto.AccountAvatarUpload(row.Type, ext), ext.GetPresignTtl(), nil
}

// avatarKeyPrefix uid 命名空间前缀（§15.1 key 服务端决定）：avatars/{uid}/。
func avatarKeyPrefix(uid int64) string {
	return fmt.Sprintf("avatars/%d/", uid)
}

// avatarObjectKey 生成头像对象 key：avatars/{uid}/{16 位随机}[.白名单扩展名]。
// 设计理由（行 839「key 由服务端生成，前端无法覆盖」）：
//   - uid 段隔离用户，CommitAvatar 同前缀校验归属（防跨用户 key 回显拼 URL）；
//   - 随机成分防猜测 / 防遍历，同参两次 presign 亦不同 key（旧签名覆盖即失效）；
//   - filename 不进 key 路径，至多取扩展名并白名单化（avatarSafeExt）。
func avatarObjectKey(uid int64, filename string) (string, error) {
	rand, err := security.RandomString(avatarKeyRandLen)
	if err != nil {
		return "", fmt.Errorf("account avatar: object key rand: %w", err)
	}
	return avatarKeyPrefix(uid) + rand + avatarSafeExt(filename), nil
}

// avatarSafeExt 从 filename 取安全扩展名（含 "."，小写归一）；缺失 / 含非
// [a-z0-9] / 超 8 位一律丢弃（无扩展名 key 不带后缀——扩展名仅 URL 展示用，
// 对象 MIME 以 presign 携带的 Content-Type 为准）。
func avatarSafeExt(filename string) string {
	dot := strings.LastIndex(filename, ".")
	if dot < 0 || dot == len(filename)-1 {
		return ""
	}
	ext := strings.ToLower(filename[dot+1:])
	if len(ext) > 8 {
		return ""
	}
	for _, r := range ext {
		if !('a' <= r && r <= 'z' || '0' <= r && r <= '9') {
			return ""
		}
	}
	return "." + ext
}

// avatarAllowedType MIME 白名单精确匹配（行 868「MIME 在 allowedTypes 内」）。
// 空名单 fail-closed、空 contentType 不在任何名单内同拒（自决：未配
// allowed_types 的 direct 行全拒，不放大例外）。
func avatarAllowedType(allowed []string, contentType string) bool {
	for _, a := range allowed {
		if a == contentType {
			return true
		}
	}
	return false
}

// avatarNormalizeTTL presign TTL 归一：0（proto 零值 = 未配置）→ 300（§12.1
// 行 1704 注释默认）；负值属乱配，自决同兜底（镜像 dto maxSize≤0 → 2MB
// 的兜底风格）。
func avatarNormalizeTTL(ttl int32) int64 {
	if ttl <= 0 {
		return avatarPresignTTLDefault
	}
	return int64(ttl)
}

// avatarCommitKeyOK CommitAvatar key 边界（行 839 key 服务端生成 + PMO
// brief 前缀归属建议）：空串必拒；必须以本 uid 前缀 avatars/{uid}/ 开头
//（归属校验，防跨用户 key 回显拼 URL）；拒含 ".." / "\"（防相对段把回显
// URL 拼到域根外）。
func avatarCommitKeyOK(uid int64, key string) bool {
	if key == "" {
		return false
	}
	if !strings.HasPrefix(key, avatarKeyPrefix(uid)) {
		return false
	}
	return !strings.Contains(key, "..") && !strings.Contains(key, `\`)
}

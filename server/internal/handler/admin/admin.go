// Package admin 实现 AdminService 的 Connect handler，全部方法需管理员会话。
// 鉴权由 admin 拦截器收口（挂 session 拦截器之内：无会话 401、非管理员 404
// 掩护管理面存在），故 handler 不做二次鉴权；会话 uid 经 ctx 注入供审计取用。
// 敏感口径：GetProvider 明文 ext 与 DecodeToken 载荷均不落日志，本文件错误文案
// 全部固定，不携带 token / payload / secret 值。
package admin

import (
	"context"
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"
	"database/sql"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/gen/go/api/admin/v1/adminv1connect"
	"authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	adminsvc "authloft/internal/service/admin"
	"authloft/internal/session"
)

// ProviderReader admin 域 provider 读取窄接口（生产注入 *repo.ProviderRepo，测试可传 fake）。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
	ListProviders(ctx context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error)
}

// ProviderService provider 写族 + 下拉 + 发送测试窄接口（生产注入 *adminsvc.Service）。
type ProviderService interface {
	CreateProvider(ctx context.Context, body *structpb.Struct) error
	UpdateProvider(ctx context.Context, body *structpb.Struct) error
	DeleteProvider(ctx context.Context, providerKey string) error
	SetProviderEnabled(ctx context.Context, providerKey string, enabled bool) error
	SortProviders(ctx context.Context, items []adminsvc.SortItem) error
	ProviderTypes() []adminsvc.ProviderTypeInfo
	TestProvider(ctx context.Context, providerKey, target string) error
}

// UserService 用户管理族窄接口（生产注入 *adminsvc.UserService）。
type UserService interface {
	GetMe(ctx context.Context, uid int64) (*model.User, error)
	ListUsers(ctx context.Context, f adminsvc.ListUsersFilter) ([]model.User, int64, error)
	CreateUser(ctx context.Context, actor int64, req *adminv1.CreateUserRequest) (int64, error)
	GetUser(ctx context.Context, id int64) (*adminsvc.UserDetail, error)
	UpdateUserProfile(ctx context.Context, actor, id int64, req *adminv1.UpdateUserProfileRequest) error
	UpdateUserContact(ctx context.Context, actor, id int64, req *adminv1.UpdateUserContactRequest) error
	SetUserMfa(ctx context.Context, actor, id int64, mfaRequired int64) error
	UnbindUserTOTP(ctx context.Context, actor, id int64) error
	ResetUserRecoveryCodes(ctx context.Context, actor, id int64) error
	SetCredentialEnabled(ctx context.Context, actor, id, credentialID int64, enabled bool) error
	DeleteCredential(ctx context.Context, actor, id, credentialID int64) error
	UpdateUserStatus(ctx context.Context, actor, id int64, userStatus int64) error
	ResetUserPassword(ctx context.Context, actor, id int64, password string) error
	UnbindUserThirdparty(ctx context.Context, actor, id int64, providerKey string) error
	UnlockUser(ctx context.Context, actor, id int64) error
	DeleteUser(ctx context.Context, actor, id int64) error
	GetUserEvents(ctx context.Context, id int64, page, pageSize int) ([]model.EventLog, int64, error)
}

// ClientService 客户端管理族窄接口（生产注入 *adminsvc.ClientService）。
type ClientService interface {
	ListSsoClients(ctx context.Context, page, pageSize int, sort, order string) ([]adminsvc.SsoClientDetail, int64, error)
	CreateSsoClient(ctx context.Context, in adminsvc.SsoClientInput) error
	GetSsoClient(ctx context.Context, id int64) (*adminsvc.SsoClientDetail, error)
	UpdateSsoClient(ctx context.Context, id int64, p adminsvc.SsoClientPatch) error
	DeleteSsoClient(ctx context.Context, id int64) error
	ListOidcClients(ctx context.Context, page, pageSize int, sort, order string) ([]adminsvc.OidcClientDetail, int64, error)
	CreateOidcClient(ctx context.Context, in adminsvc.OidcClientInput) error
	GetOidcClient(ctx context.Context, id int64) (*adminsvc.OidcClientDetail, error)
	UpdateOidcClient(ctx context.Context, id int64, p adminsvc.OidcClientPatch) error
	DeleteOidcClient(ctx context.Context, id int64) error
}

// TemplateService 模板管理族窄接口（生产注入 *adminsvc.TemplateService）。
type TemplateService interface {
	List(ctx context.Context, page, pageSize int, q string) ([]model.Template, int64, error)
	Create(ctx context.Context, key, name, content string) error
	Get(ctx context.Context, id int64) (*model.Template, error)
	Update(ctx context.Context, id int64, key, name, content *string) error
	Delete(ctx context.Context, id int64) error
}

// SettingsService 系统配置 / 事件 / 工具族窄接口（生产注入 *adminsvc.SettingsService）。
type SettingsService interface {
	GetSettings() map[string]any
	SetSettings(ctx context.Context, actor int64, req *adminv1.SetSettingsRequest) error
	ListEvents(ctx context.Context, f adminsvc.EventListFilter) ([]model.EventLog, int64, error)
	DecodeToken(purpose, token string) (proto.Message, error)
	GetStatus() adminsvc.QueueStatus
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息。
var (
	errNotFound         = errors.New("not found")
	errUnknownProvType  = errors.New("unknown provider type")
	errInvalidRequest   = errors.New("invalid request")
	errDuplicateKey     = errors.New("provider key already exists")
	errAuthRequired     = errors.New("authentication required")
	errPasswordWeak     = errors.New("password does not meet policy")
	errPermissionDenied = errors.New("permission denied")
	errTargetTaken      = errors.New("contact already bound to another user")
	errUsernameTaken    = errors.New("username already taken")
)

// providerListPageSize 管理列表分页上限（同时是 dynamic 字段 options 查询页大小）。
const providerListPageSize = 100

// dynamicKeyUnionProviderKeys union_provider 字段 Schema 声明的 DynamicKey
// （provider/schemafield.UnionProvider）：本层查库注入的动态键之一。引用键的
// DynamicKey（provider.ProxyRefDynamicKey）随声明侧常量取用，不另立字面量；
// storage_provider 的 DynamicKey 由声明侧（wechat_mp_scan 渠道包）持有，
// 与 union_provider_keys 同为字面量，两键一致性由 schema 注入断言回归兜底。
const dynamicKeyUnionProviderKeys = "union_provider_keys"

// dynamicKeyStorageProviderKeys storage_provider 字段 Schema 声明的 DynamicKey
// （wechat_mp_scan 渠道声明）：storage 类行键集的查库注入键。
const dynamicKeyStorageProviderKeys = "storage_provider_keys"

// Handler AdminService 服务实现；内嵌 Unimplemented 基类以兼容生成接口的前向演进。
type Handler struct {
	adminv1connect.UnimplementedAdminServiceHandler
	providers       ProviderReader
	svc             ProviderService
	users           UserService
	clients         ClientService
	templates       TemplateService
	settings        SettingsService
	listPermissions func(context.Context, int64) ([]string, error)
}

// New 构造 AdminService handler（读路径 / 写族 / 用户 / 客户端 / 模板 / 配置
// 六组依赖与当前用户权限点列表查询）。
func New(providers ProviderReader, svc ProviderService, users UserService, clients ClientService, templates TemplateService, settings SettingsService, listPermissions func(context.Context, int64) ([]string, error)) *Handler {
	return &Handler{providers: providers, svc: svc, users: users, clients: clients, templates: templates, settings: settings, listPermissions: listPermissions}
}

// ListProviders 筛选 + 分页的 provider 列表；列表列不含 ext 凭证字段。
// 排序固定 sort_order ASC, id ASC；请求的 sort / order 本实现不消费。
func (h *Handler) ListProviders(ctx context.Context, req *connectrpc.Request[adminv1.ListProvidersRequest]) (*connectrpc.Response[adminv1.ProviderListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.providers.ListProviders(ctx, repo.ProviderListQuery{
		Category:  req.Msg.Category, // optional 指针原样：nil 即不过滤
		Type:      req.Msg.Type,
		IsEnabled: boolPtrToInt8(req.Msg.IsEnabled),
		Page:      page,
		PageSize:  size,
	})
	if err != nil {
		return nil, fmt.Errorf("admin handler: list providers: %w", err)
	}
	items := make([]*adminv1.Provider, len(rows))
	for i := range rows {
		items[i] = dto.AdminProviderListEntry(&rows[i])
	}
	return connectrpc.NewResponse(&adminv1.ProviderListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// GetProvider {providerKey} 详情——全站唯一明文凭证出口（ext 明文，仅管理员会话可见，
// 鉴权由 admin 拦截器保证，dto 不做二次脱敏）。响应绝不进日志。
func (h *Handler) GetProvider(ctx context.Context, req *connectrpc.Request[adminv1.GetProviderRequest]) (*connectrpc.Response[adminv1.AdminProvider], error) {
	row, err := h.providers.FindByKey(ctx, req.Msg.GetProviderKey())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 资源不存在（管理后台单资源）→ 404 not_found。
			return nil, connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
		}
		return nil, fmt.Errorf("admin handler: get provider: %w", err)
	}
	// Ext 编解码唯一出口在 repo.ParseProviderExt，不另造解析。
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, fmt.Errorf("admin handler: parse ext %q: %w", req.Msg.GetProviderKey(), err)
	}
	return connectrpc.NewResponse(dto.AdminProviderDetail(row, ext)), nil
}

// GetProviderSchema 由类型 meta 声明的完整 Schema 驱动动态表单（meta 是 /schema
// 唯一数据源）：dto 把 []FieldMeta 按序转为 wire SchemaField，不在此裁剪。字段的
// 取舍 / 引用键是否呈现 / dynamic 字段是否查库，完全由 provider.Schema()
// 声明决定。未注册 / 空 type → invalid_argument + ErrorInfo(admin, invalid_request)。
func (h *Handler) GetProviderSchema(ctx context.Context, req *connectrpc.Request[adminv1.GetProviderSchemaRequest]) (*connectrpc.Response[adminv1.SchemaResponse], error) {
	providerType := req.Msg.GetType()
	category, fields, ok := lookupProviderType(providerType)
	if providerType == "" || !ok {
		return nil, connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errUnknownProvType),
			connect.NewErrorInfo("admin", "invalid_request", "unknown provider type"),
		)
	}
	// dynamic 字段的查库由声明驱动：类别只是注册表事实，Schema 声明才是表单
	// 意图，谁声明 Kind=FieldDynamicOptions 谁触发（接口文档 §5.3）。当前三个
	// 查库来源：union_provider_keys（union 行键集）、proxy_provider_keys
	// （proxy 行键集）与 storage_provider_keys（storage 行键集），均含未启用
	// 实例——允许先引用后启用；出现未知 DynamicKey 时不注入、options 留空
	// （经 dto 自然为 nil，前端渲染空候选）——本层只认得已声明的来源，宁空
	// 勿猜，不为新键伪造数据。
	dynamicKeys := make(map[string]bool)
	for _, f := range fields {
		if f.Kind == provider.FieldDynamicOptions {
			dynamicKeys[f.DynamicKey] = true
		}
	}
	dynamicOptions := make(map[string][]string)
	if dynamicKeys[dynamicKeyUnionProviderKeys] {
		keys, err := h.providerKeysByCategory(ctx, provider.CategoryUnion)
		if err != nil {
			return nil, fmt.Errorf("admin handler: list union providers: %w", err)
		}
		dynamicOptions[dynamicKeyUnionProviderKeys] = keys
	}
	if dynamicKeys[provider.ProxyRefDynamicKey] {
		keys, err := h.providerKeysByCategory(ctx, provider.CategoryProxy)
		if err != nil {
			return nil, fmt.Errorf("admin handler: list proxy providers: %w", err)
		}
		dynamicOptions[provider.ProxyRefDynamicKey] = keys
	}
	if dynamicKeys[dynamicKeyStorageProviderKeys] {
		keys, err := h.providerKeysByCategory(ctx, provider.CategoryStorage)
		if err != nil {
			return nil, fmt.Errorf("admin handler: list storage providers: %w", err)
		}
		dynamicOptions[dynamicKeyStorageProviderKeys] = keys
	}
	return connectrpc.NewResponse(dto.AdminSchema(providerType, category, fields, dynamicOptions)), nil
}

// lookupProviderType 按 type 查静态源统一 meta，返回完整字段声明的快照。
func lookupProviderType(providerType string) (category string, fields []provider.FieldMeta, ok bool) {
	meta, found := provider.LookupTypeMeta(providerType)
	if !found {
		return "", nil, false
	}
	if meta.Schema != nil {
		fields = meta.Schema()
	}
	return meta.Category, fields, true
}

// providerKeysByCategory 分页读完全部指定类别行的 provider_key（取满 total
// 即止）：union_provider / proxy_provider_key / storage_provider 三个 dynamic
// 字段共用的 options 查库源；不过滤 is_enabled——引用键候选含未启用实例
// （§5.3，允许先引用后启用，运行期 fail-closed 兜底）。
func (h *Handler) providerKeysByCategory(ctx context.Context, category string) ([]string, error) {
	var keys []string
	for page := 1; ; page++ {
		rows, total, err := h.providers.ListProviders(ctx, repo.ProviderListQuery{
			Category: &category,
			Page:     page,
			PageSize: providerListPageSize,
		})
		if err != nil {
			return nil, err
		}
		for i := range rows {
			keys = append(keys, rows[i].ProviderKey)
		}
		if len(rows) == 0 || int64(len(keys)) >= total {
			return keys, nil
		}
	}
}

// normalizeListPage 分页归一（page 从 1 开始、pageSize 默认 20、上限 100），回显生效值。
func normalizeListPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > providerListPageSize {
		size = providerListPageSize
	}
	return page, size
}

// boolPtrToInt8 optional bool → *int8（repo 查询按 tinyint 0/1 过滤）。
func boolPtrToInt8(b *bool) *int8 {
	if b == nil {
		return nil
	}
	v := int8(0)
	if *b {
		v = 1
	}
	return &v
}

// —— 写族 7 方法：service 层业务校验与缓存失效，handler 只做 Connect 形态映射 ——

// CreateProvider 新建，请求体为 schema 的动态键集合（google.protobuf.Struct）。
func (h *Handler) CreateProvider(ctx context.Context, req *connectrpc.Request[structpb.Struct]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.CreateProvider(ctx, req.Msg); err != nil {
		return nil, mapWriteError("create provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UpdateProvider 编辑，提交体含 provider_key（创建后不可改）；缺省键保留原值（PATCH）。
func (h *Handler) UpdateProvider(ctx context.Context, req *connectrpc.Request[structpb.Struct]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.UpdateProvider(ctx, req.Msg); err != nil {
		return nil, mapWriteError("update provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteProvider {providerKey} 删除；不存在 → 404 not_found。
func (h *Handler) DeleteProvider(ctx context.Context, req *connectrpc.Request[adminv1.DeleteProviderRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.DeleteProvider(ctx, req.Msg.GetProviderKey()); err != nil {
		return nil, mapWriteError("delete provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SetProviderEnabled {providerKey, isEnabled} 行内开关。
func (h *Handler) SetProviderEnabled(ctx context.Context, req *connectrpc.Request[adminv1.SetProviderEnabledRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.SetProviderEnabled(ctx, req.Msg.GetProviderKey(), req.Msg.GetIsEnabled()); err != nil {
		return nil, mapWriteError("set provider enabled", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SortProviders {items:[{providerKey, sortOrder}]} 拖拽排序。
func (h *Handler) SortProviders(ctx context.Context, req *connectrpc.Request[adminv1.SortProvidersRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	items := make([]adminsvc.SortItem, len(req.Msg.GetItems()))
	for i, it := range req.Msg.GetItems() {
		items[i] = adminsvc.SortItem{ProviderKey: it.GetProviderKey(), SortOrder: int32(it.GetSortOrder())}
	}
	if err := h.svc.SortProviders(ctx, items); err != nil {
		return nil, mapWriteError("sort providers", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetProviderTypes Provider type 下拉数据源（来自静态类型 metas，type 稳定排序）。
func (h *Handler) GetProviderTypes(ctx context.Context, req *connectrpc.Request[adminv1.GetProviderTypesRequest]) (*connectrpc.Response[adminv1.ProviderTypesResponse], error) {
	infos := h.svc.ProviderTypes()
	items := make([]*adminv1.ProviderType, len(infos))
	for i := range infos {
		items[i] = &adminv1.ProviderType{
			Type:        infos[i].Type,
			Category:    infos[i].Category,
			DisplayName: infos[i].DisplayName,
		}
	}
	return connectrpc.NewResponse(&adminv1.ProviderTypesResponse{Items: items}), nil
}

// TestProvider {providerKey, target} 短信 / 邮件 Provider 的发送测试（同步 Send 即时反馈）。
func (h *Handler) TestProvider(ctx context.Context, req *connectrpc.Request[adminv1.TestProviderRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.TestProvider(ctx, req.Msg.GetProviderKey(), req.Msg.GetTarget()); err != nil {
		return nil, mapWriteError("test provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// —— 用户管理族 8 方法：service 层业务校验与副作用编排，handler 只做形态映射与 dto 投影 ——

// GetMe 当前管理员视图；uid 取 session ctx（admin 拦截器已收口 uid==1，不做二次鉴权），
// 行缺失 → 404（安装账号被删的脏数据防御）。
func (h *Handler) GetMe(ctx context.Context, _ *connectrpc.Request[adminv1.GetMeRequest]) (*connectrpc.Response[adminv1.MeResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	row, err := h.users.GetMe(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
		}
		if errors.Is(err, adminsvc.ErrInvalidRequest) {
			return nil, connect.WithErrorInfo(
				connectrpc.NewError(connectrpc.CodeInvalidArgument, errInvalidRequest),
				connect.NewErrorInfo("admin", "invalid_request", "invalid request"),
			)
		}
		return nil, fmt.Errorf("admin handler: get me: %w", err)
	}
	perms, err := h.listPermissions(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("admin handler: get me: list permissions: %w", err)
	}
	return connectrpc.NewResponse(dto.AdminMe(row, perms)), nil
}

// ListUsers 筛选 + 分页的用户列表；sort / order 透传 service（后端不做白名单强制校验，
// 防注入字符集约束在 repo）。
func (h *Handler) ListUsers(ctx context.Context, req *connectrpc.Request[adminv1.ListUsersRequest]) (*connectrpc.Response[adminv1.UserListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.users.ListUsers(ctx, adminsvc.ListUsersFilter{
		Q:          req.Msg.GetQ(),
		UserStatus: req.Msg.UserStatus,
		Page:       page,
		PageSize:   size,
		Sort:       req.Msg.GetSort(),
		Order:      req.Msg.GetOrder(),

		CreatedFrom:    req.Msg.CreatedFrom,
		CreatedTo:      req.Msg.CreatedTo,
		LastLoginFrom:  req.Msg.LastLoginFrom,
		LastLoginTo:    req.Msg.LastLoginTo,
		MfaRequired:    req.Msg.MfaRequired,
		CredentialKind: req.Msg.GetCredentialKind(),
	})
	if err != nil {
		return nil, mapUserError("list users", err)
	}
	items := make([]*adminv1.AdminUser, len(rows))
	for i := range rows {
		items[i] = dto.AdminUser(&rows[i])
	}
	return connectrpc.NewResponse(&adminv1.UserListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// CreateUser {username, password, nickname?} 后台新建；用户名 / 密码校验
// 在 service（前缀与弱口令拒绝 → invalid_request / password_weak），返回新 id。
func (h *Handler) CreateUser(ctx context.Context, req *connectrpc.Request[adminv1.CreateUserRequest]) (*connectrpc.Response[adminv1.CreateUserResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	id, err := h.users.CreateUser(ctx, actor, req.Msg)
	if err != nil {
		return nil, mapUserError("create user", err)
	}
	return connectrpc.NewResponse(&adminv1.CreateUserResponse{Id: id}), nil
}

// GetUser {id} 详情（含凭证概览、绑定、MFA 状态、profile 与权限点投影），
// secret 不透出。permissions 与 §5.1 GetMe 同源（listPermissions 注入），
// 供前端展示态判定（服务端写门禁仍是唯一真相）。
func (h *Handler) GetUser(ctx context.Context, req *connectrpc.Request[adminv1.GetUserRequest]) (*connectrpc.Response[adminv1.UserDetailResponse], error) {
	d, err := h.users.GetUser(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapUserError("get user", err)
	}
	perms, err := h.listPermissions(ctx, req.Msg.GetId())
	if err != nil {
		return nil, fmt.Errorf("admin handler: get user: list permissions: %w", err)
	}
	return connectrpc.NewResponse(dto.AdminUserDetail(d.User, d.Credentials, d.Bindings, d.Profile, perms)), nil
}

// UpdateUserProfile {id, nickname?, avatarUrl?, profile{...}} PATCH 编辑资料；
// has 位口径在 service（未设置 = 不修改、显式空串 = 清空）；不触发会话失效。
func (h *Handler) UpdateUserProfile(ctx context.Context, req *connectrpc.Request[adminv1.UpdateUserProfileRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UpdateUserProfile(ctx, actor, req.Msg.GetId(), req.Msg); err != nil {
		return nil, mapUserError("update user profile", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UpdateUserContact {id, phone?, email?} PATCH 编辑联系方式；写即置已验证、
// 触发会话失效，仅 superadmin 操作者可执行（门禁在 service）；唯一冲突 →
// already_exists + ErrorInfo{target_taken}。
func (h *Handler) UpdateUserContact(ctx context.Context, req *connectrpc.Request[adminv1.UpdateUserContactRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UpdateUserContact(ctx, actor, req.Msg.GetId(), req.Msg); err != nil {
		return nil, mapUserError("update user contact", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SetUserMfa {id, mfaRequired 0|1} 管理端开关两步验证；关闭走 IncEpoch 会话
// 失效链 + 审计，开启不触发（副作用编排与门禁在 service）。
func (h *Handler) SetUserMfa(ctx context.Context, req *connectrpc.Request[adminv1.SetUserMfaRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.SetUserMfa(ctx, actor, req.Msg.GetId(), req.Msg.GetMfaRequired()); err != nil {
		return nil, mapUserError("set user mfa", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UnbindUserTOTP {id} 管理员救援解绑 TOTP（删 kind=totp 凭证行）；
// 强制下线与审计在 service。
func (h *Handler) UnbindUserTOTP(ctx context.Context, req *connectrpc.Request[adminv1.UnbindUserTOTPRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UnbindUserTOTP(ctx, actor, req.Msg.GetId()); err != nil {
		return nil, mapUserError("unbind user totp", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// ResetUserRecoveryCodes {id} 重生成恢复码；响应不下发明文（OkResponse 无
// 字段），门禁与审计在 service。
func (h *Handler) ResetUserRecoveryCodes(ctx context.Context, req *connectrpc.Request[adminv1.ResetUserRecoveryCodesRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.ResetUserRecoveryCodes(ctx, actor, req.Msg.GetId()); err != nil {
		return nil, mapUserError("reset user recovery codes", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SetCredentialEnabled {id, credentialId, enabled} 停用 / 启用单条凭证；
// 密码凭证停用拒绝（invalid_request 映射同 mapUserError）。
func (h *Handler) SetCredentialEnabled(ctx context.Context, req *connectrpc.Request[adminv1.SetCredentialEnabledRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.SetCredentialEnabled(ctx, actor, req.Msg.GetId(), req.Msg.GetCredentialId(), req.Msg.GetEnabled()); err != nil {
		return nil, mapUserError("set credential enabled", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteCredential {id, credentialId} 删除单条凭证；强制下线与审计在 service。
func (h *Handler) DeleteCredential(ctx context.Context, req *connectrpc.Request[adminv1.DeleteCredentialRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.DeleteCredential(ctx, actor, req.Msg.GetId(), req.Msg.GetCredentialId()); err != nil {
		return nil, mapUserError("delete credential", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UpdateUserStatus {id, userStatus 0|1} 禁用 / 启用；禁用走 IncEpoch 会话失效链 + 审计。
func (h *Handler) UpdateUserStatus(ctx context.Context, req *connectrpc.Request[adminv1.UpdateUserStatusRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UpdateUserStatus(ctx, actor, req.Msg.GetId(), req.Msg.GetUserStatus()); err != nil {
		return nil, mapUserError("update user status", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// ResetUserPassword {id, password} 管理员重置；策略不满足 → invalid_argument + ErrorInfo{password_weak}。
func (h *Handler) ResetUserPassword(ctx context.Context, req *connectrpc.Request[adminv1.ResetUserPasswordRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.ResetUserPassword(ctx, actor, req.Msg.GetId(), req.Msg.GetPassword()); err != nil {
		return nil, mapUserError("reset user password", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UnbindUserThirdparty {id, providerKey} 解绑；Union Provider 行不可单独解绑（invalid_request）。
func (h *Handler) UnbindUserThirdparty(ctx context.Context, req *connectrpc.Request[adminv1.UnbindUserThirdpartyRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UnbindUserThirdparty(ctx, actor, req.Msg.GetId(), req.Msg.GetProviderKey()); err != nil {
		return nil, mapUserError("unbind user thirdparty", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UnlockUser {id} 解除登录限制——清 uid 维度键 + 按当前 phone / email 重算 ip 维度键。
func (h *Handler) UnlockUser(ctx context.Context, req *connectrpc.Request[adminv1.UnlockUserRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.UnlockUser(ctx, actor, req.Msg.GetId()); err != nil {
		return nil, mapUserError("unlock user", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteUser {id} 删除用户 = 禁用 + 全端下线 + 匿名化；自删 / 有权限点目标
// 一律 permission_denied，已删行 not_found（service 口径）。
func (h *Handler) DeleteUser(ctx context.Context, req *connectrpc.Request[adminv1.DeleteUserRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.users.DeleteUser(ctx, actor, req.Msg.GetId()); err != nil {
		return nil, mapUserError("delete user", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetUserEvents {id} + 分页的该用户登录记录（login_success 过滤在 service）。
func (h *Handler) GetUserEvents(ctx context.Context, req *connectrpc.Request[adminv1.GetUserEventsRequest]) (*connectrpc.Response[adminv1.UserEventsResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.users.GetUserEvents(ctx, req.Msg.GetId(), page, size)
	if err != nil {
		return nil, mapUserError("get user events", err)
	}
	items := make([]*adminv1.EventItem, len(rows))
	for i := range rows {
		items[i] = dto.AdminEventItem(&rows[i])
	}
	return connectrpc.NewResponse(&adminv1.UserEventsResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// —— 客户端管理族 10 方法：secret 服务端生成、client_id 不可改等校验在 service，错误复用 mapWriteError ——

// ListSsoClients 分页列表；sort / order 透传 service（防注入字符集约束在 repo）；
// 空页 items 按 proto3 空 repeated 省略。
func (h *Handler) ListSsoClients(ctx context.Context, req *connectrpc.Request[adminv1.ListSsoClientsRequest]) (*connectrpc.Response[adminv1.SsoClientListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.clients.ListSsoClients(ctx, page, size, req.Msg.GetSort(), req.Msg.GetOrder())
	if err != nil {
		return nil, mapWriteError("list sso clients", err)
	}
	items := make([]*adminv1.SsoClient, len(rows))
	for i := range rows {
		items[i] = dto.AdminSsoClient(rows[i].Row, rows[i].RedirectURIs, rows[i].LoginMethods, rows[i].AuthProviders)
	}
	return connectrpc.NewResponse(&adminv1.SsoClientListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// CreateSsoClient 仅后台手动创建；请求中的 client_secret 被忽略——服务端生成，
// 管理员经 GetSsoClient 明文查看。成功返回 OkResponse。
func (h *Handler) CreateSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.CreateSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.CreateSsoClient(ctx, adminsvc.SsoClientInput{
		ClientID:           req.Msg.GetClientId(),
		Name:               req.Msg.GetName(),
		RedirectURIs:       req.Msg.GetRedirectUris(),
		LoginMethods:       req.Msg.GetLoginMethods(),
		AuthProviders:      req.Msg.GetAuthProviders(),
		DefaultRedirectURI: req.Msg.GetDefaultRedirectUri(),
		TemplateKey:        req.Msg.GetTemplateKey(),
		TemplateVars:       req.Msg.GetTemplateVars(),
	}); err != nil {
		return nil, mapWriteError("create sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetSsoClient {id} 定位 → 详情含明文 secret（仅 admin 会话可达）。
func (h *Handler) GetSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.GetSsoClientRequest]) (*connectrpc.Response[adminv1.SsoClient], error) {
	d, err := h.clients.GetSsoClient(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapWriteError("get sso client", err)
	}
	return connectrpc.NewResponse(dto.AdminSsoClient(d.Row, d.RedirectURIs, d.LoginMethods, d.AuthProviders)), nil
}

// UpdateSsoClient 缺省键保留原值（PATCH）；client_id 不可改（改 → invalid_request）。
// 应用级登录配置按 §5.5 has 位语义传递：has_* 伴生标志与 optional
// default_redirect_uri 的指针在场性原样透传 service。
func (h *Handler) UpdateSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.UpdateSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.UpdateSsoClient(ctx, req.Msg.GetId(), adminsvc.SsoClientPatch{
		ClientID:           req.Msg.GetClientId(),
		ClientSecret:       req.Msg.GetClientSecret(),
		Name:               req.Msg.GetName(),
		RedirectURIs:       req.Msg.GetRedirectUris(),
		LoginMethods:       req.Msg.GetLoginMethods(),
		HasLoginMethods:    req.Msg.GetHasLoginMethods(),
		AuthProviders:      req.Msg.GetAuthProviders(),
		HasAuthProviders:   req.Msg.GetHasAuthProviders(),
		DefaultRedirectURI: req.Msg.DefaultRedirectUri,
		TemplateKey:        req.Msg.GetTemplateKey(),
		TemplateVars:       req.Msg.GetTemplateVars(),
	}); err != nil {
		return nil, mapWriteError("update sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteSsoClient 硬删；不触发会话失效（待定）。
func (h *Handler) DeleteSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.DeleteSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.DeleteSsoClient(ctx, req.Msg.GetId()); err != nil {
		return nil, mapWriteError("delete sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// ListOidcClients 口径同 ListSsoClients（scopes 拆分在 service）。
func (h *Handler) ListOidcClients(ctx context.Context, req *connectrpc.Request[adminv1.ListOidcClientsRequest]) (*connectrpc.Response[adminv1.OidcClientListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.clients.ListOidcClients(ctx, page, size, req.Msg.GetSort(), req.Msg.GetOrder())
	if err != nil {
		return nil, mapWriteError("list oidc clients", err)
	}
	items := make([]*adminv1.OidcClient, len(rows))
	for i := range rows {
		items[i] = dto.AdminOidcClient(rows[i].Row, rows[i].RedirectURIs, rows[i].Scopes)
	}
	return connectrpc.NewResponse(&adminv1.OidcClientListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// CreateOidcClient SSO 基线 + scopes[] / TTL（0 落 DDL 默认）；授权类型固定
// authorization_code + refresh_token；client_secret 同 CreateSsoClient 服务端生成。
func (h *Handler) CreateOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.CreateOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.CreateOidcClient(ctx, adminsvc.OidcClientInput{
		ClientID:        req.Msg.GetClientId(),
		Name:            req.Msg.GetName(),
		RedirectURIs:    req.Msg.GetRedirectUris(),
		Scopes:          req.Msg.GetScopes(),
		AccessTokenTTL:  req.Msg.GetAccessTokenTtl(),
		RefreshTokenTTL: req.Msg.GetRefreshTokenTtl(),
		TemplateKey:     req.Msg.GetTemplateKey(),
		TemplateVars:    req.Msg.GetTemplateVars(),
	}); err != nil {
		return nil, mapWriteError("create oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetOidcClient {id} 定位 → 详情含明文 secret + scopes[] / TTL 投影。
func (h *Handler) GetOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.GetOidcClientRequest]) (*connectrpc.Response[adminv1.OidcClient], error) {
	d, err := h.clients.GetOidcClient(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapWriteError("get oidc client", err)
	}
	return connectrpc.NewResponse(dto.AdminOidcClient(d.Row, d.RedirectURIs, d.Scopes)), nil
}

// UpdateOidcClient 缺省键保留原值（PATCH）；client_id 不可改；TTL 0 保留原值。
func (h *Handler) UpdateOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.UpdateOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.UpdateOidcClient(ctx, req.Msg.GetId(), adminsvc.OidcClientPatch{
		ClientID:        req.Msg.GetClientId(),
		ClientSecret:    req.Msg.GetClientSecret(),
		Name:            req.Msg.GetName(),
		RedirectURIs:    req.Msg.GetRedirectUris(),
		Scopes:          req.Msg.GetScopes(),
		AccessTokenTTL:  req.Msg.GetAccessTokenTtl(),
		RefreshTokenTTL: req.Msg.GetRefreshTokenTtl(),
		TemplateKey:     req.Msg.GetTemplateKey(),
		TemplateVars:    req.Msg.GetTemplateVars(),
	}); err != nil {
		return nil, mapWriteError("update oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteOidcClient 硬删；口径同 DeleteSsoClient。
func (h *Handler) DeleteOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.DeleteOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.DeleteOidcClient(ctx, req.Msg.GetId()); err != nil {
		return nil, mapWriteError("delete oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// —— 系统配置 / 事件 / 工具族 5 方法：业务编排在 service，handler 只做形态映射与 dto 投影 ——

// GetSettings 全部系统配置——Store.Snapshot 全键投影（dto.AdminSettings），无入参。
func (h *Handler) GetSettings(ctx context.Context, _ *connectrpc.Request[adminv1.GetSettingsRequest]) (*connectrpc.Response[adminv1.SettingsResponse], error) {
	snap := h.settings.GetSettings()
	return connectrpc.NewResponse(dto.AdminSettings(snap)), nil
}

// SetSettings 部分更新（PATCH）系统配置：optional 标量 has 位 = 在场，四个 repeated
// 键由伴生标志取 true 判定在场（空数组 = 清空）；落库与热更通知、审计在 service。
func (h *Handler) SetSettings(ctx context.Context, req *connectrpc.Request[adminv1.SetSettingsRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	actor, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.settings.SetSettings(ctx, actor, req.Msg); err != nil {
		return nil, mapWriteError("set settings", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// ListEvents 统一事件视图：六筛选 optional 指针原样透传（nil 即不过滤）+ 分页 +
// sort / order；行 → EventItem 复用 dto.AdminEventItem；空页 items 按 proto3 省略。
func (h *Handler) ListEvents(ctx context.Context, req *connectrpc.Request[adminv1.ListEventsRequest]) (*connectrpc.Response[adminv1.EventListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.settings.ListEvents(ctx, adminsvc.EventListFilter{
		Event:     req.Msg.GetEvent(),
		ActorType: req.Msg.GetActorType(),
		ActorID:   req.Msg.ActorId,
		UserID:    req.Msg.UserId,
		From:      req.Msg.From,
		To:        req.Msg.To,
		Page:      page,
		PageSize:  size,
		Sort:      req.Msg.GetSort(),
		Order:     req.Msg.GetOrder(),
	})
	if err != nil {
		return nil, mapWriteError("list events", err)
	}
	items := make([]*adminv1.EventItem, len(rows))
	for i := range rows {
		items[i] = dto.AdminEventItem(&rows[i])
	}
	return connectrpc.NewResponse(&adminv1.EventListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// DecodeToken 令牌解码排障工具：purpose ∈ login|session|cookie，解载荷 → Struct 投影。
// 非法 purpose / 解码失败 → invalid_argument + ErrorInfo(admin, invalid_request)；
// 错误文案固定不携带 token 与 payload 内容，本方法不落日志。
func (h *Handler) DecodeToken(ctx context.Context, req *connectrpc.Request[adminv1.DecodeTokenRequest]) (*connectrpc.Response[adminv1.DecodeResponse], error) {
	msg, err := h.settings.DecodeToken(req.Msg.GetPurpose(), req.Msg.GetToken())
	if err != nil {
		return nil, mapWriteError("decode token", err)
	}
	payload, err := dto.AdminDecodePayload(msg)
	if err != nil {
		return nil, fmt.Errorf("admin handler: decode token payload: %w", err)
	}
	return connectrpc.NewResponse(&adminv1.DecodeResponse{Payload: payload}), nil
}

// GetStatus 监控三字段——队列长度 / 累计 dropped / 最近 flush 耗时（asyncqueue 只读指标）。
func (h *Handler) GetStatus(ctx context.Context, _ *connectrpc.Request[adminv1.GetStatusRequest]) (*connectrpc.Response[adminv1.StatusResponse], error) {
	st := h.settings.GetStatus()
	return connectrpc.NewResponse(&adminv1.StatusResponse{
		QueueLength: st.QueueLength,
		Dropped:     int64(st.Dropped),
		FlushMs:     st.FlushMs,
	}), nil
}

// mapWriteError service 写路径错误 → Connect 形态：参数 / 校验类 → invalid_argument +
// ErrorInfo(admin, invalid_request)；唯一键冲突 → already_exists（不挂 ErrorInfo）；
// 资源不存在 → not_found；其余上抛消毒为 internal。
func mapWriteError(op string, err error) error {
	switch {
	case errors.Is(err, adminsvc.ErrInvalidRequest):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errInvalidRequest),
			connect.NewErrorInfo("admin", "invalid_request", "invalid request"),
		)
	case errors.Is(err, adminsvc.ErrDuplicateKey):
		return connectrpc.NewError(connectrpc.CodeAlreadyExists, errDuplicateKey)
	case errors.Is(err, sql.ErrNoRows):
		return connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("admin handler: %s: %w", op, err)
	}
}

// mapUserError 用户管理族错误 → Connect 形态（口径同 mapWriteError）：参数类 →
// ErrorInfo{invalid_request}；密码不满足策略 → ErrorInfo{password_weak}；
// 权限门禁拒绝 → permission_denied（标准码，不挂 ErrorInfo 细分码）；
// username / 联系方式被他人占用 → already_exists + ErrorInfo{username_taken /
// target_taken}（字段级提示，§1.6 / §5.4：username 归 username_taken，
// 联系方式归 target_taken）；资源不存在 → not_found；其余上抛消毒为 internal。
func mapUserError(op string, err error) error {
	switch {
	case errors.Is(err, adminsvc.ErrInvalidRequest):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errInvalidRequest),
			connect.NewErrorInfo("admin", "invalid_request", "invalid request"),
		)
	case errors.Is(err, adminsvc.ErrPasswordWeak):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errPasswordWeak),
			connect.NewErrorInfo("admin", "password_weak", "password does not meet policy"),
		)
	case errors.Is(err, adminsvc.ErrUsernameTaken):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeAlreadyExists, errUsernameTaken),
			connect.NewErrorInfo("admin", "username_taken", "username already taken"),
		)
	case errors.Is(err, adminsvc.ErrTargetTaken):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeAlreadyExists, errTargetTaken),
			connect.NewErrorInfo("admin", "target_taken", "contact already bound to another user"),
		)
	case errors.Is(err, adminsvc.ErrPermissionDenied):
		return connectrpc.NewError(connectrpc.CodePermissionDenied, errPermissionDenied)
	case errors.Is(err, sql.ErrNoRows):
		return connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("admin handler: %s: %w", op, err)
	}
}

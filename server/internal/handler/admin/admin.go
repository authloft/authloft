// Package admin 实现 api.admin.v1.AdminService 的 Connect handler
// （docs/后端架构.md §3.4 行 333：admin 域方法族，全部需管理员会话）。
// 已落地 Provider 族读路径、Provider 写族、
// 管理员自身 + 用户管理族（GetMe + §5.4 七方法，service/admin/user.go 分层）、
// 客户端管理族（§5.5 十方法，service/admin/client.go 分层）、
// 系统配置 / 事件 / 工具族（§5.6 五方法，service/admin/settings.go
// 分层）——33 方法全部实装，桩清单清空。
//
// 鉴权口径（docs/接口文档.md §5 行 1145-1146）：管理员 = 安装时创建的
// user.id = 1 账号；admin 拦截器（connect.NewAdminInterceptor）挂在 session
// 拦截器之内——无会话 401 unauthenticated、非管理员 404 not_found（掩护管理
// 面存在），故 handler 不做二次鉴权；会话身份（uid）经 session.WithSessionContext
// 注入 ctx，GetMe / SetSettings 审计 actor 从 ctx 取。
//
// 敏感内容口径：GetProvider 明文 ext 与 DecodeToken 载荷均不落
// 日志（访问日志只记方法 / 路径 / 状态码 / 耗时，middleware/logger 行 12）；
// 本文件错误文案全部固定，不携带 token / payload / secret 值。
package admin

import (
	"context"
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

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

// ProviderReader admin 域 provider 读取窄接口（§20 依赖注入）：生产注入
// *repo.ProviderRepo（FindByKey / ListProviders 均已有，不扩公共接口），
// 测试可传 fake。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
	ListProviders(ctx context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error)
}

// ProviderService admin 域 provider 写族 + 下拉 + 发送测试窄接口（
// §20 依赖注入）：生产注入 *adminsvc.Service（分层 §18 行 1792：handler →
// service/admin → repo → cache），测试可传 fake。
type ProviderService interface {
	CreateProvider(ctx context.Context, body *structpb.Struct) error
	UpdateProvider(ctx context.Context, body *structpb.Struct) error
	DeleteProvider(ctx context.Context, providerKey string) error
	SetProviderEnabled(ctx context.Context, providerKey string, enabled bool) error
	SortProviders(ctx context.Context, items []adminsvc.SortItem) error
	ProviderTypes() []adminsvc.ProviderTypeInfo
	TestProvider(ctx context.Context, providerKey, target string) error
}

// UserService admin 域用户管理族窄接口（§20 依赖注入）：生产注入
// *adminsvc.UserService（分层 §18 行 1792：handler → service/admin/user.go →
// repo / cache），测试可传 fake。
type UserService interface {
	GetMe(ctx context.Context, uid int64) (*model.User, error)
	ListUsers(ctx context.Context, f adminsvc.ListUsersFilter) ([]model.User, int64, error)
	GetUser(ctx context.Context, id int64) (*adminsvc.UserDetail, error)
	UpdateUserStatus(ctx context.Context, actor, id int64, userStatus int64) error
	ResetUserPassword(ctx context.Context, actor, id int64, password string) error
	UnbindUserThirdparty(ctx context.Context, actor, id int64, providerKey string) error
	UnlockUser(ctx context.Context, id int64) error
	GetUserEvents(ctx context.Context, id int64, page, pageSize int) ([]model.EventLog, int64, error)
}

// ClientService admin 域客户端管理族窄接口（§20 依赖注入）：生产注入
// *adminsvc.ClientService（分层 §18 行 1792：handler → service/admin/client.go
// → repo/client_repo.go），测试可传 fake。
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

// SettingsService admin 域系统配置 / 事件 / 工具族窄接口（§20
// 依赖注入）：生产注入 *adminsvc.SettingsService（分层 §18 行 1792：
// handler → service/admin/settings.go → settings.Store / eventlog_repo /
// asyncqueue.Queue），测试可传 fake。
type SettingsService interface {
	GetSettings() map[string]any
	SetSettings(ctx context.Context, actor int64, req *adminv1.SetSettingsRequest) error
	ListEvents(ctx context.Context, f adminsvc.EventListFilter) ([]model.EventLog, int64, error)
	DecodeToken(purpose, token string) (proto.Message, error)
	GetStatus() adminsvc.QueueStatus
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
// （口径同 internal/connect/interceptors.go 与 account handler）。
var (
	errNotFound        = errors.New("not found")
	errUnknownProvType = errors.New("unknown provider type")
	errInvalidRequest  = errors.New("invalid request")
	errDuplicateKey    = errors.New("provider key already exists")
	errAuthRequired    = errors.New("authentication required")
	errPasswordWeak    = errors.New("password does not meet policy")
)

// providerListPageSize 管理列表分页上限（§1.7 行 277：pageSize 上限 100），
// 同时是 union_provider options 查询的页大小。
const providerListPageSize = 100

// Handler AdminService 服务实现。内嵌生成的 unimplemented 基类以兼容
// 生成接口的前向演进；33 方法已全部实装（见包注释）。
type Handler struct {
	adminv1connect.UnimplementedAdminServiceHandler
	providers ProviderReader
	svc       ProviderService
	users     UserService
	clients   ClientService
	settings  SettingsService
}

// New 构造 AdminService handler（providers：读路径；svc：写族 +
// GetProviderTypes + TestProvider；users：用户管理族 8 方法；clients：
// 客户端管理族 10 方法；settings：系统配置 / 事件 / 工具族 5 方法）。
func New(providers ProviderReader, svc ProviderService, users UserService, clients ClientService, settings SettingsService) *Handler {
	return &Handler{providers: providers, svc: svc, users: users, clients: clients, settings: settings}
}

// ListProviders（接口文档 §5.2 行 1168）：筛选 {category, type, isEnabled} +
// §1.7 分页的 provider 列表。列表列不含 ext 任何凭证字段（明文仅在
// GetProvider，§12.1 行 1719——列表消息在 proto 里就没有 ext 字段）。
// 排序固定 sort_order ASC, id ASC（§4.1，provider_repo 约束）；请求的
// sort / order 任意列排序归后续 service / handler 实现，本实现不消费。
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

// GetProvider（§5.2 行 1170）：{providerKey} 详情——全站唯一明文凭证出口
// （§12.1 行 1719：ext 明文透出，仅管理员会话可见；鉴权由 admin 拦截器保证，
// dto 不做二次脱敏）。响应绝不进日志：访问日志只记方法 / 路径 / 状态码 /
// 耗时（middleware/logger 行 12「不打印 body」），本 handler 不再自行打日志。
func (h *Handler) GetProvider(ctx context.Context, req *connectrpc.Request[adminv1.GetProviderRequest]) (*connectrpc.Response[adminv1.AdminProvider], error) {
	row, err := h.providers.FindByKey(ctx, req.Msg.GetProviderKey())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// §1.5 行 189：资源不存在（管理后台单资源）→ 404 not_found。
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

// GetProviderSchema（§5.2 行 1176、§5.3 行 1181-1244）：由注册表 meta 驱动的
// 动态表单 schema——oauth 域 Register 与消息域 RegisterSender 两张注册表按
// type 查（§15.3 行 1731：注册表 meta 是 /schema 唯一数据源；两域 type 名天然
// 不相交，sender.go 注册表取舍）。表列基线字段（全类型共有）在
// dto.AdminSchema 按 §5.3 示例组装，Ext 字段逐项来自 meta 声明、不硬编码。
// 未注册 / 空 type → §1.6 封闭集合内取值 invalid_request（参数缺失 / 格式
// 错误），Connect 标准码 invalid_argument（§1.5），ErrorInfo domain=admin。
func (h *Handler) GetProviderSchema(ctx context.Context, req *connectrpc.Request[adminv1.GetProviderSchemaRequest]) (*connectrpc.Response[adminv1.SchemaResponse], error) {
	providerType := req.Msg.GetType()
	category, extFields, ok := lookupProviderType(providerType)
	if providerType == "" || !ok {
		return nil, connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errUnknownProvType),
			connect.NewErrorInfo("admin", "invalid_request", "unknown provider type"),
		)
	}
	// union_provider 字段的 options 数据源（§5.3 行 1197：仅列 category=union
	// 的 Provider）；查询失败按 internal 上抛（错误包装拦截器消毒线上文本）。
	unionKeys, err := h.unionProviderKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin handler: list union providers: %w", err)
	}
	return connectrpc.NewResponse(dto.AdminSchema(providerType, category, extFields, unionKeys)), nil
}

// lookupProviderType 按 type 查两域注册表（§15.3）：先 oauth 域（Lookup），
// 未命中再消息域（LookupSenderMeta）。两域 meta 均带 Fields 字段级声明
// （§5.3 行 1231-1243），Ext 部分逐项来自 meta、不硬编码，两域对称。
func lookupProviderType(providerType string) (category string, extFields []provider.FieldMeta, ok bool) {
	if meta, found := provider.Lookup(providerType); found {
		return meta.Category, meta.Fields, true
	}
	if meta, found := provider.LookupSenderMeta(providerType); found {
		return meta.Category, meta.Fields, true
	}
	return "", nil, false
}

// unionProviderKeys 分页读完全部 category=union 的 provider_key（§5.3 行 1197；
// §1.7 分页上限 100，union 类数量有限，循环取满 total 即止）。
func (h *Handler) unionProviderKeys(ctx context.Context) ([]string, error) {
	category := "union"
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

// normalizeListPage §1.7 行 277 分页归一（page 从 1 开始、pageSize 默认 20、
// 上限 100）——响应回显归一后的生效值（repo.normalize 为包内私有，口径相同）。
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

// —— 写族 7 方法（§5.2 行 1169-1177）：service 层业务校验与缓存失效，
// handler 只做 Connect 形态映射（§18 行 1792 分层）——

// CreateProvider（§5.2 行 1169）：新建，请求体为 §5.3 schema 的动态键集合
//（google.protobuf.Struct）。
func (h *Handler) CreateProvider(ctx context.Context, req *connectrpc.Request[structpb.Struct]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.CreateProvider(ctx, req.Msg); err != nil {
		return nil, mapWriteError("create provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// UpdateProvider（§5.2 行 1171）：编辑，提交体平铺含 provider_key（定位），
// provider_key 创建后不可改；缺省键保留原值（PATCH，service 层口径）。
func (h *Handler) UpdateProvider(ctx context.Context, req *connectrpc.Request[structpb.Struct]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.UpdateProvider(ctx, req.Msg); err != nil {
		return nil, mapWriteError("update provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteProvider（§5.2 行 1172）：{providerKey} 删除；不存在 → 404 not_found
// （§1.5 行 189 管理后台单资源）。
func (h *Handler) DeleteProvider(ctx context.Context, req *connectrpc.Request[adminv1.DeleteProviderRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.DeleteProvider(ctx, req.Msg.GetProviderKey()); err != nil {
		return nil, mapWriteError("delete provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SetProviderEnabled（§5.2 行 1173）：{providerKey, isEnabled} 行内开关。
func (h *Handler) SetProviderEnabled(ctx context.Context, req *connectrpc.Request[adminv1.SetProviderEnabledRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.SetProviderEnabled(ctx, req.Msg.GetProviderKey(), req.Msg.GetIsEnabled()); err != nil {
		return nil, mapWriteError("set provider enabled", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// SortProviders（§5.2 行 1174）：{items:[{providerKey, sortOrder}]} 拖拽排序。
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

// GetProviderTypes（§5.2 行 1175）：Provider type 下拉数据源，来自两域注册表
// metas（§15.3），type 稳定排序（service 层保证）。
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

// TestProvider（§5.2 行 1177）：{providerKey, target} 短信 / 邮件 Provider 的
// 「发送测试」——同步 Send 给管理员即时反馈（service 层不经 Loader / asyncqueue）。
func (h *Handler) TestProvider(ctx context.Context, req *connectrpc.Request[adminv1.TestProviderRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.svc.TestProvider(ctx, req.Msg.GetProviderKey(), req.Msg.GetTarget()); err != nil {
		return nil, mapWriteError("test provider", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// —— 用户管理族 8 方法（§5.1 行 1162、§5.4 行 1249-1255）：service
// 层业务校验与副作用编排，handler 只做 Connect 形态映射与 dto 投影——

// GetMe（§5.1 行 1162）：当前管理员 {id, username, nickname, avatarUrl,
// isAdmin:true}——前端获取管理员信息的唯一来源。uid 取 session ctx（session
// 拦截器注入载荷，admin 拦截器已收口 uid==1，本方法不做二次鉴权）；行缺失
// → 404（安装账号被删的脏数据防御）。
func (h *Handler) GetMe(ctx context.Context, _ *connectrpc.Request[adminv1.GetMeRequest]) (*connectrpc.Response[adminv1.MeResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errAuthRequired)
	}
	row, err := h.users.GetMe(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
	return connectrpc.NewResponse(dto.AdminMe(row)), nil
}

// ListUsers（§5.4 行 1249）：筛选 {q, userStatus} + §1.7 分页的用户列表；
// sort / order 透传 service（§1.7 行 277 后端不做白名单强制校验，防注入
// 字符集约束在 repo）。
func (h *Handler) ListUsers(ctx context.Context, req *connectrpc.Request[adminv1.ListUsersRequest]) (*connectrpc.Response[adminv1.UserListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.users.ListUsers(ctx, adminsvc.ListUsersFilter{
		Q:          req.Msg.GetQ(),
		UserStatus: req.Msg.UserStatus,
		Page:       page,
		PageSize:   size,
		Sort:       req.Msg.GetSort(),
		Order:      req.Msg.GetOrder(),
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

// GetUser（§5.4 行 1250）：{id} 详情（含凭证概览、绑定、MFA 状态）——
// dto.AdminUserDetail 组装，secret 不透出（UserCredentialSummary 无该字段）。
func (h *Handler) GetUser(ctx context.Context, req *connectrpc.Request[adminv1.GetUserRequest]) (*connectrpc.Response[adminv1.UserDetailResponse], error) {
	d, err := h.users.GetUser(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapUserError("get user", err)
	}
	return connectrpc.NewResponse(dto.AdminUserDetail(d.User, d.Credentials, d.Bindings)), nil
}

// UpdateUserStatus（§5.4 行 1251）：{id, userStatus 0|1} 禁用 / 启用；禁用
// 走 IncEpoch 会话失效链 + 审计（service 层编排）。
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

// ResetUserPassword（§5.4 行 1252）：{id, password} 管理员重置——§5.6 密码
// 策略校验在 service；不满足 → invalid_argument + code=password_weak
// （§1.6 封闭集合既有取值，ErrorInfo domain=admin）。
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

// UnbindUserThirdparty（§5.4 行 1253）：{id, providerKey} 解绑第三方——
// Union Provider 行不可单独解绑（invalid_request）、Union 行连带在 service。
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

// UnlockUser（§5.4 行 1254）：{id} 解除登录限制——清 uid 维度键 + 按当前
// phone / email 重算 ip 维度键（service 层编排，§8.1 行 1041）。
func (h *Handler) UnlockUser(ctx context.Context, req *connectrpc.Request[adminv1.UnlockUserRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.users.UnlockUser(ctx, req.Msg.GetId()); err != nil {
		return nil, mapUserError("unlock user", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetUserEvents（§5.4 行 1255）：{id} + 分页的该用户登录记录（login_success
// 过滤在 service）；detail msgpack → JSON 对象在 dto 投影。
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

// —— 客户端管理族 10 方法（§5.5 行 1258-1268）：service 层业务校验
//（secret 服务端生成、client_id 生成/不可改、redirect_uris 校验、OIDC
// scopes/TTL 值域），handler 只做 Connect 形态映射与 dto 投影；错误复用
// mapWriteError 口径（invalid_request / already_exists / not_found 封闭集）——

// ListSsoClients（§5.5 行 1258）：§1.7 分页列表；sort / order 透传
// service（§1.7 行 277 后端不做白名单强制校验，防注入字符集约束在
// repo.orderClause，口径同 ListUsers）。空页 items
// 按 proto3 空 repeated 省略（§1.7 行 278）。
func (h *Handler) ListSsoClients(ctx context.Context, req *connectrpc.Request[adminv1.ListSsoClientsRequest]) (*connectrpc.Response[adminv1.SsoClientListResponse], error) {
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.clients.ListSsoClients(ctx, page, size, req.Msg.GetSort(), req.Msg.GetOrder())
	if err != nil {
		return nil, mapWriteError("list sso clients", err)
	}
	items := make([]*adminv1.SsoClient, len(rows))
	for i := range rows {
		items[i] = dto.AdminSsoClient(rows[i].Row, rows[i].RedirectURIs)
	}
	return connectrpc.NewResponse(&adminv1.SsoClientListResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// CreateSsoClient（§5.5 行 1258/1266）：仅后台手动创建；请求中的
// client_secret 字段被忽略——服务端生成，管理员经 GetSsoClient 明文查看
// （§5.2 行 1170 凭证口径）。成功返回 OkResponse。
func (h *Handler) CreateSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.CreateSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.CreateSsoClient(ctx, adminsvc.SsoClientInput{
		ClientID:     req.Msg.GetClientId(),
		Name:         req.Msg.GetName(),
		RedirectURIs: req.Msg.GetRedirectUris(),
	}); err != nil {
		return nil, mapWriteError("create sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetSsoClient（§5.5 行 1259）：{id} 定位（proto 唯一定位字段）→ 详情
// 含明文 secret（SsoClient 消息列表/详情两用，仅 admin 会话可达）。
func (h *Handler) GetSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.GetSsoClientRequest]) (*connectrpc.Response[adminv1.SsoClient], error) {
	d, err := h.clients.GetSsoClient(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapWriteError("get sso client", err)
	}
	return connectrpc.NewResponse(dto.AdminSsoClient(d.Row, d.RedirectURIs)), nil
}

// UpdateSsoClient（§5.5 行 1259）：缺省键保留原值（PATCH，service 层）；
// client_id 不可改（改 → invalid_request）。
func (h *Handler) UpdateSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.UpdateSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.UpdateSsoClient(ctx, req.Msg.GetId(), adminsvc.SsoClientPatch{
		ClientID:     req.Msg.GetClientId(),
		ClientSecret: req.Msg.GetClientSecret(),
		Name:         req.Msg.GetName(),
		RedirectURIs: req.Msg.GetRedirectUris(),
	}); err != nil {
		return nil, mapWriteError("update sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteSsoClient（§5.5 行 1259）：硬删；不触发会话失效（docs 未定义，
// 默认，待定）。
func (h *Handler) DeleteSsoClient(ctx context.Context, req *connectrpc.Request[adminv1.DeleteSsoClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.DeleteSsoClient(ctx, req.Msg.GetId()); err != nil {
		return nil, mapWriteError("delete sso client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// ListOidcClients（§5.5 行 1260）：口径同 ListSsoClients（scopes 拆分在
// service）。
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

// CreateOidcClient（§5.5 行 1260）：SSO 基线 + scopes[] / TTL（0 落 DDL
// 默认 3600 / 2592000）；授权类型不建模（§5.5 行 1268 固定
// authorization_code + refresh_token）。client_secret 同 CreateSsoClient
// 服务端生成。
func (h *Handler) CreateOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.CreateOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.CreateOidcClient(ctx, adminsvc.OidcClientInput{
		ClientID:        req.Msg.GetClientId(),
		Name:            req.Msg.GetName(),
		RedirectURIs:    req.Msg.GetRedirectUris(),
		Scopes:          req.Msg.GetScopes(),
		AccessTokenTTL:  req.Msg.GetAccessTokenTtl(),
		RefreshTokenTTL: req.Msg.GetRefreshTokenTtl(),
	}); err != nil {
		return nil, mapWriteError("create oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// GetOidcClient（§5.5 行 1261）：{id} 定位 → 详情含明文 secret +
// scopes[] / TTL 投影。
func (h *Handler) GetOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.GetOidcClientRequest]) (*connectrpc.Response[adminv1.OidcClient], error) {
	d, err := h.clients.GetOidcClient(ctx, req.Msg.GetId())
	if err != nil {
		return nil, mapWriteError("get oidc client", err)
	}
	return connectrpc.NewResponse(dto.AdminOidcClient(d.Row, d.RedirectURIs, d.Scopes)), nil
}

// UpdateOidcClient（§5.5 行 1261）：缺省键保留原值（PATCH）；client_id
// 不可改；scopes / TTL 同 PATCH 语义（TTL 0 保留原值）。
func (h *Handler) UpdateOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.UpdateOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.UpdateOidcClient(ctx, req.Msg.GetId(), adminsvc.OidcClientPatch{
		ClientID:        req.Msg.GetClientId(),
		ClientSecret:    req.Msg.GetClientSecret(),
		Name:            req.Msg.GetName(),
		RedirectURIs:    req.Msg.GetRedirectUris(),
		Scopes:          req.Msg.GetScopes(),
		AccessTokenTTL:  req.Msg.GetAccessTokenTtl(),
		RefreshTokenTTL: req.Msg.GetRefreshTokenTtl(),
	}); err != nil {
		return nil, mapWriteError("update oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// DeleteOidcClient（§5.5 行 1261）：硬删；口径同 DeleteSsoClient。
func (h *Handler) DeleteOidcClient(ctx context.Context, req *connectrpc.Request[adminv1.DeleteOidcClientRequest]) (*connectrpc.Response[adminv1.OkResponse], error) {
	if err := h.clients.DeleteOidcClient(ctx, req.Msg.GetId()); err != nil {
		return nil, mapWriteError("delete oidc client", err)
	}
	return connectrpc.NewResponse(&adminv1.OkResponse{}), nil
}

// —— 系统配置 / 事件 / 工具族 5 方法（§5.6 行 1270-1277）：service
// 层做业务编排（SetSettings 部分更新 + 审计、ListEvents 透传、DecodeToken
// 解载荷、GetStatus 队列指标），handler 只做 Connect 形态映射与 dto 投影——

// GetSettings（§5.6 行 1274）：全部系统配置——Store.Snapshot 35 键全键
// 投影（dto.AdminSettings，键名与 §5.6 四张表逐键一致）；无入参。
func (h *Handler) GetSettings(ctx context.Context, _ *connectrpc.Request[adminv1.GetSettingsRequest]) (*connectrpc.Response[adminv1.SettingsResponse], error) {
	snap := h.settings.GetSettings()
	return connectrpc.NewResponse(dto.AdminSettings(snap)), nil
}

// SetSettings（§5.6 行 1274）：部分更新（PATCH）系统配置（optional 标量
// has 位 = 在场，未设置不修改、显式零值覆盖；四个 repeated 键由 has_*
// 伴生标志取 true 判定在场，空数组 = 清空列表、标志缺省 = 不修改）；
// flat 消息原样透传 service，落库与热更通知、settings_update 审计
// （actor=会话 uid）在 service；值类型校验在 settings.Validate（经
// SetMany），交叉约束不兜底（行 1342）。
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

// ListEvents（§5.6 行 1275）：统一事件视图——六筛选 optional 指针原样
// 透传（nil 即不过滤）+ §1.7 分页（归一后回显）+ sort / order 透传（防
// 注入字符集约束在 repo.orderClause，口径同 ListUsers）；行 →
// EventItem 投影复用 dto.AdminEventItem（detail msgpack → JSON 对象）。
// 空页 items 按 proto3 空 repeated 省略（§1.7 行 278）。
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

// DecodeToken（§5.6 行 1276）：令牌解码排障工具——purpose ∈ login|session
// |cookie（《后端架构》§11.6.1 的 purpose 口径），解载荷 → Struct 投影
// （dto.AdminDecodePayload，protojson camelCase）。非法 purpose / 解码失败
// → invalid_argument + ErrorInfo(admin, invalid_request)（§1.5 / §1.6）；
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

// GetStatus（§5.6 行 1277）：监控三字段——队列长度 / 累计 dropped / 最近
// 一次 flush 耗时（ms），asyncqueue 只读指标透传（FlushMs 增量）。
func (h *Handler) GetStatus(ctx context.Context, _ *connectrpc.Request[adminv1.GetStatusRequest]) (*connectrpc.Response[adminv1.StatusResponse], error) {
	st := h.settings.GetStatus()
	return connectrpc.NewResponse(&adminv1.StatusResponse{
		QueueLength: st.QueueLength,
		Dropped:     int64(st.Dropped),
		FlushMs:     st.FlushMs,
	}), nil
}

// mapWriteError service 写路径错误 → Connect 形态（§1.5 行 182-195 统一口径）：
// 参数 / 校验类 → invalid_argument + ErrorInfo domain=admin code=invalid_request
// （§1.6 封闭集合，同 GetProviderSchema 先例）；唯一键冲突 → already_exists
// （行 190，409，§1.6 无对应业务细分码故不挂 ErrorInfo，前端按标准码兜底，
// 行 226）；资源不存在 → not_found（行 189）；其余原样上抛由错误包装拦截器
// 消毒为 internal（行 192）。
func mapWriteError(op string, err error) error {
	switch {
	case errors.Is(err, adminsvc.ErrInvalidRequest):
		return connect.WithErrorInfo(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errInvalidRequest),
			connect.NewErrorInfo("admin", "invalid_request", "invalid request"),
		)
	case errors.Is(err, adminsvc.ErrDuplicateKey):
		return connectrpc.NewError(connectrpc.CodeAlreadyExists, errDuplicateKey)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("admin handler: %s: %w", op, err)
	}
}

// mapUserError 用户管理族 service 错误 → Connect 形态（口径同 mapWriteError，
// §1.5 行 182-195）：参数 / 校验类 → invalid_argument + code=invalid_request；
// 密码不满足 §5.6 策略 → invalid_argument + code=password_weak（§1.6 封闭
// 集合既有业务码，前端已有映射）；资源不存在 → not_found；其余原样上抛
// 消毒为 internal。
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
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connectrpc.NewError(connectrpc.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("admin handler: %s: %w", op, err)
	}
}

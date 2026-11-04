// Package admin 实现 api.admin.v1.AdminService 的 Connect handler
// （docs/后端架构.md §3.4 行 333：admin 域方法族，全部需管理员会话）。本实现
// 仅落地 Provider 族读路径，其余方法一律由生成的
// UnimplementedAdminServiceHandler 返回 unimplemented（不自造错误信封）。
//
// 鉴权口径（docs/接口文档.md §5 行 1145-1146）：管理员 = 安装时创建的
// user.id = 1 账号；admin 拦截器（connect.NewAdminInterceptor）挂在 session
// 拦截器之内——无会话 401 unauthenticated、非管理员 404 not_found（掩护管理
// 面存在），故 handler 不做二次鉴权。
//
// TODO(后续 admin 实现)——桩方法归属（均返回生成基类的 unimplemented）：
//   - 管理员自身：GetMe（§5.1）
//   - Provider 写路径：CreateProvider / UpdateProvider / DeleteProvider /
//     SetProviderEnabled / SortProviders / TestProvider（§5.2）；下拉数据源
//     GetProviderTypes（§5.2 行 1175，同样待后续实现接线）
//   - 用户管理：ListUsers / GetUser / UpdateUserStatus / ResetUserPassword /
//     UnbindUserThirdparty / UnlockUser / GetUserEvents（§5.4）
//   - 客户端管理：ListSsoClients / CreateSsoClient / GetSsoClient /
//     UpdateSsoClient / DeleteSsoClient / ListOidcClients / CreateOidcClient /
//     GetOidcClient / UpdateOidcClient / DeleteOidcClient（§5.5）
//   - 系统配置与工具：GetSettings / SetSettings / ListEvents / DecodeToken /
//     GetStatus（§5.6）
package admin

import (
	"context"
	"errors"
	"fmt"

	connectrpc "connectrpc.com/connect"
	"gorm.io/gorm"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/gen/go/api/admin/v1/adminv1connect"
	"authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// ProviderReader admin 域 provider 读取窄接口（§20 依赖注入）：生产注入
// *repo.ProviderRepo（FindByKey / ListProviders 均已有，不扩公共接口），
// 测试可传 fake。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
	ListProviders(ctx context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error)
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
// （口径同 internal/connect/interceptors.go 与 account handler）。
var (
	errNotFound        = errors.New("not found")
	errUnknownProvType = errors.New("unknown provider type")
)

// providerListPageSize 管理列表分页上限（§1.7 行 277：pageSize 上限 100），
// 同时是 union_provider options 查询的页大小。
const providerListPageSize = 100

// Handler AdminService 服务实现。内嵌生成的 unimplemented 基类：本实现未实现的
// 方法（见包注释 TODO 清单）统一返回 Connect CodeUnimplemented。
type Handler struct {
	adminv1connect.UnimplementedAdminServiceHandler
	providers ProviderReader
}

// New 构造 AdminService handler。
func New(providers ProviderReader) *Handler {
	return &Handler{providers: providers}
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
// 未命中再消息域（LookupSenderMeta）。oauth 域只落最小 meta、无字段级
// 声明（registry.go 注释「字段级 schema 随 admin 实现扩展」）——其 Ext 字段部分
// 随该扩展自动补齐，本实现不硬编码。
func lookupProviderType(providerType string) (category string, extFields []provider.FieldMeta, ok bool) {
	if meta, found := provider.Lookup(providerType); found {
		return meta.Category, nil, true
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

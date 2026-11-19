// Package admin 实现 AdminService Provider 写族 7 方法（CreateProvider /
// UpdateProvider / DeleteProvider / SetProviderEnabled / SortProviders /
// GetProviderTypes / TestProvider，接口文档 §5.2）的业务层
// （docs/后端架构.md §3.9「Provider CRUD + 缓存失效」、§18 分层 handler →
// service/admin/provider.go → repo → cache/provider）。
//
// 职责边界：schema 键集校验（完整 Schema 声明，含表列与 Ext，§5.3
// 「提交体即 {"<key>": <value>}」）、provider_key 与出站代理引用键字符集、
// proxy 行五字段组合校验（单一来源 proxyclient.NewConfig，§5.3）、
// wechat_mp_scan 拉码模式保存期组合校验（§5.3 type 行）、
// provider_key「创建后不可改」（§12.1）、category 由 meta 按 type 决定只读、
// meta required 字段齐（仅 Create；Update 按缺省键保留原值的 PATCH 口径
// 不强制）、写后缓存失效（§15.3 固定三步，经 cache.ProviderCache.Invalidate
// 唯一出口）。Connect 错误形态映射归 handler；本层返回可判别哨兵错误：
//   - ErrInvalidRequest 参数 / 校验类（handler 映射 §1.5 invalid_argument +
//     ErrorInfo domain=admin code=invalid_request，§1.6 封闭集合）；
//   - ErrDuplicateKey 唯一键 uk_provider_key 冲突（handler 映射 §1.5
//     already_exists，409）；
//   - sql.ErrNoRows 资源不存在（handler 映射 §1.5 not_found）；
//   - 其余错误原样上抛，由错误包装拦截器消毒（§1.5 internal）。
package admin

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/protobuf/types/known/structpb"
	"regexp"
	"strings"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/dto"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// 可判别哨兵错误（映射口径见包注释）。
var (
	// ErrInvalidRequest 参数 / 校验类失败（键集外未知键、字符集不合法、required
	// 缺失、类型不符、改 provider_key / type / category、proxy 行字段组合非法、
	// 引用键不可解析、非 sms/email 类别 TestProvider 等）。
	ErrInvalidRequest = errors.New("admin service: invalid request")
	// ErrDuplicateKey Create 命中 uk_provider_key（repo.ErrProviderDuplicate 的
	// service 层转译）。
	ErrDuplicateKey = errors.New("admin service: provider key already exists")
)

// providerKeyPattern provider_key 字符集（§5.3、§12.1：
// ^[a-z0-9_]+$，创建后不可改）。
var providerKeyPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// testProviderTpl / testProviderCode TestProvider 的测试模板口径（§15.2
// Sender.Send(to, tpl, params)）：tpl 键与模板内容 docs 未细化（§5.2
// 仅「短信 / 邮件 Provider 的发送测试」），按默认最小口径固定 tpl="test" +
// params={"code":"test"}——smtp 默认模板（"您的验证码：{code}"）与 aliyun_sms
// 默认模板（Ext.template_code）均以 {code} 占位，test 值可渲染出可辨识内容。
const (
	testProviderTpl  = "test"
	testProviderCode = "test"
)

// ProviderStore provider 表写路径窄接口（§20 依赖注入）：*repo.ProviderRepo
// 天然满足（FindByKey / Create / Update / Delete 既有 + SetEnabled /
// UpdateSortOrders 列级最小增量），测试可传 fake。
type ProviderStore interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
	Create(ctx context.Context, p *model.Provider) error
	Update(ctx context.Context, p *model.Provider) error
	Delete(ctx context.Context, id int64) error
	SetEnabled(ctx context.Context, id int64, enabled int8) error
	UpdateSortOrders(ctx context.Context, updates []repo.ProviderSortUpdate) error
}

// ProviderInvalidator 写后缓存失效窄接口（§15.3 固定三步
// DEL→INCR→PUBLISH）：*cache.ProviderCache 天然满足，测试可传 fake 断言。
type ProviderInvalidator interface {
	Invalidate(ctx context.Context, providerKey string) error
}

// Service admin 域 Provider 写族业务层。
type Service struct {
	store ProviderStore
	cache ProviderInvalidator
	pools *proxyclient.PoolSet
}

// NewService 构造；store / invalidator / pools 为装配依赖，任一为 nil 属程序
// 错误（fail-fast，口径同 provider.NewLoader）。pools 是进程级出站连接池注册
// 表（bootstrap 构造一次显式注入，§15.4），仅 TestProvider 的引用解析使用。
func NewService(store ProviderStore, invalidator ProviderInvalidator, pools *proxyclient.PoolSet) *Service {
	if store == nil {
		panic("admin service: NewService: nil ProviderStore")
	}
	if invalidator == nil {
		panic("admin service: NewService: nil ProviderInvalidator")
	}
	if pools == nil {
		panic("admin service: NewService: nil PoolSet")
	}
	return &Service{store: store, cache: invalidator, pools: pools}
}

// CreateProvider（§5.2，OUTCOME ①）：提交体为 §5.3 schema 的字段集合
// （{"<key>": <value>}）。校验：type 静态源 meta 命中、provider_key 字符集、
// display_name / meta required 字段齐、category 与 meta 一致（只读）、未知键
// 拒绝。表列经 dto.ApplyProviderColumns 落行，Ext 经 dto.MergeProviderExt 构造
// 后 MarshalProviderExt（1 MiB 业务上限在唯一出口校验，§4.1）。uk 冲突
// 转译 ErrDuplicateKey；写后失效（§15.3）。
func (s *Service) CreateProvider(ctx context.Context, body *structpb.Struct) error {
	fields := body.GetFields()
	if len(fields) == 0 {
		return ErrInvalidRequest
	}
	providerType, meta, ok := lookupSchema(fields)
	if !ok {
		return ErrInvalidRequest
	}
	if err := validateSchemaKeys(fields, meta); err != nil {
		return err
	}
	if err := validateProxyRef(fields); err != nil {
		return err
	}
	providerKey, err := requireProviderKey(fields)
	if err != nil {
		return err
	}
	// Create 的 required 字段必须齐且非空（完整 Schema 声明：表列的
	// provider_key / display_name 与厂商 Ext 必填项一并覆盖；Ext 走 Proto 消息
	// 后由厂商构造兜底，此处先给管理员即时反馈）。display_name 原独立校验删除，
	// 由本循环统一补位（二者都是 Create-only，语义不变；Update 为 PATCH 缺省保留，
	// 不得加 required 校验）。缺省判定 number-aware（§5.3 五字段表 port 必填）：
	// number 标量经 GetStringValue 恒为空串，须兼看 GetNumberValue，0 视为缺省
	//（port=0 同被保存期组合校验拒绝，两道闸一致）；string 型 GetNumberValue
	// 恒为 0，行为与原口径不变。
	for _, f := range meta.Schema {
		if f.Required {
			if v, ok := fields[f.Key]; !ok || (v.GetStringValue() == "" && v.GetNumberValue() == 0) {
				return ErrInvalidRequest
			}
		}
	}

	row := &model.Provider{ProviderKey: providerKey, Category: meta.Category, Type: providerType}
	if err := dto.ApplyProviderColumns(row, fields, dto.ProviderColumnKeys(meta.Schema)); err != nil {
		return ErrInvalidRequest
	}
	ext, err := dto.MergeProviderExt(&providerpb.Ext{}, fields, metaFieldKeys(meta))
	if err != nil {
		return ErrInvalidRequest // 类型不符
	}
	if err := validateProxyConfig(row, ext); err != nil {
		return err
	}
	if err := validateQrcodeModes(meta, ext); err != nil {
		return err
	}
	if row.Ext, err = repo.MarshalProviderExt(ext); err != nil {
		return ErrInvalidRequest // 超 1 MiB 业务上限（§4.1）
	}

	if err := s.store.Create(ctx, row); err != nil {
		if errors.Is(err, repo.ErrProviderDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	// default tag 显式 false 修正（repo.Create 契约：default tag 列的零值被
	// tag 值显式写入 INSERT——is_enabled / enable_signin / enable_signup 三列
	// DDL 默认 1，提交 false 会被覆盖，管理员「新建即禁用」意图丢失，§4.1
	// 所述「显式写 0 走列级 UPDATE」）：Create 已回填 ID / created_at
	// 的完整行上按提交意图重置后走一次 repo.Update（Select("*") 整行覆盖，
	// 禁用零值可落库）。docs 未覆盖 Create 与 default tag 的冲突，本修正为
	// 默认最小口径，待定。
	reset := false
	if explicitFalse(fields, "is_enabled") {
		row.IsEnabled, reset = 0, true
	}
	if explicitFalse(fields, "enable_signin") {
		row.EnableSignin, reset = 0, true
	}
	if explicitFalse(fields, "enable_signup") {
		row.EnableSignup, reset = 0, true
	}
	if reset {
		if err := s.store.Update(ctx, row); err != nil {
			return err
		}
	}
	return s.invalidate(ctx, providerKey)
}

// UpdateProvider（§5.2，OUTCOME ②）：提交体平铺含 provider_key（定位键，
// proto 单 Struct 形态下 provider_key 兼作行定位与「不可改」校验目标）。缺省键
// 保留原值（PATCH over schema 键集——docs 未明说，按默认口径处理）：
// 表列在 FindByKey 读回的完整行上仅覆盖已提交键，Ext 经 protojson 往返合并。
// provider_key / type / category 提交值与行现值不一致 → invalid_request
// （「创建后不可改」防御式校验；生产 FindByKey 语义下 provider_key 分支不可达，
// 保留给列级定位或脏数据场景）。写后失效（§15.3）。
func (s *Service) UpdateProvider(ctx context.Context, body *structpb.Struct) error {
	fields := body.GetFields()
	if len(fields) == 0 {
		return ErrInvalidRequest
	}
	providerKey, err := requireProviderKey(fields)
	if err != nil {
		return err
	}
	row, err := s.store.FindByKey(ctx, providerKey)
	if err != nil {
		return err // sql.ErrNoRows 由 handler 映射 404
	}
	// 「创建后不可改」防御式校验（§5.2）：定位键与行现键必须一致。
	if row.ProviderKey != providerKey {
		return ErrInvalidRequest
	}
	// type / category 由注册表按 type 决定，只读：提交则须与现值一致。
	if v, ok := fields["type"]; ok {
		if t, verr := structpbString(v); verr != nil || t != row.Type {
			return ErrInvalidRequest
		}
	}
	if v, ok := fields["category"]; ok {
		if c, verr := structpbString(v); verr != nil || c != row.Category {
			return ErrInvalidRequest
		}
	}
	meta, ok := lookupSchemaByType(row.Type)
	if !ok {
		// 行的 type 未注册（存量脏数据）：schema 键集无从判定，按未知异常上抛。
		return fmt.Errorf("admin service: update provider %q: unregistered type %q", providerKey, row.Type)
	}
	if err := validateSchemaKeys(fields, meta); err != nil {
		return err
	}
	if err := validateProxyRef(fields); err != nil {
		return err
	}

	if err := dto.ApplyProviderColumns(row, fields, dto.ProviderColumnKeys(meta.Schema)); err != nil {
		return ErrInvalidRequest
	}
	origExt, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return fmt.Errorf("admin service: parse ext %q: %w", providerKey, err)
	}
	ext, err := dto.MergeProviderExt(origExt, fields, metaFieldKeys(meta))
	if err != nil {
		return ErrInvalidRequest // 类型不符
	}
	if err := validateProxyConfig(row, ext); err != nil {
		return err
	}
	if err := validateQrcodeModes(meta, ext); err != nil {
		return err
	}
	if row.Ext, err = repo.MarshalProviderExt(ext); err != nil {
		return ErrInvalidRequest // 超 1 MiB 业务上限
	}

	if err := s.store.Update(ctx, row); err != nil {
		return err
	}
	return s.invalidate(ctx, providerKey)
}

// DeleteProvider（§5.2，OUTCOME ③）：FindByKey → repo.Delete(id) →
// 失效；不存在 → sql.ErrNoRows（handler 404）。
func (s *Service) DeleteProvider(ctx context.Context, providerKey string) error {
	if providerKey == "" {
		return ErrInvalidRequest
	}
	row, err := s.store.FindByKey(ctx, providerKey)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, row.ID); err != nil {
		return err
	}
	return s.invalidate(ctx, providerKey)
}

// SetProviderEnabled（§5.2，OUTCOME ④）：行内开关，列级最小 UPDATE
// （repo.SetEnabled，不自写 SQL）→ 失效。
func (s *Service) SetProviderEnabled(ctx context.Context, providerKey string, enabled bool) error {
	if providerKey == "" {
		return ErrInvalidRequest
	}
	row, err := s.store.FindByKey(ctx, providerKey)
	if err != nil {
		return err
	}
	v := int8(0)
	if enabled {
		v = 1
	}
	if err := s.store.SetEnabled(ctx, row.ID, v); err != nil {
		return err
	}
	return s.invalidate(ctx, providerKey)
}

// SortItem SortProviders 的单个条目（§5.2：{providerKey, sortOrder}）。
type SortItem struct {
	ProviderKey string
	SortOrder   int32
}

// SortProviders（§5.2，OUTCOME ⑤）：批量列级 UPDATE（repo.
// UpdateSortOrders 事务内逐行；任一 key 不存在全批回滚 → 404）→ 逐 key 失效。
func (s *Service) SortProviders(ctx context.Context, items []SortItem) error {
	if len(items) == 0 {
		return ErrInvalidRequest
	}
	updates := make([]repo.ProviderSortUpdate, len(items))
	for i, it := range items {
		if !providerKeyPattern.MatchString(it.ProviderKey) {
			return ErrInvalidRequest
		}
		updates[i] = repo.ProviderSortUpdate{ProviderKey: it.ProviderKey, SortOrder: it.SortOrder}
	}
	if err := s.store.UpdateSortOrders(ctx, updates); err != nil {
		return err
	}
	for _, it := range items {
		if err := s.invalidate(ctx, it.ProviderKey); err != nil {
			return err
		}
	}
	return nil
}

// ProviderTypeInfo GetProviderTypes 的下拉条目（§5.2：来自类型 meta）。
type ProviderTypeInfo struct {
	Type        string
	Category    string
	DisplayName string
}

// ProviderTypes（§5.2，OUTCOME ⑥）：静态源类型并集（oauth 域注册表 +
// 消息域注册表 + 虚拟 Union meta + 服务型 captcha/storage meta，
// provider.TypeMetas()）按 type 稳定排序。无入库读取，纯注册表快照；虚拟与
// 服务型类型因此出现在管理后台新建下拉里，但不会被 NewAdapter / NewSender
// 解析（captcha / storage 走各自的运行时解析链，不经 provider 工厂注册表）。
func (s *Service) ProviderTypes() []ProviderTypeInfo {
	metas := provider.TypeMetas()
	out := make([]ProviderTypeInfo, 0, len(metas))
	for _, meta := range metas {
		out = append(out, ProviderTypeInfo{
			Type: meta.Type, Category: meta.Category, DisplayName: meta.DisplayName,
		})
	}
	return out
}

// TestProvider（§5.2，OUTCOME ⑦）：{providerKey, target} 发送测试。
// FindByKey 现构 provider.Provider{Key, Type, Row, Ext}——**不经 Loader**
// （本地 LRU TTL 60s 会让「改完配置点测试」打到旧值，§15.3 加载链）→
// ResolveOutbound 解析出站代理引用（与 Loader 装配期同一语义，§15.4）→
// NewSender(p, category) → **同步** Send（管理员即时反馈，不走 asyncqueue，
// §15.2 的异步化仅约束验证码链路）。非 sms/email 类别 / 引用不可解析
// （fail-closed 不降级直连）/ Ext 配置缺失（NewSender
// ErrChannelNotConfigured）→ invalid_request；厂商 Send 失败原样上抛
// （链路故障，错误包装拦截器按 internal 消毒）。tpl/params 口径见
// testProviderTpl 常量注释（docs 未细化，待定）。
func (s *Service) TestProvider(ctx context.Context, providerKey, target string) error {
	if providerKey == "" || target == "" {
		return ErrInvalidRequest
	}
	row, err := s.store.FindByKey(ctx, providerKey)
	if err != nil {
		return err
	}
	if row.Category != provider.CategorySMS && row.Category != provider.CategoryEmail {
		return ErrInvalidRequest
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return fmt.Errorf("admin service: parse ext %q: %w", providerKey, err)
	}
	pool, err := provider.ResolveOutbound(ctx, s.pools, s.store, row, ext)
	if err != nil {
		// 引用键不可解析（缺失 / 未启用 / 类别不符 / 组合非法）= 配置状态类，
		// 与 NewSender 失败同映射 invalid_request（错误串只含引用键，§12.1）。
		return ErrInvalidRequest
	}
	p := &provider.Provider{Key: row.ProviderKey, Type: row.Type, Row: row, Ext: ext, Outbound: pool}
	sender, err := provider.NewSender(p, row.Category)
	if err != nil {
		// Ext 缺必填项（厂商构造失败）：配置状态属校验类，docs 未细化该
		// 错误形态，按 invalid_request 给管理员字段级反馈，待定。
		return ErrInvalidRequest
	}
	return sender.Send(ctx, target, testProviderTpl, map[string]string{"code": testProviderCode})
}

// schemaMeta 提交体键集的 schema 元信息（完整字段声明投影：category 由 type
// 决定只读，Schema 是含表列与 Ext 的全量字段清单——白名单、列键、Ext 键、
// required 四处均从这一份声明派生，§4.4）。
type schemaMeta struct {
	Type     string
	Category string
	Schema   []provider.FieldMeta
}

// lookupSchema 从提交体取 type 并查静态源 meta（统一经 provider.LookupTypeMeta，
// 与 handler.lookupProviderType 同源：oauth 域 → 消息域 → 虚拟 / 服务型静态表，
// handler 包私有函数不导出，本层直用导出查询，行为一致）。
func lookupSchema(fields map[string]*structpb.Value) (string, schemaMeta, bool) {
	v, ok := fields["type"]
	if !ok {
		return "", schemaMeta{}, false
	}
	providerType, err := structpbString(v)
	if err != nil || providerType == "" {
		return "", schemaMeta{}, false
	}
	meta, ok := lookupSchemaByType(providerType)
	if !ok {
		return "", schemaMeta{}, false
	}
	return providerType, meta, true
}

// lookupSchemaByType 按 type 查静态源统一 meta（oauth / 消息 / 虚拟 / 服务型，
// provider.LookupTypeMeta），取类别与完整 Schema 声明（Schema 为 func 字段，
// 调用得到全量清单；nil 视为空切片避免 panic）。
func lookupSchemaByType(providerType string) (schemaMeta, bool) {
	meta, ok := provider.LookupTypeMeta(providerType)
	if !ok {
		return schemaMeta{}, false
	}
	var schema []provider.FieldMeta
	if meta.Schema != nil {
		schema = meta.Schema()
	}
	return schemaMeta{Type: meta.Type, Category: meta.Category, Schema: schema}, true
}

// validateSchemaKeys 未知键拒绝：提交体键集 ⊆ {type, category, provider_key} ∪
// Schema 全集（所有 f.Key，不再按 Storage 区分列/Ext——分流由 ApplyProviderColumns
// / MergeProviderExt 各自完成，§4.4）。key 恒等于 provider 表列名或 provider.Ext
// 字段名，表单外的键一律 invalid_request（§5.3）；union / local / proxy 的 Schema
// 未声明登录开关 / 引用键等键即自动拒绝。type / provider_key 的「创建后不可改」
// 逐键同值校验保留在 CreateProvider / UpdateProvider，不走白名单。Create 的
// category 一致性校验在此（类型 meta 决定、只读）。
func validateSchemaKeys(fields map[string]*structpb.Value, meta schemaMeta) error {
	valid := map[string]bool{"type": true, "category": true, "provider_key": true}
	for _, f := range meta.Schema {
		valid[f.Key] = true
	}
	for k := range fields {
		if !valid[k] {
			return ErrInvalidRequest
		}
	}
	if v, ok := fields["category"]; ok {
		if c, err := structpbString(v); err != nil || c != meta.Category {
			return ErrInvalidRequest // 由 meta 按 type 决定，只读（§5.3）
		}
	}
	return nil
}

// requireProviderKey 提取并校验 provider_key（定位 / 唯一标识，§12.1
// 字符集 [a-z0-9_]）。
func requireProviderKey(fields map[string]*structpb.Value) (string, error) {
	v, ok := fields["provider_key"]
	if !ok {
		return "", ErrInvalidRequest
	}
	key, err := structpbString(v)
	if err != nil || !providerKeyPattern.MatchString(key) {
		return "", ErrInvalidRequest
	}
	return key, nil
}

// structFieldString 取 string 键值（未提交 / 类型不符返回空串）。
func structFieldString(fields map[string]*structpb.Value, key string) (string, error) {
	v, ok := fields[key]
	if !ok {
		return "", nil
	}
	return structpbString(v)
}

// structpbString structpb.Value → string（null 视为空串；非 string 报错）。
func structpbString(v *structpb.Value) (string, error) {
	if v == nil {
		return "", nil
	}
	switch kind := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return "", nil
	case *structpb.Value_StringValue:
		return kind.StringValue, nil
	default:
		return "", fmt.Errorf("admin service: want string value, got %T", kind)
	}
}

// explicitFalse 提交体中该键显式存在且为 false / null（类型不符值已在
// dto.ApplyProviderColumns 报错拦截，此处只看语义），供 Create 的 default
// tag 显式 false 修正。
func explicitFalse(fields map[string]*structpb.Value, key string) bool {
	v, ok := fields[key]
	if !ok || v == nil {
		return false
	}
	switch kind := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return true // null = 清零语义（禁用）
	case *structpb.Value_BoolValue:
		return !kind.BoolValue
	default:
		return false
	}
}

// metaFieldKeys Schema 中落 Ext 的字段名集合（Storage == StorageExt），作为
// MergeProviderExt 的 extKeys。所有 provider 的 Ext 字段均已在 Schema 声明中
// 标注 StorageExt（含 oauthcore 基线、wechat_mp_scan 扫码追加字段与 proxy 行
// 五字段）；union / storage-local 的 Schema 无 Ext 字段即自动排除（§5.3）。
func metaFieldKeys(meta schemaMeta) []string {
	keys := make([]string, 0, len(meta.Schema))
	for _, f := range meta.Schema {
		if f.Storage == provider.StorageExt {
			keys = append(keys, f.Key)
		}
	}
	return keys
}

// validateProxyRef 出站代理引用键的保存期校验（§5.3 代理提供商与出站代理引用
// 约定）：proxy_provider_key 仅在 Schema 声明了该键的类型可提交（键集白名单
// validateSchemaKeys 已拦未声明类型），提交时仅校字符集 ^[a-z0-9_]+$、不校
// 存在性（允许先引用后建行）；空（trim 后）= 直连，放行。键名引声明侧常量
// provider.ProxyRefKey，不另立字面量。
func validateProxyRef(fields map[string]*structpb.Value) error {
	v, ok := fields[provider.ProxyRefKey]
	if !ok {
		return nil
	}
	s, err := structpbString(v)
	if err != nil {
		return ErrInvalidRequest
	}
	if key := strings.TrimSpace(s); key != "" && !providerKeyPattern.MatchString(key) {
		return ErrInvalidRequest
	}
	return nil
}

// validateProxyConfig proxy 行五字段组合校验（§5.3：字段组合校验唯一写在
// proxyclient.NewConfig，保存期与运行期引用解析共用同一函数、无第二套规则）：
// 对 category=proxy 行在 MergeProviderExt 合并后的 Ext 上执行，scheme / host /
// user / password trim 后写回（不保留首尾空白，port 原值），PATCH 部分提交
// （只改端口、只改密码）合法、未提交字段保留原值；组合非法（scheme 封闭集外、
// host 缺失或含禁用字符、port 越界、password 无 user、拼串超限）→
// ErrInvalidRequest。非 proxy 行不做组合校验（smtp 等同名字段语义不同）。
// 错误与日志不含字段值（§12.1 凭据读写约定）。
func validateProxyConfig(row *model.Provider, ext *providerpb.Ext) error {
	if row == nil || row.Category != provider.CategoryProxy {
		return nil
	}
	cfg, err := proxyclient.NewConfig(
		strings.TrimSpace(ext.GetScheme()), strings.TrimSpace(ext.GetHost()),
		ext.GetPort(), strings.TrimSpace(ext.GetUser()), strings.TrimSpace(ext.GetPassword()),
	)
	if err != nil {
		return ErrInvalidRequest
	}
	ext.Scheme = cfg.Scheme
	ext.Host = cfg.Host
	ext.User = cfg.User
	ext.Password = cfg.Password
	return nil
}

// 拉码模式封闭集与 ticket 模板占位符（接口文档 §2.8 / §12.1 Ext 33/34：
// wire 取值逐字沿用；与扫码 service 侧实现各自持有同一契约字面量）。
const (
	qrcodeModeTicket     = "ticket"
	qrcodeModeBase64     = "base64"
	qrcodeModeURL        = "url"
	ticketTplPlaceholder = "{{TICKET}}"
)

// qrcodeModeDeclared Schema 是否声明 qrcode_mode（Ext 落点）：拉码模式组合
// 校验仅对声明该键的渠道生效（当前即 wechat_mp_scan，§5.3 type 行），其余
// 渠道的 Ext 无此字段、不参与校验——声明即校验范围，不按 type 字面量分流。
func qrcodeModeDeclared(meta schemaMeta) bool {
	for _, f := range meta.Schema {
		if f.Key == "qrcode_mode" && f.Storage == provider.StorageExt {
			return true
		}
	}
	return false
}

// validateQrcodeModes 拉码模式保存期组合校验（§5.3 type=wechat_mp_scan 行）：
// 对合并后的 Ext 统一执行（PATCH 未提交键保留原值，与 proxy 行组合校验同
// 形态——「url 模式切 ticket 未同步提交模板」这类部分提交在此拦下）。空
// 模式归一为 url：url 模式 storage_provider / storage_path 必填（保持存量
// 口径）；ticket 模式 qrcode_format 必填且须含 {{TICKET}} 占位符；base64
// 不强制存储配置；封闭集外取值拒绝。非法一律 ErrInvalidRequest，错误与
// 日志不含字段值（§12.1 读写约定）。
func validateQrcodeModes(meta schemaMeta, ext *providerpb.Ext) error {
	if !qrcodeModeDeclared(meta) {
		return nil
	}
	mode := ext.GetQrcodeMode()
	if mode == "" {
		mode = qrcodeModeURL
	}
	switch mode {
	case qrcodeModeTicket:
		if !strings.Contains(ext.GetQrcodeFormat(), ticketTplPlaceholder) {
			return ErrInvalidRequest
		}
	case qrcodeModeURL:
		if ext.GetStorageProvider() == "" || ext.GetStoragePath() == "" {
			return ErrInvalidRequest
		}
	case qrcodeModeBase64:
		// 不强制存储配置（§5.3：ticket / base64 模式不要求）
	default:
		return ErrInvalidRequest
	}
	return nil
}

// invalidate 写后缓存失效（§15.3 固定三步的唯一出口）；失败上抛
// （写已落库、失效失败时按 internal 告警，缓存有 TTL 600s 自然过期兜底，
// §5.1，不回滚已落库的写）。
func (s *Service) invalidate(ctx context.Context, providerKey string) error {
	if err := s.cache.Invalidate(ctx, providerKey); err != nil {
		return fmt.Errorf("admin service: invalidate provider %q: %w", providerKey, err)
	}
	return nil
}

// compile 时断言 *repo.ProviderRepo 满足 ProviderStore（新方法签名漂移在编译
// 期暴露）。
var _ ProviderStore = (*repo.ProviderRepo)(nil)

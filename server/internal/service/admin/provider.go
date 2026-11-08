// Package admin 实现 AdminService Provider 写族 7 方法（CreateProvider /
// UpdateProvider / DeleteProvider / SetProviderEnabled / SortProviders /
// GetProviderTypes / TestProvider，接口文档 §5.2 行 1169-1177）的业务层
// （docs/后端架构.md §3.9 行 390「Provider CRUD + 缓存失效」、§18
// 行 1792 分层 handler → service/admin/provider.go → repo → cache/provider）。
//
// 职责边界：schema 键集校验（表列 ∪ 注册表 meta 声明的 Ext 字段，§5.3 行
// 1183「提交体即 {"<key>": <value>}」）、provider_key 字符集与「创建后不可改」
// （§12.1 行 1719）、category 由注册表按 type 决定只读、meta required 字段齐
// （仅 Create；Update 按缺省键保留原值的 PATCH 口径不强制）、写后缓存失效
// （§15.3 行 1734 固定三步，经 cache.ProviderCache.Invalidate 唯一出口）。
// Connect 错误形态映射归 handler；本层返回可判别哨兵错误：
//   - ErrInvalidRequest 参数 / 校验类（handler 映射 §1.5 行 186 invalid_argument
//   - ErrorInfo domain=admin code=invalid_request，§1.6 封闭集合）；
//   - ErrDuplicateKey 唯一键 uk_provider_key 冲突（handler 映射 §1.5 行 190
//     already_exists，409）；
//   - gorm.ErrRecordNotFound 资源不存在（handler 映射 §1.5 行 189 not_found）；
//   - 其余错误原样上抛，由错误包装拦截器消毒（§1.5 行 192 internal）。
package admin

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"google.golang.org/protobuf/types/known/structpb"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/dto"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// 可判别哨兵错误（映射口径见包注释）。
var (
	// ErrInvalidRequest 参数 / 校验类失败（键集外未知键、字符集不合法、required
	// 缺失、类型不符、改 provider_key / type / category、非 sms/email 类别
	// TestProvider 等）。
	ErrInvalidRequest = errors.New("admin service: invalid request")
	// ErrDuplicateKey Create 命中 uk_provider_key（repo.ErrProviderDuplicate 的
	// service 层转译）。
	ErrDuplicateKey = errors.New("admin service: provider key already exists")
)

// providerKeyPattern provider_key 字符集（§5.3 行 1193、§12.1 行 1719：
// ^[a-z0-9_]+$，创建后不可改）。
var providerKeyPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// testProviderTpl / testProviderCode TestProvider 的测试模板口径（§15.2
// Sender.Send(to, tpl, params)）：tpl 键与模板内容 docs 未细化（§5.2 行 1177
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

// ProviderInvalidator 写后缓存失效窄接口（§15.3 行 1734 固定三步
// DEL→INCR→PUBLISH）：*cache.ProviderCache 天然满足，测试可传 fake 断言。
type ProviderInvalidator interface {
	Invalidate(ctx context.Context, providerKey string) error
}

// Service admin 域 Provider 写族业务层。
type Service struct {
	store ProviderStore
	cache ProviderInvalidator
}

// NewService 构造；store / invalidator 为装配依赖，任一为 nil 属程序错误
// （fail-fast，口径同 provider.NewLoader）。
func NewService(store ProviderStore, invalidator ProviderInvalidator) *Service {
	if store == nil {
		panic("admin service: NewService: nil ProviderStore")
	}
	if invalidator == nil {
		panic("admin service: NewService: nil ProviderInvalidator")
	}
	return &Service{store: store, cache: invalidator}
}

// CreateProvider（§5.2 行 1169，OUTCOME ①）：提交体为 §5.3 schema 的字段集合
// （{"<key>": <value>}）。校验：type 两域注册表命中、provider_key 字符集、
// display_name / meta required 字段齐、category 与注册表一致（只读）、未知键
// 拒绝。表列经 dto.ApplyProviderColumns 落行，Ext 经 dto.MergeProviderExt 构造
// 后 MarshalProviderExt（1 MiB 业务上限在唯一出口校验，§4.1 行 615）。uk 冲突
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
	providerKey, err := requireProviderKey(fields)
	if err != nil {
		return err
	}
	if name, _ := structFieldString(fields, "display_name"); name == "" {
		return ErrInvalidRequest // §5.3 行 1194 required
	}
	// Create 的 meta required 字段必须齐且非空（Ext 走 Proto 消息后由厂商
	// 构造兜底，此处先给管理员即时反馈）。
	for _, f := range meta.Fields {
		if f.Required {
			if v, ok := fields[f.Key]; !ok || v.GetStringValue() == "" {
				return ErrInvalidRequest
			}
		}
	}

	row := &model.Provider{ProviderKey: providerKey, Category: meta.Category, Type: providerType}
	if err := dto.ApplyProviderColumns(row, fields); err != nil {
		return ErrInvalidRequest
	}
	ext, err := dto.MergeProviderExt(&providerpb.Ext{}, fields, metaFieldKeys(meta.Fields))
	if err != nil {
		return ErrInvalidRequest // 类型不符
	}
	if row.Ext, err = repo.MarshalProviderExt(ext); err != nil {
		return ErrInvalidRequest // 超 1 MiB 业务上限（§4.1 行 615）
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
	// 行 607 注释「显式写 0 走列级 UPDATE」）：Create 已回填 ID / created_at
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

// UpdateProvider（§5.2 行 1171，OUTCOME ②）：提交体平铺含 provider_key（定位键，
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
		return err // gorm.ErrRecordNotFound 由 handler 映射 404
	}
	// 「创建后不可改」防御式校验（§5.2 行 1171）：定位键与行现键必须一致。
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

	if err := dto.ApplyProviderColumns(row, fields); err != nil {
		return ErrInvalidRequest
	}
	origExt, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return fmt.Errorf("admin service: parse ext %q: %w", providerKey, err)
	}
	ext, err := dto.MergeProviderExt(origExt, fields, metaFieldKeys(meta.Fields))
	if err != nil {
		return ErrInvalidRequest // 类型不符
	}
	if row.Ext, err = repo.MarshalProviderExt(ext); err != nil {
		return ErrInvalidRequest // 超 1 MiB 业务上限
	}

	if err := s.store.Update(ctx, row); err != nil {
		return err
	}
	return s.invalidate(ctx, providerKey)
}

// DeleteProvider（§5.2 行 1172，OUTCOME ③）：FindByKey → repo.Delete(id) →
// 失效；不存在 → gorm.ErrRecordNotFound（handler 404）。
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

// SetProviderEnabled（§5.2 行 1173，OUTCOME ④）：行内开关，列级最小 UPDATE
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

// SortItem SortProviders 的单个条目（§5.2 行 1174：{providerKey, sortOrder}）。
type SortItem struct {
	ProviderKey string
	SortOrder   int32
}

// SortProviders（§5.2 行 1174，OUTCOME ⑤）：批量列级 UPDATE（repo.
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

// ProviderTypeInfo GetProviderTypes 的下拉条目（§5.2 行 1175：来自类型 meta）。
type ProviderTypeInfo struct {
	Type        string
	Category    string
	DisplayName string
}

// ProviderTypes（§5.2 行 1175，OUTCOME ⑥）：三源类型并集（oauth 域注册表 +
// 消息域注册表 + 虚拟 Union meta，provider.TypeMetas()）按 type 稳定排序。
// 无入库读取，纯注册表快照；虚拟类型因此出现在管理后台新建下拉里，但不会
// 被 NewAdapter / NewSender 解析（无登录入口、无消息发送）。
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

// TestProvider（§5.2 行 1177，OUTCOME ⑦）：{providerKey, target} 发送测试。
// FindByKey 现构 provider.Provider{Key, Type, Row, Ext}——**不经 Loader**
// （本地 LRU TTL 60s 会让「改完配置点测试」打到旧值，§15.3 加载链）→
// NewSender(p, category) → **同步** Send（管理员即时反馈，不走 asyncqueue，
// §15.2 行 1726 的异步化仅约束验证码链路）。非 sms/email 类别 / Ext 配置
// 缺失（NewSender ErrChannelNotConfigured）→ invalid_request；厂商 Send 失败
// 原样上抛（链路故障，错误包装拦截器按 internal 消毒）。tpl/params 口径见
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
	p := &provider.Provider{Key: row.ProviderKey, Type: row.Type, Row: row, Ext: ext}
	sender, err := provider.NewSender(p, row.Category)
	if err != nil {
		// Ext 缺必填项（厂商构造失败）：配置状态属校验类，docs 未细化该
		// 错误形态，按 invalid_request 给管理员字段级反馈，待定。
		return ErrInvalidRequest
	}
	return sender.Send(ctx, target, testProviderTpl, map[string]string{"code": testProviderCode})
}

// schemaMeta 提交体键集的 schema 元信息（两域注册表同构投影：category 由
// type 决定只读，Fields 是 Ext 字段级声明，§15.3 行 1732）。
type schemaMeta struct {
	Category string
	Fields   []provider.FieldMeta
}

// lookupSchema 从提交体取 type 并查两域注册表（与 handler.lookupProviderType
// 同源：先 oauth 域 Lookup，未命中再消息域 LookupSenderMeta——同一注册表，
// handler 包私有函数不导出，本层直用两个导出查询，行为一致）。
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

// lookupSchemaByType 按 type 查三源统一 meta（oauth / 消息 / 虚拟，
// provider.LookupTypeMeta），schema 只取类别与 Ext 字段声明。
func lookupSchemaByType(providerType string) (schemaMeta, bool) {
	meta, ok := provider.LookupTypeMeta(providerType)
	if !ok {
		return schemaMeta{}, false
	}
	return schemaMeta{Category: meta.Category, Fields: meta.Fields}, true
}

// validateSchemaKeys 未知键拒绝：提交体键集 ⊆ {type, category, provider_key} ∪
// dto.AdminProviderColumnKeysFor(meta.Category) ∪ meta.Fields（§5.3 行 1183：
// key 恒等于 provider 表列名或 provider.Ext 字段名——表单外的键一律
// invalid_request，防止管理员提交表单不可见字段）。表列白名单按 category 裁
// 剪：union_provider / enable_signin / enable_signup / auto_bind /
// auto_bind_fields 仅 oauth 可提交（sms/email 的注册登录开关在 §5.6 设置项）。
// Create 的 category 一致性校验亦在此（类型 meta 决定、只读）。
func validateSchemaKeys(fields map[string]*structpb.Value, meta schemaMeta) error {
	valid := map[string]bool{"type": true, "category": true, "provider_key": true}
	for _, k := range dto.AdminProviderColumnKeysFor(meta.Category) {
		valid[k] = true
	}
	for _, f := range meta.Fields {
		valid[f.Key] = true
	}
	for k := range fields {
		if !valid[k] {
			return ErrInvalidRequest
		}
	}
	if v, ok := fields["category"]; ok {
		if c, err := structpbString(v); err != nil || c != meta.Category {
			return ErrInvalidRequest // 由注册表按 type 决定，只读（§5.3 行 1196）
		}
	}
	return nil
}

// requireProviderKey 提取并校验 provider_key（定位 / 唯一标识，§12.1 行 1719
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

// metaFieldKeys 注册表 meta.Fields 的 Ext 字段名集合。
func metaFieldKeys(fields []provider.FieldMeta) []string {
	keys := make([]string, len(fields))
	for i := range fields {
		keys[i] = fields[i].Key
	}
	return keys
}

// invalidate 写后缓存失效（§15.3 行 1734 固定三步的唯一出口）；失败上抛
// （写已落库、失效失败时按 internal 告警，缓存有 TTL 600s 自然过期兜底，
// §5.1 行 847，不回滚已落库的写）。
func (s *Service) invalidate(ctx context.Context, providerKey string) error {
	if err := s.cache.Invalidate(ctx, providerKey); err != nil {
		return fmt.Errorf("admin service: invalidate provider %q: %w", providerKey, err)
	}
	return nil
}

// compile 时断言 *repo.ProviderRepo 满足 ProviderStore（新方法签名漂移在编译
// 期暴露）。
var _ ProviderStore = (*repo.ProviderRepo)(nil)

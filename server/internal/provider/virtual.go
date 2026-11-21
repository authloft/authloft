// 虚拟 Provider 类型元数据（docs/后端架构.md §3.9）：
// category=union 的行只承载 Union ID 归并关系，不直连外部渠道、无登录入口、
// 不产生任何 HTTP 交互，因此**没有任何 factory 槽**——NewAdapter / NewSender
// 对它恒失败，Union 归并逻辑在 service/thirdparty.go。
//
// 本文件在 provider 包内 init() 把 unionid 以 meta-only 注册进统一注册表
// （§15.3：只进 LookupTypeMeta / TypeMetas 供管理后台类型查询，不进
// AdapterTypes 登录快照）。静态内置而非独立 union/ 包 + init() 自注册：
// 避免 bootstrap 与各测试二进制漏 blank import 导致类型「凭空消失」；也符合
// 「无 adapter 调用」的约束。
package provider

import "sort"

// Provider 类别常量（§5.3：category 由注册表按 type 决定、只读）。
// CategorySMS / CategoryEmail 在 sender.go、CategoryCaptcha / CategoryStorage /
// CategoryProxy 在 servicetype.go 声明，此处补齐 auth / union。
const (
	CategoryAuth  = "auth"
	CategoryUnion = "union"
)

// UnionProviderType 虚拟 Union ID Provider 的 type（admin 后台建键用；行数据
// 的 provider_key 由管理员自定，本常量只标识类型）。
const UnionProviderType = "unionid"

// TypeMeta 统一注册表的只读投影（GetProviderTypes / GetProviderSchema /
// Create / Update 键集校验共用），不含 factory 槽与交互通道。auth 域 Meta、
// 消息域 SenderMeta、服务型 / 虚拟 meta 经统一注册表读出时收口为同一形态，
// 调用方无需感知注册来源。
type TypeMeta struct {
	Type        string
	DisplayName string
	Category    string
	Schema      func() []FieldMeta // 完整字段声明（含表列与 Ext）；nil = 无声明
}

// typeMetaOf Meta → TypeMeta 投影（丢弃仅 auth 槽消费的 Channel 与 Fields
// 字段级声明；admin 只消费 Schema 完整声明）。
func typeMetaOf(m Meta) TypeMeta {
	return TypeMeta{Type: m.Type, DisplayName: m.DisplayName, Category: m.Category, Schema: m.Schema}
}

// init 虚拟 Union 类型 meta-only 注册进统一注册表（§15.3）：Schema 是 /schema
// 的唯一数据源（见接口文档 §5.3 union 裁剪口径——虚拟类型无 Ext 字段，仅表列
// 基线）。
func init() {
	if err := register(UnionProviderType, Meta{
		Type:        UnionProviderType,
		DisplayName: "Union ID 归并（虚拟）",
		Category:    CategoryUnion,
		Schema:      unionSchema,
	}); err != nil {
		panic(err)
	}
}

// unionSchema 虚拟 Union 类型的完整字段声明（接口文档 §5.3）：仅通用表列基线，
// 无任何 Ext 字段。union_provider / 登录建号开关 / is_enabled / 出站代理引用键
// 在 union 类别整体裁剪（虚拟类型无 adapter / sender、无启用行为、无网络外呼），
// 故不在此声明。每次调用返回新切片，调用方改动互不污染。
func unionSchema() []FieldMeta {
	return []FieldMeta{
		{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: StorageColumn},
		{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: StorageColumn},
		{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: StorageColumn},
		{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: StorageColumn},
		{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: StorageColumn},
		{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: StorageColumn},
	}
}

// LookupTypeMeta 按 type 查统一注册表（单一来源，§15.3：不再四源合并）。全部
// 注册来源（auth 渠道 / 消息厂商 / 服务型 / 虚拟）只在此命中；是否有运行时
// 产物由各槽取件函数（NewAdapter / NewSender）另行判定。
func LookupTypeMeta(providerType string) (TypeMeta, bool) {
	registry.mu.RLock()
	e, ok := registry.entries[providerType]
	registry.mu.RUnlock()
	if !ok {
		return TypeMeta{}, false
	}
	return typeMetaOf(e.meta), true
}

// TypeMetas 全部已注册类型的元信息快照，按 Type 稳定排序（admin
// GetProviderTypes 全类型下拉数据源；含 auth / 消息 / 服务型 / 虚拟，§15.3）。
func TypeMetas() []TypeMeta {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]TypeMeta, 0, len(registry.entries))
	for _, e := range registry.entries {
		out = append(out, typeMetaOf(e.meta))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

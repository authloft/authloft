// 虚拟 Provider 类型元数据（docs/后端架构.md §3.3、§3.9）：
// category=union 的行只承载 Union ID 归并关系，不直连外部渠道、无登录入口、
// 不产生任何 HTTP 交互，因此**没有 adapter / sender 工厂**。
//
// 两张带 factory 的注册表都容不下它：registry.go 的 Register 要求
// AuthAdapter 工厂，sender.go 的 registerSender 进一步把 category 限死在
// sms|email。若伪造一个「永不被调用」的适配器塞进 registry.entries，还会
// 污染 provider.Types()——account/thirdparty.go 的 metas() 以它为登录快照
// 数据源。故本文件以静态 meta 表单独登记，仅被管理后台的类型查询消费。
//
// 静态内置而非独立 union/ 包 + init() 自注册：避免 bootstrap 与各测试二进制
// 漏 blank import 导致类型「凭空消失」；也符合「无 adapter 调用」的约束。
package provider

import "sort"

// Provider 类别常量（§5.3：category 由注册表按 type 决定、只读）。
// CategorySMS / CategoryEmail 在 sender.go 声明，此处补齐 oauth / union。
const (
	CategoryOAuth = "oauth"
	CategoryUnion = "union"
)

// UnionProviderType 虚拟 Union ID Provider 的 type（admin 后台建键用；行数据
// 的 provider_key 由管理员自定，本常量只标识类型）。
const UnionProviderType = "unionid"

// TypeMeta 静态源统一的只读投影（GetProviderTypes / GetProviderSchema /
// Create / Update 键集校验共用），不含 factory。oauth 域 Meta、消息域
// SenderMeta、虚拟 meta、服务型 meta 经此收口为同一形态，调用方无需感知
// 注册表分域。
type TypeMeta struct {
	Type        string
	DisplayName string
	Category    string
	Fields      []FieldMeta
	Schema      func() []FieldMeta // 完整字段声明（含表列与 Ext）；nil = 未迁移
}

// virtualMetas 虚拟类型表（当前仅 Union ID 归并；Fields 为空 = 无 Ext 字段，
// 表单只有通用表列基线）。
var virtualMetas = map[string]TypeMeta{
	UnionProviderType: {
		Type:        UnionProviderType,
		DisplayName: "Union ID 归并（虚拟）",
		Category:    CategoryUnion,
	},
}

// LookupTypeMeta 按 type 查全部静态源：oauth 域注册表 → 消息域注册表 → 虚拟
// 表 → 服务型静态表（顺序与既有 lookupProviderType / lookupSchemaByType 一致，
// type 名天然不相交）。虚拟 / 服务型类型只在此命中，NewAdapter / NewSender
// 查不到它们。
func LookupTypeMeta(providerType string) (TypeMeta, bool) {
	if meta, ok := Lookup(providerType); ok {
		return TypeMeta{
			Type: meta.Type, DisplayName: meta.DisplayName,
			Category: meta.Category, Fields: meta.Fields, Schema: meta.Schema,
		}, true
	}
	if meta, ok := LookupSenderMeta(providerType); ok {
		return TypeMeta{
			Type: meta.Type, DisplayName: meta.DisplayName,
			Category: meta.Category, Fields: meta.Fields, Schema: meta.Schema,
		}, true
	}
	if meta, ok := virtualMetas[providerType]; ok {
		return meta, true
	}
	meta, ok := serviceMetas[providerType]
	return meta, ok
}

// TypeMetas 全部已注册类型的元信息快照，按 Type 稳定排序（admin
// GetProviderTypes 下拉数据源；合并 oauth / 消息 / 虚拟 / 服务型静态表）。
func TypeMetas() []TypeMeta {
	out := make([]TypeMeta, 0, len(Types())+len(SenderTypes())+len(virtualMetas)+len(serviceMetas))
	for _, t := range Types() {
		if meta, ok := Lookup(t); ok {
			out = append(out, TypeMeta{
				Type: meta.Type, DisplayName: meta.DisplayName,
				Category: meta.Category, Fields: meta.Fields, Schema: meta.Schema,
			})
		}
	}
	for _, meta := range SenderTypes() {
		out = append(out, TypeMeta{
			Type: meta.Type, DisplayName: meta.DisplayName,
			Category: meta.Category, Fields: meta.Fields, Schema: meta.Schema,
		})
	}
	for _, meta := range virtualMetas {
		out = append(out, meta)
	}
	for _, meta := range serviceMetas {
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

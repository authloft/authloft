// 字段声明的归属与行为枚举。字段自带这些信息后，dto / service 不再需要
// 按 category 判断某字段落表列还是 Ext、是否需要运行时注入 options。
package provider

// FieldStorage 字段落点：provider 表列或 provider.Ext。
type FieldStorage string

const (
	StorageColumn FieldStorage = "column" // 落 provider 表列
	StorageExt    FieldStorage = "ext"    // 落 provider.Ext
)

// FieldKind 字段读写行为，零值为普通可写字段。
type FieldKind string

const (
	FieldNormal         FieldKind = ""        // 普通可写字段（零值）
	FieldDynamicOptions FieldKind = "dynamic" // options 运行时按 DynamicKey 注入
)

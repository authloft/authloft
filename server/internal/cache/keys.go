// Redis 键空间构造函数（docs/后端架构.md §5.1 行 206：所有键的唯一出处）。
// 键名集中在本文件定义，业务代码禁止裸拼字符串。
package cache

// settingsChgKey 配置变更通知频道（§5 行 860）：后台写 settings 时
// PUBLISH，各实例订阅后重载内存快照（§15.3 秒级生效）。
const settingsChgKey = "al:settings:chg"

// SettingsChgKey 返回 settings 变更通知的 Pub/Sub 频道名。
// PUBLISH 侧（settings 写入路径）与 Subscribe 侧（watcher）共用本函数。
func SettingsChgKey() string { return settingsChgKey }

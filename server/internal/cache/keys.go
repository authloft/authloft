// Redis 键空间构造函数（docs/后端架构.md §5.1 行 206：所有键的唯一出处）。
// 键名集中在本文件定义，业务代码禁止裸拼字符串。
package cache

import (
	"strconv"
	"time"
)

// settingsChgKey 配置变更通知频道（§5 行 860）：后台写 settings 时
// PUBLISH，各实例订阅后重载内存快照（§15.3 秒级生效）。
const settingsChgKey = "al:settings:chg"

// SettingsChgKey 返回 settings 变更通知的 Pub/Sub 频道名。
// PUBLISH 侧（settings 写入路径）与 Subscribe 侧（watcher）共用本函数。
func SettingsChgKey() string { return settingsChgKey }

// epochKeyPrefix user.epoch 缓存键前缀（§5.1 行 863：al:pwdep:{uid}）。
const epochKeyPrefix = "al:pwdep:"

// EpochKey 返回 user.epoch 的 Redis 缓存键（§5.1 行 863，TTL 24h）：
// 改密 / 重置 / 管理员禁用递增；读取回源时 SET 新值（§11.1 步骤 3）。
// 递增写路径不在本次范围（归改密 / 重置 / 禁用链路）。
func EpochKey(uid int64) string {
	return epochKeyPrefix + strconv.FormatInt(uid, 10)
}

// rpcNonceKeyPrefix RPC nonce 去重键前缀（§5.1 行 861：al:rpc:nonce:{client_id}:{sha256(nonce)}）。
const rpcNonceKeyPrefix = "al:rpc:nonce:"

// RPCNonceKey 返回 RPC nonce 去重键（§5.1 行 861，String、TTL 30s、SET NX）。
// nonceHash 为 sha256(nonce) 的小写十六进制（哈希在 nonce.go 的 NonceStore 内完成，
// 本文件保持纯字符串拼接、不引 crypto 依赖）。
func RPCNonceKey(clientID, nonceHash string) string {
	return rpcNonceKeyPrefix + clientID + ":" + nonceHash
}

// codeKeyPrefix 验证码键前缀（§5.1 行 835：al:code:{target}:{purpose}）。
const codeKeyPrefix = "al:code:"

// CodeKey 返回验证码键（§5.1 行 835，String、TTL 300s、发送 1 次）。
// 值为 JSON {code,owner,tries,sent_at}；发码与校验共用本函数，
// 保证 target / purpose 一致（§10.1 行 1126）。
func CodeKey(target, purpose string) string {
	return codeKeyPrefix + target + ":" + purpose
}

// sendCooldownKeyPrefix 重发冷却键前缀（§5.1 行 836：al:rl:send:{target}）。
const sendCooldownKeyPrefix = "al:rl:send:"

// SendCooldownKey 返回重发冷却键（§5.1 行 836，String、TTL 60s、SET NX EX）。
func SendCooldownKey(target string) string {
	return sendCooldownKeyPrefix + target
}

// sendDayKeyPrefix 单目标日限额键前缀（§5.1 行 837：al:rl:sendday:{target}:{yyyymmdd}）。
const sendDayKeyPrefix = "al:rl:sendday:"

// SendDayKey 返回单目标日限额计数键（§5.1 行 837，String、当天 24:00 过期、
// INCR）。ymd 为服务器本地日期 yyyymmdd（见 dayStamp）。
func SendDayKey(target, ymd string) string {
	return sendDayKeyPrefix + target + ":" + ymd
}

// ipDayKeyPrefix 单 IP 日限额键前缀（§5.1 行 838：al:rl:ipday:{ip}:{yyyymmdd}）。
const ipDayKeyPrefix = "al:rl:ipday:"

// IPDayKey 返回单 IP 日限额计数键（§5.1 行 838，String、当天 24:00 过期、
// INCR）。
func IPDayKey(ip, ymd string) string {
	return ipDayKeyPrefix + ip + ":" + ymd
}

// dayStamp 返回服务器本地日期 yyyymmdd（§5.1 行 837-838 键名的日期段）。
func dayStamp(t time.Time) string {
	return t.Format("20060102")
}

-- complete 阶段原子覆盖写（接口文档 §2.7.4；docs/后端架构.md §3.10 行 420）。
-- 仅当键值仍为调用方此前读到的版本（ARGV[1]，"" 表示期望键不存在）才 SET，
-- 否则返回 0 由调用方重读重试。Lua 无法解密状态，故「是否 success」的判断在
-- Go 侧，键的替换原子性由本脚本保证。
-- KEYS[1] al:ticket:{id}
-- ARGV[1] 期望原值（"" = 期望键不存在）
-- ARGV[2] 新的加密整值
-- ARGV[3] TTL 秒
-- 返回：1 已写入；0 原值已变（CAS 冲突，未写入）

local cur = redis.call('GET', KEYS[1])
if cur then
  if cur ~= ARGV[1] then
    return 0
  end
else
  if ARGV[1] ~= '' then
    return 0
  end
end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
return 1

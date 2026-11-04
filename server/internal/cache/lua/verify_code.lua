-- 校验：Lua 原子 GETDEL（docs/后端架构.md §10.1 行 1112、1126）。
-- KEYS[1] al:code:{target}:{purpose}
-- ARGV[1] 待校验验证码
-- ARGV[2] 归属标识 owner（登录链路 tid / 账号域 uid，由调用方传值）
-- ARGV[3] 最大尝试次数（otp_max_attempts）
-- 返回：1 校验成功（码已消费）；0 错码但键保留（tries < 上限）；
--       2 错码且达到上限（键已作废）；-1 无码或值损坏（视为不可用）

local raw = redis.call('GET', KEYS[1])
if not raw then
  return -1
end

local decoded, stored = pcall(cjson.decode, raw)
if not decoded or type(stored) ~= 'table' then
  redis.call('DEL', KEYS[1])
  return -1
end

if stored.code == ARGV[1] and stored.owner == ARGV[2] then
  redis.call('DEL', KEYS[1])
  return 1
end

local maxAttempts = tonumber(ARGV[3])
local tries = (tonumber(stored.tries) or 0) + 1
if tries >= maxAttempts then
  redis.call('DEL', KEYS[1])
  return 2
end

stored.tries = tries
local pttl = redis.call('PTTL', KEYS[1])
if pttl <= 0 then
  -- 剩余寿命不可知（0 / -1 无 TTL / -2 已不存在）：不写永久键，直接作废。
  redis.call('DEL', KEYS[1])
  return -1
end
redis.call('SET', KEYS[1], cjson.encode(stored), 'PX', pttl)
return 0

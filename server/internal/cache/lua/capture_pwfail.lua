-- 密码失败计数：INCR 后仅在键无 TTL 时 EXPIRE，保证首次计数与过期设置
-- 原子完成（并发首错不会留下永久键）。docs/后端架构.md §5.1 行 839。
-- KEYS[1] al:pwf:{user_ref}:{yyyymmdd}
-- ARGV[1] 距服务器本地当日 24:00 的秒数
-- 返回 INCR 后的当前计数（TTL 已存在时不重置，避免并发不断续期）

local n = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n

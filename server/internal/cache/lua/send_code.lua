-- 发码：4 次写合并为 1 次 EVAL（docs/后端架构.md §10.1 行 1108-1115）。
-- KEYS[1] al:code:{target}:{purpose}
-- KEYS[2] al:rl:send:{target}
-- KEYS[3] al:rl:sendday:{target}:{yyyymmdd}
-- KEYS[4] al:rl:ipday:{ip}:{yyyymmdd}
-- ARGV[1] 验证码 JSON {code,owner,tries,sent_at}
-- ARGV[2] 验证码 TTL（秒，otp_ttl）
-- ARGV[3] 重发冷却（秒，otp_resend_interval）
-- ARGV[4] 单目标日限额（otp_daily_limit_target）
-- ARGV[5] 单 IP 日限额（otp_daily_limit_ip）
-- ARGV[6] 日计数键 TTL（秒，至服务器本地当天 24:00）
-- 返回：0 成功；1 冷却中；2 单目标日限额到达；3 单 IP 日限额到达
-- （三种拒绝必须可区分，不得吞成同一种结果）。

if redis.call('EXISTS', KEYS[2]) == 1 then
  return 1
end

local targetCount = tonumber(redis.call('GET', KEYS[3]) or '0')
if targetCount >= tonumber(ARGV[4]) then
  return 2
end

local ipCount = tonumber(redis.call('GET', KEYS[4]) or '0')
if ipCount >= tonumber(ARGV[5]) then
  return 3
end

redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
redis.call('SET', KEYS[2], '1', 'NX', 'EX', tonumber(ARGV[3]))

local n = redis.call('INCR', KEYS[3])
if n == 1 or redis.call('TTL', KEYS[3]) == -1 then
  redis.call('EXPIRE', KEYS[3], tonumber(ARGV[6]))
end

n = redis.call('INCR', KEYS[4])
if n == 1 or redis.call('TTL', KEYS[4]) == -1 then
  redis.call('EXPIRE', KEYS[4], tonumber(ARGV[6]))
end

return 0

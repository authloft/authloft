-- 自绘图形码校验：Lua 原子 GETDEL（docs/后端架构.md §9.2 行 1088）。
-- KEYS[1] al:cap:{id}
-- ARGV[1] 用户提交的 answer
-- 返回：1 正确且已消费；0 错误或缺失（错误同样消费，缺失无副作用）

local raw = redis.call('GET', KEYS[1])
if not raw then
  return 0
end
redis.call('DEL', KEYS[1])
if raw == ARGV[1] then
  return 1
end
return 0

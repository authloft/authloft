// rueidis.go 手写客户端适配层：rueidis（RESP3）客户端经本适配器实现 cache
// 包全部 Redis 窄接口，应答翻译为自有结果类型（Status/Bool/Int/String/Eval/
// Duration/Scan Result），键缺失统一映射为 Nil 哨兵——上层不再绑定任何具体
// Redis 客户端库类型。只覆盖项目实际使用的窄 API 面（docs/后端架构.md §3.10
// cache 段）：无 Pipeline、无事务、无集群。
package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/rueidis"
)

// Nil 键缺失哨兵：GET / GETDEL / Eval 等未命中时统一以该错误返回，对齐原
// go-redis 时代 redis.Nil 的判别口径（errors.Is 与 == 均成立）。
var Nil = errors.New("cache: redis nil reply")

// ---- 结果类型（窄接口返回值，与具体客户端库解耦；跨包测试 fake 经导出
// 构造器组装）----

// StatusResult 写命令（SET 等）应答。
type StatusResult struct{ err error }

// Err 返回应答错误（成功为 nil）。
func (r StatusResult) Err() error { return r.err }

// BoolResult SetNX / SIsMember 应答。
type BoolResult struct {
	val bool
	err error
}

// Result 返回布尔值与错误。
func (r BoolResult) Result() (bool, error) { return r.val, r.err }

// IntResult Del / Incr / Exists / SAdd / Publish 应答。
type IntResult struct {
	val int64
	err error
}

// Result 返回整数值与错误。
func (r IntResult) Result() (int64, error) { return r.val, r.err }

// Err 返回应答错误（成功为 nil）。
func (r IntResult) Err() error { return r.err }

// StringResult Get / GetDel 应答；键缺失时 err = Nil。
type StringResult struct {
	val string
	err error
}

// Result 返回字符串与错误。
func (r StringResult) Result() (string, error) { return r.val, r.err }

// Int64 按十进制整数解析应答值；键缺失返回 Nil，值非整数返回解析错误。
func (r StringResult) Int64() (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	return strconv.ParseInt(r.val, 10, 64)
}

// Bytes 返回应答值的字节切片。
func (r StringResult) Bytes() ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.val), nil
}

// Err 返回应答错误（成功为 nil）。
func (r StringResult) Err() error { return r.err }

// MGetResult MGET 应答：按键序逐项返回；单键缺失以 nil 元素表达（对齐
// Nil 哨兵口径），命令级错误整批返回。MGET 是全有或全无的单命令——不存在
// 「部分键失败」，但两层必须分开表达：把单键 Nil 误读为命令错误会多一次
// 无谓回源，把命令错误误读为单键缺失会在真故障时漏掉失效判定（§11.1）。
type MGetResult struct {
	vals []*string
	err  error
}

// Result 返回按键序的逐项取值与命令级错误：nil 元素 = 该键缺失（Nil）；
// err 非 nil 时 vals 无效（返回 nil 切片）。
func (r MGetResult) Result() ([]*string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.vals, nil
}

// DurationResult PTTL / TTL 应答；键缺失为 -2、无 TTL 为 -1（与 go-redis
// 时代一致，负值不换算单位）。
type DurationResult struct {
	val time.Duration
	err error
}

// Result 返回时长与错误。
func (r DurationResult) Result() (time.Duration, error) { return r.val, r.err }

// EvalResult EVAL 应答：脚本返回单整数时走 Int64，返回数组时走 Slice
// （数组元素为 int64 或 string，与 go-redis 的 Lua 应答解码口径一致）。
type EvalResult struct {
	val   int64
	slice []any
	isInt bool
	err   error
}

// Int64 返回脚本的单整数应答；数组应答返回错误。
func (r EvalResult) Int64() (int64, error) {
	if r.err != nil {
		return 0, r.err
	}
	if !r.isInt {
		return 0, errors.New("cache: eval reply is not an integer")
	}
	return r.val, nil
}

// Slice 返回脚本的数组应答。
func (r EvalResult) Slice() ([]any, error) { return r.slice, r.err }

// ScanResult SCAN 应答：本批键与下一游标（0 = 遍历结束）。
type ScanResult struct {
	keys   []string
	cursor uint64
	err    error
}

// Result 返回键列表与下一游标。
func (r ScanResult) Result() ([]string, uint64, error) { return r.keys, r.cursor, r.err }

// ---- 结果类型导出构造器（跨包 fake 组装用；生产代码经适配器获得结果）----

// NewStatusResult 构造写命令应答。
func NewStatusResult(err error) StatusResult { return StatusResult{err: err} }

// NewBoolResult 构造布尔应答。
func NewBoolResult(val bool, err error) BoolResult { return BoolResult{val: val, err: err} }

// NewIntResult 构造整数应答。
func NewIntResult(val int64, err error) IntResult { return IntResult{val: val, err: err} }

// NewStringResult 构造字符串应答（键缺失传 Nil）。
func NewStringResult(val string, err error) StringResult { return StringResult{val: val, err: err} }

// NewMGetResult 构造 MGET 应答（跨包 fake 组装用）：vals 按 keys 序逐项，
// 缺失键以 nil 元素占位；命令级错误传 err（此时 vals 无效）。
func NewMGetResult(vals []*string, err error) MGetResult { return MGetResult{vals: vals, err: err} }

// NewEvalResultInt 构造单整数 EVAL 应答。
func NewEvalResultInt(val int64, err error) EvalResult {
	return EvalResult{val: val, isInt: true, err: err}
}

// NewEvalResultSlice 构造数组 EVAL 应答。
func NewEvalResultSlice(slice []any, err error) EvalResult {
	return EvalResult{slice: slice, err: err}
}

// NewDurationResult 构造 PTTL / TTL 应答。
func NewDurationResult(val time.Duration, err error) DurationResult {
	return DurationResult{val: val, err: err}
}

// NewScanResult 构造 SCAN 应答。
func NewScanResult(keys []string, cursor uint64, err error) ScanResult {
	return ScanResult{keys: keys, cursor: cursor, err: err}
}

// ---- Pub/Sub 适配 ----

// pubSubChannelBuffer 订阅消息通道缓冲：与 rueidis 内部订阅通道同级，
// 满时丢弃（配置变更通知低频，投递不可达；满即消费方已严重迟滞）。
const pubSubChannelBuffer = 16

// subscribeRetryDelay 断连后重新订阅的退避：对齐 go-redis PubSub 断连
// 自动重连并恢复订阅的行为（rueidis Receive 断连即返回，重订阅由本层补齐）。
const subscribeRetryDelay = time.Second

// PubSubMessage Pub/Sub 投递消息。
type PubSubMessage struct {
	// Channel 消息所属频道。
	Channel string
	// Payload 消息体（字符串原样透传）。
	Payload string
}

// PubSub 订阅句柄：Channel 在 Stop 后关闭，消费循环自然退出；Done 在
// 底层接收循环完全退出后关闭。
type PubSub interface {
	// Channel 订阅消息流（订阅确认后才开始投递）。
	Channel() <-chan PubSubMessage
	// Done 订阅彻底终止后关闭。
	Done() <-chan struct{}
	// Stop 停止订阅并释放，幂等。
	Stop()
}

// ---- rueidis 客户端适配器 ----

// RedisClient rueidis 客户端适配器：实现本包全部窄接口（codeRedis /
// epochRedis / providerRedis 等），bootstrap 构造后注入各键空间封装。
type RedisClient struct {
	c rueidis.Client
}

// NewClientWithRueidis 包装既有 rueidis 客户端（仅测试 / 特殊装配场景：
// 生产入口为 NewClient，自带 PING fail-fast）。
func NewClientWithRueidis(c rueidis.Client) *RedisClient { return &RedisClient{c: c} }

// Ping 连通性检查（NewClient fail-fast 与 health 探活共用）。
func (c *RedisClient) Ping(ctx context.Context) error {
	return c.c.Do(ctx, c.c.B().Ping().Build()).Error()
}

// Close 释放连接池。
func (c *RedisClient) Close() error {
	c.c.Close()
	return nil
}

// nilify 把 rueidis 的键缺失哨兵翻译为本包 Nil，其余错误原样透传。
func nilify(err error) error {
	if errors.Is(err, rueidis.Nil) {
		return Nil
	}
	return err
}

// redisValue 值序列化：对齐 go-redis 的参数编码口径（string / []byte 原样，
// 整数十进制，其余走 fmt.Sprint）。项目窄 API 面内实际只传 string / []byte /
// int64。
func redisValue(v any) string {
	switch m := v.(type) {
	case string:
		return m
	case []byte:
		return string(m)
	case int64:
		return strconv.FormatInt(m, 10)
	default:
		return fmt.Sprint(v)
	}
}

// Get 读键。
func (c *RedisClient) Get(ctx context.Context, key string) StringResult {
	v, err := c.c.Do(ctx, c.c.B().Get().Key(key).Build()).ToString()
	return StringResult{val: v, err: nilify(err)}
}

// GetDel 原子读取并删除。
func (c *RedisClient) GetDel(ctx context.Context, key string) StringResult {
	v, err := c.c.Do(ctx, c.c.B().Getdel().Key(key).Build()).ToString()
	return StringResult{val: v, err: nilify(err)}
}

// MGet 一次读多键（MGET）：应答按键序逐项返回，缺失键的 null 应答映射为
// nil 元素，命令级错误整批返回（nilify 对齐 Nil 口径的只有命令级错误；
// null 应答不是错误，直接表达为缺失）。
func (c *RedisClient) MGet(ctx context.Context, keys ...string) MGetResult {
	if len(keys) == 0 {
		return MGetResult{}
	}
	res := c.c.Do(ctx, c.c.B().Mget().Key(keys...).Build())
	if err := res.Error(); err != nil {
		return MGetResult{err: nilify(err)}
	}
	arr, err := res.ToArray()
	if err != nil {
		return MGetResult{err: nilify(err)}
	}
	vals := make([]*string, len(arr))
	for i := range arr {
		if arr[i].IsNil() {
			continue
		}
		s, terr := arr[i].ToString()
		if terr != nil {
			return MGetResult{err: nilify(terr)}
		}
		vals[i] = &s
	}
	return MGetResult{vals: vals}
}

// Set 写键；expiration <= 0 不带过期。
func (c *RedisClient) Set(ctx context.Context, key string, value any, expiration time.Duration) StatusResult {
	val := redisValue(value)
	var res rueidis.RedisResult
	if expiration > 0 {
		res = c.c.Do(ctx, c.c.B().Set().Key(key).Value(val).Px(expiration).Build())
	} else {
		res = c.c.Do(ctx, c.c.B().Set().Key(key).Value(val).Build())
	}
	return StatusResult{err: nilify(res.Error())}
}

// SetNX 原子写键（键已存在则失败返回 false）；expiration <= 0 不带过期。
func (c *RedisClient) SetNX(ctx context.Context, key string, value any, expiration time.Duration) BoolResult {
	val := redisValue(value)
	var res rueidis.RedisResult
	if expiration > 0 {
		res = c.c.Do(ctx, c.c.B().Set().Key(key).Value(val).Nx().Px(expiration).Build())
	} else {
		res = c.c.Do(ctx, c.c.B().Set().Key(key).Value(val).Nx().Build())
	}
	ok, err := res.AsBool()
	if err != nil {
		// 键已存在：SET NX 应答为 null，对齐 go-redis「nil 即 false 且无错」。
		if errors.Is(err, rueidis.Nil) {
			return BoolResult{}
		}
		return BoolResult{err: nilify(err)}
	}
	return BoolResult{val: ok}
}

// Del 删除键。
func (c *RedisClient) Del(ctx context.Context, keys ...string) IntResult {
	v, err := c.c.Do(ctx, c.c.B().Del().Key(keys...).Build()).ToInt64()
	return IntResult{val: v, err: nilify(err)}
}

// Exists 统计键存在数。
func (c *RedisClient) Exists(ctx context.Context, keys ...string) IntResult {
	v, err := c.c.Do(ctx, c.c.B().Exists().Key(keys...).Build()).ToInt64()
	return IntResult{val: v, err: nilify(err)}
}

// Incr 原子递增。
func (c *RedisClient) Incr(ctx context.Context, key string) IntResult {
	v, err := c.c.Do(ctx, c.c.B().Incr().Key(key).Build()).ToInt64()
	return IntResult{val: v, err: nilify(err)}
}

// SAdd 集合添加成员。
func (c *RedisClient) SAdd(ctx context.Context, key string, members ...any) IntResult {
	ms := make([]string, len(members))
	for i, m := range members {
		ms[i] = redisValue(m)
	}
	v, err := c.c.Do(ctx, c.c.B().Sadd().Key(key).Member(ms...).Build()).ToInt64()
	return IntResult{val: v, err: nilify(err)}
}

// SIsMember 判定集合成员。
func (c *RedisClient) SIsMember(ctx context.Context, key string, member any) BoolResult {
	ok, err := c.c.Do(ctx, c.c.B().Sismember().Key(key).Member(redisValue(member)).Build()).AsBool()
	return BoolResult{val: ok, err: nilify(err)}
}

// Publish 发布消息，返回接收订阅方数量。
func (c *RedisClient) Publish(ctx context.Context, channel string, message any) IntResult {
	v, err := c.c.Do(ctx, c.c.B().Publish().Channel(channel).Message(redisValue(message)).Build()).ToInt64()
	return IntResult{val: v, err: nilify(err)}
}

// PTTL 毫秒级剩余寿命；键缺失 -2、无 TTL -1（负值不换算单位）。
func (c *RedisClient) PTTL(ctx context.Context, key string) DurationResult {
	n, err := c.c.Do(ctx, c.c.B().Pttl().Key(key).Build()).ToInt64()
	return DurationResult{val: ttlDuration(n, time.Millisecond), err: nilify(err)}
}

// TTL 秒级剩余寿命（测试探查用；生产 TTL 断言走 PTTL）。
func (c *RedisClient) TTL(ctx context.Context, key string) DurationResult {
	n, err := c.c.Do(ctx, c.c.B().Ttl().Key(key).Build()).ToInt64()
	return DurationResult{val: ttlDuration(n, time.Second), err: nilify(err)}
}

// ttlDuration 对齐 go-redis DurationCmd 换算口径：负值（-1 / -2 哨兵）原样
// 保留，正值按命令精度换算。
func ttlDuration(n int64, unit time.Duration) time.Duration {
	if n < 0 {
		return time.Duration(n)
	}
	return time.Duration(n) * unit
}

// Eval 执行 Lua 脚本；keys 为 KEYS，args 逐个编码为 ARGV。
func (c *RedisClient) Eval(ctx context.Context, script string, keys []string, args ...any) EvalResult {
	argv := make([]string, len(args))
	for i, a := range args {
		argv[i] = redisValue(a)
	}
	res := c.c.Do(ctx, c.c.B().Eval().Script(script).Numkeys(int64(len(keys))).Key(keys...).Arg(argv...).Build())
	if err := res.Error(); err != nil {
		return EvalResult{err: nilify(err)}
	}
	m, err := res.ToMessage()
	if err != nil {
		return EvalResult{err: nilify(err)}
	}
	if m.IsInt64() {
		v, _ := m.ToInt64()
		return EvalResult{val: v, isInt: true}
	}
	arr, err := m.ToArray()
	if err != nil {
		// 标量应答按 go-redis Slice 口径包装为单元素数组。
		if s, serr := m.ToString(); serr == nil {
			return EvalResult{slice: []any{s}}
		}
		return EvalResult{err: err}
	}
	out := make([]any, len(arr))
	for i, e := range arr {
		if e.IsInt64() {
			out[i], _ = e.ToInt64()
		} else {
			out[i], _ = e.ToString()
		}
	}
	return EvalResult{slice: out}
}

// Scan 游标遍历匹配 match 模式的键（match 为完整 glob 模式）。应答为
// [游标, 键数组] 嵌套结构（RESP2/RESP3 同构），经 rueidis AsScanEntry 解出。
func (c *RedisClient) Scan(ctx context.Context, cursor uint64, match string, count int64) ScanResult {
	entry, err := c.c.Do(ctx, c.c.B().Scan().Cursor(cursor).Match(match).Count(count).Build()).AsScanEntry()
	return ScanResult{keys: entry.Elements, cursor: entry.Cursor, err: nilify(err)}
}

// Subscribe 订阅频道：订阅确认后才返回（fail-fast），失败返回错误。
// 运行期断连按秒级退避重新订阅（对齐 go-redis PubSub 行为）；Stop 取消
// 后由 return hook 补发 UNSUBSCRIBE，不在共享连接上残留服务端订阅。
func (c *RedisClient) Subscribe(ctx context.Context, channel string) (PubSub, error) {
	runCtx, cancel := context.WithCancel(context.Background())
	ps := &rueidisPubSub{
		msgCh:     make(chan PubSubMessage, pubSubChannelBuffer),
		done:      make(chan struct{}),
		confirmed: make(chan struct{}),
		cancel:    cancel,
	}
	var once sync.Once
	runCtx = rueidis.WithOnSubscriptionHook(runCtx, func(s rueidis.PubSubSubscription) {
		if s.Kind == "subscribe" {
			once.Do(func() { close(ps.confirmed) })
		}
	})
	runCtx = rueidis.WithOnReceiveReturnHook(runCtx, func(err error, client rueidis.CommandClient) error {
		if errors.Is(err, context.Canceled) {
			// 收尾补发 UNSUBSCRIBE；失败不影响 Receive 的原始返回值。
			_ = client.Do(context.Background(), client.B().Unsubscribe().Channel(channel).Build()).Error()
		}
		return err
	})
	startErr := make(chan error, 1)
	go func() {
		// 收尾次序：先关消息通道（消费循环据此退出），再关 done。
		finish := func() { close(ps.msgCh); close(ps.done) }
		for {
			// 命令经 Do 后即被回收，每轮重订阅须重建。
			subCmd := c.c.B().Subscribe().Channel(channel).Build()
			err := c.c.Receive(runCtx, subCmd, func(m rueidis.PubSubMessage) {
				select {
				case ps.msgCh <- PubSubMessage{Channel: m.Channel, Payload: m.Message}:
				default:
					// 满即丢：不阻塞 pipeline（见 pubSubChannelBuffer 注释）。
				}
			})
			if err == nil || runCtx.Err() != nil || errors.Is(err, rueidis.ErrClosing) {
				select {
				case startErr <- err:
				default:
				}
				finish()
				return
			}
			// 断连：退避后重新订阅；首启失败（未确认即返回）经 startErr 上抛。
			select {
			case startErr <- err:
			default:
			}
			confirmedSent := false
			select {
			case <-ps.confirmed:
				confirmedSent = true
			default:
			}
			if !confirmedSent {
				finish()
				return
			}
			select {
			case <-time.After(subscribeRetryDelay):
			case <-runCtx.Done():
				finish()
				return
			}
		}
	}()
	select {
	case <-ps.confirmed:
		return ps, nil
	case err := <-startErr:
		cancel()
		return nil, err
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

// rueidisPubSub PubSub 的 rueidis 实现。
type rueidisPubSub struct {
	msgCh     chan PubSubMessage
	done      chan struct{}
	confirmed chan struct{}
	cancel    context.CancelFunc
	stop      sync.Once
}

// Channel 返回订阅消息流；Stop 后关闭。
func (p *rueidisPubSub) Channel() <-chan PubSubMessage { return p.msgCh }

// Done 订阅彻底终止后关闭。
func (p *rueidisPubSub) Done() <-chan struct{} { return p.done }

// Stop 停止订阅并释放，幂等。
func (p *rueidisPubSub) Stop() {
	p.stop.Do(func() { p.cancel() })
}

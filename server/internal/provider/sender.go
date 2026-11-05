// 消息 Sender 基建（docs/后端架构.md §15.2 行 1715-1727、§15.3 行 1729-1736、
// §3.9 行 417）：Sender 接口、消息域注册表、发送期生效实例解析、验证码异步
// 投递桥与队列执行器。厂商实现按 internal/provider/{sms,email}/<type>/ 分层，
// init() 自注册。
//
// 注册表取舍（§15.3 语义不变）：oauth 域 AuthAdapter 注册表（registry.go，
// 既有契约）的键空间与 Factory 签名保持冻结，消息域以**并列注册表**落地
// （RegisterSender / NewSender）。理由：Register(type, meta, factory) + init()
// 自注册、meta 驱动管理后台 /schema（接口文档 §5.3）的语义两域完全一致；
// 两域 type 名天然不相交（oauth 渠道名 vs 短信 / 邮件厂商名），不会撞键；
// 若后续要求单一键空间，只需迁移 entries，注册方零改动。
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"authloft/internal/asyncqueue"
)

// §15.3 消息域 category 取值（Ext 字段按 category 生效，接口文档 §5.3 行 1236）。
const (
	CategorySMS   = "sms"
	CategoryEmail = "email"
)

// ErrChannelNotConfigured 渠道不可用：settings 键空 / 实例缺失或未启用 /
// 类型不符 / 厂商 Ext 缺必填项。属配置状态而非瞬时故障——登录链将其映射为
// 接口文档 §1.6 行 259 的封闭集合取值 provider_disabled（提供方未启用），
// 不自造 status。
var ErrChannelNotConfigured = errors.New("provider: message channel not configured")

// Sender 消息投递器（§15.2 行 1718-1720 逐字）：to 为手机号 / 邮箱，tpl 为
// 模板键（模板内容存 metadata 或系统配置），params 为模板变量。
type Sender interface {
	Send(ctx context.Context, to string, tpl string, params map[string]string) error
}

// SenderFactory 由 Provider 实例构造厂商 Sender（§13.0 口径：装配期取 Ext，
// 运行期不回读配置）。
type SenderFactory func(p *Provider) (Sender, error)

// FieldMeta 管理后台 /schema 单字段渲染口径（接口文档 §5.3 行 1183-1185：
// key 恒等于 provider 表列名或 Ext 字段名；section 取值封闭五区块；type 取
// §1.11 渲染枚举的 text / secret / checkbox / number / select / json）。
type FieldMeta struct {
	Key      string
	Label    string
	Type     string
	Section  string // basic / credential / endpoint / display / policy
	Required bool
	Default  string
	Help     string
	Advanced bool
}

// SenderMeta 消息域渠道元信息（§15.3：meta 同时是管理后台 /schema 的数据源，
// Fields 声明该厂商消费的 Ext 字段，admin 表单按 schema 渲染，不硬编码）。
type SenderMeta struct {
	Type        string
	DisplayName string
	Category    string // CategorySMS / CategoryEmail
	Fields      []FieldMeta
}

var senderRegistry = struct {
	mu      sync.RWMutex
	entries map[string]*senderEntry
}{entries: make(map[string]*senderEntry)}

type senderEntry struct {
	meta    SenderMeta
	factory SenderFactory
}

// RegisterSender 注册消息厂商（在厂商包 init() 中调用，§15.3）。重复注册 /
// 空 type / 空 factory / category 非 sms|email 属程序错误，直接 panic
// （init 无法返回错误）。
func RegisterSender(senderType string, meta SenderMeta, factory SenderFactory) {
	if err := registerSender(senderType, meta, factory); err != nil {
		panic(err)
	}
}

func registerSender(senderType string, meta SenderMeta, factory SenderFactory) error {
	if senderType == "" {
		return fmt.Errorf("%w: empty sender type", ErrUnknownType)
	}
	if factory == nil {
		return fmt.Errorf("%w: sender %q", ErrNilFactory, senderType)
	}
	if meta.Category != CategorySMS && meta.Category != CategoryEmail {
		return fmt.Errorf("provider: register sender %q: category %q must be %q or %q",
			senderType, meta.Category, CategorySMS, CategoryEmail)
	}
	if meta.Type == "" {
		meta.Type = senderType
	}
	if meta.Type != senderType {
		return fmt.Errorf("provider: register sender %q: meta.Type %q mismatch", senderType, meta.Type)
	}

	senderRegistry.mu.Lock()
	defer senderRegistry.mu.Unlock()
	if _, ok := senderRegistry.entries[senderType]; ok {
		return fmt.Errorf("%w: sender type %q", ErrAlreadyRegistered, senderType)
	}
	senderRegistry.entries[senderType] = &senderEntry{meta: meta, factory: factory}
	return nil
}

// NewSender 按 Provider 实例的 type 构造指定渠道的消息 Sender（§15.3）。
// 实例类型未注册为消息厂商 / 渠道不符 / 厂商 Ext 校验失败均属配置不可用，
// 返回 ErrChannelNotConfigured 包装错误。
func NewSender(p *Provider, category string) (Sender, error) {
	if p == nil {
		return nil, ErrNilProvider
	}
	senderRegistry.mu.RLock()
	e, ok := senderRegistry.entries[p.Type]
	senderRegistry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: type %q not a %s sender", ErrChannelNotConfigured, p.Type, category)
	}
	if e.meta.Category != category {
		return nil, fmt.Errorf("%w: type %q is category %q, want %q", ErrChannelNotConfigured, p.Type, e.meta.Category, category)
	}
	s, err := e.factory(p)
	if err != nil {
		return nil, fmt.Errorf("%w: build %q sender: %w", ErrChannelNotConfigured, p.Type, err)
	}
	if s == nil {
		return nil, fmt.Errorf("%w: factory %q returned nil sender", ErrChannelNotConfigured, p.Type)
	}
	return s, nil
}

// LookupSenderMeta 返回消息厂商元信息（管理后台 /schema 卡的数据源）。
func LookupSenderMeta(senderType string) (SenderMeta, bool) {
	senderRegistry.mu.RLock()
	defer senderRegistry.mu.RUnlock()
	e, ok := senderRegistry.entries[senderType]
	if !ok {
		return SenderMeta{}, false
	}
	return e.meta, true
}

// SenderTypes 返回消息域全部已注册厂商的元信息快照，按 Type 稳定排序
//（admin GetProviderTypes 下拉数据源的两域之一，接口文档 §5.2 行 1175；
// 与 oauth 域 Types() 对称：排序保证确定性输出）。
func SenderTypes() []SenderMeta {
	senderRegistry.mu.RLock()
	defer senderRegistry.mu.RUnlock()
	out := make([]SenderMeta, 0, len(senderRegistry.entries))
	for _, e := range senderRegistry.entries {
		out = append(out, e.meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// SettingGetter settings 快照读取窄接口（*settings.Store 天然满足；本包不
// 依赖 settings，键名由装配方注入——接口文档 §5.6 行 1335-1336）。
type SettingGetter interface {
	GetString(key string) (string, bool)
}

// codeTpl 验证码链路统一模板键（§15.2 行 1725：模板内容存 metadata 或系统
// 配置）：厂商按该键取模板——aliyun_sms：Ext.template_code 或 Ext.metadata
// "template_code.otp"；smtp：Ext.metadata "subject.otp" / "body.otp"。
// 登录 / 注册 / 重置 / MFA 的验证码内容一致，共用一档模板。
const codeTpl = "otp"

// CodeBridge 验证码异步投递桥：结构化满足 factor/otp.Sender 的
// SendCode(ctx, target, code)（不 import factor/otp，依赖方向保持单向）。
// 发送期解析（§15.3 行 1735）：settings 键 → Loader 按实例 key 取 Provider →
// NewSender 按 Ext 构造厂商客户端；键空 / 实例缺失或未启用 / 类型不符同步
// 返回 ErrChannelNotConfigured，厂商调用则投递 asyncqueue 异步执行（§15.2
// 行 1726：不阻塞登录主链路；发送失败不回滚已生成的验证码，§8.2 行 1051）。
type CodeBridge struct {
	settings SettingGetter
	loader   *Loader
	queue    *asyncqueue.Queue
	key      string // settings 键：sms_provider_key / email_provider_key
	category string // CategorySMS / CategoryEmail
	seq      atomic.Uint64
}

// NewCodeBridge 构造投递桥；任一依赖缺失 fail-fast（§3.2 约定 4，装配方校验）。
func NewCodeBridge(settings SettingGetter, loader *Loader, queue *asyncqueue.Queue, settingsKey, category string) (*CodeBridge, error) {
	if settings == nil || loader == nil || queue == nil {
		return nil, fmt.Errorf("provider: code bridge %q: settings/loader/queue not wired", settingsKey)
	}
	if category != CategorySMS && category != CategoryEmail {
		return nil, fmt.Errorf("provider: code bridge %q: category %q", settingsKey, category)
	}
	return &CodeBridge{settings: settings, loader: loader, queue: queue, key: settingsKey, category: category}, nil
}

// SendCode 解析生效厂商并把投递任务入队；验证码在调用前已写入存储（§8.2
// 行 1051），本方法失败或队列满丢弃均不回滚。
func (b *CodeBridge) SendCode(ctx context.Context, target, code string) error {
	sender, err := b.resolve(ctx)
	if err != nil {
		return err
	}
	// 投递键全局唯一：asyncqueue 同 key 合并只保留最终值（§5.2 行 884），
	// 复用键会吞掉先前未投递的发送任务。
	key := fmt.Sprintf("send:%s:%d", b.category, b.seq.Add(1))
	if !b.queue.Push(asyncqueue.Task{
		Key: key,
		Value: SendJob{
			Sender: sender,
			To:     target,
			Tpl:    codeTpl,
			Params: map[string]string{"code": code},
		},
	}) {
		// 队列满 / 已关闭：丢弃并告警（§5.2 行 893 队列满可丢弃，绝不阻塞
		// 登录主链路）；验证码已生成，用户可在冷却后重发。
		slog.Warn("provider: otp send dropped, queue full or closed", "category", b.category)
	}
	return nil
}

// resolve 发送期解析生效实例（§15.3 行 1735）。键空 / 实例缺失 / 未启用 /
// 类型不符 → ErrChannelNotConfigured（配置状态，映射 provider_disabled）；
// 其余读取错误（Redis / DB 瞬时故障）原样上抛，由编排层按未知异常置 failed。
func (b *CodeBridge) resolve(ctx context.Context) (Sender, error) {
	providerKey, _ := b.settings.GetString(b.key)
	if providerKey == "" {
		return nil, fmt.Errorf("%w: settings %q empty", ErrChannelNotConfigured, b.key)
	}
	p, err := b.loader.Get(ctx, providerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: provider %q not found", ErrChannelNotConfigured, providerKey)
		}
		return nil, fmt.Errorf("provider: resolve %q: %w", providerKey, err)
	}
	if !p.Enabled() {
		return nil, fmt.Errorf("%w: provider %q disabled", ErrChannelNotConfigured, providerKey)
	}
	return NewSender(p, b.category)
}

// SendJob 一次异步投递任务（asyncqueue.Task.Value）。Sender 为发送期已按
// Ext 构造的厂商客户端（§13.0：运行期不回读配置）。
type SendJob struct {
	Sender Sender
	To     string
	Tpl    string
	Params map[string]string
}

// 发送重试参数：厂商调用失败最多 sendAttempts 次、间隔 sendBackoff（进程内
// 短重试；验证码有 TTL，跨进程持久化重试无意义，最终失败后用户重发即可）。
const (
	sendAttempts = 3
	sendBackoff  = 200 * time.Millisecond
)

// SendExecutor 消息发送执行器（§15.2 行 1726：内存队列 + 重试）：只消费
// SendJob 任务，event_log / last_login / sign_count 等其余任务原样忽略
// （bootstrap 合并执行器先例，§5.2 行 872）。最终失败仅告警——不回滚已生成
// 的验证码（§8.2 行 1051 / §3.9 行 417），用户可在冷却后重发。
type SendExecutor struct{}

func (SendExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	for _, task := range tasks {
		job, ok := task.Value.(SendJob)
		if !ok {
			continue
		}
		var err error
		for attempt := 1; attempt <= sendAttempts; attempt++ {
			err = job.Sender.Send(ctx, job.To, job.Tpl, job.Params)
			if err == nil || ctx.Err() != nil {
				break
			}
			if attempt < sendAttempts {
				time.Sleep(sendBackoff)
			}
		}
		if err != nil {
			// 不记录 To（手机号 / 邮箱属用户资料，避免 PII 进日志）。
			slog.Warn("provider: message send failed after retries", "tpl", job.Tpl, "error", err)
		}
	}
}

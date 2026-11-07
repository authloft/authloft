# CODE_GUIDE（编码规范）

> 本文回答「代码怎么写」。三份文档分工：《接口文档》= 契约是什么（唯一真相）；《前端架构》/《后端架构》= 系统长什么样（结构事实）；本文 = 依赖、编码、测试与工程纪律规范。
> 本文规则与契约冲突时以《接口文档》为准并停报；本文只单向引用契约与结构章，被引用的文档不回指本文。

## 1. 总则

- **docs 只保留当前口径**：禁止「不再提供 / 已删除 / 旧口径 / 取代早前 X」等历史沿革写法；修订直接改写，历史见 git log。
- 文档写作与代码同理：同一规则只在唯一落点写一遍；其他位置需要时用指引句，不复制。

## 2. 依赖管理

### 2.1 引入准则

- 新增第三方依赖不再一律上报：合理小依赖（通用 utils 类、与工程风格一致、无新运行时外部服务、传递依赖少）可自行决定；引入前评估体积 / 传递依赖 / 维护活跃度 / 可否 stdlib 替代。
- **仍须上报**：框架级 / 大体积；新运行时服务（消息队列 / 监控后端）；安全敏感（密码学 / 鉴权 / 证书）；与既有口径冲突；超单次改动范围。

### 2.2 升级纪律

- 因引入新依赖导致既有间接依赖被 MVS 抬升：只允许抬升到所需最低版本，不得顺带 `go get -u` 其他依赖，`go.mod` / `go.sum` 变动面最小（只增 / 只改必需的项）。
- 升级后必须跑全量回归（`go build ./...` / `go vet ./...` / `go test ./...`，需 DB 时用 ENV.md 测试实例）并把实际输出写进验收报告；失败优先判断锁旧版本或调整代码，**不许为迁就版本改业务语义**。
- 安全敏感基础库（如 `golang.org/x/crypto`）的被动抬升须留痕上报，不得自行扩大批准范围。

### 2.3 后端依赖白名单与选型理由

> （本小节主体自《后端架构》§1.5 迁入）

- `connectrpc.com/connect` 锁 **v1.21.1**（v2 才发布且 API 重构，不用）；生成链同构锁版本。

### 2.4 前端依赖白名单与硬口径

> （本小节主体自《前端架构》§1.6 迁入）

- **不引 zod**：API 响应类型全部来自 protoc-gen-es 生成产物；login 表单手写简单校验，admin 用 Semi UI 自带表单校验。
- 前端 lint 统一 **Rslint**（rstack 自带），**不引入 ESLint**。

### 2.5 专项零依赖口径

- metrics：简单做、精度不高、不得影响性能、**零第三方依赖**——热路径仅 `sync/atomic` 原子计数，`/metrics` 读取时格式化，近似快照可接受；**禁止引入 `prometheus/client_golang`**。

## 3. 后端编码规范

### 3.1 分层与依赖方向

- 依赖方向单向向下：`factor` 与 `provider` 不知道 HTTP 的存在；`service` 不依赖 Gin（handler 层把 `*gin.Context` 转成 `context.Context` + 输入结构后传入）。service 及其下层既不知道 JSON 也不知道 Protobuf。
- rpc 域空 / 异常 procedure 一律按读路径处理（安全默认：读接口仍有三个签名头 + SecretLookup + 五项签名，非无鉴权）；写接口判定见 §3.2 第 23 条。

### 3.2 编码约束清单（写进 lint / review checklist）

1. 键名只出自 `cache/keys.go`；SQL 只出自 `repo/`；Redis 访问只出自 `cache/`
2. 时间只用注入的 Clock，禁止直接 `time.Now()`（便于测跨天 / 过期）
3. 随机只用 `security/rand.go`，禁止 `math/rand`
4. 登录主链路零同步写库：除建会话与必要的 `GETDEL` 外，所有写入必须经 `asyncqueue`。Review 时用「该写入是否影响当次响应正确性」判定（《后端架构》§5.2 白名单）
5. 不得在 `factor` / `provider` 层引入 Gin 或 HTTP 概念
6. 前台响应必须经 `dto/view.go` 裁剪成公开视图消息后返回；Connect 域禁止绕过生成 handler 手写 HTTP 响应、REST 豁免端点（OIDC / gateway / 页面 / multipart）除外（《后端架构》§3.14）
7. 日志不得打印 login_token、session_token、验证码、密钥、完整手机号 / 邮箱（必要时掩码）
8. 新增渠道的 diff 不得出现在 `handler/`、`orchestrator/`、`dto/`（§3.3 验收标准）
9. Protobuf 结构变更必须保持向下兼容（《接口文档》§12.8），`ext` 反序列化失败要能回退；`.proto` 变更必须过 `buf breaking`
10. 会话续期按《后端架构》§11.5 每次请求重签
11. 业务结果的表达：登录流程域用响应顶层 `status`（HTTP 200 数据，《接口文档》§1.3）；其余域业务失败用 `ErrorInfo.code`（Connect 错误体 details，《接口文档》§1.5）——两处取值都必须落在《接口文档》§1.6 的封闭集合内；禁止新增该集合外的常量、禁止塞第二个分支字段；兜底文案走 `ErrorInfo.message` / 流程态 `error.message`
12. 管理员判定只有 `uid == 1` 一处（仅 `internal/connect` 的 admin interceptor），禁止在 service / handler 里重复判断
13. 验证码归属标识按场景固定：登录 / 注册 / 重置 / MFA 用 `tid`，账号域 bind 用 `uid`；禁止跨场景混用（《后端架构》§10.1）
14. 三方 state 前缀即场景：`l` = 登录、`b` = 绑定已有账号；两个入口各自只接受自己前缀的 state，绑定接口不得签发 `login_token` 或重建会话（《后端架构》§12.4、§12.6）
15. ticket 的 `scene` 即扫码场景：`login` / `bind` 各自只被对应的轮询接口接受；小程序端只写 ticket，绑定判定只能在持有会话的 PC 端完成（《后端架构》§13.2b）
16. 配置只有两个来源：**启动项读 `config`（YAML，只读一次）**、**可热更新项读 `settings`（DB + 缓存）**；禁止在业务代码里写字面量默认值，禁止在 `config` 与 `settings` 放同一语义（《后端架构》§3.2）
17. 静态资源前缀只来自 `settings.static_base`：`handler/page.go` 经运行期占位符 `{{AUTHLOFT_STATIC_BASE}}` 注入、`assets` 路由共用同值；前端壳层模板与模板同步脚本一律禁止写死 `/assets` 或任何域名——产物标签的 URL 前缀只能嵌 `{{AUTHLOFT_STATIC_BASE}}`（构建期 `tools.htmlPlugin.publicPath` 注入；《接口文档》§8 / 《后端架构》§3.13）
18. 新增数据表必须同时新增 `repo` 与 `migrations` 脚本（《后端架构》§3.10）；`settings` 的键名只能来自《接口文档》§5.6 的白名单
19. 接口报文结构只在 `.proto`（`proto/api/**`）：禁止手写镜像 struct、禁止在 handler 里拼匿名结构体做响应；Go 侧类型一律来自 `gen/go`
20. 接口报文（`proto/api/**`）整型字段一律 `int64`（《接口文档》§1.12）：禁止 `int32` / `uint32` / `fixed32`（存储模型 proto 豁免，见 §3.6）；JSON 中的数字必须由序列化层输出字符串，业务代码不得自己 `fmt.Sprintf` 拼数字
21. 编解码由 connect-go 框架单点处理：业务代码不得读 `Content-Type` 判编解码、不得为某种编码写分支、不得改写 protojson 序列化选项
22. 凭证字段只允许出现在 Admin 视图消息里（`api.Admin*`）；公开视图消息若出现凭证字段，视为设计错误而非实现错误
23. rpc 域写接口判定 = 方法名前缀 `Update` / `Delete` / `Set` / `Create` / `Revoke`（《接口文档》§7「命名决定校验」）：新增写接口若不属于上述前缀语义，必须显式申请扩展前缀集合（走契约变更评审），不得静默使用读接口命名绕过 nonce 去重

### 3.3 扩展开发（新增渠道 / 因子 / 接口 / 事件）

| 新增内容 | 改动 | 不改动 |
|---------|------|--------|
| 一个第三方渠道 | `internal/provider/oauth/<type>/` 新包（`init()` 自注册） | handler、service、前端均不改 |
| 一个短信 / 邮件 / 存储厂商 | 对应 category 目录下新包 | 同上 |
| 一个 captcha 厂商 | `internal/provider/captcha/<type>/` 新包 + 前端一个 adapter | 后端其余不改；自绘图形码仍必须带 `provider_key` |
| 一个认证因子 | `internal/factor/<name>/` 新包 + 一行注册 + 前端一个组件 | 引擎不改 |
| 一个 StepKind | `factor.go` 加常量 + 对应因子 `Steps()` | 引擎按 `Steps()` 通用处理 |
| 一个事件类型 | `eventlog/event.go` 加常量与 detail 构造 | 写入路径不改 |
| 一个接口 / 一个字段 | `proto/api/<域>/*.proto` 加消息或字段（或加 service 方法）→ `buf generate` → handler 装配 | `internal/connect`、中间件、前端 transport 均不改 |
| 改某个接口的响应形状 | 只改 `.proto` + `dto/view.go` | 不新增「编码分支」，JSON 与 Protobuf 同步生效 |

- 判定是否满足「可插拔」的验收标准：新增渠道的 diff 不应出现在 `handler/`、`service/orchestrator/`、`dto/` 中；新增接口的 diff 不应出现在 `internal/connect/`、`middleware/` 中。
- 新增三方渠道时，必须同步 `bootstrap` 注册表完整性门禁的渠道清单（`TestProviderRegistryComplete` 断言 ⊇《后端架构》§12.2 全量 type），防「漏 import → 生产静默 provider_disabled」。

### 3.4 依赖注入与可测试性

1. 所有跨边界依赖是接口：`Sender`、`Storage`、`AuthAdapter`、`CaptchaVerifier`、`Factor`、`Repo`、`Cache`
2. service 只依赖接口，构造方式为显式字段注入（`bootstrap.go` 装配）。禁止在业务函数内直接调全局单例
3. 时间、随机源可注入：`Clock`、`Random` 接口，测试可固定时间（用于 TOTP、TTL、日限额跨天）
4. 密钥可注入：`keystore` 从内存 map 构造，测试用固定 kid
5. Redis 抽象为 `cache` 包接口，测试用内存实现；Lua 脚本仍走同一接口，行为一致
6. 队列可同步化：`asyncqueue` 暴露 `FlushSync()` 与「直写模式」开关，测试关闭异步，断言落库结果

### 3.5 数据库与迁移

- **GORM 知悉**：`default:N` tag 的实际行为 = 零值被 tag 值**显式写入** INSERT 并回填 struct（非「省略列由 DB 填」）；`Create` 仍无法写 0 值，`Update` 单列不受影响。
- MySQL changed-rows 语义下 UPDATE 无变化返回 `rows=0`：需要区分「行不存在」时必须做存在性补查。
- epoch 类递增用单语句原子写法（`IF(epoch+1>30000,1,epoch+1)`），行锁串行化并发，不做应用层读-改-写（无 check-then-act 竞态）。
- 事务边界：跨聚合业务事务在 service 编排；聚合内多表原子写（如建号 user+user_credential）由 repo 以单事务方法完成（既有先例 `UserRepo.CreateWithCredential`）。
- 迁移命名：单文件 `NNNNNN_name.sql` + `-- +goose Up/Down` 注解分段（goose 按 NumericComponent 解析版本，成对 `.up.sql/.down.sql` 会报 duplicate version）。
- 迁移修正口径：迁移的消费者是活库而非 git 历史；无生产部署消费迁移时，首版迁移中的笔误**直接修正首版**，不追加修正迁移（避免污染从零安装路径）。
- repo 约定：meta 封装 nil 语义（`Marshal(nil)` → NULL 列；NULL / 空列读侧归一为空 meta 非 nil，免判空）；索引由迁移 DDL 维护，model 不声明 index tag；禁用 AutoMigrate。

### 3.6 proto 与生成链

- 存储模型 proto（`provider/ext.proto`、`credential/meta.proto`、`token/**`）：**裸包名**不带 `.v1`、不建 service；整型用 `int64`；可变 / 原样透传字段用 `google.protobuf.Struct`；字段编号按 JSON 出现顺序自 1 连续分配。
- `int32` 禁令仅作用于 `proto/api/**`，存储模型 proto 豁免。
- 生成链以 **buf 为唯一口径**（勿用 protoc 原生 CLI）；生成产物提交进仓库，改 proto 后必须重跑 `buf generate` 且工作区零 diff。

> （api proto 的命名与组织规范、结构归属判定口径自《接口文档》§12 / §12.9 迁入）

### 3.7 安全编码

- 日志不得打印 login_token、session_token、验证码、密钥、完整手机号 / 邮箱（必要时掩码）；handler 层不得把 token / 密码放进 panic message（panic 值与堆栈只进日志）。
- 签名、验证码、密钥比对一律 `subtle.ConstantTimeCompare` 恒时比较。
- requestid：`crypto/rand` 16B hex（32 字符）、不透传入站头、失败留空串。
- Origin / Referer 免检判据用 `URL.Path`；未来若引入通配路由必须改 `FullPath()`（防路径参数绕过判据）。
- WebAuthn 必检字段固定：challenge / rpId / origin / 签名 + signCount。

## 4. 前端编码规范

### 4.1 编码约束清单

> （待从《前端架构》§9 迁入）

### 4.2 样式方案

> （待从《前端架构》§1.7 迁入）

### 4.3 请求层（ahooks 口径）

> （待从《前端架构》§3.2 / §9 第 19 条迁入）

### 4.4 扩展开发（新增认证方式判定）

> （待从《前端架构》§7 / §1.2 迁入）

### 4.5 壳层模板与构建纪律

> （壳层注入机制与构建期 config 口径见《前端架构》§1.5；本小节只收操作纪律）

- **`rs fmt` 全员禁令**：不得对本仓全量跑 `rs fmt`（会重排 `web/src/gen/**` 生成物），只跑 staged / 目标目录。
- 前端改动验收可跑 `pnpm build`（产物污染问题已解决，2026-11-06 起解禁）；`rs fmt` 禁令不随之解除。

### 4.6 i18n 约定

- 字典分域：主字典（common 段，键集唯一源）+ 域模块 `zh/`、`en/` 各含 `{login,account,admin,setup}.ts`；en 侧域模块用 `: typeof zhXxx` 形态做类型约束（`import type` 导入的是值绑定，不能直接作类型注解）。
- 域模块必须是**纯字面量对象**，禁 `Record` 注解（spread 空对象对类型透明、`keyof` 保持字面量键联合；`Record` 会使映射类型退化为索引签名）。
- **模块级文案常量一律改渲染期求值**（函数化 / textKey 化）：ESM 求值序使静态表先于 `setLocale` 执行，模块级 `t()` 会冻结 locale；后续实现必查顶层模块级 `t()`。

### 4.7 临时口径

- `@ts-ignore`：在 tsconfig `moduleResolution: node` 期间允许使用；tsconfig 现代化后移除。

## 5. 测试规范

### 5.1 后端

**测试栈**

| 用途 | 选型 |
|------|------|
| 断言 | `testing` 标准库，统一 table-driven；**不引入 testify** |
| Mock | 优先手写 Fake（`test/fakes/`），仅在接口宽时用 `gomock` |
| Redis | **真连 Redis**（ENV.md test 实例），Lua 脚本走同一接口实测；**不引入 miniredis** |
| DB | 集成测试**真连 MariaDB**（ENV.md test 实例，避免方言差异）；不 mock SQL 层 |
| HTTP | `net/http/httptest` + 真实 Gin / Connect 路由（含中间件），不 mock 框架 |
| 外部服务 | `httptest` 起假第三方（OIDC discovery / token / userinfo / sitesVerify）；小程序用假微信接口 |
| 并发 | `go test -race`，配合 `-count=N` |

**DB 集成测试并发口径**：统一 `GET_LOCK(uc_test_db_slot)` 持锁贯穿 TestMain 串行化；DSN / Redis 凭据经 `UC_TEST_*` 环境变量注入不落盘；测后清理零残留；env 全量 `go test ./...` 免 `-p 1`。

**验收方法论**：涉错误映射链（哨兵 → service → handler 转译）的验收，至少一条用例须走**真依赖组装**——fake 注入哨兵会掩盖真链路转译断点。

**各层测法**

A. 纯单元（无 IO，占比最大）

| 对象 | 用例 |
|------|------|
| `security/token.go` | ① round-trip；② 篡改 ciphertext/nonce/prefix 必失败；③ 跨 purpose 不可解（login→session）；④ 不同 kid 不可解；⑤ 版本降级被拒；⑥ 过期令牌被拒；⑦ 空载荷 / 超长载荷 |
| `security/keystore.go` | kid 轮换期新旧密钥并存；未知 kid 报错 |
| `security/token.go`（`purpose=cookie` / `sync_payload`） | `al_login_state` 与 `SyncCookiePayload` 的 round-trip；篡改必失败；跨 purpose（cookie ↔ sync_payload ↔ login）不互解；`exp` 过期 / `remaining` 为空的边界 |
| `security/argon2.go` | 哈希可验证、不同盐不同结果；参数与 `config.argon2` 一致 |
| `security/policy.go` | 决策矩阵：长度边界、字符类 1–3、含用户名、弱口令；固定规则（>64 / 与用户名或邮箱相同 / 含空白）不可被 settings 绕过 |
| `security/rand.go` | 位数正确、字符集正确、不重复（大样本） |
| `cache/keys.go` | 每个键的格式与 TTL 常量与《后端架构》§5.1 一致（表驱动，逐键断言） |
| `otp/limit.go` | 冷却边界（59/60/61s）、日限额边界、跨天重置（注入 Clock） |
| `oidc/redirect.go` | 精确匹配、`*` 通配、子域名陷阱（必须整段匹配）、大小写、空白名单 |
| `oidc/claims.go` | 《后端架构》§14.4 映射逐字段；`email_verified` / `phone_verified` 取 DB 标志；`amr` 来自登录链路 |
| `oidc/pkce.go` | S256 校验正误两种 |
| `schema/schema.go` | 每种 type 产出的字段清单快照；每个字段必带 `section` 且取值落在五枚举内；`secret` 字段标记、默认值、`advanced` |
| `jsonata/` | `user_mapping` 与 `storage_path` 表达式渲染（含 `ticket_id`/`timestamp` 内置变量）；非法 / 不支持表达式归一为所在域既有错误码，断言不透出 gnata 原始错误；不支持清单内语法逐条断言按归一口径返回 |
| `storage/path.go` | path_prefix 拼接、非法字符、路径穿越（`../`）被拒 |
| `orchestrator/state.go` | 载荷 round-trip；`passed` 追加；`tp` 覆盖语义（仅最后一次三方身份） |
| `orchestrator/dispatch.go` | `Usage` 校验矩阵：主因子不能当二次用、反之亦然；未知 method；step 越界 |
| `repo/model` | 字段与《后端架构》§4 表一一对应（反射比对列名，防漂移） |
| `connect`（框架编解码集成） | 同一消息两种编码：JSON 输出为 lowerCamelCase（`loginToken`）、零值字段省略、整型为字符串（`"60"` 而非 `60`）；`application/json` 与 `application/proto` 两种 `Content-Type` 解出等价消息（`proto.Equal`）；未知字段 → `invalid_argument`；超长 body 被 `WithReadMaxBytes` 拒（`resource_exhausted`） |
| `connect/errors.go` | `ErrorInfo.code` 取值封闭（越界即 panic 或 500）；detail 可被客户端按生成类型解出；`request_id` 不在错误体（走 `X-Request-Id` 头） |
| `dto/view.go` | 公开视图消息**不含**任何凭证字段（断言生成消息的字段描述符中不存在 `client_secret` / `app_id` / `cert` 等）；Admin 视图含 |

B. Fake / Mock 层

| 对象 | 用例 |
|------|------|
| `provider/captcha/*` | 用假 sitesVerify 服务：成功、失败、超时、重复 token |
| `provider/oauth/*` | 用假 OIDC 服务跑通 discovery→exchange→userinfo；`oauth2` 兜底适配器用假三 URL；`user_mapping` 抽取正确 |
| `provider/storage/{s3,local}` | Put/Get/Delete/URL/PresignPut；`local` 配置 `direct` 时自动回退 `proxy` |
| `provider/sms/*` 与 `provider/email/*` | 参数渲染正确；发送失败不回滚验证码 |
| `factor/*` | 每个因子用 Fake repo+cache 跑：`Steps()` 序列与《接口文档》§1.10 一致；`Start`/`Verify` 的成功 / 失败 / 重试三态 |

C. cache 与 Lua（真连 Redis）

| 对象 | 用例 |
|------|------|
| `cache/code.go` 发码 Lua | ① 首次成功；② 60s 内二次发被拒；③ 日限额到达被拒；④ IP 限额到达被拒；⑤ TTL 正确；⑥ 多写合并后仅 1 次往返（断言命令数） |
| `cache/code.go` 校验 Lua | ① 正确码成功且键被删；② 错码 `tries+1` 且键保留（`tries < 5`）；③ 第 5 次错码后键被删（作废，与上限 5 一致）；④ 不同归属标识（`tid` / `uid`）的码不可用；⑤ 并发 100 次校验只有 1 次成功 |
| `cache/captcha.go` | GETDEL 一次性 |
| `cache/pwfail.go` | 计数递增、当日 24:00 过期、`pwban` 的 TTL 与 `retry_after` 计算；`status` 取 `locked` |
| `cache/session.go` / `epoch.go` | epoch 读取与回源；递增到 > 30000 时回绕为 1（跳过 0，《后端架构》§4.2）；`session.go` 本期无对应键空间（令牌自包含，逐出扩展点见《后端架构》§11.1） |
| `cache/provider.go` | 版本号 + pub/sub 失效 |

D. service / orchestrator（Fake 依赖 + httptest）

| 对象 | 用例 |
|------|------|
| `orchestrator/engine.go` | 《后端架构》§7.3 的逐步断言（此为核心用例）：① 目标不存在时返回 `status=user_not_found`（不发码、不签发 login_token）；② 主因子未通过直接打二次因子被拒；③ MFA 阶段手机号只能来自 uid 绑定资料；④ 验证码 `purpose` 与 `tid` 绑定；⑤ MFA 总时长超 10 分钟回到第一步 |
| `orchestrator/methods.go` | 快照生成：开关过滤、`flow=register/reset` 过滤、`flags` 与 settings 一致、排序分组、快照无凭证；快照结构即 `__AUTHLOFT_INIT__.methods` 的值 |
| `orchestrator/binding.go` | 《后端架构》§12.5：tp 覆盖、只有两个选项、`enable_signup=0` 时创建被拒、`set_password` 的 password 按 `tp` 判定、注册端点接受 `flow=login`、auto_bind 命中与未命中 |
| `service/contact.go` | ① bind 的码内 `owner` 是 `uid` 而非 `tid`；② `verify` 时 uid 不一致即 `invalid_code`；③ 换一个 target 取不到码；④ captcha 缺失被拦（《后端架构》§9.3） |
| `service/thirdparty.go`（`BindToCurrentUser`） | ① `b` 前缀 state 正确路径；② Cookie uid ≠ 会话 uid 被拒；③ open_id 已绑他人 → `target_taken`；④ 已绑本人幂等；⑤ 成功后未签发 login_token、未 Set-Cookie；⑥ 审计事件最终落库；⑦ qrcode 通道与 redirect 通道走同一函数（注入 ticket 身份 vs 现算） |
| `service/ticket.go`（绑定轮询） | ① `scene=bind` 的 ticket 不被登录轮询接受（反之亦然）；② 命中后 GETDEL 且用会话 uid 绑定；③ 未命中且未过期 → `pending`；④ 过期 → `expired`；⑤ 未带会话 → 401 |
| `orchestrator/terminal.go` | 建会话 1 次写；日志与 `last_login_at` 走队列不阻塞；OIDC 场景授权码生成与 `redirectTo` 拼接正确 |
| `session/verify.go` | 《后端架构》§11.1 四步：kid、exp、epoch 比对（缓存命中 / 未命中 / 回源）、失败清 Cookie |
| `session/renew.go` | 每次请求均重签、按来源返回 `Set-Cookie` / `X-Authloft-Token`；重签纯计算、无存储写入（断言零队列任务） |
| `service/password.go` | 改密后 epoch 递增、refresh token 批量吊销 |
| `service/ticket.go` | 长轮询超时（上限见《接口文档》§2.8）返回 `pending`；ticket 过期返回 `expired`；`GETDEL` 原子消费、用后即毁 |
| `service/qrcode.go` | `ticket_id` 长度上限见《后端架构》§11.6.4；码图走中转；`qrcode_auto_delete=1` 时投递删除任务（同模板重算 key） |
| `service/admin/provider.go` | 写后 `al:prov:ver` 自增且缓存被删；`provider_key` 唯一性与字符集校验 |
| `service/upload.go` | presign 的 MIME / 大小校验、key 由服务端生成（前端传路径被忽略）、commit 不回读 |

E. handler / 中间件（httptest + 真实路由）

| 对象 | 用例 |
|------|------|
| `middleware/origin.go` | 同源通过、跨站 403、无 Origin 时走 Referer 白名单 |
| Connect 框架（Content-Type） | `application/json` 通过、`application/proto` 通过、`text/plain` → 415；OIDC 与 multipart 端点不受 Connect 校验（REST 豁免） |
| `middleware/csp.go` | nonce 每请求不同；`CSPSupporter` 片段按指令名聚合去重后单条输出（非拼接追加，《后端架构》§3.3 / §9.4）；各指令取值与《接口文档》§8 统一口径逐项一致（含 `static_base` 为 CDN 时追加源、captcha provider 贡献源按当前生效项聚合；setup server 渲染的 `/setup` 壳同基线） |
| `connect`（rpc HMAC interceptor） | 写接口（`Update`/`Delete`/`Set`/`Create`/`Revoke` 开头）nonce 重放被拒；写 / 读接口签名错（含 nonce 项错）被拒；签名对通过；读接口同一 `X-Nonce-ID` 重复请求均通过（nonce 参与签名、不去重） |
| `middleware/`（基础层：requestid / logger / recover / metrics） | requestid：格式（16B hex / 32 字符）、不读入站头、所有响应回写 `X-Request-Id` 头、rand 失败留空串；logger：不读 body / query / header / cookie，path 取 `URL.Path` 不含 query，panic 值与堆栈只进日志；recover：panic → 500（Connect 域为 `internal` 错误体），日志含 request_id / method / path / panic / stack，已写与未写响应两分支均 `Abort()` 截断后续链；metrics：3 个原子计数含 panic 请求、`/metrics` 纯文本、近似快照 |
| `handler/page.go` | 注入块转义 `<>&` 与 `\u2028/\u2029`；`Cache-Control: no-store`；不出现任何密钥字段；`methods` 快照必注入、不含 `admin`、无凭证；占位符替换正确：三个运行期占位符（`{{AUTHLOFT_STATIC_BASE}}` / `{{AUTHLOFT_CSP_NONCE}}` / `{{AUTHLOFT_INIT_JSON}}`）均由后端替换，`{{AUTHLOFT_STATIC_BASE}}` 尾斜杠归一（相对 `/assets` 与 CDN 绝对地址两种取值），残留未知占位符按字面输出 |
| `handler/sso.go` | 流程信封字段齐全；`loginToken` 每次重签返回新值；失败态只由 `status` 表达 |
| 全局 | admin 域未携带有效会话返回 401（`unauthenticated`）；会话有效但 `uid != 1` 返回 404（`not_found`，掩护管理面存在，《接口文档》§1.5）；所有写请求带 Origin 校验；同一接口两种 `Content-Type` 的响应解出后 `proto.Equal` |
| `handler/account.go` | `AccountService/GetConfig` 的 `captcha` 不含任何凭证字段；`AccountService/ThirdpartyOauth` 未带会话 → 401；`X-Authloft-Token` Header 可替代 Cookie 完成鉴权 |

F. 异步队列

| 用例 |
|------|
| 攒批：200 条触发一次 flush；2s 时间窗触发一次 flush |
| 合并：同一 user_id 的 `last_login_at` 取最新；同一 credential 的 sign_count 取最大 |
| 队列满：非关键项被丢弃，`dropped` 计数 +1，且业务返回值不受影响 |
| 优雅关闭：Shutdown 后剩余任务被 flush；超时 10s 强制退出 |
| `-race` 下并发 Push/Flush 无数据竞争 |

G. 集成测试（真连 ENV.md test 实例）

| 用例 |
|------|
| 真实 MariaDB + Redis + 假第三方：跑通《后端架构》§7.3 / 《接口文档》§10.2 完整 8 步；断言 `event_log` 最终落库（含队列延迟写入）、`last_login_at` 更新 |
| 迁移（goose，《后端架构》§3.16）：空库一步 `migrate up` 到最新、表结构与《后端架构》§4 一致；已最新时重复执行零变更（秒过）；人为制造失败后按恢复流程（修复半成品 → 重跑重试）可续装 |
| 会话失效：改密后旧 session_token 立即不可用 |
| OIDC 全链路：authorize → login → code → token → userinfo → refresh → revoke |
| Provider 热更新：改配置后 2 秒内新请求生效（多实例用 pub/sub） |

**安全回归清单（每次改动登录链路都要跑）**

1. 越权：主因子未通过 → 任何二次因子接口被拒
2. 篡改：`login_token` 改一个字节即失效；跨 purpose 使用失效；过期失效
3. 重放：验证码 `GETDEL` 只能成功一次；RPC **写接口** nonce 30s 内重复被拒（读接口不去重，同一 nonce 重复请求放行）；授权码一次性
4. 目标固定：MFA / 重置下发不接受请求传参的 phone/email
5. 归属标识隔离：登录链路的码只认 `tid`、账号域 bind 的码只认 `uid`；跨场景互不可解，且 bind 的码换 uid 即失效
6. 绑定隔离：`b` 前缀 state 不会被登录 oauth 端点接受；Cookie uid 与会话 uid 不一致的绑定请求被拒
7. 凭证泄露：所有 sso / account 域响应（JSON **与 Protobuf 两条编码都要跑**）与 `methods` 注入快照经 `dto/view.go` 的公开视图，不含凭证字段
8. 注入安全：空壳 HTML 的注入块转义正确
9. 编码旁路：同一 Connect 接口分别用 `Content-Type: application/json` 与 `application/proto` 请求，断言解出的消息 `proto.Equal`，且二进制路径不存在「绕过视图裁剪」的第二条组装路径

**覆盖率与门禁**

- `internal/security`、`internal/cache`、`internal/otp`、`internal/orchestrator`、`internal/oidc`、`internal/connect`：行覆盖 ≥ 90%；全量 ≥ 70%。
- 现行 CI 门禁（已落地）：后端 `go build` / `go vet` / `go test` + 前端 `tsc` / `rs test` / `rs lint` / `pnpm build` + `buf generate` 零 diff + `buf breaking --against '.git#tag=pre-connect'`（Connect 改造基线 tag）。
- 完整 CI 门禁（`go test -race ./...`、`golangci-lint`、集成测试每日跑一次）：**暂缓**，暂不排期。
- 禁止为了覆盖率写无断言的测试。

**契约一致性（前后端）**

- **双格式 golden**：每个用例在 `test/fixtures/` 落两份同源文件——`<name>.json` 与 `<name>.bin`（`proto.Marshal`，`Deterministic: true`）。CI 断言：① 两文件解出的消息 `proto.Equal`；② `<name>.json` 里**不出现裸数字**（正则扫 `:\s*-?\d`，`true/false` 除外），保证《接口文档》§1.12 被真正执行。
- `dto` 层生成 golden JSON（含 `methods` 注入快照），与前端 `tests/fixtures/*.json` 同源比对：CI 中用一个脚本比对两者，不一致即失败。
- 前端响应类型直接来自 `protoc-gen-es` 生成的 TS 消息类型（《接口文档》§12.9）；golden JSON 与生成类型比对防「多一个 / 少一个字段」的漂移，不另建 zod 契约层。
- Go 与 TS 类型由同一批 `.proto` 生成（《接口文档》§11）；生成物提交进仓库，两端 `git diff --exit-code` 均须为空。

### 5.2 前端

> （待从《前端架构》§8 迁入）

- 渲染断言方式：项目唯一渲染断言机制为 `renderToStaticMarkup`（无 testing-library）；`semi-probe` 探针长期保留作为配置绊线（配置回退即红）。

## 6. 工程纪律

- **commit 一律显式路径 add**，不用 `git add -A` / `git add .`。
- 多会话共享仓库时，commit 前 `git status` 全量核对暂存区；发现混入其他会话的 hunk 立即 soft reset 重提（共享暂存区混杂风险已有实证）。
- commit 的 add 范围必须覆盖本次改动文件全集——i18n 字典等与 SCOPE 目录分离的文件最易漏（漏提交会使键集测试在下一轮变红）。

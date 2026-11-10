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

- `connectrpc.com/connect` 锁 **v1.21.1**（v2 才发布且 API 重构，不用）；生成链同构锁版本。
- **WebAuthn 服务端校验** `github.com/go-webauthn/webauthn`（白名单外依赖，经批准引入）。选型理由：Go 生态主流 WebAuthn 实现，覆盖 W3C WebAuthn L2 注册与断言校验（attestation、challenge、origin/rpId、credential 公钥），维护活跃。可替换性：仅 `internal/factor/webauthn` 适配层引用，service / factor 接口不暴露该库类型，替换实现只改适配层。版本策略：由实现时联网核实最新稳定版后 pin 进 `server/go.mod`。
- **微信小程序服务端 SDK** `github.com/medivhzhan/weapp/v3`（pin **v3.8.4**；module path 沿用旧名，仓库现名 `royalrick/weapp`；Apache-2.0）。选型理由：小程序专用、仅 2 个直接依赖（`fatih/color`、`mitchellh/mapstructure`）、覆盖 `Code2Session` 与 `GetwxacodeUnlimit`、与项目既有 `go-redis/v9` 零冲突。可替换性：唯一引用包为 `internal/provider/oauth/wechat_mp*`，service / orchestrator 不暴露其类型。风险：仓库维护停滞（最后 push 2025-07-04）；所依赖两个接口均为微信多年稳定老接口且已做包级隔离可替换。备选：`github.com/silenceper/wechat/v2`（维护活跃但全生态偏重）。
- **JSONata 求值** `github.com/recolabs/gnata`（pin **v0.6.2**；module path 按库 go.mod 声明为小写 `recolabs`）。口径：**JSONata 求值统一使用 gnata，不自行实现**——不自行编写表达式解析 / 求值器，不再评估其他库或做自研对照。可替换性：唯一依赖点为 `internal/jsonata` 封装层（单一内部入口），service / handler 不直接 import 该库；求值失败在封装层归一为所在域既有错误码（《接口文档》§5.3 表达式字段约定），不向 API 调用方透出库原始错误；gnata 不支持的语法在封装层如实记录不支持清单，不以自研补齐。版本策略：0.x 阶段库 API 可能调整，升级版本须重跑 `internal/jsonata` 测试基线（§5.1）后另行处理。
- 既有基础依赖（已落地登记）：`gopkg.in/yaml.v3`（config 薄层隔离，可换格式只改薄层）、`gorm.io/gorm` + `gorm.io/driver/mysql`（文档明定）、`github.com/redis/go-redis/v9`、`github.com/pressly/goose/v3` + `github.com/go-sql-driver/mysql`（迁移链）、`github.com/vmihailenco/msgpack/v5`（`event_log.detail` 唯一编码）、`github.com/golang-jwt/jwt/v5`（OIDC RS256）。版本以 `server/go.mod` 为准。

### 2.4 前端依赖白名单与硬口径

- **公共依赖（所有 entry 均可使用，含 login）**：`react`、`@bufbuild/protobuf`、`@connectrpc/connect`、`@connectrpc/connect-web`、`@simplewebauthn/browser`、`ahooks`（按 hook 粒度 tree-shaking 引入，login 端同样适用）、`@modern-js/runtime/router`（路由 API 官方导出子路径，底层 react-router v7 随框架锁定，**package.json 零新增依赖**；`BrowserRouter` / `HashRouter` 等一律经此导入，禁止直接 import `react-router`）。
- ahooks 已有的能力（useRequest / useDebounce / useLocalStorage 等）**不得自行重复封装**；自定义 hook 只用于 ahooks 未覆盖的业务逻辑（细则见 §4.1 第 19 条）。
- 除公共依赖外，**login 不可依赖其他第三方库**（首屏体积）；account / admin / setup 使用 Semi UI，可适当使用其他第三方库以减少重复开发。
- **Semi UI 包名（硬性口径）**：只允许 `@douyinfe/semi-ui`；`package.json` 中 semi 相关依赖**仅此一个**，禁止新旧两个 semi 包并存（并存 = 双份体积与样式冲突）。
- **Semi UI 导入方式（硬性口径）**：一律从大包入口导入（`import { Button } from '@douyinfe/semi-ui'`），**禁止任何子路径导入**（`@douyinfe/semi-ui/lib/es/...` 一律不许）。理由：Rsbuild 自动 tree shaking，大包导入不会把整库打进产物；子路径破坏导入一致性，包升级时易碎。**纯 `import type` 豁免（受控例外）**，须同时满足四条件：① 仅类型导入（纯 `import type`，编译期擦除，零运行时产物）；② 子路径在包 `exports` 白名单内（如 `./lib/es/table`）；③ 大包入口确未转出该类型（含无法经 `ComponentProps` 等价提取的泛型类型，如 `ColumnProps<T>`）；④ 使用处注释标记豁免依据。四条件缺一不可；包升级导致的类型路径破坏由 `tsc` 编译期兜底。
- **不引 zod**：API 响应类型全部来自 protoc-gen-es 生成产物；login 表单手写简单校验，admin 用 Semi UI 自带表单校验。
- 前端 lint 统一 **Rslint**（rstack 自带），**不引入 ESLint**。
- 样式零新增依赖：`less` / `less-loader` 系 Modern.js 构建链内置传递依赖（`@modern-js/app-tools → @modern-js/builder → @rsbuild/plugin-less`），`package.json` 不新增任何样式包；禁止引入 CSS-in-JS / Tailwind / UnoCSS（样式方案见 §4.2）。

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
7. 日志不得打印 login_token、session_token、验证码、密钥、完整手机号 / 邮箱（必要时掩码）；业务日志与链路 ID 的写法见 §3.8
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

补充：分页 sort 与 settings 值域的**交叉校验**（如排序列是否在当前筛选语义下合法、settings 键间联动约束）由前端 / 管理员自律，后端不强制——后端只做字符集防注入与非法值静默回落，不做跨字段组合校验。

### 3.3 扩展开发（新增渠道 / 因子 / 接口 / 事件）

| 新增内容                   | 改动                                                                                      | 不改动                                            |
| -------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 一个第三方渠道             | `internal/provider/oauth/<type>/` 新包（`init()` 自注册）                                 | handler、service、前端均不改                      |
| 一个短信 / 邮件 / 存储厂商 | 对应 category 目录下新包                                                                  | 同上                                              |
| 一个 captcha 厂商          | `internal/provider/captcha/<type>/` 新包 + 前端一个 adapter                               | 后端其余不改；自绘图形码仍必须带 `provider_key`   |
| 一个认证因子               | `internal/factor/<name>/` 新包 + 一行注册 + 前端一个组件                                  | 引擎不改                                          |
| 一个 StepKind              | `factor.go` 加常量 + 对应因子 `Steps()`                                                   | 引擎按 `Steps()` 通用处理                         |
| 一个事件类型               | `eventlog/event.go` 加常量与 detail 构造                                                  | 写入路径不改                                      |
| 一个接口 / 一个字段        | `proto/api/<域>/*.proto` 加消息或字段（或加 service 方法）→ `buf generate` → handler 装配 | `internal/connect`、中间件、前端 transport 均不改 |
| 改某个接口的响应形状       | 只改 `.proto` + `dto/view.go`                                                             | 不新增「编码分支」，JSON 与 Protobuf 同步生效     |

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

**api proto 命名与组织（《接口文档》§12.9 的编码侧约定）**

- 源文件在 `server/proto/api/`，按域分目录（`common/`、`sso/`、`account/`、`admin/`、`oidc/`、`gateway/`、`rpc/`）；**包名 `api.<域>.v1`**；**每域一个 service，名为 `<域>Service`**（`SsoService` / `AccountService` / `AdminService` / `SetupService`；**rpc 域例外**：同包 `api.rpc.v1` 内拆两个 service——`UserService` / `TokenService`）；方法名 PascalCase 动词（`LoginDefault` / `GetProfile` / `UpdateUserStatus`…）；请求 `XxxRequest`、响应 `XxxResponse`；OIDC / gateway 豁免域不建 service。
- 源 `.proto` 字段名一律 **snake_case**（线上 lowerCamelCase 由 protojson 映射，契约形态见《接口文档》§12.9）；编号从 1 起连续分配，遵守《接口文档》§12.8 向下兼容。
- **枚举承载策略**：跨版本可能新增的取值集（`status` / `kind` / `step` / `fields[].type`）用 `string` 承载；仅真正封闭且双端同版本的集合才用 `enum`（避免旧客户端遇未知枚举值直接解码失败）。
- 存储模型 proto 的组织豁免见本节上文（裸包名、不建 service、int32 禁令豁免）。
  **结构归属判定口径（新结构定义放哪）**
- 判定标准 = **前端是否按字段读写它**：前端要渲染 / 构造 / 校验字段的结构（`provider.Ext`、`credential.Meta`、各类 API 消息）定义在《接口文档》§12（唯一契约）；前端只当**不透明字符串**透传的载荷（`login_token` / `session_token` / `ticket`）、只在 Redis 流转的存储值（`TicketResult`）、只在服务端之间流转的载荷（`SyncCookiePayload`）定义在《后端架构》§11.6。两类都由 `server/proto/` 下同一批 `.proto` 生成，字节一致性不因定义文档不同而有差别。

### 3.7 安全编码

- 日志不得打印 login_token、session_token、验证码、密钥、完整手机号 / 邮箱（必要时掩码）；handler 层不得把 token / 密码放进 panic message（panic 值与堆栈只进日志）。
- 签名、验证码、密钥比对一律 `subtle.ConstantTimeCompare` 恒时比较。
- requestid：`crypto/rand` 16B hex（32 字符）、不透传入站头、失败留空串。
- Origin / Referer 免检判据用 `URL.Path`；未来若引入通配路由必须改 `FullPath()`（防路径参数绕过判据）。
- WebAuthn 必检字段固定：challenge / rpId / origin / 签名 + signCount。

### 3.8 日志与链路 ID

- **唯一落点**：日志库为标准库 `log/slog`（结构化、零第三方依赖）。全局 logger 只由 `bootstrap.run()` 经 `internal/logx.Setup(cfg.Log.Level, cfg.Log.Format)` 装配一次；`log.level`（debug|info|warn|error）与 `log.format`（json|text）属 YAML 启动项，启动期只读、不热更新（《后端架构》§3.2）。业务代码不得自行 `slog.SetDefault`、不得自建 logger、不得引入第三方日志库；setup 模式与配置加载失败路径走默认 info/json。
- **链路 ID 从哪来**：gin 域 `middleware.RequestID` 与 Connect 域 `middleware.HTTPRequestID` 生成 16B hex 后统一经 `logx.WithRequestID` 写进标准 `context.Context`；`logx` 的 Handler 包装在 `Handle` 时自动补 `request_id` 字段。`internal/logx` 不依赖 gin / net/http，service 不得 import `middleware` 取链路 ID，也不得生成、透传入站 `X-Request-Id` 或手写 `"request_id"` 字段。
- **业务层写法**（service / handler，请求链路内的日志）：

  ```go
  import "authloft/internal/logx"

  logx.Warn(ctx, "thirdparty: write ticket result failed",
      "ticket_id", id,
      "error", err,
  )
  ```

  `logx.Debug/Info/Warn/Error(ctx, msg, args...)` 等价于 `slog.XxxContext(ctx, ...)`；直接写 `slog.WarnContext(ctx, ...)` 同样自动带 `request_id`，但新代码统一用 `logx.*`。消息为「模块: 事件」，字段用 snake_case 的 key/value 成对传，禁止 `fmt.Sprintf` 拼整句、禁止 `log.Printf` / `fmt.Println`。

- **ctx 一路传**：handler 用 `c.Request.Context()`（gin 域）/ Connect 传入的 `ctx` 调下游，中途不得换成 `context.Background()`，否则日志丢失 `request_id`。`logx.*(ctx, …)` 在没有链路 ID 的 ctx 上仍正常输出，只是不带该字段；`logx.RequestID(ctx)` 供排障读取，未注入返回空串。
- **无请求上下文的场景**：异步队列 worker、启动装配、setup 模式、页面渲染等沿用 `slog.Warn/Info/Error/Debug` 包级函数即可，不伪造 `request_id`；访问日志（`middleware/logger.go`）与 panic 日志（`middleware/recover.go`）由中间件显式带字段，它们不带 ctx，与自动注入不冲突、不会重复。
- **级别**：`Debug` 细粒度排障（默认级别下不输出）、`Info` 启动与安装关键节点、`Warn` 可降级失败（回写失败、投递失败、降级拒绝）、`Error` 致命错误。
- **敏感信息**：见 §3.2 第 7 条与 §3.7；错误文本可能含 DSN 密码 / 密钥时先脱敏（`internal/setup` 的 `redact`），日志不打印 body / query / header / cookie。
- **测试**：用 `logx.NewHandler(&buf, level, format)` 捕获输出断言字段；改动全局 logger 的用例须 `t.Cleanup` 恢复（§5.1）。

## 4. 前端编码规范

### 4.1 编码约束清单（写进 lint / review checklist）

1. 禁止 `localStorage` / `sessionStorage` / `document.cookie` 的写入；豁免仅：`login/oidcContext.ts`（键 `al_oidc_ctx`，只存 OIDC 上下文）
2. 禁止在通用层出现任何具体 `method` 字符串（如 `'otp_sms'`），只能出现在 `factors/registry.ts`
3. 禁止在组件内硬编码渠道名、字段名、失败文案，接口走统一封装；一律按 `status` 查 i18n 或取后端下发（`error.message`）
4. `fields[]` 的校验规则以下发为准，前端只做体验性校验（后端是唯一权威）
5. 所有**发往本系统接口**的请求由 `http.ts` 的 transport / client 统一发出（multipart 上传走 `http.ts` 的 `postForm`），不允许组件内裸 `fetch`。唯一豁免是《前端架构》§3.2 `direct` 分支的直传 `PUT`（目标是对象存储的临时 URL，不带 Cookie 与本系统凭证，不经过本系统接口）
6. `login_token` 只经 `api.ts` 读写，业务组件不得直接触碰 `loginTokenStore`
7. 轮询必须可中断；倒计时必须基于时间戳
8. 新增能力时先走 §4.4 的判定表；若需要改 `LoginContainer` / `reducer` 才能接入，视为设计问题而非实现问题
9. 分支只认 `status` / `ErrorInfo.code`：取值必须落在《接口文档》§1.6 的封闭集合内；禁止在前端定义任何业务错误码常量或按错误码分支（Connect 标准码兜底文案除外）
10. 小程序 / 宿主能力不在本工程实现：`login/` 下不得出现 `wx.*`、宿主桥接或 `external` 步骤组件
11. captcha **一律弹窗，禁止在业务视图内联 widget**：调用方只把 domain 窗体实现（`login/components/Modal` 或 `shared/app-ui/Modal`）交给 `shared/captcha/useCaptchaGate`、把原请求交给 `run`、给出判读函数、把 `dialogProps` 铺给根级 `<CaptchaDialog />`；`captcha_required` / `captcha_invalid` 由弹窗吸收并换凭据重提，其余状态逃逸给既有状态机（编排不得下沉到 reducer）。配置只由调用方注入：`CaptchaWidget` 不发配置请求；首屏 login 传注入快照的 `methods.captcha`、account 传 `AccountService/GetConfig` 的 `captcha`，运行期以响应顶层的 `captcha` 覆盖（《接口文档》§2.5）——`captcha` 对象不得被缓存为模块级常量。凭据一次性：每轮询问重挂 widget 换新，禁止复用上一轮凭据；取消弹窗不得清任何流程态，`login_token` 仍只由 `login/api.ts` 托管（第 6 条）
12. 三方回调按 `state` 首字母分派，不在前端判业务：`l` 走登录接口、`b` 走绑定接口；`OAuthCallbackPage` 只转发，不解析、不落盘、不自行决定跳哪个业务页
13. entry 边界由 lint 固化（Rslint，Rstack 体系自带，规则配置接入时补齐）：`login/` 禁止 import `account/`、`admin/`、`shared/app-ui/`、`@douyinfe/semi-ui`；`shared/` 禁止 import 任何 entry；跨 entry 复用只经 `shared/api`、`shared/hooks`、`shared/utils`、`shared/components`、`shared/captcha`、`shared/urls`。**澄清**：本条禁的是 entry 之间互相 import；`shared/**` 是四端合法共用位，把重复实现收进 `shared/` 不违反本条。**setup 例外**：`setup/` 允许并应优先使用 Semi 组件默认样式（Steps / Form / RadioGroup / Upload / Banner / Spin / Modal），允许 import `@douyinfe/semi-ui` 与 `shared/app-ui/`；不自造页面外壳与装饰性样式，自定义样式仅限业务必需；login 维持「不使用 Semi」不变
14. 静态资源 URL 只由 `static_base`（注入变量）拼出：禁止写死 `/assets`、`/static` 或 CDN 域名；`__webpack_public_path__` 只在根组件模块作用域赋值一次（框架接管挂载，《前端架构》§1.4）
15. 报文类型只来自 `src/gen/proto`：禁止手写接口 interface、禁止在组件里 `as` 断言出字段；`src/gen` 产物禁止手改
16. transport 与 client 只在 `http.ts` 构造：禁止组件内 `JSON.parse` / `JSON.stringify` 业务报文、禁止手拼 `Blob` 发请求；编解码选项禁止改写（标准 protojson，《接口文档》§1.1）
17. 数字只经 `utils/int.ts` 转换：禁止 `Number(id)`、禁止对 `bigint` 做隐式字符串比较；提交给后端的整型由序列化层输出字符串，禁止手写 `String(n)` 拼 JSON
18. 对缺失字段一律按零值兜底（`?? 零值`）：标准 protojson 省略零值字段（《接口文档》§1.1），禁止假设响应字段恒存在
19. Hooks 优先用 `ahooks`：useRequest / useDebounce / useLocalStorage 等已有能力**禁止重复造轮子**；自定义 hook 只用于 ahooks 未覆盖的业务逻辑。**更新（2026-11-07 定稿，唯一口径见 `review/frontend-request-layer.md`）**：自研 `useRequest`（`requestReducer` / `createRaceGuard` / `reset`）退役删除，通用请求改由 ahooks `useRequest` 承担，不留「内部换 ahooks、对外 API 不变」的过渡壳；`status` 四态不自研，由 ahooks 返回的 `loading` / `error` / `data` 经 `deriveRequestStatus` 纯函数派生（§4.3）；接口错误统一进集中 `onError`（`requestOptions` 工厂分派：401 跳转 / 字段级行内 / 其余 Toast，§4.3），`runAsync` 仅限 §4.3 登记的三类正当场景。明示例外（ahooks 未覆盖的业务逻辑，保留手写）：`useLongPoll`（hold 式长轮询，服务端挂起即重连，非 ahooks `pollingInterval` 定间隔模型）、`useUpload`（XHR 进度 / proxy-direct 上传编排）、`pollRestart`（setup 重启轮询，可注入时钟）；login 域 33 词信封状态机流程（`LoginContainer` / `runFlowStep` 族）不用请求 hook 承载
20. 样式一律 CSS Modules + `*.module.less`（与组件同目录同名、类名 camelCase、禁止内联样式做布局、`:global()` 须注明理由）；全局 CSS 仅限 `shared/styles/`（见 §4.2）；禁止引入 CSS-in-JS / Tailwind 等任何样式依赖——**"不用 UI 库"不等于"不写样式"**，login 端同样必须落样式；setup 以 Semi 默认样式为主，仅业务必需处落样式（见第 13 条）
21. Semi UI 一律从 `@douyinfe/semi-ui` 大包入口导入（具名或默认导入），禁止任何子路径（`/lib/es/...` 等）；`package.json` 只允许这一个 semi 包，禁止新旧并存（硬性口径见本文 §2.4）；**纯 `import type` 豁免（受控例外）**：仅类型导入（编译期擦除）+ 子路径在包 `exports` 白名单 + 大包入口确未转出该类型 + 使用处注释标记，四条件齐才允许子路径（如 `DataTable.tsx` 的 `ColumnProps`，细则与查证见本文 §2.4）
22. 壳层模板 CSP 产物自查（口径随《前端架构》§1.5 同步）：壳层模板由框架构建产物原样复制而来，其中 `script`（外链 + 内联，含框架生成的内联 runtime / route manifest 脚本与 init script）、`<style>`、`<link rel="stylesheet">` 标签若存在必须全部携带 `{{AUTHLOFT_CSP_NONCE}}` 占位符——**漏挂任意一个即整页被 CSP 拦**；nonce 注入由构建期 config 保证（`security.nonce` 统一挂 script / style / preload，`html.tags` Handler 补 `link[rel=stylesheet]` 缺口，见《前端架构》§1.5），同步脚本**零改写**、仅承担对账校验 fail-fast 义务（模板内三类标签出现数 = nonce 占位符出现数，逐个相等，否则整次构建失败），禁止以 `'unsafe-inline'` 放宽；产物层面 `eval` / `new Function` 仍禁止。review 增查项：同步对账通过、产物内无裸奔（未挂 nonce）标签，nonce 由构建期 config 统一注入、业务代码不手写
23. **禁止在构建配置的 filename / output 钩子里去除文件名 hash**：产物文件名一律保留 contenthash，多 chunk 引用由同步脚本按构建产物动态生成、不硬编码文件名（见《前端架构》§1.5）；缓存失效由 contenthash 文件名 + 壳层 `no-store` 承担（《接口文档》§8）
24. 路由一律走 `@modern-js/runtime/router` 路由表：禁止手写 pathname 匹配与正则提取参数；参数经 `useParams`、query 经 `useSearchParams`；Nav 高亮由路由表派生，禁止第二份路径字面量
25. hash route entry（account / admin）的 path 与 query 一律在 hash 内（`/account#/security?bind=x`）；禁止 `/entry?query#/path` 反模式（query 在 hash 外会发往服务端且前端读不到）
26. `shared/` 禁止出现 Router 选型分支：`BrowserRouter` / `HashRouter` 的选择归各 entry 顶层，`shared/urls.ts` 只产 URL 字符串与解析工具
27. 路由改造前提：系统未上线，**不做任何历史兼容**——无旧链接重定向、无 pathname→hash 兼容分支、无双写

### 4.2 样式方案（CSS Modules + Less）

自定义样式统一用 module less（Modern.js 原生支持，`.module.less` 文件默认按 CSS Modules 处理，无需任何构建配置，loader 自定义需求才用 `tools.less`）。

- **一律 CSS Modules**：组件样式文件与组件**同目录同名**，命名 `Xxx.module.less`（如 `LoginContainer.tsx` ↔ `LoginContainer.module.less`）
- **零新增依赖**：`less` / `less-loader` 系构建链内置传递依赖（见 §2.4），项目不需要安装任何样式包；禁止引入 CSS-in-JS（styled-components 等）、Tailwind、UnoCSS
- **全局 CSS 唯一例外**：`shared/styles/`（`tokens.less` 设计令牌 + `reset.less` 基础重置）——只存变量与基础重置，**禁止组件选择器**；由每个 entry 的 `entry.tsx` 顶部 import 一次。共享变量引用：组件的 `*.module.less` 顶部 `@import (reference) '../../shared/styles/tokens.less';`（`reference` 不重复产出 CSS），随后使用 `@color-primary` 等 less 变量
- **类名 camelCase**：tsx 内以 `styles.pageTitle` 方式取用；`:global()` 仅限与 Semi UI 或第三方 DOM 结构对接处，须同行注明理由
- **禁止内联样式做布局**（tsx `style={{...}}`）；按运行期数据动态计算尺寸等少数场景允许，须注释说明
- **"不用 UI 库" ≠ "不写样式"**：login 端不引任何 UI 库，但其页面与组件必须落 `*.module.less`；account / admin / setup 的 Semi UI 自带组件样式，页面级布局与自定义样式仍按本节执行（setup 自定义样式仅限业务必需，见 §4.1 第 13 条）
- **涉 UI 改动的验收追加项**（不替代既有 `tsc / rs test / rs lint / pnpm build`）：须检查——① 页面 / 组件存在对应 `*.module.less` 且被 import；② `pnpm build` 产物 `dist/**` 出现 `.css` 文件

### 4.3 请求层（ahooks 口径）

> 头条规则见 §4.1 第 19 条（自研 `useRequest` 退役、通用请求由 ahooks 承担）；本小节为落地细则。

- **`useRequest` 用法**：首取用默认自动请求；手动场景 `manual: true` + `run`（错误进 `onError`）；`runAsync` 仅限三类正当场景——需 await 结果串行（如创建后跳转）、返回值参与后续计算、错误须由调用方降级（如验证码重置、行内置位）。禁止并发提交同一请求实例；提交中按 `loading` 禁用按钮；竞态丢弃由 ahooks 内置 latest-only 承担
- `deriveRequestStatus` / `requestOptions` 两件的逐文件约束（空态判定禁令、onError 分派细则）见《前端架构》§3.2 职责表，不在此重复

### 4.4 扩展开发（新增认证方式判定）

> 判定规则（键盘输入 / 浏览器原生 API / 等待外部事件 / 仅跳转，四条按序判断）见《前端架构》§1.2；本小节为判定后的改动清单（验证抽象边界是否守住）。

| 判定结果                 | 前端改动                                                                                        | 是否触碰通用层                  |
| ------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------- |
| 1. 键盘输入              | 新增 `factors/XxxForm.tsx` + `registry.ts` 一行                                                 | 否                              |
| 2. 浏览器 / 宿主原生 API | 新增 `factors/XxxButton.tsx` + `registry.ts` 一行；后端在 `methods` 下发 `capability` 与 `hint` | 否（`useCapability` 已通用）    |
| 3. 等待外部事件          | 新增面板 + 复用 `useLongPoll`                                                                   | 否                              |
| 4. 仅跳转                | 零改动（后端给 URL）                                                                            | 否                              |
| 新 captcha 厂商          | 新增 `shared/captcha/adapters/Xxx.tsx`                                                          | 否（login 与 account 同时生效） |
| 新第三方渠道             | 零改动（列表由注入快照下发；图标由管理员自行上传到任意位置后手填 `icon_url`）                   | 否                              |
| 新 Provider 字段         | 零改动（后端 meta 声明 `section` 与类型，`SchemaForm` 按 `section` 归入区块）                   | 否                              |
| 新 StepKind              | `steps/` 新增一个组件 + `StepDispatcher` 一行                                                   | 一行                            |

若某次改动需要修改 `LoginContainer.tsx` 或 `reducer.ts`，说明抽象边界已被突破，应回到《前端架构》§1.2 重新判定。

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

| 用途     | 选型                                                                                         |
| -------- | -------------------------------------------------------------------------------------------- |
| 断言     | `testing` 标准库，统一 table-driven；**不引入 testify**                                      |
| Mock     | 优先手写 Fake（`test/fakes/`），仅在接口宽时用 `gomock`                                      |
| Redis    | **真连 Redis**（ENV.md test 实例），Lua 脚本走同一接口实测；**不引入 miniredis**             |
| DB       | 集成测试**真连 MariaDB**（ENV.md test 实例，避免方言差异）；不 mock SQL 层                   |
| HTTP     | `net/http/httptest` + 真实 Gin / Connect 路由（含中间件），不 mock 框架                      |
| 外部服务 | `httptest` 起假第三方（OIDC discovery / token / userinfo / sitesVerify）；小程序用假微信接口 |
| 并发     | `go test -race`，配合 `-count=N`                                                             |

**DB 集成测试并发口径**：统一 `GET_LOCK(uc_test_db_slot)` 持锁贯穿 TestMain 串行化；DSN / Redis 凭据经 `UC_TEST_*` 环境变量注入不落盘；测后清理零残留；env 全量 `go test ./...` 免 `-p 1`。

**验收方法论**：涉错误映射链（哨兵 → service → handler 转译）的验收，至少一条用例须走**真依赖组装**——fake 注入哨兵会掩盖真链路转译断点。

**各层测法**

A. 纯单元（无 IO，占比最大）

| 对象                                                     | 用例                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security/token.go`                                      | ① round-trip；② 篡改 ciphertext/nonce/prefix 必失败；③ 跨 purpose 不可解（login→session）；④ 不同 kid 不可解；⑤ 版本降级被拒；⑥ 过期令牌被拒；⑦ 空载荷 / 超长载荷                                                                                                                                    |
| `security/keystore.go`                                   | kid 轮换期新旧密钥并存；未知 kid 报错                                                                                                                                                                                                                                                                |
| `security/token.go`（`purpose=cookie` / `sync_payload`） | `al_login_state` 与 `SyncCookiePayload` 的 round-trip；篡改必失败；跨 purpose（cookie ↔ sync_payload ↔ login）不互解；`exp` 过期 / `remaining` 为空的边界                                                                                                                                            |
| `security/argon2.go`                                     | 哈希可验证、不同盐不同结果；参数与 `config.argon2` 一致                                                                                                                                                                                                                                              |
| `security/policy.go`                                     | 决策矩阵：长度边界、字符类 1–3、含用户名、弱口令；固定规则（>64 / 与用户名或邮箱相同 / 含空白）不可被 settings 绕过                                                                                                                                                                                  |
| `security/rand.go`                                       | 位数正确、字符集正确、不重复（大样本）                                                                                                                                                                                                                                                               |
| `cache/keys.go`                                          | 每个键的格式与 TTL 常量与《后端架构》§5.1 一致（表驱动，逐键断言）                                                                                                                                                                                                                                   |
| `otp/limit.go`                                           | 冷却边界（59/60/61s）、日限额边界、跨天重置（注入 Clock）                                                                                                                                                                                                                                            |
| `oidc/redirect.go`                                       | 精确匹配、`*` 通配、子域名陷阱（必须整段匹配）、大小写、空白名单                                                                                                                                                                                                                                     |
| `oidc/claims.go`                                         | 《后端架构》§14.4 映射逐字段；`email_verified` / `phone_verified` 取 DB 标志；`amr` 来自登录链路                                                                                                                                                                                                     |
| `oidc/pkce.go`                                           | S256 校验正误两种                                                                                                                                                                                                                                                                                    |
| `schema/schema.go`                                       | 每种 type 产出的字段清单快照；每个字段必带 `section` 且取值落在五枚举内；`secret` 字段标记、默认值、`advanced`                                                                                                                                                                                       |
| `jsonata/`                                               | `user_mapping` 与 `storage_path` 表达式渲染（含 `ticket_id`/`timestamp` 内置变量）；非法 / 不支持表达式归一为所在域既有错误码，断言不透出 gnata 原始错误；不支持清单内语法逐条断言按归一口径返回                                                                                                     |
| `storage/path.go`                                        | path_prefix 拼接、非法字符、路径穿越（`../`）被拒                                                                                                                                                                                                                                                    |
| `orchestrator/state.go`                                  | 载荷 round-trip；`passed` 追加；`tp` 覆盖语义（仅最后一次三方身份）                                                                                                                                                                                                                                  |
| `orchestrator/dispatch.go`                               | `Usage` 校验矩阵：主因子不能当二次用、反之亦然；未知 method；step 越界                                                                                                                                                                                                                               |
| `repo/model`                                             | 字段与《后端架构》§4 表一一对应（反射比对列名，防漂移）                                                                                                                                                                                                                                              |
| `connect`（框架编解码集成）                              | 同一消息两种编码：JSON 输出为 lowerCamelCase（`loginToken`）、零值字段省略、整型为字符串（`"60"` 而非 `60`）；`application/json` 与 `application/proto` 两种 `Content-Type` 解出等价消息（`proto.Equal`）；未知字段 → `invalid_argument`；超长 body 被 `WithReadMaxBytes` 拒（`resource_exhausted`） |
| `connect/errors.go`                                      | `ErrorInfo.code` 取值封闭（越界即 panic 或 500）；detail 可被客户端按生成类型解出；`request_id` 不在错误体（走 `X-Request-Id` 头）                                                                                                                                                                   |
| `internal/logx`                                          | ① `logx.NewHandler` 捕获输出：ctx 有 / 无链路 ID 两分支的 `request_id` 注入；② 级别过滤与 json/text 格式；③ `With` 派生不丢注入；④ 便捷函数在外部裸 handler 下仍带字段；⑤ `Setup` 装配后全局级别生效                                                                                                 |
| `dto/view.go`                                            | 公开视图消息**不含**任何凭证字段（断言生成消息的字段描述符中不存在 `client_secret` / `app_id` / `cert` 等）；Admin 视图含                                                                                                                                                                            |

B. Fake / Mock 层

| 对象                                   | 用例                                                                                                             |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `provider/captcha/*`                   | 用假 sitesVerify 服务：成功、失败、超时、重复 token                                                              |
| `provider/oauth/*`                     | 用假 OIDC 服务跑通 discovery→exchange→userinfo；`oauth2` 兜底适配器用假三 URL；`user_mapping` 抽取正确           |
| `provider/storage/{s3,local}`          | Put/Get/Delete/URL/PresignPut；`local` 配置 `direct` 时自动回退 `proxy`                                          |
| `provider/sms/*` 与 `provider/email/*` | 参数渲染正确；发送失败不回滚验证码                                                                               |
| `factor/*`                             | 每个因子用 Fake repo+cache 跑：`Steps()` 序列与《接口文档》§1.10 一致；`Start`/`Verify` 的成功 / 失败 / 重试三态 |

C. cache 与 Lua（真连 Redis）

| 对象                            | 用例                                                                                                                                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cache/code.go` 发码 Lua        | ① 首次成功；② 60s 内二次发被拒；③ 日限额到达被拒；④ IP 限额到达被拒；⑤ TTL 正确；⑥ 多写合并后仅 1 次往返（断言命令数）                                                                  |
| `cache/code.go` 校验 Lua        | ① 正确码成功且键被删；② 错码 `tries+1` 且键保留（`tries < 5`）；③ 第 5 次错码后键被删（作废，与上限 5 一致）；④ 不同归属标识（`tid` / `uid`）的码不可用；⑤ 并发 100 次校验只有 1 次成功 |
| `cache/captcha.go`              | GETDEL 一次性                                                                                                                                                                           |
| `cache/pwfail.go`               | 计数递增、当日 24:00 过期、`pwban` 的 TTL 与 `retry_after` 计算；`status` 取 `locked`                                                                                                   |
| `cache/session.go` / `epoch.go` | epoch 读取与回源；递增到 > 30000 时回绕为 1（跳过 0，《后端架构》§4.2）；`session.go` 本期无对应键空间（令牌自包含，逐出扩展点见《后端架构》§11.1）                                     |
| `cache/provider.go`             | 版本号 + pub/sub 失效                                                                                                                                                                   |

D. service / orchestrator（Fake 依赖 + httptest）

| 对象                                           | 用例                                                                                                                                                                                                                                                               |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `orchestrator/engine.go`                       | 《后端架构》§7.3 的逐步断言（此为核心用例）：① 目标不存在时返回 `status=user_not_found`（不发码、不签发 login_token）；② 主因子未通过直接打二次因子被拒；③ MFA 阶段手机号只能来自 uid 绑定资料；④ 验证码 `purpose` 与 `tid` 绑定；⑤ MFA 总时长超 10 分钟回到第一步 |
| `orchestrator/methods.go`                      | 快照生成：开关过滤、`flow=register/reset` 过滤、`flags` 与 settings 一致、排序分组、快照无凭证；快照结构即 `__AUTHLOFT_INIT__.methods` 的值                                                                                                                        |
| `orchestrator/binding.go`                      | 《后端架构》§12.5：tp 覆盖、只有两个选项、`enable_signup=0` 时创建被拒、`set_password` 的 password 按 `tp` 判定、注册端点接受 `flow=login`、auto_bind 命中与未命中                                                                                                 |
| `service/contact.go`                           | ① bind 的码内 `owner` 是 `uid` 而非 `tid`；② `verify` 时 uid 不一致即 `invalid_code`；③ 换一个 target 取不到码；④ captcha 缺失被拦（《后端架构》§9.3）                                                                                                             |
| `service/thirdparty.go`（`BindToCurrentUser`） | ① `b` 前缀 state 正确路径；② Cookie uid ≠ 会话 uid 被拒；③ open_id 已绑他人 → `target_taken`；④ 已绑本人幂等；⑤ 成功后未签发 login_token、未 Set-Cookie；⑥ 审计事件最终落库；⑦ qrcode 通道与 redirect 通道走同一函数（注入 ticket 身份 vs 现算）                   |
| `service/ticket.go`（绑定轮询）                | ① `scene=bind` 的 ticket 不被登录轮询接受（反之亦然）；② 命中后 GETDEL 且用会话 uid 绑定；③ 未命中且未过期 → `pending`；④ 过期 → `expired`；⑤ 未带会话 → 401                                                                                                       |
| `orchestrator/terminal.go`                     | 建会话 1 次写；日志与 `last_login_at` 走队列不阻塞；OIDC 场景授权码生成与 `redirectTo` 拼接正确                                                                                                                                                                    |
| `session/verify.go`                            | 《后端架构》§11.1 四步：kid、exp、epoch 比对（缓存命中 / 未命中 / 回源）、失败清 Cookie                                                                                                                                                                            |
| `session/renew.go`                             | 每次请求均重签、按来源返回 `Set-Cookie` / `X-Authloft-Token`；重签纯计算、无存储写入（断言零队列任务）                                                                                                                                                             |
| `service/password.go`                          | 改密后 epoch 递增、refresh token 批量吊销                                                                                                                                                                                                                          |
| `service/ticket.go`                            | 长轮询超时（上限见《接口文档》§2.8）返回 `pending`；ticket 过期返回 `expired`；`GETDEL` 原子消费、用后即毁                                                                                                                                                         |
| `service/qrcode.go`                            | `ticket_id` 长度上限见《后端架构》§11.6.4；码图走中转；`qrcode_auto_delete=1` 时投递删除任务（同模板重算 key）                                                                                                                                                     |
| `service/admin/provider.go`                    | 写后 `al:prov:ver` 自增且缓存被删；`provider_key` 唯一性与字符集校验                                                                                                                                                                                               |
| `service/upload.go`                            | presign 的 MIME / 大小校验、key 由服务端生成（前端传路径被忽略）、commit 不回读                                                                                                                                                                                    |

E. handler / 中间件（httptest + 真实路由）

| 对象                                                            | 用例                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `middleware/origin.go`                                          | 同源通过、跨站 403、无 Origin 时走 Referer 白名单                                                                                                                                                                                                                                                                                                                                                                              |
| Connect 框架（Content-Type）                                    | `application/json` 通过、`application/proto` 通过、`text/plain` → 415；OIDC 与 multipart 端点不受 Connect 校验（REST 豁免）                                                                                                                                                                                                                                                                                                    |
| `middleware/csp.go`                                             | nonce 每请求不同；`CSPSupporter` 片段按指令名聚合去重后单条输出（非拼接追加，《后端架构》§3.3 / §9.4）；各指令取值与《接口文档》§8 统一口径逐项一致（含 `static_base` 为 CDN 时追加源、captcha provider 贡献源按当前生效项聚合；setup server 渲染的 `/setup` 壳同基线）                                                                                                                                                        |
| `connect`（rpc HMAC interceptor）                               | 写接口（`Update`/`Delete`/`Set`/`Create`/`Revoke` 开头）nonce 重放被拒；写 / 读接口签名错（含 nonce 项错）被拒；签名对通过；读接口同一 `X-Nonce-ID` 重复请求均通过（nonce 参与签名、不去重）                                                                                                                                                                                                                                   |
| `middleware/`（基础层：requestid / logger / recover / metrics） | requestid：格式（16B hex / 32 字符）、不读入站头、所有响应回写 `X-Request-Id` 头、rand 失败留空串；logger：不读 body / query / header / cookie，path 取 `URL.Path` 不含 query，panic 值与堆栈只进日志；recover：panic → 500（Connect 域为 `internal` 错误体），日志含 request_id / method / path / panic / stack，已写与未写响应两分支均 `Abort()` 截断后续链；metrics：3 个原子计数含 panic 请求、`/metrics` 纯文本、近似快照 |
| `handler/page.go`                                               | 注入块转义 `<>&` 与 `\u2028/\u2029`；`Cache-Control: no-store`；不出现任何密钥字段；`methods` 快照必注入、不含 `admin`、无凭证；占位符替换正确：三个运行期占位符（`{{AUTHLOFT_STATIC_BASE}}` / `{{AUTHLOFT_CSP_NONCE}}` / `{{AUTHLOFT_INIT_JSON}}`）均由后端替换，`{{AUTHLOFT_STATIC_BASE}}` 尾斜杠归一（相对 `/assets` 与 CDN 绝对地址两种取值），残留未知占位符按字面输出                                                    |
| `handler/sso.go`                                                | 流程信封字段齐全；`loginToken` 每次重签返回新值；失败态只由 `status` 表达                                                                                                                                                                                                                                                                                                                                                      |
| 全局                                                            | admin 域未携带有效会话返回 401（`unauthenticated`）；会话有效但 `uid != 1` 返回 404（`not_found`，掩护管理面存在，《接口文档》§1.5）；所有写请求带 Origin 校验；同一接口两种 `Content-Type` 的响应解出后 `proto.Equal`                                                                                                                                                                                                         |
| `handler/account.go`                                            | `AccountService/GetConfig` 的 `captcha` 不含任何凭证字段；`AccountService/ThirdpartyOauth` 未带会话 → 401；`X-Authloft-Token` Header 可替代 Cookie 完成鉴权                                                                                                                                                                                                                                                                    |

F. 异步队列

| 用例                                                                               |
| ---------------------------------------------------------------------------------- |
| 攒批：200 条触发一次 flush；2s 时间窗触发一次 flush                                |
| 合并：同一 user_id 的 `last_login_at` 取最新；同一 credential 的 sign_count 取最大 |
| 队列满：非关键项被丢弃，`dropped` 计数 +1，且业务返回值不受影响                    |
| 优雅关闭：Shutdown 后剩余任务被 flush；超时 10s 强制退出                           |
| `-race` 下并发 Push/Flush 无数据竞争                                               |

G. 集成测试（真连 ENV.md test 实例）

| 用例                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 真实 MariaDB + Redis + 假第三方：跑通《后端架构》§7.3 / 《接口文档》§10.2 完整 8 步；断言 `event_log` 最终落库（含队列延迟写入）、`last_login_at` 更新                               |
| 迁移（goose，《后端架构》§3.16）：空库一步 `migrate up` 到最新、表结构与《后端架构》§4 一致；已最新时重复执行零变更（秒过）；人为制造失败后按恢复流程（修复半成品 → 重跑重试）可续装 |
| 会话失效：改密后旧 session_token 立即不可用                                                                                                                                          |
| OIDC 全链路：authorize → login → code → token → userinfo → refresh → revoke                                                                                                          |
| Provider 热更新：改配置后 2 秒内新请求生效（多实例用 pub/sub）                                                                                                                       |

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

**测试栈与配置**

| 用途     | 选型                                                                                                                                                                                                                     |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 运行器   | Rstack（底层为 Rstest，配置见 `rstack.config.mts`，脚手架）                                                                                                                                                              |
| 环境     | jsdom；WebAuthn 相关用例注入 `window.PublicKeyCredential` stub                                                                                                                                                           |
| 组件测试 | 渲染断言经 `renderToStaticMarkup`（rstest externalize 与 Semi 子路径不兼容，testing-library 暂不可用，工具链修复后恢复）；按可访问性角色 / 文案断言，不做快照测试；`semi-probe` 探针长期保留作为配置绊线（配置回退即红） |
| 网络     | msw（handler 内联于各测试文件，非集中 mocks/），拦截所有 `/api/**`                                                                                                                                                       |
| 契约     | 响应类型来自生成的 TS 消息类型，msw fixture 直接以生成类型断言，防止前后端漂移                                                                                                                                           |
| E2E      | Playwright（体系未建，本节 E2E 用例为规划口径）                                                                                                                                                                          |
| 覆盖率   | 全量 ≥ 80% 行覆盖；`login/flow/*`、`loginTokenStore`、`oidcContext`、`shared/captcha/*`、`login/factors/WebAuthnButton.tsx`（webauthn 认证胶水）要求 100% 分支覆盖                                                       |

**各层测法与重点用例**

A. 纯函数层

| 对象                     | 用例                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `flow/reducer.ts`        | ① 《接口文档》§1.6 每个 `status` 的迁移正确性（表驱动逐项覆盖大集合）；② `mfa_required` 不跳页、就地切换 method；③ `captcha_required` / `captcha_invalid` 只镜像终局 status，编排归弹窗（不在 reducer）；④ `request_cancelled`（取消弹窗）只撤 loading，status / method / step / 信封原样保留；⑤ `binding_required` 分支；⑥ `success` 清空 token；⑦ 未知 status 走兜底           |
| `loginTokenStore.ts`     | ① set/get/clear；② 响应覆盖语义（旧值作废）；③ 订阅通知；④ 断言 `localStorage.setItem` / `sessionStorage.setItem` / `document.cookie` 均未被调用（spy）                                                                                                                                                                                                                          |
| `oidcContext.ts`         | ① 写入 / 读出 / 清除 round-trip；② 读出后立即清除（`load` 两次第二次为空）；③ 断言写入内容不含 `login_token` / `session_token`（spy）                                                                                                                                                                                                                                            |
| `utils/validate.ts`      | 用户名边界（规则见《接口文档》§2.3；用例覆盖 4/5/20/21、含中文、含 `-`）、密码强度矩阵（规则见《接口文档》§5.6）、provider_key 正则、邮箱 / 手机号                                                                                                                                                                                                                               |
| `utils/mask.ts`          | 掩码结果、短号码、空值                                                                                                                                                                                                                                                                                                                                                           |
| `shared/api/errors.ts`   | ① 《接口文档》§1.6 每个取值 → `{retryable, action}`（表驱动逐项覆盖大集合，含登录域顶层 `status` 与其余域 `ErrorInfo.code` 两个位置）；i18n 优先于 `ErrorInfo.message`；未知取值兜底；② Connect 标准码（§1.5）逐个映射，未知标准码兜底且不透出 `message` 原文                                                                                                                    |
| `shared/api/http.ts`     | ① transport 对同一消息 JSON / 二进制往返等价（msw 按 `Content-Type` 分别返回 JSON / proto 字节）；② 非 2xx 抛 `ConnectError`，`findDetail(ErrorInfo)` 解出 `{domain, code, message, retryAfter, attemptsLeft}`；③ 无 detail 时按 Connect 标准码归一；④ 超时 / `AbortController` 中断；⑤ 请求体 JSON 文本里整型为字符串（`"60"` 而非 `60`）、字段名为 camelCase（标准 protojson） |
| `shared/utils/int.ts`    | `toCount` 在 2^53 边界抛错；`toDisplay` 对 `bigint` 与字符串输入输出一致                                                                                                                                                                                                                                                                                                         |
| `shared/api`（契约）     | 用 `tests/fixtures/*.json`（取自《接口文档》示例）以生成的消息类型 `fromJson` 断言可解码；故意删字段可解码为零值（省略零值口径）但类型不符应失败；**整型字段按十进制字符串断言**（《接口文档》§1.12）                                                                                                                                                                            |
| `hooks/useCountdown.ts`  | 用 fake timers：到期归零、卸载清理、后台节流下仍按时间戳计算                                                                                                                                                                                                                                                                                                                     |
| `hooks/useLongPoll.ts`   | 超时重连、指数退避次数上限、卸载后 abort 且不再发起、错误上限停止                                                                                                                                                                                                                                                                                                                |
| `hooks/useCapability.ts` | 属性链解析：存在 / 不存在 / 非法表达式（非法按不存在处理，不抛错）三种分支                                                                                                                                                                                                                                                                                                       |

B. 组件层（msw + 渲染断言）

| 对象                                                         | 用例                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MethodTabs.tsx`                                             | 按 `sort_order` 排序、`ui_group` 分组、空列表、能力不满足项隐藏（mock `useCapability`）；数据源为注入快照（mock `__AUTHLOFT_INIT__.methods`）                                                                                                                                                                                                               |
| `FieldRenderer.tsx`                                          | 每种 `type` 渲染正确、必填校验、未知 type 兜底                                                                                                                                                                                                                                                                                                              |
| `CodeInput.tsx`                                              | 粘贴 6 位自动拆分、退格跨格、非数字过滤、`autocomplete` 属性存在、长度由 `length` 驱动                                                                                                                                                                                                                                                                      |
| `PasswordForm.tsx`                                           | 提交载荷结构、不内联 captcha widget（弹窗承接、不清空已输入密码）、CapsLock 提示、`locked` 时展示剩余时长                                                                                                                                                                                                                                                   |
| `OTPForm.tsx`                                                | challenge → form 两段、重发倒计时期间禁用按钮、错误计数文案、`expires_in` 到期提示                                                                                                                                                                                                                                                                          |
| `WebAuthnButton.tsx`                                         | 能力缺失时不渲染；`startAuthentication` 以 usernameless 方式调用（不传 `allowCredentials`、不收集用户名）；challenge 过期后前端自动重取一次 options 再让用户重试；`NotAllowedError` / `InvalidStateError` 语义化提示                                                                                                                                        |
| `ProviderButtons.tsx`                                        | 三种 channel 的分派、图标取自下发 `icon`；点击先调 `SsoService/Authorize` 取 URL 再 `location.replace`（断言未直接跳外域）；跳转前调用 `saveOidcContext`                                                                                                                                                                                                    |
| `QRCodeStep.tsx`                                             | 四态流转（pending → scanned → success / `expired`），`failed` 时按信封 `status` 出文案；`expired` 触发重拉且经弹窗换新 captcha；取消弹窗卸面板并留重入按钮（重入换新凭据）；卸载中断轮询；`ticket_id` 全程一致                                                                                                                                              |
| `shared/QRCodePanel.tsx`                                     | 两组 props 注入下四态流转一致；组件自身不发业务请求（拉码 / 轮询都由 props 决定）；`expired` 重拉要求新 captcha；卸载中断轮询                                                                                                                                                                                                                               |
| `account/ThirdPartyBindDialog.tsx`                           | 拉码带 `scene:"bind"`；轮询走 `AccountService/GetThirdpartyTicket`；命中后成功关闭并刷新列表、`target_taken` 展示"该账号已被其他账号绑定"；断言未触碰 `loginTokenStore`                                                                                                                                                                                     |
| `login/components/ModalView.tsx`                             | 窗体纯视图可 SSR：dialog 骨架与标题关联、关闭图标、两按钮文案；`confirmLoading` / `cancelLoading` / `okButtonProps.disabled` 禁用对应按钮、`hasCancel` / `footer` / `closable` 的 Semi 同名语义；组件壳的 portal / 焦点 / 滚动锁属 DOM 副作用不在本链覆盖                                                                                                   |
| `shared/app-ui/Modal.tsx`                                    | 适配层为无 hook 纯函数，直接调用取回 SemiModal 入参断言：域基线（centered / width / `zIndex=@z-modal` / `maskClosable` 默认关）与 Semi 同名字段透传；`confirmLoading` / `cancelLoading` 归一为两按钮硬 `disabled`（Semi 原生 loading 只用 pointer-events 挡鼠标，键盘 Enter 仍会触发）；契约 ⊆ Semi API 由同文件编译期断言钉死                              |
| `shared/captcha/captchaGate.ts`                              | `upfront` 有配置只发一次带凭据的请求（无裸探）、无配置退化为先探一次；`reactive` 先裸发、命中才问；`captcha_invalid` 窗内循环且 `attempt` 递增、`invalid=true`；响应顶层 `captcha` 覆盖首屏配置（含降级为 `image`）；取消返回 `cancelled` 且不再发请求；非 captcha 动作 / 不可判读错误原样逃逸；两种协议形态（200 信封 `status` / `ApiError.code`）判读一致 |
| `shared/captcha/CaptchaDialogView.tsx` + `CaptchaDialog.tsx` | 纯内容可 SSR（提示 / widget / 错误位，不含窗体骨架）；壳用 stub `ModalRenderer` 断言透传的 Semi 风格 props（`visible` / `okText` / `confirmLoading` / `closable` / `closeOnEsc` / `maskClosable`）与在途封死五条动作路径；`onOk` 未取到凭据走 `onNotReady`；widget 以 `attempt` 为 key（每轮换新凭据）；未知 `type` 的兜底错误态在窗内可见                  |
| `shared/captcha/CaptchaWidget.tsx` + adapters                | 分派到正确 adapter；两种首屏配置来源（注入快照 prop / `AccountService/GetConfig` 结果）渲染一致且组件自身不发配置请求；`captcha.type` 变化（含 `image` 降级）时按新 `type` 重渲染；`reset()` 在失败 / 过期时被调用；每个 adapter 只产出 `{providerKey, token}` 或 `{providerKey, id, answer}`（都必须带 `providerKey`）；不在 adapter 内发业务请求          |
| `LoginContainer.tsx`                                         | 端到端跑一遍《接口文档》§10.2 的 8 步（用 msw 编排 8 段响应）：重点是主因子未通过时不允许进入 MFA、success 后清空 token                                                                                                                                                                                                                                     |
| `BindingChoice.tsx`                                          | 两个分支：创建新账号（仅提交 `username`）与退出重登（不发请求、清空 token 后跳 `/sso/login`）；信封字段 `binding.allowSignup=false` 时创建项禁用                                                                                                                                                                                                            |

C. 页面 / 容器层（少量，重集成语义）

| 对象                                       | 用例                                                                                                                                                                                                                                                                                    |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OAuthCallbackPage.tsx`                    | `location.search` 原样转发（含 code/state），不解析；按 `state` 首字母分派：`l` → `SsoService/LoginOauth`（附 `oidc`，读完即清）、`b` → `AccountService/ThirdpartyOauth`、其他 / 缺失 → 跳 `/sso/login`；绑定成功后跳 `/account#/security?bind=success`                                 |
| `RegisterPage.tsx` / `ResetPage.tsx`       | challenge → verify → set_password 三段；密码强度门禁                                                                                                                                                                                                                                    |
| `admin/SchemaForm.tsx`                     | 六种字段类型渲染；按 `section` 分五区块且 `endpoint` 整块默认折叠；`advanced` 默认折叠；`pattern` 校验；`secret` 默认掩码；新增一种假 schema 类型不需改组件；缺 `section` 时报错而非猜测                                                                                                |
| `admin` 入口                               | 注入变量不含 `admin`，通过 `AdminService/GetMe` 获取管理员信息                                                                                                                                                                                                                          |
| 三端入口                                   | 注入 `static_base` 为 `/assets`、`https://cdn.x/uc`、带尾斜杠三种取值时，`__webpack_public_path__` 归一为以 `/` 结尾；缺省回落 `/assets/`                                                                                                                                               |
| `shared/app-ui/DataTable.tsx`              | 分页 / 排序 / 筛选回调参数、行内开关的乐观更新与回滚                                                                                                                                                                                                                                    |
| `admin/ProviderEditPage.tsx`               | provider_key 创建后只读、回调地址提示拼接、保存前校验                                                                                                                                                                                                                                   |
| `account/WebauthnList.tsx`                 | 重命名 / 删除；最后一个可用方式不允许解绑的按钮禁用                                                                                                                                                                                                                                     |
| `account/ThirdPartyList.tsx`               | `items` / `available` 两段渲染；解绑前置校验（解绑后仍持 password 凭证，或仍绑定 ≥ 1 个非 Union 第三方 Provider，不满足置灰，口径见《接口文档》§3.7）；按 `channel` 分流绑定入口（`redirect` 跳转 / `qrcode` 开对话框 / `api` 不给入口）；`target_taken` 时提示"该账号已被其他账号绑定" |
| `account/ContactBindForm.tsx`              | challenge → verify 两段；captcha 配置取自 `AccountService/GetConfig`（不读 `__AUTHLOFT_INIT__`）；`verify` 回传与 `challenge` 相同的 target                                                                                                                                             |
| `account/AvatarUploader.tsx` + `useUpload` | 两种模式（mock `AccountService/GetConfig` 返回 `proxy` / `direct`）下最终都得到 url；`direct` 三步走（presign → PUT → commit）；超限 / 类型不符的预校验文案与后端一致                                                                                                                   |

**测试数据**

- `tests/fixtures/`：直接采用《接口文档》§1.3（登录流程信封）、§2.1（`methods` 注入快照）、§2.7.1（`providers`）、§3.2（`account/config`）、§3.7（`thirdparty` 列表）、§5.3（`schema`）的示例作为基线，派生出成功 / 失败 / 多分支变体。这些 JSON 与后端 `test/fixtures/` 同源（见 §5.1 契约一致性），**整型一律字符串**；msw handler 的响应体必须由生成的消息类型序列化（`toJson` / `toBinary`）产出，不手写 JSON 字面量
- msw handler 内联于各测试文件（现状惯例），按场景而非按 URL 组织（`smsLoginWithMfa`、`passwordLocked`、`qrcodeExpired`、`bindEmailFlow`、`bindThirdPartyTaken`…），供组件测试按需切换

**不写什么**

- 不写快照测试（UI 细节易变，收益低）
- 不测第三方 SDK 自身行为（Turnstile / 微信），只测 adapter 的胶水逻辑

**E2E（Playwright，体系未建，以下为规划口径）**

| 场景                       | 断言要点                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 《接口文档》§10.2 完整链路 | 邮箱验证码登录 → MFA → 改用短信 → 成功跳转                                                                                                                 |
| 方式列表注入               | 打开 `/sso/login` 即用注入快照渲染，不另发配置请求                                                                                                         |
| 刷新页面                   | 任意中间态刷新 → 回到第一步并提示超时                                                                                                                      |
| 多域名同步                 | 命中 `sync_cookie_url`（后端已拼好载荷的首跳 URL）后直接 `location.replace`，前端不读不写任何同步状态；跳转链（中心域 → 业务域 → …）走完落到 `redirect_to` |
| 密码失败渐进               | 第 3 次失败后要求 captcha；第 6 次后 locked 展示剩余时长（默认阈值 3 / 6，后台可配）                                                                       |
| 扫码登录                   | 码图展示 → 模拟写入 ticket（`ticket_id`）→ 状态变 success；`expired` 后重拉需 captcha                                                                      |
| 已登录绑定邮箱             | 安全中心 → 验证码 + captcha 两段 → 刷新后邮箱已更新                                                                                                        |
| 已登录绑定第三方           | 安全中心点绑定 → 跳转 → 回调（`state` 前缀 `b`）→ 回到安全中心且列表新增一项；绑到已绑他人的账号时提示 `target_taken`                                      |
| 已登录扫码绑定             | 安全中心点扫码绑定 → 码图展示 → 模拟写入 ticket → 面板变成功且列表新增一项；过程中未产生登录态；`expired` 后重拉需 captcha                                 |
| 三方登录带 OIDC            | 跳转前 `al_oidc_ctx` 写入 `localStorage`；回调后 `oidc` 被回传且 `localStorage` 已清空                                                                     |
| 管理端                     | 新建 Provider 全流程 + 列表排序持久化                                                                                                                      |

## 6. 工程纪律

- **commit 一律显式路径 add**，不用 `git add -A` / `git add .`。
- 多会话共享仓库时，commit 前 `git status` 全量核对暂存区；发现混入其他会话的 hunk 立即 soft reset 重提（共享暂存区混杂风险已有实证）。
- commit 的 add 范围必须覆盖本次改动文件全集——i18n 字典等与 SCOPE 目录分离的文件最易漏（漏提交会使键集测试在下一轮变红）。

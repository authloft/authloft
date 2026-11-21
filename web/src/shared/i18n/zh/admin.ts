/**
 * zh-CN 管理后台域文案模块（分域底座）：admin 域的键由后续域
 * 收口在本模块内追加，经 zh-CN.ts 尾部 spread 汇入总字典。
 *
 * 禁止给本对象加 Record<string, string> 等索引类型注解：会被 spread 进
 * 总字典，把 I18nMessages 弱化成索引签名，破坏 en/zh 编译期键对齐。
 */
export const admin = {
  // ---- settingsLogic.ts 设置表单（分区 / 字段 label / hint / 单位）----------
  'admin.settingsSectionSiteInfo': '站点信息',
  'admin.settingsSectionRegistration': '注册与找回',
  'admin.settingsSectionPasswordPolicy': '密码策略',
  'admin.settingsSectionLoginFailureLock': '登录失败锁定',
  'admin.settingsSectionLoginMethods': '登录方式',
  'admin.settingsSectionMfa': '两步验证 MFA',
  'admin.settingsSectionOtpRateLimit': '验证码限流',
  'admin.settingsSectionSessionCookie': '会话与 Cookie',
  'admin.settingsSectionDomainHttps': '域名与 HTTPS',
  'admin.settingsSectionQueue': '队列参数',
  'admin.settingsSectionExternalServices': '外部服务',
  'admin.settingsSectionGatewayToken': '网关令牌',
  'admin.settingsSectionLogPartition': '日志分区',

  'admin.pwdMinLengthLabel': '最小长度',
  'admin.pwdMinLengthHint': '默认 8',
  'admin.pwdMaxLengthLabel': '最大长度',
  'admin.pwdMaxLengthHint': '服务端上限 64（默认 64）',
  'admin.pwdRequireClassesLabel': '须满足的字符类数',
  'admin.pwdRequireClassesHint':
    '1-3；字符类 = 大写 / 小写 / 数字，符号不计入（默认 3）',
  'admin.pwdDisallowUsernameLabel': '禁止密码包含用户名',
  'admin.pwdDisallowCommonLabel': '禁止命中弱口令字典',
  'admin.allowPasswordResetLabel': '开放自助重置密码',
  'admin.allowPasswordResetHint': '关闭后重置密码一律被拒绝',
  'admin.allowRegistrationLabel': '注册总开关',
  'admin.allowRegistrationHint': '关闭后注册一律被拒绝',
  'admin.allowSignupPasswordLabel': '用户名 + 密码注册入口',
  'admin.allowSignupPhoneLabel': '手机号注册入口',
  'admin.allowSignupEmailLabel': '邮箱注册入口',
  'admin.otpResendIntervalLabel': '同目标重发冷却',
  'admin.otpResendIntervalHint': '默认 60',
  'admin.otpTtlLabel': '验证码有效期',
  'admin.otpTtlHint': '默认 300',
  'admin.otpMaxAttemptsLabel': '单条验证码最大校验失败次数',
  'admin.otpMaxAttemptsHint': '超限即作废（默认 5）',
  'admin.otpDailyLimitTargetLabel': '单目标每日发送上限',
  'admin.otpDailyLimitTargetHint': '默认 10',
  'admin.otpDailyLimitIpLabel': '单 IP 每日发送上限',
  'admin.otpDailyLimitIpHint': '默认 50',
  'admin.loginMethodsLabel': '已启用的登录方式',
  'admin.loginMethodsHint':
    '只控登录，不参与注册判定；不在其中的方式登录时被拒绝',
  'admin.mfaEnabledLabel': '两步验证总开关',
  'admin.mfaEnabledHint': '关闭后两步验证不生效，用户开关不可用',
  'admin.mfaMethodsLabel': '可用于两步验证的因子',
  'admin.mfaMethodsHint': '用户绑定白名单内的因子后即可用于两步验证',
  'admin.pwdFailCaptureLabel': '当日密码错误人机校验阈值',
  'admin.pwdFailCaptureHint':
    '同一账号当日密码错误达此次数后，登录必须携带人机校验（默认 3）',
  'admin.pwdFailBanLabel': '禁止密码登录阈值',
  'admin.pwdFailBanHint': '累计失败达此次数后禁止密码登录（默认 6）',
  'admin.pwdBanTtlLabel': '禁止密码登录时长',
  'admin.pwdBanTtlHint': '默认 21600（6 小时）',
  'admin.sessionTtlLabel': '会话与 Cookie 有效期',
  'admin.sessionTtlHint': '默认 604800（7 天）',
  'admin.cookieNameLabel': '会话 Cookie 名',
  'admin.cookieNameHint': '默认 al_session',
  'admin.httpsDeploymentLabel': 'HTTPS 部署',
  'admin.httpsDeploymentHint':
    '声明本实例的 HTTPS 部署形态，决定会话 Cookie 的 Secure 属性：自动推断 = 仅 HTTPS 请求下标记为安全；强制开启 = 按部署于 HTTPS 处理，明文 HTTP 环境下浏览器将不保存该 Cookie；强制关闭 = 按明文部署处理，Cookie 不带 Secure 标记',
  'admin.ssoDomainsLabel': '多域名同步地址列表',
  'admin.ssoDomainsHint':
    '填完整 URL（如 https://example.com/prefix/sync_cookie），登录 / 登出时逐个同步',
  'admin.queueWorkersLabel': '延迟写入队列 worker 数',
  'admin.queueWorkersHint': '默认 4',
  'admin.queueCapacityLabel': '队列长度（ring buffer）',
  'admin.queueCapacityHint': '默认 8192',
  'admin.queueBatchLabel': '攒批条数阈值',
  'admin.queueBatchHint': '默认 200',
  'admin.queueFlushMsLabel': '攒批时间窗',
  'admin.queueFlushMsHint': '默认 2000',
  'admin.captchaProviderKeyLabel': '当前生效的 Captcha Provider',
  'admin.captchaProviderKeyHint': '留空 = 内置图形码',
  'admin.smsProviderKeyLabel': '当前生效的短信 Provider',
  'admin.smsProviderKeyHint': '留空 = 未启用外部短信渠道',
  'admin.emailProviderKeyLabel': '当前生效的邮件 Provider',
  'admin.emailProviderKeyHint': '留空 = 未启用外部邮件渠道',
  'admin.avatarStorageProviderLabel': '头像 / 渠道图标使用的 Storage Provider',
  'admin.avatarStorageProviderHint': '留空 = 未启用外部存储',
  'admin.providerOptionLabel': '{name}（{key}）',
  'admin.gatewayTokensLabel': '网关 Token',
  'admin.eventlogPartitionDaysLabel': '事件日志分区天数',
  'admin.eventlogPartitionDaysHint': '默认 7，分区任务按此天数滚动建分区',
  'admin.eventlogMaxPartitionsLabel': '事件日志最大分区数',
  'admin.eventlogMaxPartitionsHint': '默认 26，超出后淘汰最旧分区',
  'admin.siteNameLabel': '站点名称',
  'admin.siteNameHint': '页面标题，留空则显示默认名称 Authloft',
  'admin.staticBaseLabel': '静态资源基址（CDN）',
  'admin.staticBaseHint': '决定页面脚本 / 样式 URL 前缀；改后需刷新页面生效',
  'admin.clientIpHeaderLabel': '从 Header 读取客户端 IP',
  'admin.clientIpHeaderHint':
    '反代注入客户端 IP 的头名（如 X-Forwarded-For）；留空则仅取直连地址',

  'admin.unitSeconds': '秒',
  'admin.unitTimes': '次',
  'admin.unitMilliseconds': '毫秒',
  'admin.unitDays': '天',
  'admin.addDomain': '添加',
  'admin.addGatewayToken': '添加 Token',
  'admin.gatewayTokenPlaceholder': '网关调用方令牌',

  'admin.httpsDeploymentAuto': '自动推断',
  'admin.httpsDeploymentForceOn': '强制开启',
  'admin.httpsDeploymentForceOff': '强制关闭',

  'admin.settingsNumberIssue': '数字设置项须为不小于 0 的整数',
  'admin.pwdRequireClassesIssue': '须满足的字符类数须为 1-3',
  'admin.pwdMinOverMaxIssue': '密码最小长度不能大于最大长度',
  'admin.pwdMaxOverCapIssue': '密码最大长度不能超过 64',
  'admin.httpsDeploymentIssue':
    'HTTPS 部署取值须为 自动推断 / 强制开启 / 强制关闭',

  // ---- api.ts 展示纯函数------------------------------------------------------
  'admin.policyTagAllowSignin': '允许登录',
  'admin.policyTagAllowSignup': '允许注册',
  'admin.policyTagAutoBind': '自动绑定',
  'admin.displayNameFallback': '管理员',
  'admin.userStatusEnabled': '正常',
  'admin.userStatusDisabled': '禁用',
  'admin.redirectUrisIssue': '回调地址须为 * 或以 http:// / https:// 开头',
  'admin.scopesIssue': '权限范围条目不能为空，且不能包含逗号',
  'admin.listSummary': '{first} 等 {count} 条',
  'admin.durationDays': '{count} 天',
  'admin.durationHours': '{count} 小时',
  'admin.durationMinutes': '{count} 分钟',
  'admin.durationSeconds': '{count} 秒',
  'admin.tokenTtlSummary': '访问 {access} / 刷新 {refresh}',
  'admin.ttlDetail': '{duration}（{seconds} 秒）',

  'admin.actorUser': '用户',
  'admin.actorAdmin': '管理员',
  'admin.actorSystem': '系统',

  // ---- schema/schemaLogic.ts（区块标题 / 校验文案）--------------------------
  'admin.schemaSectionBasic': '基础信息',
  'admin.schemaSectionCredential': '凭证',
  'admin.schemaSectionEndpoint': '端点',
  'admin.schemaSectionDisplay': '展示与排序',
  'admin.schemaSectionPolicy': '策略开关',
  'admin.schemaSectionError':
    'provider schema 字段 {key} 的 section 缺失或非法：{section}',
  'admin.validateRequired': '此项为必填',
  'admin.validatePattern': '格式不正确',
  'admin.validateNumber': '必须是数字',
  'admin.validateJson': '不是合法的 JSON',

  // ---- schema/SchemaForm.tsx--------------------------------------------------
  'admin.endpointSummary': '端点配置',
  'admin.advancedOptions': '高级选项',
  'admin.sectionErrorPrefix': '表单结构异常：',

  // ---- schema/fields/FieldRenderers.tsx---------------------------------------
  'admin.unsupportedFieldType': '暂不支持的字段类型：{type}',

  // ---- schema 字段文案（后端 GetProviderSchema 下发 label / help 的 i18n 键）----
  // 后端只发键不发文案；同一 Ext 字段在不同渠道可有不同标签，故键按语义命名
  // （如 client_id：auth 用 clientIdLabel、阿里云短信用 aliyunAccessKeyIdLabel）。
  // 表列基线（dto/admin.go）。
  'admin.schemaField.providerKeyLabel': '唯一标识',
  'admin.schemaField.providerKeyHelp': '创建后不可修改，将出现在回调地址中',
  'admin.schemaField.displayNameLabel': '显示名称',
  // §5.3 契约示例的 category 只读字段（现由页面级类型下拉取代，后端不再下发；
  // 键保留供旧版 schema / 契约示例使用）。
  'admin.schemaField.categoryLabel': '类别',
  'admin.schemaField.categoryHelp': '由注册表按 type 决定，只读',
  'admin.schemaField.unionProviderLabel': '联合登录归属',
  'admin.schemaField.unionProviderHelp': '留空表示不参与 Union ID 归并',
  'admin.schemaField.iconUrlLabel': '图标 URL',
  'admin.schemaField.iconUrlHelp': '留空时前端渲染通用占位图标',
  'admin.schemaField.sortOrderLabel': '排序',
  'admin.schemaField.remarkLabel': '备注',
  'admin.schemaField.isEnabledLabel': '启用',
  'admin.schemaField.enableSigninLabel': '允许用于登录',
  'admin.schemaField.enableSignupLabel': '允许用于注册',
  'admin.schemaField.enableSignupHelp': '关闭后该渠道不得用于建号',
  'admin.schemaField.autoBindLabel': '按联系方式自动绑定',
  'admin.schemaField.autoBindFieldsLabel': '自动绑定字段',
  'admin.schemaField.autoBindFieldsHelp': 'auto_bind 开启时生效',

  // proxy 提供商五真实字段（§5.3 代理提供商与出站代理引用约定）：scheme 封闭集
  // select、host 禁空白与 /?#@[]、port number、user / password 可选折叠；
  // host / port 与 smtp 行共用字段名、标签键独立（proxy 行内语义为代理地址）。
  'admin.schemaField.proxySchemeLabel': '代理协议',
  'admin.schemaField.proxyHostLabel': '代理地址',
  'admin.schemaField.proxyHostHelp':
    '主机名 / IPv4 / IPv6 字面量；禁空白与 /?#@[]；IPv6 直接写 ::1 形态（不带括号）',
  'admin.schemaField.proxyPortLabel': '代理端口',
  'admin.schemaField.proxyPortHelp': '1 ≤ port ≤ 65535',
  'admin.schemaField.proxyUserLabel': '代理用户名',
  'admin.schemaField.proxyPasswordLabel': '代理密码',
  'admin.schemaField.proxyPasswordHelp': '填写密码必须同时填写用户名',
  // 引用键 proxy_provider_key（§5.3）：候选 = category=proxy 行（含未启用实例）。
  'admin.schemaField.proxyProviderKeyLabel': '出站代理',
  'admin.schemaField.proxyProviderKeyHelp': '留空 = 直连',

  // auth 域 Ext 字段基线（oauthcore.NewMeta / wechat_mp / wechat_mp_scan）。
  'admin.schemaField.clientIdLabel': 'AppID',
  'admin.schemaField.clientSecretLabel': 'AppSecret',
  'admin.schemaField.appIdLabel': '小程序 AppID',
  'admin.schemaField.certLabel': '证书 / 公钥',
  'admin.schemaField.scopesLabel': '授权范围',
  'admin.schemaField.providerUrlLabel': '服务地址',
  'admin.schemaField.customAuthUrlLabel': '授权地址',
  'admin.schemaField.customTokenUrlLabel': '令牌地址',
  'admin.schemaField.customUserInfoUrlLabel': 'UserInfo 地址',
  'admin.schemaField.userMappingLabel': '字段映射',
  'admin.schemaField.userMappingHelp':
    '三方字段 → Authloft 字段，值为 JSONata 表达式',
  'admin.schemaField.metadataLabel': '长尾键值',
  'admin.schemaField.oauth2UserMappingHelp':
    '必填 open_id：三方字段 → Authloft 字段，值为 JSONata 表达式（如 {"open_id": "$.id"}）',
  'admin.schemaField.oidcProviderUrlHelp':
    'IdP issuer 地址，自动 discovery（.well-known/openid-configuration）',

  // wechat_mp_scan 追加字段。拉码模式三字段（接口文档 §5.3 type=wechat_mp_scan
  // 行）：mode 三选一（空 = url 存量行为）、format 为 ticket 模式内容模板
  // （{{TICKET}} 占位填完整加密 ticket）、tip 为随 CreateQrcode 下发的 HTML
  // 提示文案（站点 CSP 兜底，§2.8）。
  'admin.schemaField.qrcodeAutoDeleteLabel': '登录后自动删除码图',
  'admin.schemaField.needCaptchaLabel': '需人机验证',
  'admin.schemaField.needCaptchaHelp':
    '拉取二维码前要求用户先通过人机校验；关闭后直接拉码（登录与绑定共同生效）',
  'admin.schemaField.storageProviderLabel': '存储 Provider',
  'admin.schemaField.storagePathLabel': '存储路径模板',
  'admin.schemaField.storagePathHelp':
    "JSONata 表达式，内置变量 ticket_id / timestamp，如 'qrcodes_' & $.ticket_id & '.jpg'",
  'admin.schemaField.qrcodeModeLabel': '拉码模式',
  'admin.schemaField.qrcodeModeHelp':
    'ticket=下发二维码内容由前端自绘；base64=下发内联 JPEG 图片；url=经存储中转下发链接；留空同 url',
  'admin.schemaField.qrcodeFormatLabel': '二维码内容模板',
  'admin.schemaField.qrcodeFormatHelp':
    'ticket 模式生效：{{TICKET}} 占位符替换为完整加密 ticket，如 https://example.com/scan?ticket={{TICKET}}',
  'admin.schemaField.qrcodeTipLabel': '扫码提示文案',
  'admin.schemaField.qrcodeTipHelp': 'HTML 原文，随二维码展示在扫码页',

  // captcha / storage 服务型 Provider 字段（captcha 用 client_id 作站点密钥、
  // client_secret 作密钥、endpoint 作自定义校验地址；storage/local 用 bucket 作
  // 本地目录、domain 作公开域名、path_prefix 作 key 前缀）。
  'admin.schemaField.captchaSiteKeyLabel': '站点密钥（Site Key）',
  'admin.schemaField.captchaSecretLabel': '密钥（Secret Key）',
  'admin.schemaField.captchaEndpointLabel': '自定义校验地址',
  'admin.schemaField.storageBucketLabel': '本地目录',
  'admin.schemaField.storageDomainLabel': '公开访问域名',
  'admin.schemaField.storagePathPrefixLabel': '对象键前缀',

  // s3 存储字段（s3.go）：endpoint 标签复用 providerUrlLabel（帮助文案独立）；
  // 桶名 / 寻址 / 上传链限额与白名单为头像上传链消费。
  'admin.schemaField.s3EndpointHelp':
    '可带 scheme（默认 https）；默认端口自动剥离后参与 SigV4 签名',
  'admin.schemaField.s3BucketLabel': '存储桶',
  'admin.schemaField.s3BucketHelp': '必填；不能含 / 或 \\',
  'admin.schemaField.s3RegionLabel': '区域（Region）',
  'admin.schemaField.s3RegionHelp': 'SigV4 region；留空回退 us-east-1',
  'admin.schemaField.s3PathStyleLabel': '路径寻址（Path Style）',
  'admin.schemaField.s3PathStyleHelp':
    '勾选按 host/bucket/key 寻址（MinIO 等自建常见）；不勾按 bucket.host 虚拟主机寻址',
  'admin.schemaField.s3PublicReadLabel': '公开读',
  'admin.schemaField.s3PublicReadHelp':
    '上传对象附 public-read ACL，可直链读取；敏感内容勿开启',
  'admin.schemaField.uploadModeLabel': '上传模式',
  'admin.schemaField.uploadModeHelp':
    'proxy=经服务端中转上传；direct=预签名 URL 直传',
  'admin.schemaField.presignTtlLabel': '预签名有效期（秒）',
  'admin.schemaField.presignTtlHelp':
    'direct 模式预签名 URL 有效期；默认 300，上限 604800（7 天）',
  'admin.schemaField.maxSizeLabel': '单文件大小上限（字节）',
  'admin.schemaField.maxSizeHelp': '头像上传单文件上限；未配置默认 2MB',
  'admin.schemaField.allowedTypesLabel': 'MIME 白名单',
  'admin.schemaField.allowedTypesHelp':
    '逗号分隔 MIME 类型（如 image/png,image/jpeg）；留空则拒绝一切上传',

  // 渠道语义化覆盖（alipay / microsoft）。
  'admin.schemaField.alipayPrivateKeyLabel': '应用私钥（PEM）',
  'admin.schemaField.alipayPrivateKeyHelp':
    'PKCS8 / PKCS1 RSA 私钥，用于请求 RSA2 签名',
  'admin.schemaField.alipayPublicKeyLabel': '支付宝公钥（PEM）',
  'admin.schemaField.alipayPublicKeyHelp':
    '用于验签网关响应；留空跳过验签（不推荐）',
  'admin.schemaField.alipayGatewayLabel': '网关地址',
  'admin.schemaField.alipayGatewayHelp':
    '留空默认 https://openapi.alipay.com/gateway.do（沙箱可改填沙箱网关）',
  'admin.schemaField.microsoftTenantLabel':
    'Tenant（common / organizations / 租户 ID）',
  'admin.schemaField.microsoftTenantHelp': '留空默认 common',

  // 消息域 Ext 字段（smtp / aliyun_sms）。
  'admin.schemaField.smtpHostLabel': 'SMTP 服务器',
  'admin.schemaField.smtpPortLabel': '端口',
  'admin.schemaField.smtpPortHelp':
    '465 = 隐式 TLS；其余明文连接并在服务器支持时 STARTTLS 升级',
  'admin.schemaField.smtpFromLabel': '发件人地址',
  'admin.schemaField.smtpFromHelp': '留空使用 SMTP 用户名作为发件地址',
  'admin.schemaField.smtpSignNameLabel': '发件人名称',
  'admin.schemaField.smtpUserLabel': 'SMTP 用户名',
  'admin.schemaField.smtpPasswordLabel': 'SMTP 密码',
  'admin.schemaField.smtpDisableSslLabel': '禁用 STARTTLS',
  'admin.schemaField.smtpDisableSslHelp': '内网自签场景跳过 STARTTLS 升级',
  'admin.schemaField.smtpMetadataHelp':
    'subject.<tpl> / body.<tpl> = 标题与正文模板（{code} 占位）',
  'admin.schemaField.aliyunAccessKeyIdLabel': 'AccessKeyId',
  'admin.schemaField.aliyunAccessKeySecretLabel': 'AccessKeySecret',
  'admin.schemaField.aliyunSignNameLabel': '短信签名',
  'admin.schemaField.aliyunTemplateCodeLabel': '短信模板 ID',
  'admin.schemaField.aliyunIntranetEndpointLabel': '内网 endpoint',
  'admin.schemaField.aliyunMetadataHelp':
    'template_code.<tpl> 按模板键覆盖短信模板 ID',

  // select options 显示名（options 仍是 wire 取值；键 =
  // admin.schemaOption.<fieldKey>.<value>，按字段命名空间取键，避免
  // union_provider 的自定义 provider_key 撞上通用枚举值；未定义键原样显示）。
  // scheme 封闭集（§5.3 代理提供商与出站代理引用约定）：协议名通用，zh / en 同文。
  'admin.schemaOption.scheme.socks5': 'SOCKS5',
  'admin.schemaOption.scheme.http': 'HTTP',
  'admin.schemaOption.scheme.https': 'HTTPS',

  // ---- components/*-----------------------------------------------------------
  'admin.removeAction': '删除',
  'admin.dragSortHandle': '拖拽排序',
  'admin.callbackUrlLabel': '回调地址：',

  // ---- layout/AdminLayout.tsx + routes.tsx + entry.tsx（壳层文案）--------
  'admin.rootTitle': '管理后台',
  'admin.switchToAccount': '切换到个人中心',
  'admin.navProviders': '提供商',
  'admin.navUsers': '用户',
  'admin.navClients': '客户端',
  'admin.navSsoClients': 'SSO 客户端',
  'admin.navOidcClients': 'OIDC 客户端',
  'admin.navTemplates': '模板管理',
  'admin.navSettings': '设置',
  'admin.navAudit': '事件日志',
  'admin.navStatus': '监控',
  'admin.navDecode': '解码工具',
  'admin.newAction': '新建',
  'admin.editAction': '编辑',
  'admin.userDetailTitle': '用户详情',
  'admin.logout': '退出登录',
  'admin.loading': '加载中…',
  'admin.routeNotFound': '页面不存在',
  // 未知路径兜底页的返回链接。
  'admin.backToHome': '返回管理首页',
  'admin.renderError': '页面出现异常，请刷新重试',
  'admin.meAvatarAlt': '管理员头像',

  // ---- pages/{SsoClientsPage,OidcClientsPage}.tsx（客户端族共用）--------
  'admin.clientIdLabel': '客户端标识',
  'admin.clientNameLabel': '展示名',
  'admin.redirectUrisLabel': '回调白名单',
  'admin.scopesLabel': '权限范围',
  'admin.createdAtLabel': '创建时间',
  'admin.updatedAtLabel': '更新时间',
  'admin.actionsLabel': '操作',
  'admin.viewAction': '查看',
  'admin.clientDeleteConfirm': '确定删除客户端「{clientId}」？删除后不可恢复',
  'admin.clientsLoadFailed': '客户端列表加载失败，请刷新重试',
  'admin.createClientAction': '新建客户端',
  'admin.noClients': '暂无客户端',
  'admin.clientDetailTitle': '客户端详情',
  'admin.clientSecretLabel': '客户端密钥',
  'admin.editClientTitle': '编辑客户端「{clientId}」',
  'admin.editClientFallbackTitle': '编辑客户端',
  'admin.clientCreateSuccess':
    '客户端创建成功，密钥由服务端生成，点击「查看」即可获取',
  'admin.clientUpdateSuccess': '已更新客户端「{clientId}」',
  'admin.clientDeleteSuccess': '已删除客户端「{clientId}」',
  'admin.redirectUrisRequired': '回调白名单不能为空（清空后保存将保留原值）',
  'admin.clientIdAutoGenPlaceholder': '留空自动生成',
  'admin.clientNamePlaceholder': '客户端展示名',
  'admin.redirectUriEntryHint': '每条须为 * 或以 http:// / https:// 开头',
  'admin.redirectUriAriaLabel': '回调地址',
  'admin.addRedirectUri': '添加回调地址',
  'admin.redirectUriPlaceholder': 'https://example.com/callback 或 *',
  'admin.noRedirectUrisHint': '暂无回调地址，点击下方按钮添加',
  'admin.clientIdImmutable': '创建后不可修改',
  'admin.newSecretLabel': '新密钥',
  'admin.newSecretPlaceholder': '留空保留原密钥',
  'admin.secretRotateHint': '填写后保存将轮换密钥，请同步更新接入方',
  'admin.cancelAction': '取消',
  'admin.saveAction': '保存',
  'admin.createAction': '创建',
  'admin.createSsoClientTitle': '新建 SSO 客户端',

  // ---- pages/SsoClientsPage.tsx 应用级登录配置（编辑 SideSheet；§5.5）----
  'admin.ssoLoginMethodsLabel': '登录方式',
  'admin.ssoLoginMethodsHint':
    '控制该应用可用的登录方式；全部不选 = 跟随全局配置',
  'admin.ssoMfaRiskHint':
    '注意：已关闭部分两步验证可用因子（短信 / 邮箱验证码 / 通行密钥），仅绑定这些因子的用户将无法登录该应用',
  'admin.ssoAuthProvidersLabel': 'Auth Provider',
  'admin.ssoAuthProvidersHint':
    '细化第三方登录可用渠道；全部不选 = 跟随全局配置',
  'admin.ssoAuthProvidersPlaceholder': '选择该应用可用的 Auth Provider',
  'admin.ssoDefaultRedirectUriLabel': '默认回跳地址',
  'admin.ssoDefaultRedirectUriPlaceholder':
    'https://example.com/callback（须在回调白名单内）',
  'admin.ssoDefaultRedirectUriHint':
    '该地址须命中本客户端回调白名单（支持 * 通配）；仅在登录未携带回跳地址时使用',

  // ---- pages/OidcClientsPage.tsx（OIDC 增量）------------------------------
  'admin.createOidcClientTitle': '新建 OIDC 客户端',
  'admin.tokenTtlLabel': '令牌有效期',
  'admin.accessTokenTtlFieldLabel': '访问令牌有效期（秒）',
  'admin.accessTokenTtlLabel': '访问令牌有效期',
  'admin.refreshTokenTtlFieldLabel': '刷新令牌有效期（秒）',
  'admin.refreshTokenTtlLabel': '刷新令牌有效期',
  'admin.accessTtlIssue': '访问令牌有效期须为 1-{max} 的整数秒',
  'admin.refreshTtlIssue': '刷新令牌有效期须为 1-{max} 的整数秒',
  'admin.scopesRequired': '权限范围不能为空（清空后保存将保留原值）',
  'admin.scopesDefaultHint': '留空使用默认 openid,profile,email',
  'admin.addScope': '添加权限范围',
  'admin.scopePlaceholder': '如 openid',
  'admin.scopesEntryHint': '每条不能为空且不能包含逗号',
  'admin.ttlPlaceholder': '默认 {value}',
  'admin.ttlRangeHint': '1-{max}，留空使用默认 {value}',
  'admin.ttlKeepHint': '1-{max}，留空保存将保留原值',

  // ---- api.ts 模板校验 / 下拉展示--------------------------------------
  'admin.templateKeyRequired': '模板 key 不能为空',
  'admin.templateKeyTooLong': '模板 key 不能超过 {max} 个字符',
  'admin.templateKeyBuiltinConflict': '模板 key 不能与内置模板同名',
  'admin.templateKeyTaken': '模板 key 已被占用，请换一个',
  'admin.templateVarsIssue': '模板变量须为合法的 JSON 对象',
  'admin.templateUnspecified': '不指定（默认文件壳）',

  // ---- pages/TemplatesPage.tsx 模板管理-------------------------------
  'admin.templateKeyLabel': '模板 key',
  'admin.templateNameLabel': '显示名',
  'admin.templateContentLabel': '模板内容',
  'admin.templateKeyPlaceholder': '如 my_login_theme',
  'admin.templateNamePlaceholder': '模板显示名',
  'admin.templateContentHint': '创建后模板 key 不可修改',
  'admin.templateKeyImmutable': '创建后不可修改',
  'admin.templatesLoadFailed': '模板列表加载失败，请刷新重试',
  'admin.noTemplates': '暂无自定义模板',
  'admin.createTemplateAction': '新建模板',
  'admin.createTemplateTitle': '新建模板',
  'admin.editTemplateTitle': '编辑模板「{name}」',
  'admin.templateDeleteConfirm': '确定删除模板「{name}」？删除后不可恢复',
  'admin.templateCreateSuccess': '模板创建成功',
  'admin.templateUpdateSuccess': '模板「{name}」已更新',
  'admin.templateDeleteSuccess': '模板「{name}」已删除',
  'admin.templateSearchPlaceholder': '搜索模板显示名',
  'admin.templateSearchAriaLabel': '搜索模板',

  // ---- pages/{SsoClientsPage,OidcClientsPage}.tsx 模板表单------------
  'admin.templateLabel': '模板',
  'admin.templateVarsLabel': '模板变量',
  'admin.templateVarsPlaceholder': '{"key": "value"}',
  'admin.templateVarsHint': '填写 JSON 对象文本；留空按空对象 {} 注入',
  'admin.templateSelectHint':
    '可选内置 login 或自定义模板；不指定则使用默认文件壳',

  // ---- pages/{UsersPage,UserDetailPage}.tsx 用户族----------------
  'admin.usernameLabel': '用户名',
  'admin.nicknameLabel': '昵称',
  'admin.phoneLabel': '手机号',
  'admin.emailLabel': '邮箱',
  'admin.statusLabel': '状态',
  'admin.lastLoginLabel': '最后登录',
  'admin.userSearchPlaceholder': '搜索用户名 / 昵称 / 手机号 / 邮箱',
  'admin.userSearchAriaLabel': '搜索用户',
  'admin.searchAction': '搜索',
  'admin.usersLoadFailed': '用户列表加载失败，请刷新重试',
  'admin.noUsers': '暂无用户',
  'admin.resetPasswordAction': '重置密码',
  'admin.resetPasswordTitle': '重置「{username}」的密码',
  'admin.resetPasswordHint':
    '新密码需满足系统密码策略，重置成功后原会话全部失效，请将新密码转交该用户。',
  'admin.newPasswordLabel': '新密码',
  'admin.newPasswordPlaceholder': '输入新密码',
  'admin.confirmPasswordLabel': '确认新密码',
  'admin.confirmPasswordPlaceholder': '再次输入新密码',
  'admin.passwordMismatchError': '两次输入的密码不一致',
  'admin.confirmResetAction': '确认重置',
  'admin.resetPasswordSuccess':
    '已重置「{username}」的密码，请将新密码转交该用户',
  'admin.unlockAction': '解除登录限制',
  'admin.unlockConfirm': '确定解除「{username}」的登录限制？',
  'admin.unlockSuccess': '已解除「{username}」的登录限制',
  'admin.userStatusToggleColumn': '禁用/启用',
  'admin.userDetailLoadFailed': '用户详情加载失败，请刷新重试',
  'admin.basicInfoSection': '基本信息',
  'admin.noUserData': '无用户数据',
  'admin.mfaRequiredLabel': '两步验证',
  'admin.verifiedTag': '（已验证）',
  'admin.yesText': '是',
  'admin.noText': '否',
  'admin.mfaStatusSection': 'MFA 状态',
  'admin.mfaRequiredNotice': '用户已开启两步验证',
  'admin.mfaBoundSummary': '已绑定：{factors}',
  'admin.mfaNoneBound': '未绑定任何二次因子',
  'admin.credentialsSection': '凭证概览',
  'admin.noCredentials': '暂无凭证',
  'admin.credentialEnabled': '启用',
  'admin.credentialDisabled': '禁用',
  'admin.boundAt': '绑定于 {time}',
  'admin.credentialLastUsed': ' · 最近使用 {time}',
  'admin.bindingsSection': '三方绑定',
  'admin.noBindings': '暂无第三方绑定',
  'admin.unbindConfirm': '确定解绑「{providerKey}」？解绑后无法再用它登录。',
  'admin.unbindAction': '解绑',
  'admin.unbindSuccess': '已解绑「{providerKey}」',
  'admin.loginLogSection': '登录日志',
  'admin.loginLogLoadFailed': '登录日志加载失败，请刷新重试',
  'admin.noLoginRecords': '暂无登录记录',
  'admin.timeColumn': '时间',
  'admin.eventColumn': '事件',
  'admin.methodColumn': '方式',
  'admin.deviceUaColumn': '设备（UA）',

  // ---- UserDetailPage 用户详情编辑态 / 救援写操作----------------------
  'admin.usernameReservedPrefixHint':
    '用户名不能以 deleted_ 开头，该前缀为系统保留',
  'admin.avatarUrlLabel': '头像地址',
  'admin.genderLabel': '性别',
  'admin.birthdayLabel': '生日',
  'admin.localeLabel': '语言区域',
  'admin.timezoneLabel': '时区',
  'admin.extraLabel': '扩展资料（JSON 对象）',
  'admin.extraPlaceholder': '{"key": "value"}',
  'admin.genderUnspecified': '保密',
  'admin.genderMale': '男',
  'admin.genderFemale': '女',
  'admin.editNicknameIssue': '昵称最多 12 个字',
  'admin.editAvatarIssue': '头像链接最多 120 个字符',
  'admin.editGenderIssue': '性别只能取保密 / 男 / 女',
  'admin.editBirthdayIssue': '生日须为 YYYY-MM-DD 格式',
  'admin.editExtraIssue': '扩展资料须为合法 JSON 对象',
  'admin.editPhoneIssue': '手机号格式不正确',
  'admin.editEmailIssue': '邮箱格式不正确',
  'admin.editProfileSuccess': '资料已保存',
  'admin.editContactSuccess': '联系方式已保存',
  'admin.noEditChanges': '资料无改动，无需提交',
  'admin.contactEditConfirm':
    '确定修改联系方式？写入的手机号 / 邮箱将标记为已验证，且该用户所有会话将失效，须重新登录。',
  'admin.mfaEnableAction': '开启两步验证',
  'admin.mfaDisableAction': '关闭两步验证',
  'admin.mfaEnableConfirm': '确定为「{username}」开启两步验证？',
  'admin.mfaDisableConfirm':
    '确定关闭「{username}」的两步验证？该用户所有会话将失效，须重新登录。',
  'admin.mfaEnableSuccess': '已开启两步验证',
  'admin.mfaDisableSuccess': '已关闭两步验证',
  'admin.unbindTotpAction': '解绑动态口令',
  'admin.unbindTotpConfirm':
    '确定解绑「{username}」的动态口令？该用户所有会话将失效，须重新登录。',
  'admin.unbindTotpSuccess': '已解绑动态口令',
  'admin.resetRecoveryCodesAction': '重置恢复码',
  'admin.resetRecoveryCodesConfirm':
    '确定重置「{username}」的恢复码？旧恢复码将立即作废。',
  'admin.resetRecoveryCodesSuccess': '恢复码已重置',
  'admin.credentialEnableAction': '启用',
  'admin.credentialDisableAction': '停用',
  'admin.credentialDeleteAction': '删除',
  'admin.credentialDisableConfirm': '确定停用「{kind}」凭证？',
  'admin.credentialDeleteConfirm':
    '确定删除「{kind}」凭证？该用户所有会话将失效，须重新登录。',
  'admin.credentialEnabledSuccess': '凭证已启用',
  'admin.credentialDisabledSuccess': '凭证已停用',
  'admin.credentialDeletedSuccess': '凭证已删除',

  // ---- 删除用户危险操作 + 列表四维度筛选（§5.4）---------------------------
  'admin.deleteUserAction': '删除用户',
  'admin.deleteUserTitle': '删除用户「{username}」',
  'admin.deleteUserWarning':
    '删除后不可恢复：该用户将被禁用，用户名改写为 deleted_ 前缀标记，手机号 / 邮箱 / 资料 / 凭证 / 三方绑定全部清空，全部会话与令牌立即失效。',
  'admin.deleteUserConfirmLabel': '请输入用户名「{username}」确认删除',
  'admin.deleteUserInputAriaLabel': '输入用户名以确认删除',
  'admin.deleteUserConfirmAction': '确认删除',
  'admin.deleteUserSuccess': '已删除用户「{username}」',
  'admin.deletedUserNotice':
    '该用户已删除（用户名以 deleted_ 开头）：资料已匿名化、凭证已清空，所有写操作不可用。',
  'admin.deletedUserTag': '已删除',
  'admin.filterAnyOption': '不限',
  'admin.createdFromFilterPlaceholder': '创建时间（起）',
  'admin.createdToFilterPlaceholder': '创建时间（止）',
  'admin.lastLoginFromFilterPlaceholder': '最后登录（起）',
  'admin.lastLoginToFilterPlaceholder': '最后登录（止）',
  'admin.mfaFilterPlaceholder': '两步验证',
  'admin.mfaFilterEnabled': '已开启',
  'admin.mfaFilterDisabled': '已关闭',
  'admin.credentialFilterPlaceholder': '凭证类型',
  'admin.resetFiltersAction': '重置筛选',

  // ---- pages/AuditPage.tsx----------------------------------------
  'admin.auditPresetAll': '全部事件',
  'admin.auditPresetLoginRecords': '登录记录',
  'admin.eventTypeColumn': '事件类型',
  'admin.actorColumn': '操作者',
  'admin.targetUserColumn': '对象用户',
  'admin.clientColumn': '客户端',
  'admin.authMethodColumn': '认证方法',
  'admin.sourceIpColumn': '来源 IP',
  'admin.actionTargetColumn': '操作目标',
  'admin.detailColumn': '详情',
  'admin.occurredAtColumn': '发生时间',
  'admin.auditLoadFailed': '事件日志加载失败，请刷新重试',
  'admin.eventFilterPlaceholder': '事件类型：全部',
  'admin.eventFilterAriaLabel': '按事件类型筛选',
  'admin.actorFilterPlaceholder': '操作者类型：全部',
  'admin.actorFilterAriaLabel': '按操作者类型筛选',
  'admin.noEvents': '暂无事件记录',

  // ---- pages/AuditPage.tsx 四项筛选（actorId/userId/from/to）----
  'admin.actorIdFilterPlaceholder': '操作者 ID',
  'admin.actorIdFilterAriaLabel': '按操作者 ID 筛选',
  'admin.userIdFilterPlaceholder': '用户 ID',
  'admin.userIdFilterAriaLabel': '按用户 ID 筛选',
  'admin.fromFilterPlaceholder': '开始时间',
  'admin.toFilterPlaceholder': '结束时间',

  // ---- pages/AuditPage.tsx「敏感操作」预设（五类封闭集）--
  'admin.auditPresetSensitiveRecords': '敏感操作',
  'admin.auditPresetSensitiveHint':
    '敏感操作：改密、重置密码、解绑、启用/停用两步验证',

  // ---- pages/{ProvidersPage,ProviderEditPage}.tsx 提供商族--------
  'admin.providerColumnDisplayName': '显示名',
  'admin.providerColumnKey': '标识',
  'admin.providerColumnCategory': '类别',
  'admin.providerColumnType': '类型',
  // type=proxy 展示名（§5.3 代理提供商与出站代理引用约定）。
  'admin.providerType.proxy': '出站代理',
  // category 展示名，键集 = 后端 Category* 常量全集（auth|union|sms|email|
  // captcha|storage|proxy）；缺键由页面回显 wire 值，不在此兜底。
  'admin.providerCategory.auth': '认证授权',
  'admin.providerCategory.union': 'Union ID 归并',
  'admin.providerCategory.sms': '短信服务',
  'admin.providerCategory.email': '邮件服务',
  'admin.providerCategory.captcha': '人机校验',
  'admin.providerCategory.storage': '存储服务',
  'admin.providerCategory.proxy': '出站代理',
  'admin.providerColumnPolicyTags': '策略标签',
  'admin.providerColumnSortOrder': '排序',
  'admin.providersLoadFailed': '提供商列表加载失败，请刷新重试',
  'admin.providersDragDisabledNote':
    '提供商数量超过单页上限（100），拖拽排序已停用',
  'admin.providerSortFilterDisabledNote':
    '筛选中不可拖拽排序，清空筛选后可排序',
  'admin.providerDragSortLabel': '拖拽调整提供商排序',
  'admin.noProviders': '暂无提供商',
  'admin.providerEnableSuccess': '已启用「{name}」',
  'admin.providerDisableSuccess': '已停用「{name}」',
  'admin.providerSortSuccess': '提供商排序已保存',
  'admin.providerDeleteConfirm': '确定删除提供商「{name}」？删除后不可恢复',
  'admin.providerDeleteSuccess': '已删除提供商「{name}」',
  'admin.providerSortAction': '排序',
  'admin.providerSortTitle': '提供商排序',
  'admin.createProviderAction': '新建提供商',
  'admin.providerKeyTaken': '唯一标识已被占用，请换一个',
  'admin.providerTypeRequired': '请先选择提供商类型',
  'admin.testTargetRequired': '请输入测试接收目标',
  'admin.testSent': '已发送，请查收',
  'admin.testNote': '使用已保存的配置发送一条测试消息',
  'admin.iconPreviewAlt': '图标预览',
  'admin.providerTypesLoadFailed': '提供商类型列表加载失败，请刷新重试',
  'admin.providerLoadFailed': '提供商加载失败，请刷新重试',
  'admin.schemaLoadFailed': '表单结构加载失败，请刷新重试',
  'admin.editProviderTitle': '编辑提供商',
  'admin.createProviderTitle': '新建提供商',
  'admin.providerTypeLabel': '类型',
  'admin.selectTypePlaceholder': '请选择类型',
  'admin.sendTestAction': '发送测试',
  'admin.testTargetAriaLabel': '测试接收目标',

  // ---- pages/{SettingsPage,StatusPage,DecodePage}.tsx-------------
  'admin.settingsTitle': '系统设置',
  // ---- SettingsPage 分 Tab（4 组 / 每 Tab 独立保存）----
  'admin.settingsTabSite': '站点与账号',
  'admin.settingsTabPassword': '密码与防护',
  'admin.settingsTabLogin': '登录与会话',
  'admin.settingsTabDeploy': '部署与集成',
  'admin.settingsTabUnsaved': '该页签有未保存的修改',
  'admin.settingsTabSaveAction': '保存本页',
  'admin.settingsSaved': '设置已保存',
  'admin.settingsLoadFailed': '系统设置加载失败，请刷新重试',
  'admin.saveSettingsAction': '保存设置',
  'admin.settingsDiffTitle': '确认保存设置',
  'admin.settingsDiffSummary': '将变更 {count} 项设置：',
  'admin.settingsDiffEmptyValue': '（空）',
  'admin.statusLoadFailed': '监控数据加载失败，请刷新重试',
  'admin.statusHint':
    '队列长度不含已取出、尚未落库的批次；flush 耗时为 0 表示自启动以来尚未发生过批量落库',
  'admin.statusQueueLength': '队列长度',
  'admin.statusDropped': '累计丢弃条数',
  'admin.statusFlushMs': '最近 flush 耗时（毫秒）',
  'admin.refreshAction': '刷新',
  'admin.decodePurposeLogin': 'login_token（登录令牌）',
  'admin.decodePurposeSession': 'session_token（会话令牌）',
  'admin.decodePurposeCookie': 'al_login_state（登录态 Cookie）',
  'admin.decodeResultHint':
    '解码结果为令牌内部载荷（Struct 原样透传），仅供排障参考，请勿外泄令牌与载荷内容。',
  'admin.decodePurposeAriaLabel': '解码口径',
  'admin.decodeTokenPlaceholder': '粘贴待解码的令牌原文',
  'admin.decodeTokenAriaLabel': '待解码令牌',
  'admin.decodeAction': '解码',
  // ---- 编辑未保存保护（Modal.confirm 二次确认）----
  'admin.unsavedChangesTitle': '放弃未保存的修改？',
  'admin.unsavedChangesContent': '当前编辑尚未保存，关闭后修改将丢失。',
};

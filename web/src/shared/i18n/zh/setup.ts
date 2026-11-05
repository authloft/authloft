/**
 * zh-CN 安装域文案模块（分域底座）：setup 域的键由后续域收口在
 * 本模块内追加，经 zh-CN.ts 尾部 spread 汇入总字典。
 *
 * 禁止给本对象加 Record<string, string> 等索引类型注解：会被 spread 进
 * 总字典，把 I18nMessages 弱化成索引签名，破坏 en/zh 编译期键对齐。
 */
export const setup = {
  // ---- §13 域内业务码 + Connect 标准码 → 展示文案（setup/api.ts setupMessage 表）----
  // not_found / already_exists 的 zh 文案与 errors.code.* 逐字相同，直接复用既有键。
  'setup.error.configInvalid':
    '配置文件校验失败：内容不完整、非法或缺少 sign_key，请修正后重新上传',
  'setup.error.dbUnreachable': '数据库连接失败，请检查连接串后重试',
  'setup.error.redisUnreachable': 'Redis 连接失败，请检查地址与密码后重试',
  'setup.error.migrationFailed':
    '数据库初始化（迁移执行）失败，请检查数据库状态后重试',
  'setup.error.adminMissing': '版本已最新但缺少管理员账号，请改走全新安装',
  'setup.error.usernameInvalid': '管理员用户名不符合规则',
  'setup.error.passwordWeak': '密码强度不足，请更换更复杂的密码',
  'setup.error.invalidArgument': '请求参数错误',
  'setup.error.unauthenticated': '请求未授权',
  'setup.error.permissionDenied': '请求被拒绝',
  'setup.error.resourceExhausted': '请求过于频繁，请稍后重试',
  'setup.error.internal': '服务器内部错误，请稍后重试',
  'setup.error.unavailable': '网络错误，请稍后重试',
  'setup.error.unknown': '操作失败，请检查输入后重试',

  // ---- 重启页（§13.4，上传配置 / 全新安装两条路径共用）----
  'setup.restartingTitle': '重启中',
  'setup.restartingNotice':
    '程序已退出，请手动重新运行；如使用 Docker 或 systemd，会自动重启',
  'setup.restartTimeoutNotice': '重启超时，请检查服务状态',
  'setup.waitingRestart': '等待服务重启…',

  // ---- 上传已有配置页（路径 A，§13.2）----
  'setup.uploadConfigTitle': '上传已有配置',
  'setup.uploadConfigIntro':
    '粘贴或选择已有的 config.yaml 全文；系统将按序完成配置校验、数据库 / Redis 连接检查与初始化，成功后自动进入重启。',
  'setup.uploadConfigPlaceholder': 'config.yaml 全文',
  'setup.unreadableFile': '无法读取所选文件',
  'setup.adminMissingHint':
    '该配置对应版本已最新但缺少管理员账号，需改走全新安装创建管理员。',
  'setup.initializing': '正在初始化…',
  'setup.startInitialize': '开始初始化',
  'setup.switchToInstall': '改走全新安装',

  // ---- 全新安装页（路径 B，§13.3；rpId 标签「WebAuthn RP ID」无中文不设键）----
  'setup.installTitle': '全新安装',
  'setup.installIntro':
    '填写数据库与 Redis 连接信息及管理员账号；成功后自动进入重启。',
  'setup.fieldDbDsn': '数据库连接串（DSN）',
  'setup.fieldRedisAddr': 'Redis 地址',
  'setup.fieldRedisPassword': 'Redis 密码',
  'setup.fieldRedisDb': 'Redis 库号',
  'setup.fieldRoot': '主域名',
  'setup.fieldAdminUsername': '管理员用户名',
  'setup.fieldAdminPassword': '管理员密码',
  'setup.hintRedisDb': '默认 0',
  'setup.hintRoot': '默认取当前站点',
  'setup.hintRpId': '默认取当前域名',
  'setup.requiredMark': '（必填）',
  'setup.installing': '正在安装…',
  'setup.startInstall': '开始安装',

  // ---- 入口页（模式判定 + 两条路径入口；两个按钮复用 uploadConfigTitle / installTitle）----
  'setup.checkingMode': '正在检测运行模式…',
  'setup.initTitle': 'Authloft 初始化',
  'setup.setupModeDetected': '检测到首次启动（setup 模式），请选择初始化方式：',
};

/**
 * zh-CN 登录域文案模块（分域底座）：login 域的键由后续域收口在
 * 本模块内追加，经 zh-CN.ts 尾部 spread 汇入总字典。
 *
 * 禁止给本对象加 Record<string, string> 等索引类型注解：会被 spread 进
 * 总字典，把 I18nMessages 弱化成索引签名，破坏 en/zh 编译期键对齐。
 */
export const login = {
  // ---- 容器 / 方式列表（LoginContainer、MethodTabs）------------------------
  'login.title': '登录',
  'login.register': '注册',
  'login.forgotPassword': '忘记密码',
  'login.noMethods': '暂无可用登录方式',
  'login.selectMethodHint': '请选择登录方式',
  'login.mfaSelectHint': '请选择二次验证方式',
  // 评审 P0-1：next / mfa 分支「返回方式列表」入口。
  'login.backToMethods': '返回方式列表',
  'login.pollPlaceholder': '扫码流程即将支持',
  'login.redirecting': '登录成功，正在跳转…',
  // 评审 P1-7：footer 语言切换（语言名保持原生写法，双语同值）。
  'login.langZh': '中文',
  'login.langEn': 'EN',
  // ---- 注册页（RegisterPage）----------------------------------------------
  'login.noRegisterMethods': '暂无可用注册方式',
  'login.nextStep': '下一步',
  'login.resend': '重新发送',
  'login.resendCountdown': '{seconds} 秒后可重发',
  'login.usernameHint': '用户名须为 5-20 位字母、数字或下划线',
  'login.registerSuccess': '注册成功，正在跳转…',
  'login.codeLabel': '验证码',
  'login.usernameLabel': '用户名',
  'login.passwordLabel': '密码',
  // 评审 P1-3：注册 / 重置确认密码（只本地比对，不进 payload）。
  'login.confirmPasswordLabel': '确认密码',
  'login.errPasswordMismatch': '两次输入的密码不一致',
  'login.attemptsLeft': '还可尝试 {count} 次',
  'login.registerMethodPassword': '用户名密码注册',
  'login.registerMethodOtpSms': '手机号注册',
  'login.registerMethodOtpEmail': '邮箱注册',
  // ---- 重置页（ResetPage）--------------------------------------------------
  'login.reset': '重置密码',
  'login.newPasswordLabel': '新密码',
  'login.resetMethodOtpSms': '手机号找回',
  'login.resetMethodOtpEmail': '邮箱找回',
  'login.resetSuccess': '密码重置成功，请使用新密码登录',
  'login.goLogin': '去登录',
  // ---- 绑定（BindingPage、BindingChoice）-----------------------------------
  'login.createAccount': '创建账号',
  'login.accountCreated': '账号创建成功，正在跳转…',
  'login.bindingIdentity': '登录方式「{name}」',
  'login.createAccountOption': '创建新账号',
  'login.exitBinding': '退出并使用其他账号登录',
  'login.channelSignupClosed': '该渠道未开放注册',
  // ---- OAuth 回调页（OAuthCallbackPage）------------------------------------
  'login.processing': '正在处理，请稍候…',
  'login.backToLogin': '返回登录',
  // ---- 因子表单（factors/：OTPForm、PasswordForm、WebAuthnButton、
  //      RecoveryCodeForm、ProviderButtons）------------------------------------
  'login.submit': '登录',
  // 提交 / 发送在途的按钮文案（与 Spinner 内嵌同款帧）。
  'login.submitting': '登录中…',
  'login.sending': '发送中…',
  'login.sendCode': '发送验证码',
  'login.codeWillBeSentTo': '验证码将发送至 {target}',
  'login.capsLockOn': '已开启大写锁定（Caps Lock）',
  'login.passkeySignIn': '使用通行密钥登录',
  'login.passkeyVerify': '验证',
  'login.passkeyCancelled': '已取消通行密钥验证',
  'login.passkeyFailed': '通行密钥验证失败，请重试',
  // 评审 P2-9：第三方跳转失败文案带 provider 展示名。
  'login.oauthRedirectFailed': '无法跳转 {provider}，请重试',
  // ---- 步骤杂项（steps/、routes、entry）--------------------------------------
  // 「请刷新重试」复用 common.refreshAndRetry（收口，login.refreshRetry 已删）。
  'login.qrNeedCaptcha': '请先完成人机校验',
  'login.fetchQrcodeAction': '获取二维码',
  'login.redirectInProgress': '正在跳转…',
  'login.initMissing': '初始化数据缺失，请刷新重试',
  'login.routeNotFound': '页面不存在',
  'login.renderError': '页面出现异常，请刷新重试',

  // ---- 后端下发字段文案（sso.v1.Field.label / 注入快照 SnapshotField.label）----
  // 登录流程的 factor.Field、pages.SnapshotField、orchestrator.FieldSnapshot
  // 只下发 login.field.* 键，文案一律放本字典；由 shared/components/
  // FieldRenderer 渲染期 t() 解析。与 admin 侧 admin.schemaField.* 同口径，
  // 但按分域收敛到 login 模块。缺键时 t() 回显键本身（旧版后端的中文字面量
  // 也按原文显示），故 zh 译文与迁移前逐字一致。
  'login.field.usernameOrIdentifier': '用户名/邮箱/手机号',
  'login.field.password': '密码',
  'login.field.captcha': '人机校验',
  'login.field.otpCode': '验证码',
  'login.field.recoveryCode': '恢复码',
  'login.field.totpCode': '动态口令',
  'login.field.phone': '手机号',
  'login.field.email': '邮箱',
  'login.field.username': '用户名',
};

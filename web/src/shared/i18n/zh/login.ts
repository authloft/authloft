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
  'login.pollPlaceholder': '扫码流程即将支持',
  'login.refreshRetry': '请刷新重试',
  'login.redirecting': '登录成功，正在跳转…',
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
  'login.bindUnavailable': '绑定功能即将上线',
  'login.mfaPlaceholder': '登录需要二次验证，请返回重新登录',
  'login.backToLogin': '返回登录',
  // ---- 因子表单（factors/：OTPForm、PasswordForm、WebAuthnButton、
  //      RecoveryCodeForm、ProviderButtons）------------------------------------
  'login.submit': '登录',
  'login.sendCode': '发送验证码',
  'login.codeWillBeSentTo': '验证码将发送至 {target}',
  'login.capsLockOn': '已开启大写锁定（Caps Lock）',
  'login.passkeySignIn': '使用通行密钥登录',
  'login.passkeyVerify': '验证',
  'login.passkeyCancelled': '已取消通行密钥验证',
  'login.passkeyFailed': '通行密钥验证失败，请重试',
};

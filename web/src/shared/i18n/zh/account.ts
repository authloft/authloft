/**
 * zh-CN 安全中心域文案模块（分域底座）：account 域的键由后续域
 * 收口在本模块内追加，经 zh-CN.ts 尾部 spread 汇入总字典。
 *
 * 禁止给本对象加 Record<string, string> 等索引类型注解：会被 spread 进
 * 总字典，把 I18nMessages 弱化成索引签名，破坏 en/zh 编译期键对齐。
 */
export const account = {
  // ---- 布局 / 路由 / entry ------------------------------------------------
  'account.personalCenter': '个人中心',
  'account.profileTitle': '个人资料',
  'account.securityTitle': '安全中心',
  'account.auditTitle': '登录日志',
  'account.logout': '退出登录',
  'account.appTitle': 'Authloft 用户中心',
  'account.routeNotFound': '页面不存在',
  'account.renderError': '页面出现异常，请刷新重试',

  // ---- SecurityPage（「通行密钥」卡片题复用 factors.webauthn）-------------
  'account.configLoadFailed': '配置加载失败，请刷新重试',
  'account.close': '关闭',
  'account.twoFactorTitle': '两步验证',
  'account.mfaEnabledStatus': '已开启两步验证',
  'account.mfaDisabledStatus': '未开启两步验证',
  'account.mfaRequiredNote': '（策略强制开启，不可关闭）',
  'account.trustDeviceNote': '信任设备：暂不支持（每次登录均需二次验证）',
  'account.passwordCardTitle': '登录密码',
  'account.contactCardTitle': '联系方式',
  'account.thirdpartyCardTitle': '第三方账号',

  // ---- ProfilePage ---------------------------------------------------------
  'account.profileLoadFailed': '资料加载失败，请刷新重试',
  'account.avatarAlt': '用户头像',
  'account.usernameLabel': '用户名',
  'account.nicknameLabel': '昵称',

  // ---- api.ts 展示纯函数（未知异常兜底复用 errors.code.unknown）-----------
  'account.mfaNotBound': '尚未绑定',
  'account.mfaLastUsedAt': ' · 最近使用 {time}',
  'account.boundAt': '绑定于 {time}',
  'account.mfaTarget': '目标 {target}',
  'account.mfaCredentialCount': '已绑定 {count} 个凭据',
  'account.mfaRemainingCount': '剩余 {count} 个可用',
  'account.bindTargetTaken': '该账号已被其他账号绑定',
  'account.bindSuccess': '第三方账号绑定成功',

  // ---- ThirdPartyList（「请刷新重试」复用 common.refreshAndRetry）---------
  'account.unionTag': '联合身份',
  'account.unbindConfirm': '确定解绑「{name}」？解绑后无法再用它登录。',
  'account.unbindAction': '解绑',
  'account.bindAction': '绑定',
  'account.thirdpartyLoadFailed': '第三方账号加载失败，请刷新重试',
  'account.thirdpartyEmpty': '尚未绑定第三方账号',
  'account.thirdpartyAvailableTitle': '可绑定的第三方账号',

  // ---- RecoveryCodePanel ---------------------------------------------------
  'account.recoveryNotice': '恢复码仅展示一次，请复制保存到安全的地方',
  'account.recoveryIssuedAt': '签发时间：{time}',
  'account.recoveryRegenerateConfirm': '重新生成将作废全部现有恢复码，确定继续？',
  'account.recoveryRegenerate': '重新生成',

  // ---- MfaMethodList（因子名复用 factors.*，「恢复码」弹窗题复用
  //      factors.recovery_code，「绑定」按钮复用 account.bindAction，「尚未绑定」
  //      复用 account.mfaNotBound，「 · 最近使用 {time}」复用 account.mfaLastUsedAt）--
  'account.factorTotp': 'TOTP 动态码',
  'account.factorBoundTag': '已绑定',
  'account.factorUnboundTag': '未绑定',
  'account.mfaEnableFactorAria': '启用{factor}',
  'account.mfaBindPhoneHint': '请先在「联系方式」中绑定手机号',
  'account.mfaBindEmailHint': '请先在「联系方式」中绑定邮箱',
  'account.mfaBindWebauthnHint': '请先在下方「通行密钥」中注册',
  'account.mfaLocked': '策略要求开启两步验证，不可全部关闭',
  'account.mfaShowDetails': '绑定明细',
  'account.mfaHideDetails': '收起明细',
  'account.mfaDetailsLoadFailed': '明细加载失败，{error}',
  'account.viewRecoveryCodes': '查看恢复码',
  'account.recoveryIssuedAtLabel': '恢复码签发时间',
  'account.recoveryLoadFailed': '恢复码加载失败',

  // ---- WebauthnList------------------------------------------------------------
  'account.webauthnLabelPlaceholder': '为通行密钥命名（可选）',
  'account.webauthnRegisterAction': '注册通行密钥',
  'account.webauthnCancelled': '已取消通行密钥注册',
  'account.webauthnRegisterFailed': '通行密钥注册失败，请重试',
  'account.webauthnLoadFailed': '通行密钥加载失败，请刷新重试',
  'account.webauthnEmpty': '尚未注册通行密钥',
  'account.webauthnUnsupported': '当前浏览器或设备不支持通行密钥',
  'account.saveAction': '保存',
  'account.cancelAction': '取消',
  'account.unnamedCredential': '未命名',
  'account.webauthnAddedAt': '添加于 {time}',
  'account.webauthnRenameAction': '重命名',
  'account.webauthnDeleteConfirm': '确定删除「{name}」？删除后无法用它登录。',
  'account.deleteAction': '删除',

  // ---- ContactBindForm（「请完成人机校验」复用 errors.status.captcha_required，
  //      「邮箱」kind 标签复用 channels.email）----------------------------------
  'account.phoneLabel': '手机号',
  'account.bindInvalidPhone': '请输入正确的手机号',
  'account.bindInvalidEmail': '请输入正确的邮箱',
  'account.bindCodeInvalid': '请输入 {count} 位数字验证码',
  'account.bindDone': '{kind}绑定成功',
  'account.bindContinue': '继续绑定 / 换绑',
  'account.bindCodeSentToPrefix': '验证码已发送至',
  'account.bindCodeAria': '{kind}绑定验证码',
  'account.bindConfirmAction': '确认绑定',
  'account.bindResendAction': '重新发送',
  'account.phonePlaceholder': '请输入手机号',
  'account.emailPlaceholder': '请输入邮箱',
  'account.sendCodeAction': '发送验证码',

  // ---- ThirdPartyBindDialog---------------------------------------------------
  'account.qrNeedCaptcha': '请先完成人机校验',
  'account.fetchQrcodeAction': '获取二维码',
  'account.qrBindHint': '扫码后将绑定到当前账号',
  'account.scanBindTitle': '扫码绑定',
  'account.bindNameTitle': '绑定{name}',

  // ---- PasswordChangeForm-----------------------------------------------------
  'account.currentPasswordRequired': '请输入当前密码',
  'account.currentPasswordIncorrect': '当前密码不正确',
  'account.passwordChangedDone': '密码修改成功，已退出登录，请重新登录',
  'account.currentPasswordLabel': '当前密码',
  'account.newPasswordLabel': '新密码',
  'account.changePasswordAction': '修改密码',
  'account.setPasswordAction': '设置密码',

  // ---- AvatarUploader（「用户头像」alt 复用 account.avatarAlt）-------------
  'account.uploadProgress': '上传中 {percent}%',
  'account.avatarChooseFileAria': '选择头像文件',
  'account.avatarUploadAction': '上传头像',

  // ---- TotpBindDialog（「重试」复用 common.retry，「TOTP 动态码」
  //      aria-label 复用 account.factorTotp）----------------------------------
  'account.totpCodeInvalid': '请输入 {count} 位数字动态码',
  'account.totpBindTitle': '绑定 TOTP 动态码',
  'account.totpBindSuccess': 'TOTP 绑定成功。以下 10 个恢复码仅展示一次，请妥善保存',
  'account.totpDoneAction': '我已保存，完成绑定',
  'account.totpManualHint': '请使用验证器应用（如 Google Authenticator）手动输入密钥或粘贴 otpauth 地址完成添加，然后输入当前 6 位动态码验证',
  'account.totpSecretLabel': '密钥',
  'account.totpOtpauthLabel': 'otpauth 地址',
  'account.totpVerifyAction': '验证并完成绑定',

  // ---- EventLogTable-----------------------------------------------------------
  'account.logTimeColumn': '时间',
  'account.logMethodColumn': '方式',
  'account.logUaColumn': '设备（UA）',
  'account.logLoadFailed': '登录记录加载失败，请刷新重试',
  'account.logEmpty': '暂无登录记录',
};

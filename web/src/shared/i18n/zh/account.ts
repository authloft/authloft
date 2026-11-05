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
};

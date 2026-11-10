/**
 * zh-CN 文案字典（docs/前端架构.md §3.4 行 343）：
 * - 因子名（接口文档 §1.10 因子 × 步骤序列表；`device` 为内部因子不出现在
 *   注入快照与任何对外响应，故不设键）；
 * - 按 status 组织的失败文案（接口文档 §1.6 封闭集合；键口径与
 *   shared/api/errors.ts 的 i18nKey 一致：`errors.status.<status>` /
 *   `errors.code.<code>`，不造第二套）；
 * - 渠道名（兜底文案；业务展示优先用后端下发的 display_name）；
 * - shared 组件公共文案（common.*，避免组件内硬编码文案，§9 第 3 条）。
 *
 * 本文件是字典形状（键集）的唯一定义源：其他语言包以 I18nMessages 类型
 * 约束，两套 key 全量对齐由编译期强制（缺译 / 多译都过不了 tsc）。
 *
 * 分域结构：login/setup/account/admin 域键在各域模块（zh/<域>.ts）
 * 内维护、于本对象尾部 spread 汇入，供后续域收口并行扩展。
 */
import { login } from './zh/login';
import { setup } from './zh/setup';
import { account } from './zh/account';
import { admin } from './zh/admin';

export const zhCN = {
  // ---- shared 组件公共文案 ------------------------------------------------
  'common.copy': '复制',
  'common.copied': '已复制',
  'common.retry': '重试',
  'common.remainingSeconds': '剩余 {seconds} 秒',
  'common.remainingAttempts': '剩余 {count} 次尝试机会',
  'common.reveal': '显示',
  'common.hide': '隐藏',
  'common.selectPlaceholder': '请选择',
  'common.pwdTooShort': '长度至少 8 位',
  'common.pwdTooLong': '长度至多 64 位',
  'common.pwdNoWhitespace': '不能包含空白字符',
  'common.pwdNeedClasses': '须包含大写、小写、数字中的 3 类',
  'common.pwdNoUsername': '不能包含用户名',
  'common.pwdNotSameAsIdentifier': '不能与用户名或邮箱相同',
  'common.qrFetching': '正在获取二维码…',
  'common.qrCodeAlt': '扫码二维码',
  'common.qrScanPrompt': '请使用手机扫码',
  'common.providerIconAlt': '渠道图标',
  'common.refreshAndRetry': '请刷新重试',
  'common.captchaLoadFailed': '验证码加载失败',
  'common.loading': '加载中…',
  // 域弹窗公共文案（login / account 两侧窗体共用；captcha 内容见下）。
  'common.close': '关闭',
  'common.cancel': '取消',
  'common.captchaTitle': '安全验证',
  'common.captchaHint': '请完成下方人机校验后继续',
  'common.captchaConfirm': '验证并继续',
  // 前置校验字段级文案（validate.ts FieldIssue → 键映射见 FIELD_ISSUE_I18N_KEY）。
  'common.errRequired': '请填写此项',
  'common.errInvalidEmail': '邮箱格式不正确',
  'common.errInvalidPhone': '手机号格式不正确',
  'common.errIncompleteCode': '请输入完整验证码',

  // ---- 因子名（§1.10）------------------------------------------------------
  'factors.password': '密码登录',
  'factors.otp_sms': '短信',
  'factors.otp_email': '邮箱',
  'factors.webauthn': '通行密钥',
  'factors.totp': '动态口令',
  'factors.recovery_code': '恢复码',
  'factors.thirdparty': '第三方登录',

  // ---- 渠道名（兜底；优先用后端下发的 display_name）------------------------
  'channels.sms': '短信',
  'channels.email': '邮箱',

  // ---- 位置一：登录流程域顶层 status（§1.6 全表 33 词 + unknown 兜底）------
  'errors.status.next': '请继续',
  'errors.status.mfa_required': '需要进行二次验证',
  'errors.status.binding_required': '该第三方身份尚未绑定账号，请选择处理方式',
  'errors.status.success': '操作成功',
  'errors.status.pending': '处理中，请稍候',
  'errors.status.scanned': '已扫码，请在手机上确认',
  'errors.status.expired': '已过期，请刷新后重试',
  'errors.status.failed': '操作失败，请重试',
  'errors.status.captcha_required': '请完成验证',
  'errors.status.captcha_invalid': '验证未通过，请重试',
  'errors.status.too_many_requests': '操作过于频繁，请稍后再试',
  'errors.status.too_many_attempts': '尝试次数超限，请重新获取验证码',
  'errors.status.locked': '密码登录已被暂时锁定',
  'errors.status.invalid_request': '请求参数有误，请检查后重试',
  'errors.status.invalid_credentials': '账号或密码错误',
  'errors.status.invalid_code': '验证码错误',
  'errors.status.code_expired': '验证码已过期，请重新获取',
  'errors.status.method_disabled': '该登录方式未开放',
  'errors.status.step_invalid': '当前状态已失效，请重新操作',
  'errors.status.token_invalid': '登录状态无效，请重新登录',
  'errors.status.token_expired': '登录已超时，请重新登录',
  'errors.status.state_mismatch': '状态校验失败，请重新操作',
  'errors.status.user_disabled': '账号已被禁用，请联系管理员',
  'errors.status.user_not_found': '账号不存在，或该手机号/邮箱未绑定账号',
  'errors.status.password_weak': '密码强度不足，请调整后重试',
  'errors.status.username_taken': '用户名已被占用',
  'errors.status.target_taken': '该手机号/邮箱已被占用',
  'errors.status.signup_disabled': '注册未开放',
  'errors.status.reset_disabled': '找回密码未开放',
  'errors.status.provider_disabled': '该登录渠道未启用',
  'errors.status.file_too_large': '文件大小超出限制',
  'errors.status.file_type_not_allowed': '文件类型不受支持',
  'errors.status.internal_error': '服务内部错误，请稍后重试',
  'errors.status.unknown': '操作失败，请稍后重试',

  // ---- 位置二：ErrorInfo.code（§1.6 失败词 26 + §1.5 标准码 8 + unknown）--
  'errors.code.failed': '操作失败，请重试',
  'errors.code.captcha_required': '请完成验证',
  'errors.code.captcha_invalid': '验证未通过，请重试',
  'errors.code.too_many_requests': '操作过于频繁，请稍后再试',
  'errors.code.too_many_attempts': '尝试次数超限，请重新获取验证码',
  'errors.code.locked': '密码登录已被暂时锁定',
  'errors.code.invalid_request': '请求参数有误，请检查后重试',
  'errors.code.invalid_credentials': '账号或密码错误',
  'errors.code.invalid_code': '验证码错误',
  'errors.code.code_expired': '验证码已过期，请重新获取',
  'errors.code.method_disabled': '该登录方式未开放',
  'errors.code.step_invalid': '当前状态已失效，请重新操作',
  'errors.code.token_invalid': '登录状态无效，请重新登录',
  'errors.code.token_expired': '登录已超时，请重新登录',
  'errors.code.state_mismatch': '状态校验失败，请重新操作',
  'errors.code.user_disabled': '账号已被禁用，请联系管理员',
  'errors.code.user_not_found': '账号不存在，或该手机号/邮箱未绑定账号',
  'errors.code.password_weak': '密码强度不足，请调整后重试',
  'errors.code.username_taken': '用户名已被占用',
  'errors.code.target_taken': '该手机号/邮箱已被占用',
  'errors.code.signup_disabled': '注册未开放',
  'errors.code.reset_disabled': '找回密码未开放',
  'errors.code.provider_disabled': '该登录渠道未启用',
  'errors.code.file_too_large': '文件大小超出限制',
  'errors.code.file_type_not_allowed': '文件类型不受支持',
  'errors.code.internal_error': '服务内部错误，请稍后重试',
  'errors.code.invalid_argument': '请求参数有误',
  'errors.code.unauthenticated': '请先登录',
  'errors.code.permission_denied': '没有权限执行该操作',
  'errors.code.not_found': '资源不存在',
  'errors.code.already_exists': '资源已存在',
  'errors.code.resource_exhausted': '操作过于频繁，请稍后再试',
  'errors.code.internal': '服务内部错误，请稍后重试',
  'errors.code.unavailable': '服务暂时不可用，请稍后重试',
  'errors.code.unknown': '操作失败，请稍后重试',

  // ---- 分域模块（底座）：域键在 zh/<域>.ts 维护，供后续域收口并行扩展
  ...login,
  ...setup,
  ...account,
  ...admin,
} as const;

/** 字典形状（键集唯一定义处）；各语言包必须与之完全对齐（编译期强制）。 */
export type I18nMessages = { [K in keyof typeof zhCN]: string };

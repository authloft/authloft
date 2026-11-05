/**
 * admin 设置页纯逻辑（docs/前端架构.md §6 行 520 SettingsPage；docs/接口文档.md
 * §5.6 行 1292-1363 四张表 = 键名 / 默认值 / 类型 / 值域的唯一定义处，逐字对齐）：
 * 键集映射 / 默认值 / 草稿初始化 / 交叉校验全部收口在此，零 Semi 依赖、node
 * 可测（schemaLogic 同模式；页面壳渲染不可测见 admin.test.tsx 头注 Blocker）。
 *
 * ⚠️ SetSettings 全量替换语义（§5.6 行 1287）：零值也
 * 会被写入（protojson 零值字段在 wire 省略 = 服务端读零值 = 写入零值，语义
 * 等价）——表单必须以 GetSettings 响应初始化完整键集（draftFromSettings）、
 * 保存时全量提交全部键（api.buildSetSettingsRequest），不能只提交改动字段；
 * UI 须提示「保存将覆盖全部设置」（SettingsPage 保存按钮旁落位）。
 *
 * 键集 = 36 字段（§5.6 行 1296-1354 四张表之和），含定稿新增的
 * https_deployment（=36，行 1354/1360 proto 变更条款）。server proto 与
 * web 生成物已同步刷入 36——文档 / proto /
 * 生成物三处一致，照常建键；行 1361「取值非 true / false / auto →
 * invalid_request」由 settingsDraftIssue 前端自律拦截（缺该键的全量提交
 * 会置空该键被后端拒收，故该键为全量提交必含项）。
 *
 * 固定规则（§5.6 行 1302-1306：长度 > 64 一律拒绝、与用户名 / 邮箱完全相同
 * 拒绝、含空白拒绝）写死在服务端代码、不进 settings → 不在表单暴露。
 * 值域交叉约束（行 1363）由前端设置页自律保证：settingsDraftIssue。
 */
import type { SettingsResponse } from '../gen/proto/api/admin/v1/settings_pb';
import { toCount } from '../shared/utils/int';

/** 密码最大长度服务端硬上限（§5.6 行 1297「可调低不可调高」；行 1304 防 DoS）。 */
export const PWD_MAX_LENGTH_HARD_CAP = 64;

/** 须满足的字符类数值域（§5.6 行 1298「1–3」；字符类 = 大写 / 小写 / 数字）。 */
export const PWD_REQUIRE_CLASSES_MIN = 1;
export const PWD_REQUIRE_CLASSES_MAX = 3;

/** 数字键清单（SettingsDraft 类型收窄 + 非负整数校验遍历共用）。 */
const NUMBER_KEYS = [
  'pwdMinLength',
  'pwdMaxLength',
  'pwdRequireClasses',
  'otpResendInterval',
  'otpTtl',
  'otpMaxAttempts',
  'otpDailyLimitTarget',
  'otpDailyLimitIp',
  'pwdFailCapture',
  'pwdFailBan',
  'pwdBanTtl',
  'sessionTtl',
  'queueWorkers',
  'queueCapacity',
  'queueBatch',
  'queueFlushMs',
  'eventlogRetentionDays',
] as const satisfies readonly string[];

export type SettingsNumberKey = (typeof NUMBER_KEYS)[number];

export type SettingsBoolKey =
  | 'pwdDisallowUsername'
  | 'pwdDisallowCommon'
  | 'allowPasswordReset'
  | 'allowRegistration'
  | 'allowSignupPassword'
  | 'allowSignupPhone'
  | 'allowSignupEmail'
  | 'mfaEnabled';

export type SettingsTextKey =
  | 'cookieName'
  | 'captchaProviderKey'
  | 'smsProviderKey'
  | 'emailProviderKey'
  | 'avatarStorageProvider'
  | 'staticBase'
  | 'httpsDeployment';

export type SettingsListKey = 'loginMethods' | 'mfaMethods' | 'ssoDomains' | 'gatewayTokens';

/**
 * 设置表单草稿（int64 字段以 number 编辑，提交前经 api.buildSetSettingsRequest
 * 收敛 BigInt；值域均远小于 Number.MAX_SAFE_INTEGER）。
 */
export type SettingsDraft = Readonly<{
  [K in SettingsNumberKey]: number;
}> &
  Readonly<{
    [K in SettingsBoolKey]: boolean;
  }> &
  Readonly<{
    [K in SettingsTextKey]: string;
  }> &
  Readonly<{
    [K in SettingsListKey]: readonly string[];
  }>;

/**
 * §5.6 默认值逐字（行 1296-1353 四张表）：测试断言锚点 + 文档口径唯一来源；
 * 表单草稿初始化以 GetSettings 响应为准（draftFromSettings），本常量不作运行
 * 兜底（后端 GetSettings 全键投影，落库值即真值）。
 */
export const DEFAULT_SETTINGS: SettingsDraft = {
  pwdMinLength: 8,
  pwdMaxLength: 64,
  pwdRequireClasses: 3,
  pwdDisallowUsername: true,
  pwdDisallowCommon: true,
  allowPasswordReset: true,
  otpResendInterval: 60,
  otpTtl: 300,
  otpMaxAttempts: 5,
  otpDailyLimitTarget: 10,
  otpDailyLimitIp: 50,
  loginMethods: ['password', 'otp_sms', 'otp_email', 'webauthn', 'thirdparty'],
  allowRegistration: true,
  allowSignupPassword: true,
  allowSignupPhone: true,
  allowSignupEmail: true,
  mfaEnabled: true,
  mfaMethods: ['totp', 'otp_sms', 'otp_email', 'webauthn'],
  pwdFailCapture: 3,
  pwdFailBan: 6,
  pwdBanTtl: 21600,
  sessionTtl: 604800,
  cookieName: 'al_session',
  ssoDomains: [],
  queueWorkers: 4,
  queueCapacity: 8192,
  queueBatch: 200,
  queueFlushMs: 2000,
  captchaProviderKey: '',
  smsProviderKey: '',
  emailProviderKey: '',
  avatarStorageProvider: '',
  gatewayTokens: [],
  eventlogRetentionDays: 180,
  staticBase: '/assets',
  httpsDeployment: 'auto',
};

/**
 * GetSettings 响应 → 表单草稿（36 键全量直映射；int64 bigint → number 经
 * toCount 收窄）。零值即真值（全量替换语义的对称面：后端读出的零值 = 管理
 * 员明确设置或默认值本身为零值，如 captcha_provider_key 空串 = 内置图形码）。
 */
export function draftFromSettings(response: SettingsResponse): SettingsDraft {
  return {
    pwdMinLength: toCount(response.pwdMinLength),
    pwdMaxLength: toCount(response.pwdMaxLength),
    pwdRequireClasses: toCount(response.pwdRequireClasses),
    pwdDisallowUsername: response.pwdDisallowUsername,
    pwdDisallowCommon: response.pwdDisallowCommon,
    allowPasswordReset: response.allowPasswordReset,
    otpResendInterval: toCount(response.otpResendInterval),
    otpTtl: toCount(response.otpTtl),
    otpMaxAttempts: toCount(response.otpMaxAttempts),
    otpDailyLimitTarget: toCount(response.otpDailyLimitTarget),
    otpDailyLimitIp: toCount(response.otpDailyLimitIp),
    loginMethods: [...response.loginMethods],
    allowRegistration: response.allowRegistration,
    allowSignupPassword: response.allowSignupPassword,
    allowSignupPhone: response.allowSignupPhone,
    allowSignupEmail: response.allowSignupEmail,
    mfaEnabled: response.mfaEnabled,
    mfaMethods: [...response.mfaMethods],
    pwdFailCapture: toCount(response.pwdFailCapture),
    pwdFailBan: toCount(response.pwdFailBan),
    pwdBanTtl: toCount(response.pwdBanTtl),
    sessionTtl: toCount(response.sessionTtl),
    cookieName: response.cookieName,
    ssoDomains: [...response.ssoDomains],
    queueWorkers: toCount(response.queueWorkers),
    queueCapacity: toCount(response.queueCapacity),
    queueBatch: toCount(response.queueBatch),
    queueFlushMs: toCount(response.queueFlushMs),
    captchaProviderKey: response.captchaProviderKey,
    smsProviderKey: response.smsProviderKey,
    emailProviderKey: response.emailProviderKey,
    avatarStorageProvider: response.avatarStorageProvider,
    gatewayTokens: [...response.gatewayTokens],
    eventlogRetentionDays: toCount(response.eventlogRetentionDays),
    staticBase: response.staticBase,
    httpsDeployment: response.httpsDeployment,
  };
}

/**
 * 已启用的登录方式选项（§5.6 行 1330 值域 = 因子名 / thirdparty，默认全集）。
 * 文案与 api.ts mfaFactorLabel 语义同源但独立持有（api.ts 将 import 本模块
 * 类型，反向 import 成环；label 小量重复可接受）。
 */
export const LOGIN_METHOD_OPTIONS: readonly { readonly value: string; readonly label: string }[] = [
  { value: 'password', label: '密码' },
  { value: 'otp_sms', label: '短信验证码' },
  { value: 'otp_email', label: '邮箱验证码' },
  { value: 'webauthn', label: '通行密钥' },
  { value: 'thirdparty', label: '第三方登录' },
];

/**
 * 系统开放的二次因子选项（§5.6 行 1336 值域：recovery_code 随 totp 生效、
 * 不单列，故不入选项）。
 */
export const MFA_METHOD_OPTIONS: readonly { readonly value: string; readonly label: string }[] = [
  { value: 'totp', label: 'TOTP 动态码' },
  { value: 'otp_sms', label: '短信验证码' },
  { value: 'otp_email', label: '邮箱验证码' },
  { value: 'webauthn', label: '通行密钥' },
];

/**
 * https_deployment 三态选项（§5.6 行 1354：string 三态 true / false / auto，
 * 默认 auto；行 1356 admin 设置页中文文案定稿：选项「自动推断 / 强制开启 /
 * 强制关闭」逐字）。
 */
export const HTTPS_DEPLOYMENT_OPTIONS: readonly { readonly value: string; readonly label: string }[] = [
  { value: 'auto', label: '自动推断' },
  { value: 'true', label: '强制开启' },
  { value: 'false', label: '强制关闭' },
];

/** https_deployment 合法取值集（§5.6 行 1354/1361：非三态 → invalid_request）。 */
export const HTTPS_DEPLOYMENT_VALUES: readonly string[] = HTTPS_DEPLOYMENT_OPTIONS.map(
  (option) => option.value,
);

/** 字段控件形态（判别联合：kind 收窄 → key 类型随之收窄，渲染零断言）。 */
export type SettingsFieldMeta =
  | {
      readonly kind: 'number';
      readonly key: SettingsNumberKey;
      readonly label: string;
      /** 单位（渲染在标签括号内，如「秒」「天」）。 */
      readonly unit?: string;
      readonly hint?: string;
    }
  | {
      readonly kind: 'switch';
      readonly key: SettingsBoolKey;
      readonly label: string;
      readonly hint?: string;
    }
  | {
      readonly kind: 'text';
      readonly key: SettingsTextKey;
      readonly label: string;
      readonly hint?: string;
    }
  | {
      readonly kind: 'select';
      readonly key: SettingsTextKey;
      readonly label: string;
      readonly options: readonly { readonly value: string; readonly label: string }[];
      readonly hint?: string;
    }
  | {
      readonly kind: 'multiSelect';
      readonly key: SettingsListKey;
      readonly label: string;
      readonly options: readonly { readonly value: string; readonly label: string }[];
      readonly hint?: string;
    }
  | {
      readonly kind: 'stringList';
      readonly key: SettingsListKey;
      readonly label: string;
      /** StringListEditor 添加按钮文案（如「添加域名」）。 */
      readonly addText: string;
      /** 条目输入占位提示。 */
      readonly placeholder: string;
      readonly hint?: string;
    };

/** 表单分区（§5.6 四张表的展示归组；36 键全覆盖、无重复）。 */
export interface SettingsSectionMeta {
  readonly title: string;
  readonly fields: readonly SettingsFieldMeta[];
}

/**
 * 设置表单分区清单（渲染数据源）：按 §5.6 四张表归组为 9 区——密码策略 /
 * 账号与注册 / 验证码限流 / 登录方式与 MFA / 密码失败保护 / 会话 Cookie 多
 * 域名与 HTTPS 部署 / 队列参数 / Provider 与网关 / 日志与静态资源；36 键
 * 全覆盖、无重复。
 */
export const SETTINGS_SECTIONS: readonly SettingsSectionMeta[] = [
  {
    title: '密码策略',
    fields: [
      {
        kind: 'number',
        key: 'pwdMinLength',
        label: '最小长度',
        hint: '默认 8',
      },
      {
        kind: 'number',
        key: 'pwdMaxLength',
        label: '最大长度',
        hint: '可调低不可调高，服务端硬上限 64（默认 64）',
      },
      {
        kind: 'number',
        key: 'pwdRequireClasses',
        label: '须满足的字符类数',
        hint: '1-3；字符类 = 大写 / 小写 / 数字，符号不计入（默认 3）',
      },
      {
        kind: 'switch',
        key: 'pwdDisallowUsername',
        label: '禁止密码包含用户名',
      },
      {
        kind: 'switch',
        key: 'pwdDisallowCommon',
        label: '禁止命中弱口令字典',
      },
    ],
  },
  {
    title: '账号与注册',
    fields: [
      {
        kind: 'switch',
        key: 'allowPasswordReset',
        label: '开放自助重置密码',
        hint: '关闭后重置密码一律被拒绝，不发码、不校验验证码',
      },
      {
        kind: 'switch',
        key: 'allowRegistration',
        label: '注册总开关',
        hint: '关闭后注册一律被拒绝',
      },
      {
        kind: 'switch',
        key: 'allowSignupPassword',
        label: '用户名 + 密码注册入口',
      },
      {
        kind: 'switch',
        key: 'allowSignupPhone',
        label: '手机号注册入口',
      },
      {
        kind: 'switch',
        key: 'allowSignupEmail',
        label: '邮箱注册入口',
      },
    ],
  },
  {
    title: '验证码限流',
    fields: [
      {
        kind: 'number',
        key: 'otpResendInterval',
        label: '同目标重发冷却',
        unit: '秒',
        hint: '默认 60',
      },
      {
        kind: 'number',
        key: 'otpTtl',
        label: '验证码有效期',
        unit: '秒',
        hint: '默认 300',
      },
      {
        kind: 'number',
        key: 'otpMaxAttempts',
        label: '单条验证码最大校验失败次数',
        hint: '超限即作废（默认 5）',
      },
      {
        kind: 'number',
        key: 'otpDailyLimitTarget',
        label: '单目标每日发送上限',
        unit: '次',
        hint: '默认 10',
      },
      {
        kind: 'number',
        key: 'otpDailyLimitIp',
        label: '单 IP 每日发送上限',
        unit: '次',
        hint: '默认 50',
      },
    ],
  },
  {
    title: '登录方式与 MFA',
    fields: [
      {
        kind: 'multiSelect',
        key: 'loginMethods',
        label: '已启用的登录方式',
        options: LOGIN_METHOD_OPTIONS,
        hint: '只控登录，不参与注册判定；不在其中的方式登录时被拒绝',
      },
      {
        kind: 'switch',
        key: 'mfaEnabled',
        label: '两步验证总开关',
        hint: '关闭后所有用户不再二次验证',
      },
      {
        kind: 'multiSelect',
        key: 'mfaMethods',
        label: '系统开放的二次因子',
        options: MFA_METHOD_OPTIONS,
        hint: '恢复码随 TOTP 生效，不单列',
      },
    ],
  },
  {
    title: '密码失败保护',
    fields: [
      {
        kind: 'number',
        key: 'pwdFailCapture',
        label: '当日密码错误人机校验阈值',
        hint: '同一账号当日密码错误达此次数后，登录必须携带人机校验（默认 3）',
      },
      {
        kind: 'number',
        key: 'pwdFailBan',
        label: '禁止密码登录阈值',
        hint: '累计失败达此次数后禁止密码登录（默认 6）',
      },
      {
        kind: 'number',
        key: 'pwdBanTtl',
        label: '禁止密码登录时长',
        unit: '秒',
        hint: '默认 21600（6 小时）',
      },
    ],
  },
  {
    title: '会话、Cookie 与多域名',
    fields: [
      {
        kind: 'number',
        key: 'sessionTtl',
        label: '会话与 Cookie 有效期',
        unit: '秒',
        hint: '默认 604800（7 天）',
      },
      {
        kind: 'text',
        key: 'cookieName',
        label: '会话 Cookie 名',
        hint: '默认 al_session',
      },
      {
        kind: 'select',
        key: 'httpsDeployment',
        label: 'HTTPS 部署',
        options: HTTPS_DEPLOYMENT_OPTIONS,
        // §5.6 行 1356 admin 设置页中文文案定稿逐字。
        hint: '声明本实例的 HTTPS 部署形态，决定会话 Cookie 的 Secure 属性：自动推断 = 仅 HTTPS 请求下标记为安全；强制开启 = 按部署于 HTTPS 处理，明文 HTTP 环境下浏览器将不保存该 Cookie；强制关闭 = 按明文部署处理，Cookie 不带 Secure 标记',
      },
      {
        kind: 'stringList',
        key: 'ssoDomains',
        label: '多根域名同步列表',
        addText: '添加域名',
        placeholder: 'example.com',
        hint: '登录 / 登出时逐个同步',
      },
    ],
  },
  {
    title: '队列参数',
    fields: [
      {
        kind: 'number',
        key: 'queueWorkers',
        label: '延迟写入队列 worker 数',
        hint: '默认 4',
      },
      {
        kind: 'number',
        key: 'queueCapacity',
        label: '队列长度（ring buffer）',
        hint: '默认 8192',
      },
      {
        kind: 'number',
        key: 'queueBatch',
        label: '攒批条数阈值',
        hint: '默认 200',
      },
      {
        kind: 'number',
        key: 'queueFlushMs',
        label: '攒批时间窗',
        unit: '毫秒',
        hint: '默认 2000',
      },
    ],
  },
  {
    title: 'Provider 与网关',
    fields: [
      {
        kind: 'text',
        key: 'captchaProviderKey',
        label: '当前生效的 Captcha Provider',
        hint: '留空 = 内置图形码',
      },
      {
        kind: 'text',
        key: 'smsProviderKey',
        label: '当前生效的短信 Provider',
        hint: '留空 = 未启用外部短信渠道',
      },
      {
        kind: 'text',
        key: 'emailProviderKey',
        label: '当前生效的邮件 Provider',
        hint: '留空 = 未启用外部邮件渠道',
      },
      {
        kind: 'text',
        key: 'avatarStorageProvider',
        label: '头像 / 渠道图标使用的 Storage Provider',
        hint: '留空 = 未启用外部存储',
      },
      {
        kind: 'stringList',
        key: 'gatewayTokens',
        label: '网关 Token',
        addText: '添加 Token',
        placeholder: '网关调用方令牌',
        hint: '可多个',
      },
    ],
  },
  {
    title: '日志与静态资源',
    fields: [
      {
        kind: 'number',
        key: 'eventlogRetentionDays',
        label: '事件日志保留天数',
        unit: '天',
        hint: '默认 180',
      },
      {
        kind: 'text',
        key: 'staticBase',
        label: '静态资源基址（CDN）',
        hint: '决定空壳页面脚本 / 样式 URL 前缀；改后需刷新页面生效',
      },
    ],
  },
];

/** 数字字段非负整数校验失败文案。 */
const NUMBER_ISSUE_TEXT = '数字设置项须为不小于 0 的整数';

/** 交叉校验失败文案（§5.6 行 1363 交叉约束由前端设置页自律保证）。 */
export function settingsDraftIssue(draft: SettingsDraft): string | null {
  for (const key of NUMBER_KEYS) {
    const value = draft[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      return NUMBER_ISSUE_TEXT;
    }
  }
  if (
    draft.pwdRequireClasses < PWD_REQUIRE_CLASSES_MIN ||
    draft.pwdRequireClasses > PWD_REQUIRE_CLASSES_MAX
  ) {
    return '须满足的字符类数须为 1-3';
  }
  if (draft.pwdMinLength > draft.pwdMaxLength) {
    return '密码最小长度不能大于最大长度';
  }
  if (draft.pwdMaxLength > PWD_MAX_LENGTH_HARD_CAP) {
    return '密码最大长度不能超过 64（服务端硬上限，可调低不可调高）';
  }
  // §5.6 行 1361：https_deployment 取值非 true / false / auto → invalid_request
  //（服务端拒绝；前端自律前置拦截，防全量提交被整体打回）。
  if (!HTTPS_DEPLOYMENT_VALUES.includes(draft.httpsDeployment)) {
    return 'HTTPS 部署取值须为 自动推断 / 强制开启 / 强制关闭';
  }
  return null;
}

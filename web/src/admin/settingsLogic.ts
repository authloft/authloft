/**
 * admin 设置页纯逻辑（docs/前端架构.md §6 行 520 SettingsPage；docs/接口文档.md
 * §5.6 行 1292-1363 四张表 = 键名 / 默认值 / 类型 / 值域的唯一定义处，逐字对齐）：
 * 键集映射 / 默认值 / 草稿初始化 / 交叉校验全部收口在此，零 Semi 依赖、node
 * 可测（schemaLogic 同模式；页面壳渲染不可测见 admin.test.tsx 头注 Blocker）。
 *
 * ⚠️ SetSettings 部分更新语义（§5.6 行 1287；proto3 optional has 位 +
 * 四个 repeated 键的 has_* 伴生标志）：未设置 = 不修改、显式零值 = 覆盖；
 * 标志置 true = 列表在场，空数组即清空（protojson 下 [] 与缺省同为 nil）。
 * 表单仍以 GetSettings 响应初始化完整键集（draftFromSettings）、保存时
 * 全量提交全部键 + 四个伴生标志（api.buildSetSettingsRequest），UI 仍
 * 提示「保存将覆盖全部设置」（SettingsPage 保存按钮旁落位）。
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
import { t } from '../shared/i18n';
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
 * 因子名文案复用 factors.* 既有键（与 api.ts mfaFactorLabel 同键同源，无重复；
 * api.ts 仍 import 本模块类型，反向 import 成环，各自取键不入模块依赖）。
 * 改函数调用期求值——模块级常量求值先于 entry setLocale 执行，
 * label 会冻结在默认语言（en 浏览器恒显 zh）；本文件四表统一此形态
 * （NAV_ITEMS textKey 先例的等价受纳形态，stringList placeholder
 * 含非文案字面 example.com 故整体取函数化）。
 */
export function getLoginMethodOptions(): readonly {
  readonly value: string;
  readonly label: string;
}[] {
  return [
    { value: 'password', label: t('factors.password') },
    { value: 'otp_sms', label: t('factors.otp_sms') },
    { value: 'otp_email', label: t('factors.otp_email') },
    { value: 'webauthn', label: t('factors.webauthn') },
    { value: 'thirdparty', label: t('factors.thirdparty') },
  ];
}

/**
 * 系统开放的二次因子选项（§5.6 行 1336 值域：recovery_code 随 totp 生效、
 * 不单列，故不入选项）。因子名文案复用 factors.* 既有键（求值时机同上）。
 */
export function getMfaMethodOptions(): readonly {
  readonly value: string;
  readonly label: string;
}[] {
  return [
    { value: 'totp', label: t('factors.totp') },
    { value: 'otp_sms', label: t('factors.otp_sms') },
    { value: 'otp_email', label: t('factors.otp_email') },
    { value: 'webauthn', label: t('factors.webauthn') },
  ];
}

/**
 * https_deployment 三态选项（§5.6 行 1354：string 三态 true / false / auto，
 * 默认 auto；行 1356 admin 设置页中文文案定稿：选项「自动推断 / 强制开启 /
 * 强制关闭」逐字，经 admin.* 键维护；求值时机同上，调用期取文案）。
 */
export function getHttpsDeploymentOptions(): readonly {
  readonly value: string;
  readonly label: string;
}[] {
  return [
    { value: 'auto', label: t('admin.httpsDeploymentAuto') },
    { value: 'true', label: t('admin.httpsDeploymentForceOn') },
    { value: 'false', label: t('admin.httpsDeploymentForceOff') },
  ];
}

/**
 * https_deployment 合法取值集（§5.6 行 1354/1361：非三态 → invalid_request）。
 * 纯值集合不涉文案求值时机，保持模块级常量（与 getHttpsDeploymentOptions
 * 的 value 集恒等：§5.6 行 1354 三态封闭值域）。
 */
export const HTTPS_DEPLOYMENT_VALUES: readonly string[] = ['auto', 'true', 'false'];

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
 * 全覆盖、无重复。函数调用期求值（消费方组件渲染期调用），label /
 * hint / unit / addText / placeholder 经 t() 取当前语言文案——模块级常量
 * 求值先于 entry setLocale，会冻结在默认语言（en 浏览器恒显 zh）。
 */
export function getSettingsSections(): readonly SettingsSectionMeta[] {
  return [
  {
    title: t('admin.settingsSectionPasswordPolicy'),
    fields: [
      {
        kind: 'number',
        key: 'pwdMinLength',
        label: t('admin.pwdMinLengthLabel'),
        hint: t('admin.pwdMinLengthHint'),
      },
      {
        kind: 'number',
        key: 'pwdMaxLength',
        label: t('admin.pwdMaxLengthLabel'),
        hint: t('admin.pwdMaxLengthHint'),
      },
      {
        kind: 'number',
        key: 'pwdRequireClasses',
        label: t('admin.pwdRequireClassesLabel'),
        hint: t('admin.pwdRequireClassesHint'),
      },
      {
        kind: 'switch',
        key: 'pwdDisallowUsername',
        label: t('admin.pwdDisallowUsernameLabel'),
      },
      {
        kind: 'switch',
        key: 'pwdDisallowCommon',
        label: t('admin.pwdDisallowCommonLabel'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionAccountRegistration'),
    fields: [
      {
        kind: 'switch',
        key: 'allowPasswordReset',
        label: t('admin.allowPasswordResetLabel'),
        hint: t('admin.allowPasswordResetHint'),
      },
      {
        kind: 'switch',
        key: 'allowRegistration',
        label: t('admin.allowRegistrationLabel'),
        hint: t('admin.allowRegistrationHint'),
      },
      {
        kind: 'switch',
        key: 'allowSignupPassword',
        label: t('admin.allowSignupPasswordLabel'),
      },
      {
        kind: 'switch',
        key: 'allowSignupPhone',
        label: t('admin.allowSignupPhoneLabel'),
      },
      {
        kind: 'switch',
        key: 'allowSignupEmail',
        label: t('admin.allowSignupEmailLabel'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionOtpRateLimit'),
    fields: [
      {
        kind: 'number',
        key: 'otpResendInterval',
        label: t('admin.otpResendIntervalLabel'),
        unit: t('admin.unitSeconds'),
        hint: t('admin.otpResendIntervalHint'),
      },
      {
        kind: 'number',
        key: 'otpTtl',
        label: t('admin.otpTtlLabel'),
        unit: t('admin.unitSeconds'),
        hint: t('admin.otpTtlHint'),
      },
      {
        kind: 'number',
        key: 'otpMaxAttempts',
        label: t('admin.otpMaxAttemptsLabel'),
        hint: t('admin.otpMaxAttemptsHint'),
      },
      {
        kind: 'number',
        key: 'otpDailyLimitTarget',
        label: t('admin.otpDailyLimitTargetLabel'),
        unit: t('admin.unitTimes'),
        hint: t('admin.otpDailyLimitTargetHint'),
      },
      {
        kind: 'number',
        key: 'otpDailyLimitIp',
        label: t('admin.otpDailyLimitIpLabel'),
        unit: t('admin.unitTimes'),
        hint: t('admin.otpDailyLimitIpHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionLoginAndMfa'),
    fields: [
      {
        kind: 'multiSelect',
        key: 'loginMethods',
        label: t('admin.loginMethodsLabel'),
        options: getLoginMethodOptions(),
        hint: t('admin.loginMethodsHint'),
      },
      {
        kind: 'switch',
        key: 'mfaEnabled',
        label: t('admin.mfaEnabledLabel'),
        hint: t('admin.mfaEnabledHint'),
      },
      {
        kind: 'multiSelect',
        key: 'mfaMethods',
        label: t('admin.mfaMethodsLabel'),
        options: getMfaMethodOptions(),
        hint: t('admin.mfaMethodsHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionPwdFailProtection'),
    fields: [
      {
        kind: 'number',
        key: 'pwdFailCapture',
        label: t('admin.pwdFailCaptureLabel'),
        hint: t('admin.pwdFailCaptureHint'),
      },
      {
        kind: 'number',
        key: 'pwdFailBan',
        label: t('admin.pwdFailBanLabel'),
        hint: t('admin.pwdFailBanHint'),
      },
      {
        kind: 'number',
        key: 'pwdBanTtl',
        label: t('admin.pwdBanTtlLabel'),
        unit: t('admin.unitSeconds'),
        hint: t('admin.pwdBanTtlHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionSessionCookie'),
    fields: [
      {
        kind: 'number',
        key: 'sessionTtl',
        label: t('admin.sessionTtlLabel'),
        unit: t('admin.unitSeconds'),
        hint: t('admin.sessionTtlHint'),
      },
      {
        kind: 'text',
        key: 'cookieName',
        label: t('admin.cookieNameLabel'),
        hint: t('admin.cookieNameHint'),
      },
      {
        kind: 'select',
        key: 'httpsDeployment',
        label: t('admin.httpsDeploymentLabel'),
        options: getHttpsDeploymentOptions(),
        // §5.6 行 1356 admin 设置页中文文案定稿逐字。
        hint: t('admin.httpsDeploymentHint'),
      },
      {
        kind: 'stringList',
        key: 'ssoDomains',
        label: t('admin.ssoDomainsLabel'),
        addText: t('admin.addDomain'),
        placeholder: 'example.com',
        hint: t('admin.ssoDomainsHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionQueue'),
    fields: [
      {
        kind: 'number',
        key: 'queueWorkers',
        label: t('admin.queueWorkersLabel'),
        hint: t('admin.queueWorkersHint'),
      },
      {
        kind: 'number',
        key: 'queueCapacity',
        label: t('admin.queueCapacityLabel'),
        hint: t('admin.queueCapacityHint'),
      },
      {
        kind: 'number',
        key: 'queueBatch',
        label: t('admin.queueBatchLabel'),
        hint: t('admin.queueBatchHint'),
      },
      {
        kind: 'number',
        key: 'queueFlushMs',
        label: t('admin.queueFlushMsLabel'),
        unit: t('admin.unitMilliseconds'),
        hint: t('admin.queueFlushMsHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionProviderAndGateway'),
    fields: [
      {
        kind: 'text',
        key: 'captchaProviderKey',
        label: t('admin.captchaProviderKeyLabel'),
        hint: t('admin.captchaProviderKeyHint'),
      },
      {
        kind: 'text',
        key: 'smsProviderKey',
        label: t('admin.smsProviderKeyLabel'),
        hint: t('admin.smsProviderKeyHint'),
      },
      {
        kind: 'text',
        key: 'emailProviderKey',
        label: t('admin.emailProviderKeyLabel'),
        hint: t('admin.emailProviderKeyHint'),
      },
      {
        kind: 'text',
        key: 'avatarStorageProvider',
        label: t('admin.avatarStorageProviderLabel'),
        hint: t('admin.avatarStorageProviderHint'),
      },
      {
        kind: 'stringList',
        key: 'gatewayTokens',
        label: t('admin.gatewayTokensLabel'),
        addText: t('admin.addGatewayToken'),
        placeholder: t('admin.gatewayTokenPlaceholder'),
        hint: t('admin.gatewayTokensHint'),
      },
    ],
  },
  {
    title: t('admin.settingsSectionLogAndStatic'),
    fields: [
      {
        kind: 'number',
        key: 'eventlogRetentionDays',
        label: t('admin.eventlogRetentionDaysLabel'),
        unit: t('admin.unitDays'),
        hint: t('admin.eventlogRetentionDaysHint'),
      },
      {
        kind: 'text',
        key: 'staticBase',
        label: t('admin.staticBaseLabel'),
        hint: t('admin.staticBaseHint'),
      },
    ],
  },
  ];
}

/**
 * 交叉校验失败文案（§5.6 行 1363 交叉约束由前端设置页自律保证）。
 */
export function settingsDraftIssue(draft: SettingsDraft): string | null {
  for (const key of NUMBER_KEYS) {
    const value = draft[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      return t('admin.settingsNumberIssue');
    }
  }
  if (
    draft.pwdRequireClasses < PWD_REQUIRE_CLASSES_MIN ||
    draft.pwdRequireClasses > PWD_REQUIRE_CLASSES_MAX
  ) {
    return t('admin.pwdRequireClassesIssue');
  }
  if (draft.pwdMinLength > draft.pwdMaxLength) {
    return t('admin.pwdMinOverMaxIssue');
  }
  if (draft.pwdMaxLength > PWD_MAX_LENGTH_HARD_CAP) {
    return t('admin.pwdMaxOverCapIssue');
  }
  // §5.6 行 1361：https_deployment 取值非 true / false / auto → invalid_request
  //（服务端拒绝；前端自律前置拦截，防全量提交被整体打回）。
  if (!HTTPS_DEPLOYMENT_VALUES.includes(draft.httpsDeployment)) {
    return t('admin.httpsDeploymentIssue');
  }
  return null;
}

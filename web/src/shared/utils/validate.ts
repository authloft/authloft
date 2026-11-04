/**
 * 纯函数校验器（docs/前端架构.md §3.4 validate.ts 行 338）：用户名（接口文档
 * §2.3 行 449 唯一定义）、邮箱 / 手机号（体验性格式预校验，§1.11：后端为唯一
 * 权威）、密码强度（§5.6 策略与默认值同源）、provider_key（^[a-z0-9_]+$）。
 */

/** 用户名规则唯一来源：接口文档 §2.3 行 449 —— ^[A-Za-z0-9_]{5,20}$（设置后不可改）。 */
export const USERNAME_PATTERN = /^[A-Za-z0-9_]{5,20}$/;

/** provider_key 规则（docs/前端架构.md §3.4）：^[a-z0-9_]+$。 */
export const PROVIDER_KEY_PATTERN = /^[a-z0-9_]+$/;

/** 中国大陆手机号（体验性预校验；§1.11 phone：仅格式体验校验，后端为唯一权威）。 */
const PHONE_PATTERN = /^1[3-9]\d{9}$/;

/** 邮箱（体验性预校验；§1.11 email：同上）。 */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** 用户名（§2.3 行 449）。 */
export function isValidUsername(value: string): boolean {
  return USERNAME_PATTERN.test(value);
}

/** provider_key（^[a-z0-9_]+$）。 */
export function isValidProviderKey(value: string): boolean {
  return PROVIDER_KEY_PATTERN.test(value);
}

/** 手机号（体验性预校验，后端为唯一权威）。 */
export function isValidPhone(value: string): boolean {
  return PHONE_PATTERN.test(value);
}

/** 邮箱（体验性预校验，后端为唯一权威）。 */
export function isValidEmail(value: string): boolean {
  return EMAIL_PATTERN.test(value);
}

/**
 * §5.6 密码策略（键名与默认值同源；前端按同值预校验，服务端为权威）。
 * 各键值域交叉约束（如 min ≤ max ≤ 64）由设置页与管理员自律保证（§5.6 末段）。
 */
export interface PasswordPolicy {
  /** pwd_min_length，默认 8。 */
  minLength: number;
  /** pwd_max_length，默认 64；可调低不可调高（服务端硬上限 64）。 */
  maxLength: number;
  /** pwd_require_classes，默认 3（1–3）；字符类 = 大写 / 小写 / 数字，符号不计入。 */
  requireClasses: number;
  /** pwd_disallow_username，默认 true：禁止密码包含用户名。 */
  disallowUsername: boolean;
}

/** §5.6 密码策略默认值。 */
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 8,
  maxLength: 64,
  requireClasses: 3,
  disallowUsername: true,
};

/** 密码预校验未满足项（i18n 文案由字典层落，本层只给结构化原因）。 */
export type PasswordWeakReason =
  | 'too_short'
  | 'too_long'
  | 'contains_whitespace'
  | 'too_few_classes'
  | 'contains_username'
  | 'same_as_identifier';

export interface ValidatePasswordOptions {
  /** 覆盖 §5.6 默认策略的部分项。 */
  policy?: Partial<PasswordPolicy>;
  /** 当前用户名（pwd_disallow_username 与「与用户名完全相同」固定项）。 */
  username?: string;
  /** 当前邮箱（固定项：密码与邮箱完全相同 → 拒绝）。 */
  email?: string;
}

const HAS_UPPER = /[A-Z]/;
const HAS_LOWER = /[a-z]/;
const HAS_DIGIT = /[0-9]/;
const HAS_WHITESPACE = /\s/;

/**
 * 密码强度预校验（§5.6）：返回未满足项，空数组 = 通过。
 *
 * 固定不可配项（§5.6 行 1289-1293）：长度 > 64 一律拒绝（maxLength 上限硬压 64）、
 * 与用户名或邮箱完全相同拒绝、含空白拒绝。pwd_disallow_common 是服务端弱口令
 * 字典能力，前端无字典不做预判（服务端权威）。
 */
export function validatePassword(
  password: string,
  options: ValidatePasswordOptions = {},
): PasswordWeakReason[] {
  const policy: PasswordPolicy = { ...DEFAULT_PASSWORD_POLICY, ...options.policy };
  // §5.6：pwd_max_length 可调低不可调高（服务端硬上限 64）。
  const maxLength = Math.min(policy.maxLength, 64);
  const reasons: PasswordWeakReason[] = [];

  if (password.length < policy.minLength) {
    reasons.push('too_short');
  }
  if (password.length > maxLength) {
    reasons.push('too_long');
  }
  if (HAS_WHITESPACE.test(password)) {
    reasons.push('contains_whitespace');
  }
  const classes = [HAS_UPPER, HAS_LOWER, HAS_DIGIT].filter((pattern) =>
    pattern.test(password),
  ).length;
  if (classes < policy.requireClasses) {
    reasons.push('too_few_classes');
  }
  if (
    policy.disallowUsername &&
    options.username !== undefined &&
    options.username !== '' &&
    password.includes(options.username)
  ) {
    reasons.push('contains_username');
  }
  if (
    (options.username !== undefined && password === options.username) ||
    (options.email !== undefined && password === options.email)
  ) {
    reasons.push('same_as_identifier');
  }
  return reasons;
}

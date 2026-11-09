/**
 * 密码强度实时提示条（docs/前端架构.md §3.3 行 328）：注册 /
 * 改密 / 重置场景的 set_password 步渲染。规则与默认值同源于接口文档 §5.6
 * （唯一定义），经 shared/utils/validate.ts 的 validatePassword 预校验——
 * 前端按默认策略做体验性提示，服务端为权威（pwd_disallow_common 弱口令字典
 * 前端无字典不预判，password_weak 由响应 status 权威判定，§1.6 行 255）。
 *
 * 形态：适用规则清单逐条实时打勾 / 打叉（不自造「弱 / 中 / 强」分级——§5.6
 * 未定义强度枚举，规则清单即「与后端策略同源」的直接呈现）。空密码不渲染
 * （未输入不提示）；与用户名 / 邮箱相关的规则仅在调用方传入对应标识时展示。
 */
import {
  validatePassword,
  type PasswordWeakReason,
  type ValidatePasswordOptions,
} from '../utils/validate';
import { t, type I18nKey } from '../i18n';
import styles from './PasswordStrengthMeter.module.less';

/** 适用规则 → i18n 键（common.pwd*；文案见 zh-CN / en-US 字典）。 */
const RULE_LABEL_KEYS: Readonly<Record<PasswordWeakReason, I18nKey>> = {
  too_short: 'common.pwdTooShort',
  too_long: 'common.pwdTooLong',
  contains_whitespace: 'common.pwdNoWhitespace',
  too_few_classes: 'common.pwdNeedClasses',
  contains_username: 'common.pwdNoUsername',
  same_as_identifier: 'common.pwdNotSameAsIdentifier',
};

/** 单条规则的展示形态（key 对应 validatePassword 的未满足项）。 */
export interface MeterRule {
  key: PasswordWeakReason;
  label: string;
  satisfied: boolean;
}

/**
 * 密码 → 适用规则清单（纯函数，node 可测）：satisfied = 该项不在未满足原因中。
 * contains_username / same_as_identifier 仅在调用方传入 username / email 时适用
 * （与 validatePassword 的判定条件一致）。
 */
export function meterRules(
  password: string,
  options: ValidatePasswordOptions = {},
): MeterRule[] {
  const reasons = validatePassword(password, options);
  const keys: PasswordWeakReason[] = [
    'too_short',
    'too_long',
    'contains_whitespace',
    'too_few_classes',
  ];
  const hasUsername = options.username !== undefined && options.username !== '';
  if (hasUsername) {
    keys.push('contains_username');
  }
  if (options.username !== undefined || options.email !== undefined) {
    keys.push('same_as_identifier');
  }
  return keys.map((key) => ({
    key,
    label: t(RULE_LABEL_KEYS[key]),
    satisfied: !reasons.includes(key),
  }));
}

export interface PasswordStrengthMeterProps {
  /** 当前密码输入（受控；空串不渲染提示）。 */
  password: string;
  /** 当前用户名（注册 set_password 步传入；驱动 contains_username / same_as_identifier）。 */
  username?: string;
  /** 当前邮箱（验证码注册场景传入；驱动 same_as_identifier）。 */
  email?: string;
}

export function PasswordStrengthMeter({
  password,
  username,
  email,
}: PasswordStrengthMeterProps) {
  if (password === '') {
    return null;
  }
  const rules = meterRules(password, { username, email });
  return (
    // 评审 P0-3e：aria-live="polite" 显式标注（role="status" 的
    // 隐式语义补强，规则打勾变化时向读屏播报）。
    <div role="status" aria-live="polite" className={styles.meter}>
      {rules.map((rule) => (
        <p
          key={rule.key}
          className={rule.satisfied ? styles.ruleOk : styles.ruleWeak}
          data-satisfied={rule.satisfied}
        >
          {rule.satisfied ? '✓' : '✗'} {rule.label}
        </p>
      ))}
    </div>
  );
}

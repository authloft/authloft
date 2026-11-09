/**
 * login 域提交前置校验（FRONTEND-UX-REVIEW P0-2）：shared/utils/validate.ts
 * 纯函数的域内组装——FieldIssue → i18n 文案映射（FIELD_ISSUE_I18N_KEY）、首错字段
 * 定位、焦点移动（浏览器环境；node 测试无 DOM 静默跳过）。
 *
 * 各因子 / 步骤 / 页表单在 onSubmit 前统一走一道 validateFormValues：未过则不
 * 发请求（必然失败的请求不打满网络往返），错误文案落 FieldRenderer 错误槽 /
 * 字段旁内联，焦点移到首错字段。体验性预校验，服务端为唯一权威（§1.11）。
 */
import { t } from '../shared/i18n';
import {
  FIELD_ISSUE_I18N_KEY,
  firstInvalidField,
  isCodeComplete,
  validateFields,
  type ValidatableField,
} from '../shared/utils/validate';

/** 前置校验结果：错误文案映射 + 首错字段（全过时 errors 空、firstField undefined）。 */
export interface FormValidation {
  /** 字段名 → 已解析的错误文案（FieldRenderer errors prop 直接消费）。 */
  errors: Readonly<Record<string, string>>;
  /** 按 fields 顺序的首个未通过字段名（聚焦首错字段用）。 */
  firstField: string | undefined;
}

/**
 * 提交前整表前置校验：required 空值 → email / phone 格式 → otp / totp 满格
 * （规则唯一来源 shared/utils/validate.ts，本层只做 i18n 文案组装）。
 */
export function validateFormValues(
  fields: ValidatableField[],
  values: Readonly<Record<string, string>>,
): FormValidation {
  const issues = validateFields(fields, values);
  const errors: Record<string, string> = {};
  for (const [name, issue] of Object.entries(issues)) {
    errors[name] = t(FIELD_ISSUE_I18N_KEY[issue]);
  }
  return { errors, firstField: firstInvalidField(fields, issues) };
}

/** 验证码满格校验（verify 段 CodeInput，P0-2「空验证码 6 格未输满不可提交」）：未过 → 错误文案。 */
export function codeErrorText(
  code: string,
  length: number,
): string | undefined {
  return isCodeComplete(code, length)
    ? undefined
    : t('common.errIncompleteCode');
}

/**
 * ErrorBanner 接 onRetry（重提当前表单值）的失败态白名单（评审 P1-4）：
 * 二者均「可重试」（§1.6 列）且重提同值有意义——captcha_invalid 换新人机凭据
 * 后重提、internal_error 属瞬时故障；invalid_credentials / invalid_code 这类
 * 「同值必败」的状态不接（重提只是再失败一次，用户应改值后自行提交）。
 */
export const RETRY_RESUBMIT_STATUSES: ReadonlySet<string> = new Set([
  'captcha_invalid',
  'internal_error',
]);

/** 聚焦指定 id 的控件（首错字段定位）；node 测试环境无 DOM → 静默跳过。 */
export function focusField(id: string): void {
  if (typeof document === 'undefined') {
    return;
  }
  document.getElementById(id)?.focus();
}

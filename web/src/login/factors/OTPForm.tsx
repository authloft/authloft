/**
 * OTP 因子表单（otp_sms / otp_email 共用；docs/前端架构.md §4.3 行 436）：
 * 双段组件，按容器注入的 step（请求侧，§2.2 行 422）切换——
 * - challenge 段：主因子场景渲染目标输入（注入快照 challengeFields，§2.1 行
 *   390-394；challenge payload {phone}/{email}，§2.6 行 544）；MFA 场景不传
 *   目标（§2.6 行 545，目标取 uid 绑定资料），渲染掩码目标（§1.3 行 123-125
 *   maskedTarget）；
 * - verify 段：CodeInput 输码（§2.6 行 546 payload {code}）；autocomplete=
 *   "one-time-code" 与整串粘贴拆分由 shared CodeInput 承担（§1.11 行 330），
 *   本组件不重复实现；重发倒计时消费 useCountdown（入参 bigint、基于
 *   时间戳，§3.2 行 303）；错误计数提示 error.attemptsLeft（§1.3 行 151；
 *   §1.6 行 247 invalid_code 提示 + 剩余次数）。
 *
 * 组件不感知登录 / 注册场景（可被 RegisterPage 复用）：场景差异经 props 注入
 * （step / maskedTarget / onResend 由容器派生），提交统一上抛 props.onSubmit
 * （容器组装 payload 走 api 封装，§9 第 6 条）。
 *
 * verify 段已输码支持受控注入（code / onCodeChange 成对提供时走容器持值）：
 * OTPForm 实例随容器状态分支（StepDispatcher next 槽位 ↔ 失败态
 * 直渲染位）切换而重建，本地 state 会丢已输码——invalid_code 可重试原地重试
 * （§1.6 行 247）不应清空输入；缺省走组件本地 state（独立渲染 / 测试可用）。
 *
 * 文案（i18n 收口）：经 shared/i18n 的 t() 消费——login.codeLabel /
 * login.sendCode / login.resend / login.resendCountdown / login.attemptsLeft /
 * login.codeWillBeSentTo / login.submit（zh 原文照搬，en 镜像）。
 */
import { useState, type FormEvent } from 'react';
import { CodeInput, FieldRenderer } from '../../shared/components';
import { useCountdown } from '../../shared/hooks/useCountdown';
import { t } from '../../shared/i18n';
import { toDisplay } from '../../shared/utils/int';
import type { FactorProps } from './registry';
import styles from './OTPForm.module.less';

/** verify 段验证码分段数（§1.10 行 306-307：otp 六位码；下发 fields[].length 的通用渲染归 FormStep）。 */
const OTP_CODE_LENGTH = 6;

/** OTP 系专属扩展 props（全部可选，不破坏 registry 的 FactorProps 契约）。 */
export interface OTPFormProps extends FactorProps {
  /** 当前请求侧 step（§2.2 行 422）：'verify'=输码段；其余按 challenge 段渲染（§9 第 18 条零值兜底）。 */
  step?: string;
  /** 重发冷却剩余秒（§1.3 行 115 nextStep.retryAfter / 行 150 error.retryAfter；int64 bigint；undefined=无倒计时）。 */
  retryAfter?: bigint;
  /** 验证码剩余尝试次数（§1.3 行 151 error.attemptsLeft；undefined=不展示）。 */
  attemptsLeft?: bigint;
  /** MFA 场景掩码目标（§1.3 行 123-125；非空时 challenge 段只展示、不渲染目标输入，§2.6 行 545）。 */
  maskedTarget?: string;
  /** 重发回调（verify 段重发按钮；容器以 step=challenge 重发，§1.10 challenge→form 序列重走）。 */
  onResend?: () => void;
  /** verify 段已输码（受控值，容器持值防实例重建丢失）；缺省走组件本地 state。 */
  code?: string;
  /** verify 段输码变化上抛（与 code 成对注入即受控模式）。 */
  onCodeChange?: (value: string) => void;
}

/**
 * OTP 系因子判定（组件引用比较；method 字符串只许出现在 registry，§9 第 2 条）：
 * 容器据此走「专属因子组件 + 扩展 props」的渲染路径（OTPForm verify 段）。
 * 入参宽化为 unknown：组件引用的恒等比较无需结构约束（值即组件函数本身）。
 */
export function isOtpForm(factor: unknown): boolean {
  return factor === OTPForm;
}

export function OTPForm({
  fields,
  loading,
  disabled,
  onSubmit,
  step,
  retryAfter,
  attemptsLeft,
  maskedTarget,
  onResend,
  code: codeProp,
  onCodeChange,
}: OTPFormProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [localCode, setLocalCode] = useState('');
  // 受控 / 非受控双模式：容器注入（code + onCodeChange）→ 容器持值，
  // 实例随状态分支重建不丢已输码；缺省 → 本地 state（独立渲染）。
  const code = codeProp ?? localCode;
  const setCode = onCodeChange ?? setLocalCode;
  // 重发倒计时（§4.3 行 436）：入参 bigint（§1.12），内部经 toCount 归一。
  const countdown = useCountdown(retryAfter);

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  };

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!loading && !disabled) {
      // verify 段 {code}（§2.6 行 546）；challenge 段目标字段（行 544-545，MFA 场景空对象）。
      onSubmit(step === 'verify' ? { code } : values);
    }
  };

  if (step === 'verify') {
    return (
      <form onSubmit={submit} className={styles.form}>
        <label className={styles.label}>{t('login.codeLabel')}</label>
        <CodeInput
          value={code}
          onChange={setCode}
          length={OTP_CODE_LENGTH}
          ariaLabel={t('login.codeLabel')}
          disabled={loading || disabled}
        />
        {attemptsLeft !== undefined && (
          <p role="status" className={styles.status}>
            {t('login.attemptsLeft', { count: toDisplay(attemptsLeft) })}
          </p>
        )}
        <button
          type="button"
          disabled={loading || disabled || !countdown.expired}
          onClick={onResend}
          className={styles.resend}
        >
          {countdown.expired
            ? t('login.resend')
            : t('login.resendCountdown', { seconds: countdown.seconds })}
        </button>
        <button
          type="submit"
          disabled={loading || disabled}
          className={styles.submit}
        >
          {t('login.submit')}
        </button>
      </form>
    );
  }

  // challenge 段：主因子场景目标输入（快照 challengeFields）；MFA 场景掩码目标（§2.6 行 544-545）。
  return (
    <form onSubmit={submit} className={styles.form}>
      {maskedTarget !== undefined && maskedTarget !== '' ? (
        <p role="status" className={styles.status}>
          {t('login.codeWillBeSentTo', { target: maskedTarget })}
        </p>
      ) : (
        <FieldRenderer fields={fields} values={values} onChange={onChange} />
      )}
      <button
        type="submit"
        disabled={loading || disabled}
        className={styles.submit}
      >
        {t('login.sendCode')}
      </button>
    </form>
  );
}

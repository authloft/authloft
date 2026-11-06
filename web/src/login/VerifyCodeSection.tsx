/**
 * verify 段共享实现（FRONTEND-UX-REVIEW P2-10）：OTPForm（登录 /
 * MFA）与 RegisterPage / ResetPage（注册 / 重置）三处同构的「CodeInput 输码
 * + 未输满前置校验 + 剩余次数提示 + 重发倒计时 + 提交」段收敛为单份（原
 * 三份仅按钮文案 / id / 分段数 / 类名不同而各自自建）。
 *
 * 场景差异全部经 props 注入，不改任一消费方既有语义：
 * - 提交按钮文案键（submitLabelKey）：登录 = login.submit、注册 / 重置 =
 *   login.nextStep（按钮文案与流程语义保持不变）；
 * - id / length：OTPForm 固定 otp-code / 6；页族 reg-code / reset-code 与
 *   快照 codeLength；
 * - classes：各消费方 module.less 类名原样注入（less 零改动，与移动端
 *   适配改动零重叠）；
 * - resendDisabled：重发按钮禁用口径差异保留——OTPForm 原实现随 disabled
 *   一并禁用、页族原实现不含，缺省 false（页族口径）。
 *
 * 行为不变量（与原三实现逐条对齐）：提交前 codeErrorText 前置校验
 * （评审 P0-2，未过聚焦 CodeInput 不发请求）；attemptsLeft / retryAfter 为
 * bigint（§1.12）；重发倒计时基于时间戳（useCountdown，§9 第 7 条）；输码
 * 变化即清内联错误。
 */
import { useState, type FormEvent } from 'react';
import { CodeInput } from '../shared/components';
import { useCountdown } from '../shared/hooks/useCountdown';
import { t } from '../shared/i18n';
import { toDisplay } from '../shared/utils/int';
import { codeErrorText, focusField } from './validate';

/** 消费方 module.less 类名注入（各键缺省 = 该节点无类名，结构不变）。 */
export interface VerifyCodeSectionClasses {
  readonly form?: string;
  readonly label?: string;
  readonly error?: string;
  readonly status?: string;
  readonly resend?: string;
  readonly submit?: string;
}

export interface VerifyCodeSectionProps {
  /** CodeInput 稳定 id（label htmlFor / 错误槽 aria-describedby / 聚焦锚共用）。 */
  readonly id: string;
  /** 验证码分段数（OTPForm 固定 6；页族取快照 codeLength）。 */
  readonly length: number;
  /** 已输码（受控，容器持值防实例重建丢失，同款语义）。 */
  readonly code: string;
  readonly onCodeChange: (value: string) => void;
  /** 前置校验通过后上抛已输码（payload 组装归消费方，§9 第 6 条）。 */
  readonly onSubmit: (code: string) => void;
  /** 提交按钮文案 i18n 键（P2-10 可配文案：login.submit / login.nextStep）。 */
  readonly submitLabelKey: string;
  /** 类名注入（见 VerifyCodeSectionClasses）。 */
  readonly classes: VerifyCodeSectionClasses;
  readonly loading?: boolean;
  readonly disabled?: boolean;
  /** 剩余尝试次数（§1.3 行 151 error.attemptsLeft；undefined 不展示）。 */
  readonly attemptsLeft?: bigint;
  /** 重发冷却（§1.3 行 115 nextStep.retryAfter / 行 150 error.retryAfter；undefined 无倒计时）。 */
  readonly retryAfter?: bigint;
  readonly onResend?: () => void;
  /** 重发按钮随 disabled 一并禁用（OTPForm 原口径；页族原口径不含，缺省 false）。 */
  readonly resendDisabled?: boolean;
}

export function VerifyCodeSection({
  id,
  length,
  code,
  onCodeChange,
  onSubmit,
  submitLabelKey,
  classes,
  loading,
  disabled,
  attemptsLeft,
  retryAfter,
  onResend,
  resendDisabled,
}: VerifyCodeSectionProps) {
  const [codeError, setCodeError] = useState<string | undefined>(undefined);
  // 重发倒计时（§4.3 行 436）：入参 bigint，内部按时间戳计（§9 第 7 条）。
  const countdown = useCountdown(retryAfter);
  const controlsDisabled = loading === true || disabled === true;

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (controlsDisabled) {
      return;
    }
    // 评审 P0-2：未输满不提交，字段旁内联错误 + 聚焦首错。
    const issue = codeErrorText(code, length);
    if (issue !== undefined) {
      setCodeError(issue);
      focusField(id);
      return;
    }
    setCodeError(undefined);
    onSubmit(code);
  };

  return (
    <form onSubmit={submit} className={classes.form}>
      <label className={classes.label} htmlFor={id}>
        {t('login.codeLabel')}
      </label>
      <CodeInput
        value={code}
        onChange={(value) => {
          onCodeChange(value);
          setCodeError(undefined);
        }}
        length={length}
        ariaLabel={t('login.codeLabel')}
        id={id}
        disabled={controlsDisabled}
        ariaInvalid={codeError !== undefined}
        ariaDescribedBy={codeError !== undefined ? `${id}-error` : undefined}
      />
      {codeError !== undefined && (
        <p id={`${id}-error`} className={classes.error}>
          {codeError}
        </p>
      )}
      {attemptsLeft !== undefined && (
        <p role="status" className={classes.status}>
          {t('login.attemptsLeft', { count: toDisplay(attemptsLeft) })}
        </p>
      )}
      <button
        type="button"
        disabled={
          loading === true || resendDisabled === true || !countdown.expired
        }
        onClick={onResend}
        className={classes.resend}
      >
        {countdown.expired
          ? t('login.resend')
          : t('login.resendCountdown', { seconds: countdown.seconds })}
      </button>
      <button
        type="submit"
        disabled={controlsDisabled}
        className={classes.submit}
      >
        {t(submitLabelKey)}
      </button>
    </form>
  );
}

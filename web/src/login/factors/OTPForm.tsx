/**
 * OTP 因子表单（otp_sms / otp_email 共用；docs/前端架构.md §4.3 行 436）：
 * 双段组件，按容器注入的 step（请求侧，§2.2 行 422）切换——
 * - challenge 段：主因子场景渲染目标输入（注入快照 challengeFields，§2.1 行
 *   390-394；challenge payload {phone}/{email}，§2.6 行 544）；MFA 场景不传
 *   目标（§2.6 行 545，目标取 uid 绑定资料），渲染掩码目标（§1.3 行 123-125
 *   maskedTarget）；
 * - verify 段：CodeInput 输码（§2.6 行 546 payload {code}）——评审
 *   P2-10 起收敛为 login/VerifyCodeSection 共享实现（提交按钮文案
 *   login.submit、重发随 disabled 禁用为本组件口径，经 props 注入）；
 *   autocomplete="one-time-code" 与整串粘贴拆分由 shared CodeInput 承担
 *   （§1.11 行 330）；错误计数提示 error.attemptsLeft（§1.3 行 151）。
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
import { FieldRenderer, Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';
import { focusField, validateFormValues } from '../validate';
import { VerifyCodeSection } from '../VerifyCodeSection';
import type { FactorProps } from './registry';
import styles from './OTPForm.module.less';

/** verify 段验证码分段数（§1.10 行 306-307：otp 六位码；下发 fields[].length 的通用渲染归 FormStep）。 */
const OTP_CODE_LENGTH = 6;

/** verify 段 CodeInput 稳定 id（label htmlFor / 错误槽 aria-describedby 关联）。 */
const OTP_CODE_INPUT_ID = 'otp-code';

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
  /**
   * challenge 段初始表单值（评审 P1-5：传输失败 reset 后回填已输入
   * 目标——容器持值 challengeValues 注入；仅作本地 state 初值，后续编辑不回写）。
   */
  initialValues?: Readonly<Record<string, string>>;
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
  initialValues,
}: OTPFormProps) {
  // challenge 段表单值：容器持值注入作初值（评审 P1-5 reset 后回填），
  // 仅挂载时消费一次，后续编辑走本地 state。
  const [values, setValues] = useState<Record<string, string>>(() => ({
    ...initialValues,
  }));
  const [localCode, setLocalCode] = useState('');
  // 评审 P0-2：challenge 段字段级错误（verify 段输码校验归 VerifyCodeSection）。
  const [errors, setErrors] = useState<Readonly<Record<string, string>>>({});
  // 受控 / 非受控双模式：容器注入（code + onCodeChange）→ 容器持值，
  // 实例随状态分支重建不丢已输码；缺省 → 本地 state（独立渲染）。
  const code = codeProp ?? localCode;
  const setCode = onCodeChange ?? setLocalCode;

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
    setErrors((prev) => {
      if (prev[name] === undefined) {
        return prev;
      }
      const next = { ...prev };
      delete next[name];
      return next;
    });
  };

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading || disabled) {
      return;
    }
    // challenge 段目标字段（§2.6 行 544-545，MFA 场景空对象）：前置校验（P0-2）。
    const { errors: issues, firstField } = validateFormValues(fields, values);
    if (firstField !== undefined) {
      setErrors(issues);
      focusField(`fr-${firstField}`);
      return;
    }
    setErrors({});
    onSubmit(values);
  };

  // verify 段收敛为共享 VerifyCodeSection（评审 P2-10）：提交按钮文案
  // login.submit、重发随 disabled 禁用为本组件口径，经 props 注入保持原语义。
  if (step === 'verify') {
    return (
      <VerifyCodeSection
        id={OTP_CODE_INPUT_ID}
        length={OTP_CODE_LENGTH}
        code={code}
        onCodeChange={setCode}
        onSubmit={(value) => onSubmit({ code: value })} // §2.6 行 546
        submitLabelKey="login.submit"
        classes={{
          form: styles.form,
          label: styles.label,
          error: styles.error,
          status: styles.status,
          resend: styles.resend,
          submit: styles.submit,
        }}
        loading={loading}
        disabled={disabled}
        resendDisabled={disabled}
        attemptsLeft={attemptsLeft}
        retryAfter={retryAfter}
        onResend={onResend}
      />
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
        <FieldRenderer
          fields={fields}
          values={values}
          onChange={onChange}
          errors={errors}
        />
      )}
      <button
        type="submit"
        disabled={loading || disabled}
        className={styles.submit}
      >
        {/* 下发在途的加载视觉。 */}
        {loading ? (
          <>
            <Spinner size="sm" /> {t('login.sending')}
          </>
        ) : (
          t('login.sendCode')
        )}
      </button>
    </form>
  );
}

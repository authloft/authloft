/**
 * kind=challenge 步骤实体（docs/前端架构.md §4.2 行 441）：
 * 渲染 challenge_fields（信封 next_step.fields，§1.3 行 114）+ 触发按钮。
 *
 * captcha 走弹窗（shared/captcha 的 useCaptchaGate + CaptchaDialog）：challenge
 * 类后端恒拦截 → 点击即弹窗、一次带凭据的请求（upfront，§2.5）；凭据一次性
 * （服务端校验即失效，行 520），captcha_invalid 在窗内换新凭据循环，每次触发
 * 也重新问——不再内联插 widget、不再要求用户回头点一次提交。
 *
 * onTrigger 是**裸请求**（表单值 + gate 注入的凭据 → 信封，不做状态机分派）：
 * captcha_required / captcha_invalid 由本组件的 gate 吸收，终局信封经 onResult
 * 上抛给调用方分派。StepDispatcher 防御分派形态两者皆缺省——按钮渲染但无动作
 * （LoginContainer 不经信封驱动挑战步，OTP 系挑战段由 OTPForm form 槽承载）。
 *
 * 布局复用 FormStep.module.less（同构表单布局 .form / .submit，避免新增
 * 样式文件）。文案：触发按钮经 i18n 字典 login.sendCode 键取用（复用既有键）。
 */
import { useState, type FormEvent } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type {
  Field,
  LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import { CaptchaDialog } from '../../shared/captcha/CaptchaDialog';
import { flowCaptchaOutcome } from '../../shared/captcha/captchaGate';
import { useCaptchaGate } from '../../shared/captcha/useCaptchaGate';
import { ErrorBanner, FieldRenderer } from '../../shared/components';
import { t } from '../../shared/i18n';
import { getInit } from '../../shared/types/init';
import styles from './FormStep.module.less';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

export interface ChallengeStepProps {
  /** challenge 步渲染字段（§1.3 行 114 fields[]；captcha 字段被 FieldRenderer 跳过）。 */
  fields?: Field[];
  /** 请求在途（触发按钮禁用，§3.2）。 */
  loading?: boolean;
  /** 不可重试失败态禁用触发（§1.6「可重试」列）。 */
  disabled?: boolean;
  /**
   * 触发下发的裸请求：表单值 + captcha 凭据 → 信封（缺省无动作——防御分派
   * 形态）。凭据由 gate 弹窗提供，调用方并入 payload.captcha（§1.11 skip：
   * 不经表单值通道）；本回调不做状态机分派，终局信封走 onResult。
   */
  onTrigger?: (
    values: Readonly<Record<string, string>>,
    captcha?: CaptchaPayload,
  ) => Promise<LoginFlowResponse>;
  /** 终局信封上抛（gate 吸收 captcha_* 后的结果；调用方据此分派状态机）。 */
  onResult?: (envelope: LoginFlowResponse) => void;
  /** captcha 配置对象（缺省取注入快照 methods.captcha；来源三处见 §2.5 行 477）。 */
  captcha?: CaptchaConfig;
}

export function ChallengeStep({
  fields = [],
  loading = false,
  disabled = false,
  onTrigger,
  onResult,
  captcha: captchaConfig = initCaptcha(),
}: ChallengeStepProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const gate = useCaptchaGate();
  // 本地在途（防御分派形态无调用方 loading 注入）：弹窗确认后的重提也在途。
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  };

  const trigger = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading || disabled || pending || onTrigger === undefined) {
      return;
    }
    setPending(true);
    setFailed(false);
    const outcome = await gate.run({
      mode: 'upfront',
      config: captchaConfig,
      request: (token) => onTrigger(values, token),
      readOutcome: flowCaptchaOutcome,
    });
    setPending(false);
    if (outcome.kind === 'result') {
      onResult?.(outcome.result);
    } else if (outcome.kind === 'error') {
      // 传输层失败兜底（§1.6 行 272：不暴露内部信息）；取消不动作、表单原样可重提。
      setFailed(true);
    }
  };

  return (
    <>
      <form onSubmit={trigger} className={styles.form}>
        <FieldRenderer fields={fields} values={values} onChange={onChange} />
        <button
          type="submit"
          disabled={loading || disabled || pending}
          className={styles.submit}
        >
          {t('login.sendCode')}
        </button>
        {failed && <ErrorBanner i18nKey="errors.status.failed" />}
      </form>
      <CaptchaDialog {...gate.dialogProps} />
    </>
  );
}

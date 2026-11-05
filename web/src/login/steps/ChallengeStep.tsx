/**
 * kind=challenge 步骤实体（docs/前端架构.md §4.2 行 441）：
 * 渲染 challenge_fields（信封 next_step.fields，§1.3 行 114）+ CaptchaWidget，
 * 触发下发——每次下发都需新的 captcha（行 441）：触发即取当前凭据上抛并
 * reset（服务端校验即失效，§2.5 行 520，用户下次触发前重新作答）。
 *
 * 触发回调 onTrigger 上抛表单值 + captcha 凭据（payload 组装归调用方——
 * 与容器 submit 的 getCaptchaToken 模式同构，§1.11 skip）；StepDispatcher
 * 防御分派形态无触发通道（LoginContainer 不经信封驱动挑战步，OTP 系挑战段
 * 由 OTPForm form 槽承载），按钮渲染但无动作。
 *
 * 布局复用 FormStep.module.less（同构表单布局 .form / .submit，避免新增
 * 样式文件）。文案：i18n 无键，中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useRef, useState, type FormEvent } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { Field } from '../../gen/proto/api/sso/v1/envelope_pb';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../../shared/captcha/CaptchaWidget';
import { FieldRenderer } from '../../shared/components';
import { getInit } from '../../shared/types/init';
import styles from './FormStep.module.less';

/** 触发下发按钮文案（与 OTPForm challenge 段同款，§2.6 行 544 挑战场景）。 */
const TRIGGER_TEXT = '发送验证码';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

export interface ChallengeStepProps {
  /** challenge 步渲染字段（§1.3 行 114 fields[]；captcha 字段被 FieldRenderer 跳过）。 */
  fields?: readonly Field[];
  /** 请求在途（触发按钮禁用，§3.2）。 */
  loading?: boolean;
  /** 不可重试失败态禁用触发（§1.6「可重试」列）。 */
  disabled?: boolean;
  /** 触发下发：表单值 + captcha 凭据上抛（缺省无动作——防御分派形态）。 */
  onTrigger?: (
    values: Readonly<Record<string, string>>,
    captcha?: CaptchaPayload,
  ) => void;
  /** captcha 配置对象（缺省取注入快照 methods.captcha；来源三处见 §2.5 行 477）。 */
  captcha?: CaptchaConfig;
}

export function ChallengeStep({
  fields = [],
  loading = false,
  disabled = false,
  onTrigger,
  captcha = initCaptcha(),
}: ChallengeStepProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  const onChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  };

  const trigger = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (loading || disabled) {
      return;
    }
    onTrigger?.(values, captchaRef.current?.getToken());
    // 每次下发都需新的 captcha（§4.2 行 441）：凭据已取走（一次性语义），
    // reset 换新供下次触发（image 型换新图，§3.5 行 364）。
    captchaRef.current?.reset();
  };

  return (
    <form onSubmit={trigger} className={styles.form}>
      <FieldRenderer fields={fields} values={values} onChange={onChange} />
      {captcha !== undefined && <CaptchaWidget captcha={captcha} ref={captchaRef} />}
      <button type="submit" disabled={loading || disabled} className={styles.submit}>
        {TRIGGER_TEXT}
      </button>
    </form>
  );
}

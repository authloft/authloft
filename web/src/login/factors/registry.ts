/**
 * 因子组件映射表（docs/前端架构.md §4.3 行 434）：method → 组件。
 *
 * - totp 显式映射为 null：它由通用 FormStep（§4.2 steps/）渲染、
 *   不设专属组件（§1.2 行 48「totp 不设专属组件，由通用 FormStep +
 *   CodeInput 渲染」）——null 是「通用表单渲染」的语义标记，不是缺映射；
 * - otp_sms / otp_email → OTPForm（双段组件，扩展 props 由容器按 step 派生，
 *   OTPForm.isOtpForm 判定）；recovery_code → RecoveryCodeForm；webauthn →
 *   WebAuthnButton（usernameless 免密按钮，challengeData 注入 / 断言
 *   经 onCredential 上抛，容器 isWebAuthnForm 判定）；
 * - 缺映射（lookupFactor 返回 undefined，如 thirdparty——由 MethodTabs 链路
 *   接入，不进本表）走兜底错误态，**不许无映射静默回退**（§4.3 行
 *   434）；新增因子只改本表一行（§4.3 行 434）。
 */
import type { ComponentType } from 'react';
import type { Field } from '../../gen/proto/api/sso/v1/envelope_pb';
import { OTPForm } from './OTPForm';
import { PasswordForm } from './PasswordForm';
import { RecoveryCodeForm } from './RecoveryCodeForm';
import { WebAuthnButton } from './WebAuthnButton';

/** 因子组件契约：容器以统一 props 驱动各因子表单（fields 以后端下发为准，§2.1）。 */
export interface FactorProps {
  /** 该因子 form 步的后端下发字段（§2.1 fields[]；captcha 字段被 FieldRenderer 跳过）。 */
  fields: Field[];
  /** 请求在途（提交按钮禁用，§3.2）。 */
  loading: boolean;
  /** 不可重试失败态禁用提交（selectors.selectSubmitDisabled，§1.6「可重试」列）。 */
  disabled: boolean;
  /** 提交：表单值（字段名 → 字符串）上抛，由容器组装 payload（含 captcha）。 */
  onSubmit: (values: Readonly<Record<string, string>>) => void;
}

/** 因子组件类型（registry 的值；null = 通用 FormStep 语义）。 */
export type FactorComponent = ComponentType<FactorProps>;

/** method → 组件映射表（§4.3）。 */
export const FACTOR_REGISTRY: Readonly<Record<string, FactorComponent | null>> =
  {
    password: PasswordForm,
    totp: null,
    otp_sms: OTPForm,
    otp_email: OTPForm,
    webauthn: WebAuthnButton,
    recovery_code: RecoveryCodeForm,
  };

/**
 * 查表：三态返回——组件（渲染专属因子表单）｜null（totp 语义：通用 FormStep
 * 渲染，由 steps/FormStep 落地）｜undefined（缺映射 → 兜底错误态）。
 */
export function lookupFactor(
  method: string,
): FactorComponent | null | undefined {
  return Object.prototype.hasOwnProperty.call(FACTOR_REGISTRY, method)
    ? FACTOR_REGISTRY[method]
    : undefined;
}

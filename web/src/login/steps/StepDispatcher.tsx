/**
 * 步骤分派器（status=next 的 next_step.kind 分派；docs/前端架构.md §4.2 行 423）：
 * 本实现只实现 kind=form——渲染容器构造的 form 段（专属因子组件的
 * verify 段（如 OTPForm）或通用 FormStep；容器按 nextStep.method 查 registry
 * 构造，本层不 import 因子组件，保持步骤层与因子层解耦）。
 *
 * - challenge / redirect / qrcode / poll 未实现走兜底「请刷新重试」
 *   （实体组件 ChallengeStep / RedirectStep / QRCodeStep / PollStep 归后续实现，
 *   §4.2 行 425-428）；
 * - external 由宿主承载（§9 第 10 条：login/ 下不实现 external 步骤组件），
 *   同走兜底；未识别 kind 同兜底；新增 StepKind 时只改本文件（§4.2 行 423）。
 *
 * 文案：兜底文案在 i18n 字典无键，中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import type { ReactNode } from 'react';
import type { NextStep } from '../../gen/proto/api/sso/v1/envelope_pb';
import styles from './StepDispatcher.module.less';

/** kind 兜底文案（i18n 无键，字面量声明见文件头；与 registry 缺映射兜底同款，§4.2 行 423）。 */
export const STEP_FALLBACK_TEXT = '请刷新重试';

export interface StepDispatcherProps {
  /** status=next 时的下一步渲染信息（§1.3 行 110-118）。 */
  nextStep: NextStep;
  /** kind=form 的渲染内容（容器构造：OTPForm verify 段 / FormStep / 缺映射兜底）。 */
  form: ReactNode;
}

export function StepDispatcher({ nextStep, form }: StepDispatcherProps) {
  if (nextStep.kind === 'form') {
    return <>{form}</>;
  }
  // challenge / redirect / qrcode / poll：未实现（实体组件归后续实现）；
  // external：宿主承载（§9 第 10 条）；未识别 kind：同兜底。
  return (
    <p role="status" className={styles.status}>
      {STEP_FALLBACK_TEXT}
    </p>
  );
}

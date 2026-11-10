/**
 * 步骤分派器（status=next 的 next_step.kind 分派；docs/前端架构.md §4.2 行 423）：
 * kind=form 渲染容器构造的 form 段（专属因子组件的 verify 段（如 OTPForm）或
 * 通用 FormStep；容器按 nextStep.method 查 registry 构造，本层不 import 因子
 * 组件，保持步骤层与因子层解耦）；kind=redirect / challenge / qrcode 分派实体
 * 组件（不再走兜底）；kind=poll 扩展位保留（当前无实例，§4.2 行 444）。
 *
 * - 信封 NextStep 无 authorize_url / providerKey 字段（§12.9 生成物）——
 *   redirect / qrcode 分派为防御形态（RedirectStep 空 URL 不跳、QRCodeStep
 *   空 providerKey 占位，零值兜底 §9 第 18 条）：真实链路经 ProviderButtons
 *   主方式渲染入口（§4.3 行 454，redirect 渠道点击 / qrcode 面板）；
 * - challenge 分派 ChallengeStep（fields + 触发按钮，captcha 由其自带弹窗承接；
 *   无触发通道——防御形态；OTP 系挑战段由 OTPForm form 槽承载）；
 * - external 由宿主承载（§9 第 10 条：login/ 下不实现 external 步骤组件），
 *   走兜底；未识别 kind 同兜底；新增 StepKind 时只改本文件（§4.2 行 423）。
 *
 * 文案：kind 兜底文案经 i18n 字典 common.refreshAndRetry 键取用
 * （与 registry 缺映射兜底同款口径，§4.2 行 423）。
 */
import type { ReactNode } from 'react';
import type { NextStep } from '../../gen/proto/api/sso/v1/envelope_pb';
import { t } from '../../shared/i18n';
import { ChallengeStep } from './ChallengeStep';
import { QRCodeStep } from './QRCodeStep';
import { RedirectStep } from './RedirectStep';
import styles from './StepDispatcher.module.less';

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
  if (nextStep.kind === 'redirect') {
    // §4.2 行 442：防御分派（NextStep 无 authorize_url 字段）——空 URL 仅
    // 展示文案不跳转；URL 就绪的跳转经 ProviderButtons 主链路注入。
    return <RedirectStep />;
  }
  if (nextStep.kind === 'challenge') {
    // §4.2 行 441：fields（挑战字段）+ 触发按钮（captcha 弹窗由 ChallengeStep
    // 自持）；无触发通道（防御形态，onTrigger / onResult 归容器接线后续实现）。
    return <ChallengeStep fields={nextStep.fields} />;
  }
  if (nextStep.kind === 'qrcode') {
    // §4.2 行 443：NextStep 无 providerKey 字段——空值兜底占位；真实拉码
    // 链路经 ProviderButtons（qrcode 渠道点击）。
    return <QRCodeStep providerKey="" />;
  }
  // poll：扩展位保留（§4.2 行 444，当前无实例）；external：宿主承载
  // （§9 第 10 条）；未识别 kind：同兜底。
  return (
    <p role="status" className={styles.status}>
      {t('common.refreshAndRetry')}
    </p>
  );
}

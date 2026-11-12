/**
 * login 域状态机 selectors（docs/前端架构.md §4.1 行 382）：纯函数，从
 * FlowState 派生渲染决策输入——当前 step、当前 method、是否禁用提交。
 * captcha 的展示决策不在此：弹窗由 shared/captcha 的 gate 驱动（编排态在
 * useCaptchaGate，不在 FlowState），FlowState 只镜像逃逸后的终局 status。
 */
import { resolveFlowStatus } from '../../shared/api/errors';
import type { FlowState } from './machine';

/** 当前 step（select_method 设定 / advance 推进 / request_started 镜像）。 */
export function selectCurrentStep(state: FlowState): string {
  return state.step;
}

/** 当前认证方式（select_method 设定；status=next 时已按 next_step.method 更新）。 */
export function selectCurrentMethod(state: FlowState): string {
  return state.method;
}

/**
 * 是否禁用提交：请求在途（§3.2：提交按钮按 loading 禁用）或已完成（success）
 * 或 §1.6「可重试 = 否」的失败态（如 too_many_requests / locked 倒计时）。
 * 流程中间态（next / mfa_required / binding_required）、轮询态（pending /
 * scanned 为进行中不作失败，expired 为提示刷新的终态，§4.1 行 395）与可重试
 * 失败（如 invalid_credentials）不禁用。captcha 两码仅作 ErrorInfo.code、不进
 * 流程态（§1.6 行 286），故不在此列——其编排由 shared/captcha 的 gate 承担。
 */
export function selectSubmitDisabled(state: FlowState): boolean {
  if (state.loading || state.status === 'success') {
    return true;
  }
  switch (state.status) {
    case 'idle':
    case 'next':
    case 'mfa_required':
    case 'binding_required':
    case 'pending':
    case 'scanned':
    case 'expired':
      return false;
    default:
      // 其余为失败态：按 §1.6「可重试」列（FLOW_STATUS_TABLE 表驱动）。
      return !resolveFlowStatus(state.status).retryable;
  }
}

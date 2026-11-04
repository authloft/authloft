/**
 * login 域状态机 selectors（docs/前端架构.md §4.1 行 382）：纯函数，从
 * FlowState 派生渲染决策输入——当前 step、当前 method、是否展示 captcha、
 * 是否禁用提交。
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
 * 是否展示 captcha：§1.6 行 240-241——captcha_required 按响应顶层 captcha
 * 渲染 CaptchaWidget 并重提、captcha_invalid reset widget 后重试；captcha
 * 对象按零值兜底缺失时不展示（§2.5 行 518 服务端必附，此处防御）。
 */
export function selectShowCaptcha(state: FlowState): boolean {
  return (
    (state.status === 'captcha_required' ||
      state.status === 'captcha_invalid') &&
    state.envelope?.captcha !== undefined
  );
}

/**
 * 是否禁用提交：请求在途（§3.2：提交按钮按 loading 禁用）或已完成（success）
 * 或 §1.6「可重试 = 否」的失败态（如 too_many_requests / locked 倒计时）。
 * 流程中间态（next / mfa_required / binding_required / captcha_*）、轮询态
 * （pending / scanned 为进行中不作失败，expired 为提示刷新的终态，§4.1 行 395）
 * 与可重试失败（如 invalid_credentials）不禁用。
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
    case 'captcha_required':
    case 'captcha_invalid':
    case 'pending':
    case 'scanned':
    case 'expired':
      return false;
    default:
      // 其余为失败态：按 §1.6「可重试」列（FLOW_STATUS_TABLE 表驱动）。
      return !resolveFlowStatus(state.status).retryable;
  }
}

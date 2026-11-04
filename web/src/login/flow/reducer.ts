/**
 * login 域状态机 reducer（docs/前端架构.md §4.1 行 381）：纯函数
 * (state, event) → state，承载全部状态迁移与副作用标记（state.effects）；
 * 无副作用、无网络调用——发请求在 api.ts / 容器，localStorage 在
 * oidcContext.ts，login_token 内存变量在 loginTokenStore。
 */
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import { FLOW_STATUS_TABLE, type FlowStatusKey } from '../../shared/api/errors';
import {
  INITIAL_FLOW_STATE,
  type FlowEffect,
  type FlowState,
  type MachineStatus,
} from './machine';

/** 状态机事件。 */
export type FlowEvent =
  /**
   * 选择认证方式（主流程方式或 mfa.methods 之一，§4.1 行 407：mfa 就地渲染
   * 选择器、不跳页）；firstStep 由调用方按注入快照 methods[].steps 的首个
   * kind 映射（challenge → 'challenge'，form → 'verify' / 'set_password'）。
   */
  | { readonly type: 'select_method'; readonly method: string; readonly firstStep: string }
  /** 发起请求（step 为本次提交的 step，§2.2 行 422）；loading → true。 */
  | { readonly type: 'request_started'; readonly step: string }
  /** 收到登录流程信封（§1.3）：status 镜像 + 副作用标记，loading → false。 */
  | { readonly type: 'response'; readonly envelope: LoginFlowResponse }
  /** 推进到新 step（容器按 next_step 决定，如 challenge → verify）；reducer 不做 kind→step 推演。 */
  | { readonly type: 'advance'; readonly step: string }
  /** 回到第一步（restart 副作用的落地 / 刷新后重置 / 用户退出重登）。 */
  | { readonly type: 'reset' };

/**
 * 未知 status 一律映射为 failed（§1.6 行 272：登录流程域未知异常 → failed
 * + 兜底文案，不暴露内部信息）；封闭集合成员关系由 FLOW_STATUS_TABLE 判定
 * （shared/api/errors，§1.6 行 270 单一真相）。
 */
function normalizeStatus(status: string): MachineStatus {
  return Object.prototype.hasOwnProperty.call(FLOW_STATUS_TABLE, status)
    ? (status as FlowStatusKey)
    : 'failed';
}

/** §1.6「前端动作 = 回到第一步」类：step / token / state 校验失败。 */
const RESTART_STATUSES: ReadonlySet<string> = new Set([
  'step_invalid',
  'token_invalid',
  'token_expired',
  'state_mismatch',
]);

/** response 迁移的副作用标记（§4.1 行 383 终点 / 行 403 回到第一步）。 */
function effectsFor(
  status: MachineStatus,
  envelope: LoginFlowResponse,
): readonly FlowEffect[] {
  if (status === 'success') {
    return [{ type: 'complete', envelope }];
  }
  if (status !== 'idle' && RESTART_STATUSES.has(status)) {
    return [{ type: 'restart', status: status as FlowStatusKey }];
  }
  return [];
}

/** 状态机 reducer（纯函数）。 */
export function flowReducer(state: FlowState, event: FlowEvent): FlowState {
  switch (event.type) {
    case 'select_method':
      // 换方式 = 全新流程（含 mfa 方式切换）：回 idle、清信封与副作用标记。
      return { ...INITIAL_FLOW_STATE, method: event.method, step: event.firstStep };
    case 'request_started':
      return { ...state, loading: true, step: event.step, effects: [] };
    case 'response': {
      const status = normalizeStatus(event.envelope.status);
      // §1.3 行 112：next_step.method 为当前认证方式；零值兜底（§9 第 18 条）——空串保持原值。
      const nextMethod = event.envelope.nextStep?.method ?? '';
      return {
        ...state,
        status,
        method: nextMethod !== '' ? nextMethod : state.method,
        envelope: event.envelope,
        loading: false,
        effects: effectsFor(status, event.envelope),
      };
    }
    case 'advance':
      return { ...state, step: event.step, effects: [] };
    case 'reset':
      return INITIAL_FLOW_STATE;
  }
}

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化落地后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { create, type MessageInitShape } from '@bufbuild/protobuf';
import {
  LoginFlowResponseSchema,
  type LoginFlowResponse,
} from '../../gen/proto/api/sso/v1/envelope_pb';
import { FLOW_STATUS_TABLE } from '../../shared/api/errors';
import {
  INITIAL_FLOW_STATE,
  type FlowState,
  type MachineStatus,
} from './machine';
import { flowReducer, type FlowEvent } from './reducer';
import {
  selectCurrentMethod,
  selectCurrentStep,
  selectShowCaptcha,
  selectSubmitDisabled,
} from './selectors';

/** 信封 init（§1.3）：status 必填，其余按需覆盖。 */
type EnvelopeInit = MessageInitShape<typeof LoginFlowResponseSchema>;

/** 构造信封（§1.3）：status 必填，其余按需覆盖。 */
function envelope(status: string, overrides: EnvelopeInit = {}): LoginFlowResponse {
  return create(LoginFlowResponseSchema, { status, ...overrides });
}

/** 依次派发事件（从初始态起）。 */
function reduce(events: readonly FlowEvent[], state: FlowState = INITIAL_FLOW_STATE): FlowState {
  return events.reduce(flowReducer, state);
}

/** 到达指定状态的捷径（经 select_method → request_started → response）。 */
function at(status: string, overrides: EnvelopeInit = {}): FlowState {
  return reduce([
    { type: 'select_method', method: 'password', firstStep: 'verify' },
    { type: 'request_started', step: 'verify' },
    { type: 'response', envelope: envelope(status, overrides) },
  ]);
}

describe('machine 初始态（§4.1 状态机图 idle 起点）', () => {
  test('status=idle、无方式 / step / 信封、不在途、无副作用标记', () => {
    expect(INITIAL_FLOW_STATE).toEqual({
      status: 'idle',
      method: '',
      step: '',
      envelope: undefined,
      loading: false,
      effects: [],
    });
  });
});

describe('reducer status 迁移（§1.3 行 145：status 是唯一分支依据；§1.6 封闭全量表）', () => {
  test('§1.6 全部 33 个 status 逐字镜像到 state.status', () => {
    const statuses = Object.keys(FLOW_STATUS_TABLE);
    expect(statuses).toHaveLength(33); // 封闭集合规模锚点（§1.6 行 230-263）
    for (const status of statuses) {
      const state = at(status);
      expect(state.status, `status=${status}`).toBe(status);
      expect(state.envelope?.status).toBe(status);
      expect(state.loading).toBe(false);
    }
  });

  test('未知 status → failed（§1.6 行 272：登录流程域未知异常一律映射 failed）', () => {
    expect(at('no_such_status').status).toBe('failed');
    expect(at('').status).toBe('failed');
  });

  test('success → 副作用标记 complete（§4.1 行 383：终点处理归容器）', () => {
    const state = at('success', { redirectTo: '/home', userId: BigInt(60) });
    expect(state.effects).toEqual([
      { type: 'complete', envelope: state.envelope },
    ]);
  });

  test('回到第一步类（§1.6：step_invalid / token_invalid / token_expired / state_mismatch）→ restart 标记', () => {
    for (const status of ['step_invalid', 'token_invalid', 'token_expired', 'state_mismatch']) {
      expect(at(status).effects, `status=${status}`).toEqual([
        { type: 'restart', status },
      ]);
    }
  });

  test('其余 status 不产生副作用标记（渲染决策由 selectors / 容器读 state 派生）', () => {
    for (const status of [
      'next',
      'mfa_required',
      'binding_required',
      'pending',
      'scanned',
      'expired',
      'failed',
      'captcha_required',
      'captcha_invalid',
      'too_many_requests',
      'locked',
      'invalid_credentials',
      'internal_error',
    ]) {
      expect(at(status).effects, `status=${status}`).toEqual([]);
    }
  });
});

describe('reducer 事件迁移', () => {
  test('select_method：设 method / firstStep，回 idle、清信封与在途（含 mfa 方式切换，§4.1 行 407）', () => {
    const state = reduce([
      { type: 'select_method', method: 'password', firstStep: 'verify' },
      { type: 'request_started', step: 'verify' },
      { type: 'response', envelope: envelope('mfa_required') },
      { type: 'select_method', method: 'totp', firstStep: 'verify' },
    ]);
    expect(state).toEqual({ ...INITIAL_FLOW_STATE, method: 'totp', step: 'verify' });
  });

  test('request_started：loading=true 并记录本次提交的 step（§2.2 行 422）', () => {
    const state = reduce([
      { type: 'select_method', method: 'otp_email', firstStep: 'challenge' },
      { type: 'request_started', step: 'challenge' },
    ]);
    expect(state.loading).toBe(true);
    expect(state.step).toBe('challenge');
  });

  test('response：loading=false；next_step.method 更新当前方式（§1.3 行 112），空串零值兜底保持原值（§9 第 18 条）', () => {
    const switched = at('next', {
      nextStep: { kind: 'challenge', method: 'otp_email' },
    });
    expect(switched.method).toBe('otp_email');

    const kept = at('next', { nextStep: { kind: 'form' } });
    expect(kept.method).toBe('password'); // select_method 设定的原值
  });

  test('advance：推进 step，容器按 next_step 决定（reducer 不做 kind→step 推演）', () => {
    const state = reduce([
      { type: 'select_method', method: 'otp_email', firstStep: 'challenge' },
      { type: 'response', envelope: envelope('next', { nextStep: { kind: 'form', method: 'otp_email' } }) },
      { type: 'advance', step: 'verify' },
    ]);
    expect(selectCurrentStep(state)).toBe('verify');
  });

  test('reset：回到初始态（restart 副作用的落地 / 刷新后重置）', () => {
    const state = reduce([{ type: 'reset' }], at('success'));
    expect(state).toEqual(INITIAL_FLOW_STATE);
  });

  test('每次事件迁移重置副作用标记（容器处理后继续派发不重复执行）', () => {
    const state = reduce([{ type: 'request_started', step: 'verify' }], at('success'));
    expect(state.effects).toEqual([]);
  });
});

describe('selectors（§4.1 行 382：当前 step / method / captcha / 禁用提交）', () => {
  test('selectCurrentStep / selectCurrentMethod', () => {
    const state = reduce([
      { type: 'select_method', method: 'otp_sms', firstStep: 'challenge' },
    ]);
    expect(selectCurrentStep(state)).toBe('challenge');
    expect(selectCurrentMethod(state)).toBe('otp_sms');
  });

  test('selectShowCaptcha：仅 captcha_required / captcha_invalid 且响应顶层 captcha 存在（§1.6 行 240-241）', () => {
    expect(
      selectShowCaptcha(at('captcha_required', { captcha: { providerKey: 'builtin_image', type: 'image' } })),
    ).toBe(true);
    expect(
      selectShowCaptcha(at('captcha_invalid', { captcha: { providerKey: 'cf_turnstile', type: 'turnstile' } })),
    ).toBe(true);
    // 零值兜底：captcha 对象缺失不展示（§2.5 行 518 服务端必附，防御）
    expect(selectShowCaptcha(at('captcha_required'))).toBe(false);
    expect(selectShowCaptcha(at('next'))).toBe(false);
    expect(selectShowCaptcha(at('success'))).toBe(false);
  });

  test('selectSubmitDisabled：loading / success / 不可重试失败态 → true（§3.2 + §1.6「可重试」列）', () => {
    // 请求在途（§3.2：提交按钮按 loading 禁用）
    expect(
      selectSubmitDisabled(reduce([{ type: 'request_started', step: 'verify' }])),
    ).toBe(true);
    // 已完成
    expect(selectSubmitDisabled(at('success'))).toBe(true);
    // 不可重试失败：倒计时类（§1.6 行 242-244）
    expect(selectSubmitDisabled(at('too_many_requests'))).toBe(true);
    expect(selectSubmitDisabled(at('locked'))).toBe(true);
    expect(selectSubmitDisabled(at('method_disabled'))).toBe(true);
  });

  test('selectSubmitDisabled：中间态 / 轮询态 / 可重试失败 → false（§4.1 行 395：pending / scanned 不作失败）', () => {
    for (const status of [
      'idle',
      'next',
      'mfa_required',
      'binding_required',
      'captcha_required',
      'captcha_invalid',
      'pending',
      'scanned',
      'expired',
    ] as MachineStatus[]) {
      const state = status === 'idle' ? INITIAL_FLOW_STATE : at(status);
      expect(selectSubmitDisabled(state), `status=${status}`).toBe(false);
    }
    // 可重试失败（§1.6「可重试 = 是」）：允许重提
    expect(selectSubmitDisabled(at('invalid_credentials'))).toBe(false);
    expect(selectSubmitDisabled(at('invalid_code'))).toBe(false);
    expect(selectSubmitDisabled(at('user_not_found'))).toBe(false);
  });
});

/**
 * captcha 弹窗编排（纯逻辑：请求 / 结果判读 / 弹窗询问全部由调用方注入，
 * node 环境可测，沿 runSubmit 与 createQRPanelController 的边界惯例）。
 *
 * 取代原「内联 widget + 用户再点一次提交」的重试驱动：弹窗确认即重提原请求，
 * captcha_invalid 在弹窗内换凭据循环，其余状态一律关窗交调用方既有状态机。
 *
 * 两种触发时机（docs/接口文档.md §2.5）：
 * - upfront：challenge 类后端 Challenge 恒拦截，前端已知必经 → 先问再发，
 *   省一次注定被拦的往返；
 * - reactive：密码 verify 由当日失败计数阈值触发，前端无法预知 → 先发裸请求，
 *   命中 captcha_required 才问。
 *
 * captcha 失败统一走非 200 Connect 错误体（`ErrorInfo.code` =
 * captcha_required / captcha_invalid，已由 http.ts 归一为 ApiError）；
 * 弹窗所需配置取自同一错误体 details 的 `api.common.v1.CaptchaConfig`
 * （`ApiError.captcha`，§1.5 行 228 / §2.5），不再依赖登录流程信封。
 * 判读一律经 errors.ts 的动作表（§1.6 一套词汇两个位置），本模块不自造状态常量。
 */
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import {
  ApiError,
  resolveCode,
  resolveFlowStatus,
  type StatusAction,
} from '../api/errors';

export type CaptchaGateMode = 'upfront' | 'reactive';

/** 一次请求的 captcha 判读结果：动作取 §1.6 动作表，配置取错误体 details。 */
export interface CaptchaOutcome {
  action: StatusAction;
  /** 仅错误体 details 携带（`ApiError.captcha`）；缺失时沿用调用方注入的配置。 */
  captcha?: CaptchaConfig;
}

/** 一次弹窗询问。 */
export interface CaptchaPrompt {
  config: CaptchaConfig;
  /** 上一轮凭据被判无效（reset_captcha）：弹窗内出错误文案。 */
  invalid: boolean;
  /** 本轮 gate 内第几次询问（0 起）；视图以此为 widget key，保证每次换新凭据。 */
  attempt: number;
}

export type CaptchaGateResult<T> =
  | { kind: 'result'; result: T }
  | { kind: 'cancelled' }
  | { kind: 'error'; error: unknown };

export interface CaptchaGateOptions<T> {
  mode: CaptchaGateMode;
  /** 首屏快照（login）/ GetConfig（account）注入的配置；错误体 details 到达后被覆盖。 */
  config?: CaptchaConfig;
  /** 原请求；凭据由 gate 注入，调用方挂到请求顶层 `captcha`（与 payload 平级）后重提同一请求。 */
  request: (captcha?: CaptchaPayload) => Promise<T>;
  readOutcome: (result: T) => CaptchaOutcome;
  /** 抛出形态的判读；缺省用 `errorCaptchaOutcome`（captcha 失败统一走 ErrorInfo.code）。 */
  readError?: (error: unknown) => CaptchaOutcome | undefined;
  /** 打开弹窗并等用户作答；确认 → 凭据，取消 → undefined。 */
  prompt: (prompt: CaptchaPrompt) => Promise<CaptchaPayload | undefined>;
}

/** §1.6 动作表里归本 gate 吸收的两个动作；其余一律逃逸给调用方状态机。 */
function isCaptchaAction(action: StatusAction): boolean {
  return action === 'require_captcha' || action === 'reset_captcha';
}

/**
 * 登录流程域判读（位置一：200 信封顶层 status）。captcha 失败已改为非 200
 * 错误体，故此处只取 status 对应动作，不再读信封上的 captcha 字段。
 */
export function flowCaptchaOutcome(
  envelope: LoginFlowResponse,
): CaptchaOutcome {
  return { action: resolveFlowStatus(envelope.status).action };
}

/** 抛出形态判读（位置二：ApiError.code + 错误体 details 的配置）；非 ApiError 不可判读。 */
export function errorCaptchaOutcome(
  error: unknown,
): CaptchaOutcome | undefined {
  return error instanceof ApiError
    ? { action: resolveCode(error).action, captcha: error.captcha }
    : undefined;
}

/**
 * 跑一轮带 captcha 弹窗的请求。返回终局结果、用户取消、或原样错误三者之一；
 * 取消不清任何流程态（loginToken 由 api.ts 托管，本模块不触碰）。
 */
export async function runCaptchaGate<T>(
  options: CaptchaGateOptions<T>,
): Promise<CaptchaGateResult<T>> {
  let config = options.config;
  let invalid = false;
  let attempt = 0;
  // captcha 失败统一为 ErrorInfo.code（§1.5 / §1.6）；未注入 readError 时用默认判读，
  // 登录 / 注册 / 重置 / 扫码 / 绑定各域共用同一条吸收路径。
  const readError = options.readError ?? errorCaptchaOutcome;

  /** 发一次请求：终局 → 返回结果；仍需 captcha → 更新循环态并返回 undefined。 */
  const send = async (
    captcha: CaptchaPayload | undefined,
  ): Promise<CaptchaGateResult<T> | undefined> => {
    let outcome: CaptchaOutcome;
    try {
      const result = await options.request(captcha);
      outcome = options.readOutcome(result);
      if (!isCaptchaAction(outcome.action)) {
        return { kind: 'result', result };
      }
    } catch (error) {
      const mapped = readError(error);
      if (mapped === undefined || !isCaptchaAction(mapped.action)) {
        return { kind: 'error', error };
      }
      outcome = mapped;
    }
    // 权威配置以错误体 details 为准（含服务端降级为 image，§2.5）；缺失沿用上一轮。
    config = outcome.captcha ?? config;
    invalid = outcome.action === 'reset_captcha';
    return undefined;
  };

  // upfront 且已有配置才先问；无配置时退化为先探一次（服务端未启用 captcha
  // 的部署下不该凭空弹窗）。
  if (options.mode !== 'upfront' || config === undefined) {
    const terminal = await send(undefined);
    if (terminal !== undefined) {
      return terminal;
    }
  }

  for (;;) {
    if (config === undefined) {
      // 服务端判需要 captcha 却未下发配置（§2.5 服务端必附，此处防御）：
      // 无挑战可渲染，交调用方兜底文案。
      return { kind: 'error', error: new Error('captcha config missing') };
    }
    const token = await options.prompt({ config, invalid, attempt });
    if (token === undefined) {
      return { kind: 'cancelled' };
    }
    attempt += 1;
    const terminal = await send(token);
    if (terminal !== undefined) {
      return terminal;
    }
  }
}

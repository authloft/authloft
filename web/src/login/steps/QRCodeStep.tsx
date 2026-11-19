/**
 * kind=qrcode 步骤实体（docs/前端架构.md §4.2 行 443）：
 * shared/QRCodePanel 的登录包装——只写胶水，四态流转与轮询在面板内（不再
 * 经 PollStep，避免双份轮询，行 443）。
 *
 * - requestQR 调 SsoService/CreateQrcode（scene 缺省即 login，§2.8 行 702；
 *   captcha 必带、每次拉码都要新的，行 703——凭据由 captcha 弹窗每轮现取）；
 *   pollUrl 调 GetLoginTicket（poll 秒数与面板 pollSeconds 同值，
 *   §2.8 行 714 上限 15；signal 忽略——api 薄封装不支持中断，结果丢弃由
 *   面板 disposed 检查兜底）；
 * - captcha 门控（§2.8 行 690「必须携带 captcha」）：面板挂载即拉码，拉码经
 *   shared/captcha 的 gate 走 upfront——先在弹窗里问凭据再发一次请求；
 *   captcha_invalid 在窗内换凭据重试；用户取消则卸下面板、留「获取二维码」
 *   按钮原地重入（新 key 重挂 → 再次弹窗），expired 重拉走面板「重试」；
 * - onResult 完整状态机（§2.8 行 739-743）：面板 success（外层
 *   ticket 终态）后登录结论在**内层 `login`**（§1.3 同构信封）——success →
 *   completeLogin 终点跳转（终点字段 syncCookieUrl / redirectTo 在内层，
 *   §4.1 行 383 与 LoginContainer.terminalUrl 同口径，就地实现避免
 *   LoginContainer ↔ MethodTabs 循环依赖）；binding_required / 失败态经
 *   onResult 上抛交登录页注入的受控链路，由 LoginPage 转交容器状态机分派；
 * - needs_step_up（§2.8 行 884 MFA×扫码）：轮询顶层 status=needs_step_up
 *   （ticket.status 仍为 scanned，面板按 scanned 继续轮询）时，信封同时下发
 *   loginToken；本组件把它存入 loginTokenStore 后弹出 StepUpDialog，复用登录主路径
 *   的 startLoginVerification / submitStepUp（以 loginToken 为主体凭证）→
 *   SubmitVerification；按 §2.8 / §3.8.1，SubmitVerification 响应即登录流程结论，
 *   就地交登录终点跳转，票据不写终态、不依赖下次轮询。取挑战的 captcha gate
 *   由 StepUpDialog 自闭环（§2.5），本组件只注入基础配置。
 *   同一 ticket 首次 needs_step_up 时弹窗；无论通过还是取消都保留已处理标记，
 *   轮询不再自动重弹。取消后由面板区域的「重新验证」入口显式重开（挑战令牌已
 *   随窗体丢弃，重开即重取；loginToken 仍随每轮 needs_step_up 刷新）。
 *
 * 文案：经 i18n 字典 login.* / common.* 键取用。
 */
import { useCallback, useRef, useState } from 'react';
import { useSearchParams } from '@modern-js/runtime/router';
import type { JsonObject } from '@bufbuild/protobuf';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { SubmitVerificationResponse } from '../../gen/proto/api/common/v1/verification_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { CaptchaDialog } from '../../shared/captcha/CaptchaDialog';
import { errorCaptchaOutcome } from '../../shared/captcha/captchaGate';
import { useCaptchaGate } from '../../shared/captcha/useCaptchaGate';
import { StepUpDialog } from '../../shared/components/StepUpDialog';
import { ApiError } from '../../shared/api/errors';
import {
  QRCodePanel,
  MAX_POLL_SECONDS,
  ticketPhaseOf,
} from '../../shared/components/QRCodePanel';
import { t } from '../../shared/i18n';
import { getInit } from '../../shared/types/init';
import {
  DEFAULT_ACCOUNT_HOME,
  isValidReturnTo,
  sanitizeReturnTo,
} from '../../shared/urls';
import { hasOidcContext } from '../oidcContext';
import { setLoginToken } from '../loginTokenStore';
import { Modal } from '../components/Modal';
import { defaultNavigate } from './RedirectStep';
import styles from './QRCodeStep.module.less';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

/** 登录终点跳转所需字段（§1.3 行 158-162；登录信封与 SubmitVerification 成功响应同形）。 */
export type LoginTerminal = Pick<
  LoginFlowResponse,
  'syncCookieUrl' | 'redirectTo'
>;

/**
 * 扫码登录终点（§1.3 定稿 + returnTo 消费，与
 * LoginContainer.terminalUrl 同口径：syncCookieUrl 是后端拼好的多域名同步
 * 首跳完整 URL → 优先（同步链 returnTo 不生效）；否则按流程分派——OIDC 流
 * （oidc 上下文在场，§1.3）redirectTo 优先（fail-closed），非 OIDC
 * 流 returnTo（白名单校验通过）优先——显式落点不做应用默认回跳，非法 /
 * 缺失再取 redirectTo；皆空（直登场景）→ 默认落点 DEFAULT_ACCOUNT_HOME，
 * 禁止停留提示页。returnTo 由调用方 useSearchParams 取值（已解码，不二次
 * decode）。
 */
export function completeLogin(
  envelope: LoginTerminal,
  navigate: (url: string) => void = defaultNavigate,
  returnTo?: string,
): void {
  let url: string;
  if (envelope.syncCookieUrl !== '') {
    url = envelope.syncCookieUrl;
  } else if (hasOidcContext()) {
    url =
      envelope.redirectTo !== ''
        ? envelope.redirectTo
        : returnTo === undefined
          ? DEFAULT_ACCOUNT_HOME
          : sanitizeReturnTo(returnTo);
  } else if (returnTo !== undefined && isValidReturnTo(returnTo)) {
    url = returnTo;
  } else if (envelope.redirectTo !== '') {
    url = envelope.redirectTo;
  } else {
    url = DEFAULT_ACCOUNT_HOME;
  }
  if (url !== '') {
    navigate(url);
  }
}

/** requestQR 包装依赖（拉码替身注入）。 */
export interface QrcodeRequesterDeps {
  /** 拉码（缺省 login/api.ts createQrcode，scene 缺省 login）。 */
  request?: (req: {
    providerKey: string;
    captcha: CaptchaPayload;
  }) => Promise<CreateQrcodeResponse>;
}

/**
 * 缺省拉码：login/api.ts createQrcode。运行时动态 import——StepDispatcher /
 * ProviderButtons 静态 import 本组件，顶层引入 api 会连带 transport 单例在
 * 测试全局 __AUTHLOFT_INIT__ 注入前求值（login-container.test 模式），故按需加载。
 */
async function defaultCreateQrcode(req: {
  providerKey: string;
  captcha: CaptchaPayload;
}): Promise<CreateQrcodeResponse> {
  const { createQrcode } = await import('../api');
  return createQrcode(req);
}

/** 缺省轮询：login/api.ts getLoginTicket（动态 import，同 defaultCreateQrcode）。 */
async function defaultPollTicket(
  ticket: string,
  pollSeconds?: number,
): Promise<LoginFlowResponse> {
  const { getLoginTicket } = await import('../api');
  return getLoginTicket(ticket, pollSeconds);
}

/**
 * 拉码请求体组装（CreateQrcode 必带 captcha，§2.8 行 703）：凭据由 gate 每轮
 * 注入（一次性，不可复用）。纯工厂，node 可测。
 */
export function qrcodeRequester(
  providerKey: string,
  deps: QrcodeRequesterDeps = {},
): (captcha: CaptchaPayload) => Promise<CreateQrcodeResponse> {
  const request = deps.request ?? defaultCreateQrcode;
  return (captcha) => request({ providerKey, captcha });
}

/**
 * 扫码结果分派（§2.8 行 739-743）：面板 success（外层 ticket 终态）
 * 后，登录结论在**内层 `login`**（§1.3 同构信封，后端 pollResult 必填）：
 * - 内层 success → completeLogin 终点跳转（终点字段 syncCookieUrl /
 *   redirectTo 在内层，§1.3 行 136-138）；
 * - 内层 binding_required / 失败态 → 不跳转，经 onResult 上抛外层信封，
 *   交容器状态机分派（binding 原地渲染 BindingPage / 失败态表驱动文案，
 *   §1.6 行 234/240）；
 * - mfa_required 不会出现（§2.8 行 750 MFA×扫码：PC 端轮询至 expired
 *   终态）——不做分支；
 * - 内层缺失（防御，外层 success 必附 login）：不跳转仍上抛，交消费方
 *   零值兜底。纯函数，node 可测。
 */
export function dispatchQrResult(
  outer: LoginFlowResponse,
  handlers: {
    completeLogin: (login: LoginFlowResponse) => void;
    onResult?: (envelope: LoginFlowResponse) => void;
  },
): void {
  const login = outer.login;
  if (login !== undefined && login.status === 'success') {
    handlers.completeLogin(login);
  }
  handlers.onResult?.(outer);
}

/**
 * 扫码轮询 → step-up 弹窗决策（§2.8 行 884，纯函数 node 可测）：顶层
 * status=needs_step_up 且信封下发 loginToken、票据带 ticketId、该票据尚未处理过时，
 * 返回需弹窗的票据标记；其余（非 needs_step_up / 无 loginToken / 无 ticketId /
 * 已处理过）返回 undefined。ticket.status 仍为 scanned，面板按 scanned 继续轮询、
 * 不被终止。loginToken 缺省时不弹窗（§2.8 行 872：主体凭证随信封下发）。
 */
export function stepUpTicketOf(
  envelope: LoginFlowResponse,
  handledTicketId: string | undefined,
): string | undefined {
  if (envelope.status !== 'needs_step_up') {
    return undefined;
  }
  if (envelope.loginToken === '') {
    return undefined;
  }
  const ticketId = envelope.ticket?.ticketId ?? '';
  if (ticketId === '' || ticketId === handledTicketId) {
    return undefined;
  }
  return ticketId;
}

/**
 * 轮询响应 → step-up 动作（§2.8 行 884，纯函数）：needs_step_up 每轮都会下发
 * 新的 loginToken，即使不自动弹窗（同一票据已处理 / 已取消）也要刷新主体凭证，
 * 否则显式重开会拿到丢弃前的旧凭证；票据进入终态（expired / failed）后显式
 * 重开入口随之失效。
 */
export interface StepUpPollAction {
  /** 需要写入 loginTokenStore 的主体凭证（非 needs_step_up → 空串）。 */
  loginToken: string;
  /** 需要自动弹窗的票据（已处理 / 非 needs_step_up → undefined）。 */
  openTicketId: string | undefined;
  /** 票据已进入终态（expired / failed）。 */
  terminal: boolean;
}

export function stepUpPollAction(
  envelope: LoginFlowResponse,
  handledTicketId: string | undefined,
): StepUpPollAction {
  const phase = ticketPhaseOf(envelope);
  return {
    loginToken: envelope.status === 'needs_step_up' ? envelope.loginToken : '',
    openTicketId: stepUpTicketOf(envelope, handledTicketId),
    terminal: phase === 'expired' || phase === 'failed',
  };
}

/**
 * 弹窗关闭后的票据标记与重开入口（§2.8 行 884，纯函数）：无论验证通过还是
 * 用户取消都保留已处理标记，同一票据的后续轮询不得自动重弹——取消只给出
 * 显式重开入口（返回 reopenTicketId），由用户点击再次打开弹窗。验证通过则
 * 不提供入口（结论已交登录终点，等票据转终态）。
 */
export interface StepUpDismissState {
  handledTicketId: string | undefined;
  reopenTicketId: string | undefined;
}

export function stepUpDismissState(
  ticketId: string | undefined,
  dismissed: 'verified' | 'cancelled',
): StepUpDismissState {
  return {
    handledTicketId: ticketId,
    reopenTicketId: dismissed === 'cancelled' ? ticketId : undefined,
  };
}

/**
 * Submit 非 success → 窗内可展示的错误（§1.6「提示 + 剩余次数」）：把登录流程
 * 信封的失败 status 归一为错误码，交 StepUpDialog 按 errors.code.* 文案展示，
 * 不再落成空串被当成「响应无效」。attemptsLeft 取自 SubmitVerificationResponse
 * 响应字段（§3.8.2），经本函数写入 ApiError init，不是 transport 侧错误体的
 * attempts_left；零值 / 缺失即不展示剩余次数（§1.6 行 290）。
 */
export function stepUpSubmitError(
  status: string,
  attemptsLeft?: bigint,
): ApiError {
  return new ApiError({
    httpStatus: 200,
    code: status === '' ? 'failed' : status,
    message: '',
    requestId: '',
    attemptsLeft,
  });
}

/**
 * SubmitVerification 响应 → 登录结论（§3.8.1 成功返回登录流程结论，§2.8 行 872
 * 票据不写终态、不依赖下次轮询，纯函数）：成功即把响应当登录终点交
 * completeLogin 跳转，并回传非空占位让 StepUpDialog 判成功关窗；失败态抛窗内
 * 错误，不跳转。
 */
export function completeStepUpSubmit(
  response: SubmitVerificationResponse,
  complete: (terminal: LoginTerminal) => void,
): string {
  if (response.status !== 'success') {
    throw stepUpSubmitError(response.status, response.attemptsLeft);
  }
  complete(response);
  return 'ok';
}

export interface QRCodeStepProps {
  /** 扫码类 Provider 的 providerKey（§2.8 行 701）。 */
  providerKey: string;
  /**
   * 扫码登录结论上抛（外层信封；内层 login 为 §1.3 登录流程信封）：
   * success 已由本组件 completeLogin 完成终点跳转；binding_required /
   * 失败态经本回调交容器状态机分派（§2.8 行 739-743）。
   */
  onResult?: (envelope: LoginFlowResponse) => void;
  /** captcha 配置（缺省取注入快照 methods.captcha；来源三处见 §2.5 行 477）。 */
  captcha?: CaptchaConfig;
  /** 拉码替身（缺省 createQrcode；测试注入）。 */
  requestQrcode?: (req: {
    providerKey: string;
    captcha: CaptchaPayload;
  }) => Promise<CreateQrcodeResponse>;
  /** 轮询替身（缺省 getLoginTicket；测试注入）。 */
  pollTicket?: (
    ticket: string,
    pollSeconds?: number,
  ) => Promise<LoginFlowResponse>;
  /** 轮询单次最长等待秒数（§2.8 行 714 上限 15；缺省 15）。 */
  pollSeconds?: number;
  /** 终点跳转动作（缺省 location.replace；测试记录函数）。 */
  navigate?: (url: string) => void;
}

export function QRCodeStep({
  providerKey,
  onResult,
  captcha = initCaptcha(),
  requestQrcode,
  pollTicket = defaultPollTicket,
  pollSeconds = MAX_POLL_SECONDS,
  navigate = defaultNavigate,
}: QRCodeStepProps) {
  const gate = useCaptchaGate(Modal);
  const [cancelled, setCancelled] = useState(false);
  // 取消后重入：新 key 重挂面板 → 再次走 upfront 弹窗（凭据一次性，不能复用）。
  const [panelKey, setPanelKey] = useState(0);
  // 扫码登录成功终点的 returnTo 消费（useSearchParams 已解码）。
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get('returnTo') ?? undefined;
  // needs_step_up（§2.8 行 884）：票据标记弹二次验证窗体（主体凭证取信封 loginToken）；
  // 同一票据只弹一次。
  const [stepUpTicket, setStepUpTicket] = useState<string | undefined>(
    undefined,
  );
  // 取消后不自动重弹：改由该状态承载用户可见的显式重开入口（票据 id）。
  const [stepUpReopen, setStepUpReopen] = useState<string | undefined>(
    undefined,
  );
  const handledStepUpRef = useRef<string | undefined>(undefined);

  // start 保持引用稳定（useCallback）：弹窗内部 ref 固定 start，在途挑战
  // 令牌不因重渲染被打断。取挑战的 captcha gate 由 StepUpDialog 自闭环
  // （§2.5），此处直连 startLoginVerification（凭据经 captcha 参数注入）。
  // 主体凭证 loginToken 由 loginTokenStore 托管（needs_step_up 时轮询写入），
  // 不在闭包内捕获。
  const startStepUp = useCallback(
    async (method: string, captcha?: CaptchaPayload) => {
      const { startLoginVerification } = await import('../api');
      return startLoginVerification({
        method,
        ...(captcha !== undefined ? { captcha } : {}),
      });
    },
    [],
  );

  // Submit 成功后就地交登录终点跳转（deps 只有 navigate 与 returnTo 两个原始值，
  // StepUpDialog 的 start 引用稳定不受影响）。主体凭证 loginToken 由
  // loginTokenStore 托管（每轮 needs_step_up 写入），不在闭包内捕获。
  const submitStepUp = useCallback(
    async (
      challengeToken: string,
      method: string,
      payload: JsonObject,
    ): Promise<string> => {
      const { submitStepUp: submitStepUpApi } = await import('../api');
      const response = await submitStepUpApi(challengeToken, method, payload);
      return completeStepUpSubmit(response, (terminal) =>
        completeLogin(terminal, navigate, returnTo),
      );
    },
    [navigate, returnTo],
  );

  if (providerKey === '') {
    // 零值兜底（§9 第 18 条）：信封驱动的防御分派形态无 provider（NextStep
    // 无 providerKey 字段，§12.9 生成物）；真实拉码链路经 ProviderButtons。
    return <p role="alert">{t('common.refreshAndRetry')}</p>;
  }

  const requestQR = async () => {
    const outcome = await gate.run({
      mode: 'upfront',
      config: captcha,
      request: (token) =>
        token === undefined
          ? Promise.reject(new Error(t('login.qrNeedCaptcha')))
          : qrcodeRequester(providerKey, { request: requestQrcode })(token),
      // CreateQrcode 响应无 status 字段（§12.9 生成物）：结论只在错误侧。
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
    });
    if (outcome.kind === 'result') {
      return outcome.result;
    }
    if (outcome.kind === 'cancelled') {
      // 面板随即被卸载，其 disposed 检查会吞掉这次 reject 的 failed 态。
      setCancelled(true);
      throw new Error(t('login.qrNeedCaptcha'));
    }
    throw outcome.error;
  };

  // 轮询包装：needs_step_up 时刷新主体凭证并弹二次验证窗体（start/submit 复用
  // 登录主路径编排）。ticket.status 仍为 scanned → 面板按 scanned 继续轮询、不被
  // needs_step_up 终止；SubmitVerification 响应即登录流程结论（§2.8 / §3.8.1），
  // 票据不写终态、不依赖下次轮询。
  const pollAndDetectStepUp = async (
    ticket: string,
    seconds?: number,
  ): Promise<LoginFlowResponse> => {
    const response = await pollTicket(ticket, seconds);
    const action = stepUpPollAction(response, handledStepUpRef.current);
    if (action.loginToken !== '') {
      setLoginToken(action.loginToken);
    }
    if (action.openTicketId !== undefined) {
      handledStepUpRef.current = action.openTicketId;
      setStepUpTicket(action.openTicketId);
    }
    if (action.openTicketId !== undefined || action.terminal) {
      setStepUpReopen(undefined);
    }
    return response;
  };

  const dismissStepUp = (dismissed: 'verified' | 'cancelled') => {
    const state = stepUpDismissState(handledStepUpRef.current, dismissed);
    handledStepUpRef.current = state.handledTicketId;
    setStepUpTicket(undefined);
    setStepUpReopen(state.reopenTicketId);
  };

  return (
    <div className={styles.panel}>
      {cancelled ? (
        <button
          type="button"
          className={styles.fetchButton}
          onClick={() => {
            setCancelled(false);
            setPanelKey((key) => key + 1);
          }}
        >
          {t('login.fetchQrcodeAction')}
        </button>
      ) : (
        <QRCodePanel
          key={panelKey}
          requestQR={requestQR}
          // 面板第二参是 AbortSignal（api 薄封装不支持中断，signal 忽略）；
          // poll 秒数取本组件 pollSeconds，与面板 pollTimeoutMs 同值（§2.8 上限 15）。
          pollUrl={(ticket) => pollAndDetectStepUp(ticket, pollSeconds)}
          onResult={(outer) =>
            // 完整状态机分派：success 用内层信封终点跳转；
            // binding_required / 失败态上抛交容器。
            dispatchQrResult(outer, {
              completeLogin: (login) =>
                completeLogin(login, navigate, returnTo),
              onResult,
            })
          }
          pollSeconds={pollSeconds}
        />
      )}
      <CaptchaDialog {...gate.dialogProps} />
      {stepUpReopen !== undefined && stepUpTicket === undefined ? (
        <button
          type="button"
          className={styles.fetchButton}
          onClick={() => {
            setStepUpTicket(stepUpReopen);
            setStepUpReopen(undefined);
          }}
        >
          {t('login.stepUpReopen')}
        </button>
      ) : null}
      {stepUpTicket !== undefined ? (
        <StepUpDialog
          modal={Modal}
          captcha={captcha}
          start={startStepUp}
          submit={submitStepUp}
          onVerified={() => dismissStepUp('verified')}
          onCancel={() => dismissStepUp('cancelled')}
        />
      ) : null}
    </div>
  );
}

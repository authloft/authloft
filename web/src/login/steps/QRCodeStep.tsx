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
 *   onResult 上抛交容器状态机分派（ProviderButtons → MethodTabs →
 *   LoginContainer 链，「LoginContainer 禁改」约束已解除）；
 * - needs_step_up（§2.8 行 884 MFA×扫码）：轮询顶层 status=needs_step_up
 *   （ticket.status 仍为 scanned，面板按 scanned 继续轮询）时，以 mfaPendingId
 *   = ticketId 弹出 shared/components/StepUpDialog 走 StartVerification →
 *   SubmitVerification；扫码场景服务端以票据链路收尾（§3.8.1），Submit 成功写终态
 *   TicketResult、不直接登录，本组件关窗后由面板下一次轮询进入 success 再走终点。
 *   同一 ticket 只在首次 needs_step_up 时弹窗（完成 / 取消后不再自动重弹，
 *   取消后由面板轮询至 expired 兜底、用户重拉码）。
 *
 * 文案：经 i18n 字典 login.* / common.* 键取用。
 */
import { useCallback, useRef, useState } from 'react';
import { useSearchParams } from '@modern-js/runtime/router';
import type { JsonObject } from '@bufbuild/protobuf';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { CaptchaDialog } from '../../shared/captcha/CaptchaDialog';
import { errorCaptchaOutcome } from '../../shared/captcha/captchaGate';
import { useCaptchaGate } from '../../shared/captcha/useCaptchaGate';
import { StepUpDialog } from '../../shared/components/StepUpDialog';
import {
  QRCodePanel,
  MAX_POLL_SECONDS,
} from '../../shared/components/QRCodePanel';
import { t } from '../../shared/i18n';
import { getInit } from '../../shared/types/init';
import { DEFAULT_ACCOUNT_HOME, sanitizeReturnTo } from '../../shared/urls';
import { Modal } from '../components/Modal';
import { defaultNavigate } from './RedirectStep';
import styles from './QRCodeStep.module.less';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

/**
 * 扫码登录终点（§1.3 行 158-162 定稿 + returnTo 消费，与
 * LoginContainer.terminalUrl 同口径：syncCookieUrl 是后端拼好的多域名同步
 * 首跳完整 URL → 优先；否则 redirectTo；皆空（直登场景）→ query `returnTo`
 * 经 sanitizeReturnTo 白名单校验（调用方已解码，不二次 decode），非法 /
 * 缺失 → 默认落点 DEFAULT_ACCOUNT_HOME，禁止停留提示页）。
 */
export function completeLogin(
  envelope: LoginFlowResponse,
  navigate: (url: string) => void = defaultNavigate,
  returnTo?: string,
): void {
  const url =
    envelope.syncCookieUrl !== ''
      ? envelope.syncCookieUrl
      : envelope.redirectTo !== ''
        ? envelope.redirectTo
        : returnTo === undefined
          ? DEFAULT_ACCOUNT_HOME
          : sanitizeReturnTo(returnTo);
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
 * status=needs_step_up 且票据带 ticketId、且该票据尚未处理过时，返回需弹窗的
 * mfaPendingId（= ticketId）；其余（非 needs_step_up / 无 ticketId / 已处理过）
 * 返回 undefined。ticket.status 仍为 scanned，面板按 scanned 继续轮询、不被终止。
 */
export function stepUpTicketOf(
  envelope: LoginFlowResponse,
  handledTicketId: string | undefined,
): string | undefined {
  if (envelope.status !== 'needs_step_up') {
    return undefined;
  }
  const ticketId = envelope.ticket?.ticketId ?? '';
  if (ticketId === '' || ticketId === handledTicketId) {
    return undefined;
  }
  return ticketId;
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
  // needs_step_up（§2.8 行 884）：mfaPendingId=ticketId 弹二次验证窗体；同一票据只弹一次。
  const [stepUpTicket, setStepUpTicket] = useState<string | undefined>(
    undefined,
  );
  const handledStepUpRef = useRef<string | undefined>(undefined);
  // step-up 取因子时的人机校验 gate（StartVerification 选定因子按 §2.5 需要 captcha）。
  const stepUpGate = useCaptchaGate(Modal);

  // start / submit 必须引用稳定（useCallback）：StepUpDialog 的 loadMethods 以
  // start 为 dep、useEffect 随 loadMethods 重跑——内联闭包每次渲染换新，会在
  // captcha 弹窗触发重渲染时把验证中的窗体重置回 loading、清挑战令牌并重复
  // StartVerification（§3.3）。deps 取 stepUpGate.run（其本身 useCallback([prompt])、
  // 引用稳定），不依赖 stepUpGate 对象（每次渲染新建）。
  const startStepUp = useCallback(
    async (method: string) => {
      const { startStepUp: startStepUpApi } = await import('../api');
      if (method === '') {
        return startStepUpApi({ mfaPendingId: stepUpTicket ?? '' });
      }
      const outcome = await stepUpGate.run({
        mode: 'reactive',
        request: (token) =>
          startStepUpApi({
            mfaPendingId: stepUpTicket ?? '',
            method,
            ...(token !== undefined ? { captcha: token } : {}),
          }),
        // StartVerification 响应无流程状态字段：captcha 结论只在 ApiError 一侧。
        readOutcome: () => ({ action: 'message' }),
        readError: errorCaptchaOutcome,
      });
      if (outcome.kind === 'result') {
        return outcome.result;
      }
      if (outcome.kind === 'cancelled') {
        return undefined;
      }
      throw outcome.error;
    },
    [stepUpTicket, stepUpGate.run],
  );

  // 不捕获任何响应式值（api 动态 import + 纯透传）：deps 空集即恒定引用。
  const submitStepUp = useCallback(
    async (
      challengeToken: string,
      method: string,
      payload: JsonObject,
    ): Promise<string> => {
      const { submitStepUp: submitStepUpApi } = await import('../api');
      // 扫码场景服务端以票据链路收尾、不回 verificationToken（§3.8.1）：Submit 成功
      // 即视为完成，回传非空占位使 StepUpDialog 判成功并关窗；登录结论由后续轮询
      // success 承担。
      const response = await submitStepUpApi(challengeToken, method, payload);
      return response.status === 'success' ? 'ok' : '';
    },
    [],
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

  // 轮询包装：顶层 status=needs_step_up 时以 mfaPendingId=ticketId 弹二次验证窗体。
  // ticket.status 仍为 scanned → 面板按 scanned 继续轮询、不被 needs_step_up 终止；
  // Submit 成功后票据转终态，下一次轮询即 success（§2.8 行 884）。
  const pollAndDetectStepUp = async (
    ticket: string,
    seconds?: number,
  ): Promise<LoginFlowResponse> => {
    const response = await pollTicket(ticket, seconds);
    const ticketId = stepUpTicketOf(response, handledStepUpRef.current);
    if (ticketId !== undefined) {
      handledStepUpRef.current = ticketId;
      setStepUpTicket(ticketId);
    }
    return response;
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
                completeLogin(
                  login,
                  navigate,
                  searchParams.get('returnTo') ?? undefined,
                ),
              onResult,
            })
          }
          pollSeconds={pollSeconds}
        />
      )}
      <CaptchaDialog {...gate.dialogProps} />
      {stepUpTicket !== undefined ? (
        <>
          <StepUpDialog
            modal={Modal}
            start={startStepUp}
            submit={submitStepUp}
            onVerified={() => setStepUpTicket(undefined)}
            onCancel={() => setStepUpTicket(undefined)}
          />
          <CaptchaDialog {...stepUpGate.dialogProps} />
        </>
      ) : null}
    </div>
  );
}

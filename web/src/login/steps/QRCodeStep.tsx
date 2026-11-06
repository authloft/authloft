/**
 * kind=qrcode 步骤实体（docs/前端架构.md §4.2 行 443）：
 * shared/QRCodePanel 的登录包装——只写胶水，四态流转与轮询在面板内（不再
 * 经 PollStep，避免双份轮询，行 443）。
 *
 * - requestQR 调 SsoService/CreateQrcode（scene 缺省即 login，§2.8 行 702；
 *   captcha 必带、每次拉码都要新的，行 703——凭据经 CaptchaWidget getToken
 *   实时取）；pollUrl 调 GetLoginTicket（poll 秒数与面板 pollSeconds 同值，
 *   §2.8 行 714 上限 15；signal 忽略——api 薄封装不支持中断，结果丢弃由
 *   面板 disposed 检查兜底）；
 * - captcha 门控（§2.8 行 690「必须携带 captcha」）：配置存在时先渲染
 *   CaptchaWidget +「获取二维码」，凭据就绪才挂面板（挂载即拉码，
 *   面板契约）；expired 重拉走面板「重试」，requestQR 实时取新凭据；
 *   无配置（服务端未启用 captcha）直挂面板；
 * - onResult 完整状态机（§2.8 行 739-743）：面板 success（外层
 *   ticket 终态）后登录结论在**内层 `login`**（§1.3 同构信封）——success →
 *   completeLogin 终点跳转（终点字段 syncCookieUrl / redirectTo 在内层，
 *   §4.1 行 383 与 LoginContainer.terminalUrl 同口径，就地实现避免
 *   LoginContainer ↔ MethodTabs 循环依赖）；binding_required / 失败态经
 *   onResult 上抛交容器状态机分派（ProviderButtons → MethodTabs →
 *   LoginContainer 链，「LoginContainer 禁改」约束已解除）；
 *   mfa_required 不会出现（§2.8 行 750 MFA×扫码：PC 端轮询至 expired
 *   终态，扫码通道不在 PC 端续走 MFA）——不做分支。
 *
 * 文案：经 i18n 字典 login.* / common.* 键取用。
 */
import { useRef, useState } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../../shared/captcha/CaptchaWidget';
import { QRCodePanel, MAX_POLL_SECONDS } from '../../shared/components/QRCodePanel';
import { t } from '../../shared/i18n';
import { getInit } from '../../shared/types/init';
import { DEFAULT_ACCOUNT_HOME } from '../../shared/urls';
import { defaultNavigate } from './RedirectStep';
import styles from './QRCodeStep.module.less';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

/**
 * 扫码登录终点（§1.3 行 158-162 定稿，与 LoginContainer.terminalUrl 同口径：
 * syncCookieUrl 是后端拼好的多域名同步首跳完整 URL → 优先；否则 redirectTo；
 * 皆空 → 默认落点 DEFAULT_ACCOUNT_HOME，禁止停留提示页）。
 */
export function completeLogin(
  envelope: LoginFlowResponse,
  navigate: (url: string) => void = defaultNavigate,
): void {
  const url =
    envelope.syncCookieUrl !== ''
      ? envelope.syncCookieUrl
      : envelope.redirectTo !== ''
        ? envelope.redirectTo
        : DEFAULT_ACCOUNT_HOME;
  if (url !== '') {
    navigate(url);
  }
}

/** requestQR 包装依赖（拉码替身注入；getToken 为 captcha 凭据实时源）。 */
export interface QrcodeRequesterDeps {
  /** captcha 凭据（CaptchaWidget ref getToken；undefined = 用户未完成）。 */
  getToken?: () => CaptchaPayload | undefined;
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
 * requestQR 包装（QRCodePanel props 契约，§3.3 行 345）：CreateQrcode 必带
 * captcha（§2.8 行 703）；凭据未就绪 → reject（面板 failed 态走
 * fetchFailureText 兜底文案）。纯工厂，node 可测。
 */
export function qrcodeRequester(
  providerKey: string,
  deps: QrcodeRequesterDeps = {},
): (_signal: AbortSignal) => Promise<CreateQrcodeResponse> {
  return () => {
    const captcha = deps.getToken?.();
    if (captcha === undefined) {
      return Promise.reject(new Error(t('login.qrNeedCaptcha')));
    }
    const request = deps.request ?? defaultCreateQrcode;
    return request({ providerKey, captcha });
  };
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
  const [started, setStarted] = useState(false);
  const [notice, setNotice] = useState(false);
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  if (providerKey === '') {
    // 零值兜底（§9 第 18 条）：信封驱动的防御分派形态无 provider（NextStep
    // 无 providerKey 字段，§12.9 生成物）；真实拉码链路经 ProviderButtons。
    return <p role="alert">{t('common.refreshAndRetry')}</p>;
  }

  /** 门控按钮：凭据就绪才挂面板（挂载即拉码，面板契约）。 */
  const start = () => {
    if (captchaRef.current?.getToken() === undefined) {
      setNotice(true);
      return;
    }
    setStarted(true);
  };

  return (
    <div className={styles.panel}>
      {captcha !== undefined && (
        <div className={styles.captchaBox}>
          <CaptchaWidget captcha={captcha} ref={captchaRef} />
          {!started && (
            <button
              type="button"
              className={styles.fetchButton}
              onClick={start}
            >
              {t('login.fetchQrcodeAction')}
            </button>
          )}
          {!started && notice && (
            <p role="alert" className={styles.notice}>
              {t('login.qrNeedCaptcha')}
            </p>
          )}
        </div>
      )}
      {(started || captcha === undefined) && (
        <QRCodePanel
          requestQR={qrcodeRequester(providerKey, {
            getToken: () => captchaRef.current?.getToken(),
            request: requestQrcode,
          })}
          pollUrl={(ticket) => pollTicket(ticket, pollSeconds)}
          onResult={(outer) =>
            // 完整状态机分派：success 用内层信封终点跳转；
            // binding_required / 失败态上抛交容器（mfa_required 不会出现，
            // §2.8 行 750——MFA×扫码 PC 端轮询至 expired，不做分支）。
            dispatchQrResult(outer, {
              completeLogin: (login) => completeLogin(login, navigate),
              onResult,
            })
          }
          pollSeconds={pollSeconds}
        />
      )}
    </div>
  );
}

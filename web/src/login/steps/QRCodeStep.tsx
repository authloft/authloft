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
 * - onResult（success 信封）→ completeLogin 终点跳转（syncCookieUrl 优先 /
 *   redirectTo 回退，§4.1 行 383 与 LoginContainer.terminalUrl 同口径——
 *   就地实现避免 LoginContainer ↔ MethodTabs 循环依赖）；onResult prop 为
 *   观测钩子（完整状态机接线归容器后续实现，LoginContainer 本次不改）。
 *
 * 文案：i18n 无键，中文字面量 + 注释声明，扩键归后续 i18n 实现。
 */
import { useRef, useState } from 'react';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../../shared/captcha/CaptchaWidget';
import { QRCodePanel, MAX_POLL_SECONDS } from '../../shared/components/QRCodePanel';
import { getInit } from '../../shared/types/init';
import { defaultNavigate } from './RedirectStep';
import styles from './QRCodeStep.module.less';

/** 门控提示（i18n 无键，字面量声明见文件头）。 */
const NEED_CAPTCHA_TEXT = '请先完成人机校验';
/** 门控拉码按钮文案（同上）。 */
const FETCH_QR_TEXT = '获取二维码';
/** providerKey 缺失占位（零值兜底 §9 第 18 条；与缺映射兜底同款文案口径）。 */
const MISSING_PROVIDER_TEXT = '请刷新重试';

/** 首屏注入快照的 captcha 配置（§2.1 行 409：login 端首屏来源；§2.5 行 477 三处之一）。 */
function initCaptcha(): CaptchaConfig | undefined {
  return getInit()?.methods?.captcha;
}

/**
 * 扫码登录终点（§4.1 行 383 与 LoginContainer.terminalUrl 同口径：syncCookieUrl
 * 是后端拼好的多域名同步首跳完整 URL → 优先；否则 redirectTo；皆空不跳）。
 */
export function completeLogin(
  envelope: LoginFlowResponse,
  navigate: (url: string) => void = defaultNavigate,
): void {
  const url =
    envelope.syncCookieUrl !== ''
      ? envelope.syncCookieUrl
      : envelope.redirectTo;
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
      return Promise.reject(new Error(NEED_CAPTCHA_TEXT));
    }
    const request = deps.request ?? defaultCreateQrcode;
    return request({ providerKey, captcha });
  };
}

export interface QRCodeStepProps {
  /** 扫码类 Provider 的 providerKey（§2.8 行 701）。 */
  providerKey: string;
  /** 结果就绪观测钩子（success 信封上抛；终点跳转固定经 completeLogin）。 */
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
    return <p role="alert">{MISSING_PROVIDER_TEXT}</p>;
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
              {FETCH_QR_TEXT}
            </button>
          )}
          {!started && notice && (
            <p role="alert" className={styles.notice}>
              {NEED_CAPTCHA_TEXT}
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
          onResult={(envelope) => {
            onResult?.(envelope);
            completeLogin(envelope, navigate);
          }}
          pollSeconds={pollSeconds}
        />
      )}
    </div>
  );
}

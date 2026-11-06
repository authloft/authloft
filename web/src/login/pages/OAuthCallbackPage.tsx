/**
 * OAuth 回调页（docs/前端架构.md §4.4 行 467；docs/接口文档.md §2.7.3 行
 * 602-616、§10.5 行 1534-1550）：不做任何业务逻辑——把 location.search（code、
 * state 等）原样装进请求报文，补上路径参数 providerKey（routes.tsx 从 pathname
 * 提取传入），按 state 首字母分派（§2.7.3 行 606-610）：
 * - `l` → SsoService/LoginOauth（api.loginOauth；oidc 由 api 层从 al_oidc_ctx
 *   读回注入请求体、读完即清，§2.7.2 行 599-600——本页不读 localStorage）；
 * - `b` → AccountService/ThirdpartyOauth（shared/api/account 的 thirdpartyOauth，
 *   完整编排，§3.7.1 A 行 969-1003）：code / state 从 location.search
 *   原样透传 + providerKey 路径参数；成功 / 失败一律回跳安全中心
 *   `/account/security?bind={success｜ErrorInfo.code}`（§4.4 行 467），结果横幅
 *   由 SecurityPage 消费（已交付）；响应非信封、不 Set-Cookie、不签发
 *   login_token——绑定不改变登录态（行 1000），失败码经 errors.ts 归一取
 *   ErrorInfo.code（§1.6 位置二）；
 * - 其他 / 缺失 → 视为 state_mismatch，跳 /sso/login（§2.7.3 行 610）。
 *
 * LoginOauth 响应走 §1.3 登录流程信封（loginToken 无条件覆盖 / success 清空由
 * api 层 applyEnvelope 托管），页面级处理（既定分派口径，完整编排）：
 * - success → 终点跳转（flowTerminalUrl：syncCookieUrl 优先，§1.3 行 136）；
 * - binding_required → 原地渲染 BindingPage（§1.6 行 234「渲染绑定选择页」，
 *   LoginContainer binding 分支同款用法；建号 / 退出编排由其自带）；
 * - mfa_required → **完整编排**（§1.6 行 233「就地渲染 mfa.methods
 *   选择器 + 因子组件，不跳页」）：复用 LoginContainer 既有能力
 *   （initialEnvelope 进状态机；MFA 提交走 SsoService/LoginDefault，success
 *   终点跳转 executeEffects；loginToken 由 api 层托管续接，页面不自管）；
 * - 失败态 → ErrorBanner（§1.6 表驱动文案）+ 返回登录：回调页无表单，字段级
 *   提示无处着落，「回到第一步」类动作统一为回 /sso/login。
 *
 * 结构沿 RegisterPage / BindingPage 模式：View 纯状态帧（renderToStaticMarkup
 * 可测任意 status 帧）+ 页壳薄胶水；分派编排抽为 dispatchCallback（依赖注入、
 * node 可测），页壳 useEffect 挂载即分派一次（ref 守卫防 dev 严格模式双跑）。
 *
 * 文案：回调页专属（处理中 / 成功 / 返回登录）经 i18n 字典 login.* 键取用；
 * b 分支成功 / 失败均回跳安全中心，在途沿处理中帧。
 */
import { useEffect, useRef, useState } from 'react';
import { create } from '@bufbuild/protobuf';
import {
  ThirdpartyOauthRequestSchema,
  type ThirdpartyOauthRequest,
  type ThirdpartyOauthResponse,
} from '../../gen/proto/api/account/v1/thirdparty_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import { thirdpartyOauth } from '../../shared/api/account';
import { ApiError, resolveFlowStatus } from '../../shared/api/errors';
import { ErrorBanner } from '../../shared/components';
import { t } from '../../shared/i18n';
import type { MethodsSnapshot } from '../../shared/types/init';
import { loginOauth, type LoginOauthInput } from '../api';
import { LoginContainer } from '../LoginContainer';
import { clearLoginToken } from '../loginTokenStore';
import { BindingPage, exitBinding } from './BindingPage';
import { flowTerminalUrl, isFlowErrorStatus, ssoPath } from './RegisterPage';
import styles from './OAuthCallbackPage.module.less';

// ---------------------------------------------------------------------------
// 纯函数（node 可测；state 分派 / 请求报文组装是本实现契约落点）
// ---------------------------------------------------------------------------

/** state 首字母分派结果（§2.7.3 行 606-610：l 登录 / b 绑定 / 其他缺失回登录）。 */
export type CallbackDispatch = 'login' | 'bind' | 'mismatch';

/** 按 state 首字母分派（§2.7.3）：`l` → login、`b` → bind、其他 / 空串 → mismatch。 */
export function callbackDispatch(state: string): CallbackDispatch {
  if (state.startsWith('l')) {
    return 'login';
  }
  return state.startsWith('b') ? 'bind' : 'mismatch';
}

/** location.search → query 对象（§2.7.3 行 604「原样作为 body JSON」；键重复取首值，与 URLSearchParams.get 同口径）。 */
export function callbackQuery(search: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of new URLSearchParams(search)) {
    if (!(key in out)) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * LoginOauth 请求报文（§2.7.3 行 612-615）：query 原样透传 + 路径参数
 * providerKey 补上（同名以路径为准）；loginToken / oidc 由 api 层托管注入。
 */
export function buildLoginOauthInput(
  providerKey: string,
  search: string,
): LoginOauthInput {
  return { ...callbackQuery(search), providerKey };
}

/**
 * ThirdpartyOauth 请求报文（§3.7.1 A 行 990-994）：code / state 从
 * location.search 原样透传（复用 callbackQuery）+ 路径参数 providerKey 补上
 * （同名以路径为准）；缺省键按零值空串上送，由服务端 invalid_request 判定
 * （行 994，不因前端放宽契约）。
 */
export function buildThirdpartyOauthInput(
  providerKey: string,
  search: string,
): ThirdpartyOauthRequest {
  const query = callbackQuery(search);
  return create(ThirdpartyOauthRequestSchema, {
    providerKey,
    code: query.code,
    state: query.state,
  });
}

/**
 * b 分支失败回跳码（§3.7.1 A 行 986）：Connect 错误经 errors.ts 归一
 * （ApiError.code = ErrorInfo.code，无 detail 时 Connect 标准码兜底）；非归一
 * 形态（防御，transport 恒归一）按 §1.6 行 273「其余域映射 Connect internal」
 * 口径兜底，不透出原文。
 */
export function bindErrorCode(error: unknown): string {
  return error instanceof ApiError ? error.code : 'internal';
}

/**
 * 绑定结果回跳安全中心（§3.7.1 A 行 985-986 / §4.4 行 467）：
 * `{al_root}/account/security?bind={success｜ErrorInfo.code}`（ssoPath 即
 * al_root 前缀拼接）——结果横幅由 SecurityPage 挂载时消费，本页不
 * 渲染绑定终态帧。
 */
export function securityBindUrl(bind: string): string {
  return ssoPath(`/account/security?bind=${bind}`);
}

/** dispatchCallback 依赖（注入；页壳给真实实现，node 测试给记录函数）。 */
export interface CallbackDispatchDeps {
  /** l 分派的 LoginOauth 请求（api.loginOauth）。 */
  loginOauthRequest: (req: LoginOauthInput) => Promise<LoginFlowResponse>;
  /** b 分派的 ThirdpartyOauth 请求（shared/api/account 的 thirdpartyOauth）。 */
  thirdpartyOauthRequest: (
    req: ThirdpartyOauthRequest,
  ) => Promise<ThirdpartyOauthResponse>;
  /** 信封落地（含 binding_required / mfa_required / 失败态；success 亦落地驱动「正在跳转」帧）。 */
  onEnvelope: (envelope: LoginFlowResponse) => void;
  /** 传输层异常（§1.6 行 272：failed 兜底，不暴露内部信息）。 */
  onTransportError: () => void;
  /** mismatch → /sso/login（§2.7.3 行 610）；success → 终点 URL（§1.3 行 136）；b 分支 → 绑定结果回跳（§3.7.1 A 行 985-986）。 */
  navigate: (url: string) => void;
}

/**
 * 回调分派编排（§2.7.3 / §10.5 行 1541-1545）：mismatch 跳登录、b 实调
 * ThirdpartyOauth 后成功 / 失败一律回跳安全中心（§3.7.1 A 行 985-986）、
 * l 发 LoginOauth 并按 §1.3 信封处理（success 终点跳转；其余状态交页面帧渲染）。
 */
export async function dispatchCallback(
  input: { providerKey: string; search: string },
  deps: CallbackDispatchDeps,
): Promise<void> {
  const state = new URLSearchParams(input.search).get('state') ?? '';
  const kind = callbackDispatch(state);
  if (kind === 'mismatch') {
    deps.navigate(ssoPath('/sso/login'));
    return;
  }
  if (kind === 'bind') {
    // b 分支（§3.7.1 A 行 985-986）：成功 / 失败一律回跳安全中心出结果横幅，
    // 失败码经 errors.ts 归一取 ErrorInfo.code（位置二），本页不渲染终态帧。
    try {
      await deps.thirdpartyOauthRequest(
        buildThirdpartyOauthInput(input.providerKey, input.search),
      );
      deps.navigate(securityBindUrl('success'));
    } catch (error) {
      deps.navigate(securityBindUrl(bindErrorCode(error)));
    }
    return;
  }
  try {
    const envelope = await deps.loginOauthRequest(
      buildLoginOauthInput(input.providerKey, input.search),
    );
    deps.onEnvelope(envelope);
    if (envelope.status === 'success') {
      const url = flowTerminalUrl(envelope);
      if (url !== '') {
        deps.navigate(url);
      }
    }
  } catch {
    deps.onTransportError();
  }
}

// ---------------------------------------------------------------------------
// 视图（纯状态帧渲染；renderToStaticMarkup 下不执行副作用）
// ---------------------------------------------------------------------------

export interface OAuthCallbackViewProps {
  /** 注入快照（§2.1；mfa_required 完整编排经 LoginContainer 消费）。 */
  readonly snapshot: MethodsSnapshot;
  /** 帧状态：idle（处理中，含 b 分支回跳前）/ 信封 status。 */
  readonly status: string;
  /** 最近一次响应信封（binding_required 的 binding、失败态 error 来源）。 */
  readonly envelope: LoginFlowResponse | undefined;
  /** 返回登录（清内存 login_token → 跳 /sso/login；exitBinding 同款动作）。 */
  onBackToLogin: () => void;
}

export function OAuthCallbackView({
  snapshot,
  status,
  envelope,
  onBackToLogin,
}: OAuthCallbackViewProps) {
  // 失败态（§1.6 表驱动文案；idle / 非失败帧不进此分支——b 分支两态均回跳，
  // 无绑定终态帧）。
  const failed = status !== 'idle' && isFlowErrorStatus(status);
  const resolution = failed ? resolveFlowStatus(status) : undefined;
  const error = envelope?.error;

  return (
    <main className={styles.page}>
      <div className={styles.card}>
        {status === 'success' ? (
          <section className={styles.section}>
            <p role="status" className={styles.status}>
              {t('login.redirecting')}
            </p>
          </section>
        ) : status === 'binding_required' ? (
          // §1.6 行 234：原地渲染绑定选择页（不跳路由；建号 / 退出编排自带）。
          <BindingPage binding={envelope?.binding} />
        ) : status === 'mfa_required' ? (
          // §1.6 行 233 完整编排：就地渲染 mfa.methods 选择器 + 因子
          // 组件（不跳页）——复用 LoginContainer 既有能力（信封进状态机；
          // MFA 提交走 LoginDefault，success 终点跳转 executeEffects；loginToken
          // 由 api 层托管续接，页面不自管）。
          <LoginContainer snapshot={snapshot} initialEnvelope={envelope} />
        ) : resolution !== undefined ? (
          // 失败态（§1.6 表驱动文案）：回调页无表单，字段级提示无处着落，
          // 「回到第一步」类动作统一为返回登录（绑定中间态 restart 类同口径）。
          <section className={styles.section}>
            <ErrorBanner
              i18nKey={resolution.i18nKey}
              fallbackMessage={error?.message}
              retryAfter={error?.retryAfter}
              attemptsLeft={error?.attemptsLeft}
              retryable={resolution.retryable}
            />
            <button
              type="button"
              className={styles.backButton}
              onClick={onBackToLogin}
            >
              {t('login.backToLogin')}
            </button>
          </section>
        ) : (
          // 初始 / l / b 分派请求在途（静态渲染不跑 effect，此帧即回调路由首帧；
          // b 两态均回跳安全中心，不会落此页终态帧）。
          <section className={styles.section}>
            <p role="status" className={styles.status}>
              {t('login.processing')}
            </p>
          </section>
        )}
      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// 页壳（薄胶水：挂载即分派一次；状态帧由 View 渲染）
// ---------------------------------------------------------------------------

export interface OAuthCallbackPageProps {
  /** 路径参数 provider_key（routes.tsx 从 pathname 提取，§2.7.3）。 */
  readonly providerKey: string;
  /** 注入快照（§2.1；mfa_required 完整编排经 LoginContainer 消费）。 */
  readonly snapshot: MethodsSnapshot;
}

export function OAuthCallbackPage({
  providerKey,
  snapshot,
}: OAuthCallbackPageProps) {
  const [status, setStatus] = useState('idle');
  const [envelope, setEnvelope] = useState<LoginFlowResponse | undefined>(
    undefined,
  );
  // 挂载即分派一次（回调 code 单次有效）：dev 严格模式 effect 双跑守卫。
  const dispatchedRef = useRef(false);

  useEffect(() => {
    if (dispatchedRef.current) {
      return;
    }
    dispatchedRef.current = true;
    void dispatchCallback(
      { providerKey, search: window.location.search },
      {
        loginOauthRequest: loginOauth,
        thirdpartyOauthRequest: thirdpartyOauth,
        onEnvelope: (env) => {
          setEnvelope(env);
          setStatus(env.status);
        },
        onTransportError: () => {
          setStatus('failed');
        },
        navigate: (url) => {
          location.replace(url);
        },
      },
    );
  }, [providerKey]);

  // 返回登录（§1.6「回到第一步」）：清内存 login_token → 跳 /sso/login
  //（BindingPage.exitBinding 同款动作，导出复用）。
  const backToLogin = () => {
    exitBinding(clearLoginToken, (url) => location.replace(url));
  };

  return (
    <OAuthCallbackView
      snapshot={snapshot}
      status={status}
      envelope={envelope}
      onBackToLogin={backToLogin}
    />
  );
}

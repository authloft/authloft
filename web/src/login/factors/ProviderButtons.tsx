/**
 * 第三方渠道图标墙 + 点击分派（docs/前端架构.md §4.3 行 454）：
 * thirdparty 因子的主方式渲染入口——由 MethodTabs 消费链路接入（图标墙
 * 渲染归本组件、MethodTabs 不再重复渲染 thirdparty 图标，防双份渲染）。
 *
 * - 按 channel 分派（§2.7.1 行 576）：redirect → 先调 SsoService/Authorize
 *   取 authorize_url（§2.7.2：RPC 非 302，不得 <a href> 直跳——该路径返回
 *   JSON）→ 跳转前 saveOidcContext()（§2.7.2 行 599-600）→ location.replace
 *   （移动端 replace 防回退死循环，§4.2 行 442）；qrcode → 原地打开
 *   shared/QRCodePanel 登录包装 QRCodeStep（不新开页面）；api → 不渲染
 *   （宿主承载，§9 第 10 条）；
 * - 图标统一经 ProviderIcon 渲染（icon 空则占位，§3.3 行 344）；不硬编码
 *   任何渠道——未知 channel 不渲染（缺映射不静默回退同款精神，§4.3 行 450）；
 * - uiGroup 分组 / sortOrder 排序纯函数 groupProviders 自 MethodTabs 迁入
 *   （本组件是图标墙唯一实现），MethodTabs re-export 保持既有导入面
 *   （login-container.test 经 MethodTabs 消费）。
 *
 * 文案（i18n 收口）：redirect 失败提示经 shared/i18n 的 t() 消费——
 * 评审 P2-9 起由通用「请刷新重试」细化为带 provider 展示名的
 * login.oauthRedirectFailed，图标墙保留可重点（失败帧即重试入口）。
 */
import { useState, type ComponentType } from 'react';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import { RedirectStep } from '../steps/RedirectStep';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { t } from '../../shared/i18n';
import {
  getInit,
  type OidcContext,
  type SnapshotProvider,
} from '../../shared/types/init';
import { saveOidcContext } from '../oidcContext';
import styles from './ProviderButtons.module.less';

// ---------------------------------------------------------------------------
// 图标墙分组（纯函数，自 MethodTabs 迁入，行为不变；node 可测）
// ---------------------------------------------------------------------------

/** 图标墙不渲染的 channel（§4.3 行 456：api 由宿主承载）。 */
const HIDDEN_CHANNELS: ReadonlySet<string> = new Set(['api']);

/** 图标墙按钮渲染的 channel（§4.3 行 454：可分派的两种渠道；未知值不渲染）。 */
const RENDER_CHANNELS: ReadonlySet<string> = new Set(['redirect', 'qrcode']);

/**
 * sortOrder 排序键：int64 十进制字符串（§1.12）→ bigint 比较基准（不转
 * number，防超 2^53 丢精度）；缺失 / 空串 / 非法串兜底 0（§9 第 18 条）。
 */
function sortOrderKey(provider: SnapshotProvider): bigint {
  try {
    return BigInt(provider.sortOrder ?? '');
  } catch {
    return BigInt(0);
  }
}

/** 组内按 sortOrder 升序（bigint 比较，无精度损失）。 */
function compareBySortOrder(a: SnapshotProvider, b: SnapshotProvider): number {
  const x = sortOrderKey(a);
  const y = sortOrderKey(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * 图标墙分组（纯函数，可测）：过滤 channel=api → 按 sortOrder 升序 → 按
 * uiGroup 分组（Map 保插入序，组序 = 排序后首元素的出现顺序；uiGroup 缺省
 * 归空串组）。
 */
export function groupProviders(
  providers: SnapshotProvider[],
): ReadonlyMap<string, SnapshotProvider[]> {
  const sorted = providers
    .filter((p) => !HIDDEN_CHANNELS.has(p.channel))
    .sort(compareBySortOrder);
  const groups = new Map<string, SnapshotProvider[]>();
  for (const p of sorted) {
    const key = p.uiGroup ?? '';
    const bucket = groups.get(key);
    if (bucket === undefined) {
      groups.set(key, [p]);
    } else {
      bucket.push(p);
    }
  }
  return groups;
}

// ---------------------------------------------------------------------------
// redirect 渠道分派（纯函数，node 可测；副作用全注入）
// ---------------------------------------------------------------------------

/** startRedirect 依赖注入（缺省生产实现；测试替身）。 */
export interface RedirectDeps {
  /** 取授权 URL（缺省 SsoService/Authorize 薄封装，§2.7.2 行 580）。 */
  request?: (provider: string) => Promise<string>;
  /** OIDC 上下文读取（缺省注入快照 __AUTHLOFT_INIT__.oidc，§2.7.2 行 585）。 */
  readOidc?: () => OidcContext | undefined;
  /** 落盘（缺省 oidcContext.saveOidcContext；测试替身）。 */
  save?: (ctx: OidcContext) => void;
}

/**
 * 缺省取授权 URL：login/api.ts authorize（scene 缺省即 login，§2.7.2 行 584）。
 * 运行时动态 import——MethodTabs 静态 import 本组件（图标墙链路），顶层引入
 * api 会连带 transport 单例在测试全局 __AUTHLOFT_INIT__ 注入前求值（login-
 * container.test 模式），故按需加载。
 */
async function requestAuthorizeUrl(provider: string): Promise<string> {
  const { authorize } = await import('../api');
  const response = await authorize({ provider });
  return response.authorizeUrl;
}

/** 缺省 OIDC 来源：注入快照（§2.7.2 行 585：OIDC 上下文来自 /auth/authorize）。 */
function readSnapshotOidc(): OidcContext | undefined {
  return getInit()?.oidc;
}

/**
 * redirect 渠道分派（§4.3 行 454 → §2.7.2）：调 Authorize 取 authorize_url
 * → 跳转前 saveOidcContext()（§2.7.2 行 599-600）→ 由调用方 location.replace
 * （非 <a href> 直跳：该路径返回 JSON 而非 302）。成功返回 URL；失败 / 空
 * URL 返回 undefined（零值兜底不跳转）。
 */
export async function startRedirect(
  providerKey: string,
  deps: RedirectDeps = {},
): Promise<string | undefined> {
  const request = deps.request ?? requestAuthorizeUrl;
  try {
    const url = await request(providerKey);
    if (url === '') {
      return undefined;
    }
    const ctx = (deps.readOidc ?? readSnapshotOidc)();
    if (ctx !== undefined) {
      (deps.save ?? saveOidcContext)(ctx);
    }
    return url;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// 组件（图标墙 + 分派状态编排）
// ---------------------------------------------------------------------------

/** redirect 分派三态：pending（取 URL 在途）/ ready（URL 就绪，跳转）/ failed（携带 providerKey 供失败帧文案）。 */
type RedirectState =
  | { phase: 'pending' }
  | { phase: 'ready'; url: string }
  | { phase: 'failed'; providerKey: string };

/**
 * 失败帧展示名（评审 P2-9）：快照 displayName 优先，缺省 / 未知 key
 * 回显 providerKey（§9 第 18 条零值兜底，与图标墙按钮文案同款取舍）。纯函数。
 */
export function providerDisplayName(
  providers: SnapshotProvider[],
  providerKey: string,
): string {
  return (
    providers.find((p) => p.providerKey === providerKey)?.displayName ??
    providerKey
  );
}

export interface ProviderButtonsProps {
  /** thirdparty 方式条目的 providers（§2.7.1；channel=api 与未知渠道不渲染）。 */
  providers: SnapshotProvider[];
  /** 跳转动作注入（透传 RedirectStep，缺省 location.replace；测试记录函数）。 */
  navigate?: (url: string) => void;
  /** 取授权 URL（缺省 SsoService/Authorize；测试替身）。 */
  request?: (provider: string) => Promise<string>;
  /**
   * 扫码登录结论上抛（§2.8 行 739-743）：QRCodeStep onResult 透传——
   * success 已在面板侧完成终点跳转；binding_required / 失败态交容器状态机
   * 分派（LoginContainer qrResultEvent）。上抛后关闭扫码面板（图标墙恢复
   * 可重点，失败态重试 = 重新点击拉码，每次拉码新 captcha §2.8 行 703）。
   */
  onQrResult?: (envelope: LoginFlowResponse) => void;
}

/** qrcode 面板组件的加载态（动态 import 产物，见 pickQr）。 */
type QRCodeStepComponent = ComponentType<{
  providerKey: string;
  onResult?: (envelope: LoginFlowResponse) => void;
}>;

export function ProviderButtons({
  providers,
  navigate,
  request,
  onQrResult,
}: ProviderButtonsProps) {
  const [redirect, setRedirect] = useState<RedirectState | undefined>(
    undefined,
  );
  const [qrProvider, setQrProvider] = useState<string | undefined>(undefined);
  const [qrStep, setQrStep] = useState<QRCodeStepComponent | null>(null);

  /** redirect 渠道点击：取 authorize_url → RedirectStep 跳转（§4.3 行 454）。 */
  const pickRedirect = (providerKey: string) => {
    setRedirect({ phase: 'pending' });
    void startRedirect(
      providerKey,
      request === undefined ? {} : { request },
    ).then((url) => {
      setRedirect(
        url === undefined
          ? { phase: 'failed', providerKey }
          : { phase: 'ready', url },
      );
    });
  };

  /**
   * qrcode 渠道点击：原地打开扫码面板（不新开页面，§4.3 行 454）。QRCodeStep
   * 运行时动态加载——MethodTabs 静态 import 本组件（图标墙链路），而 QRCodeStep
   * → CaptchaWidget → shared/api/http 会连带 transport 单例在测试全局
   * __AUTHLOFT_INIT__ 注入前求值（login-container.test 静态/动态 import 时序），
   * 故图标墙静态链保持零 http 依赖，面板组件按需加载。
   */
  const pickQr = (providerKey: string) => {
    setQrProvider(providerKey);
    if (qrStep === null) {
      void import('../steps/QRCodeStep').then((m) => {
        setQrStep(() => m.QRCodeStep);
      });
    }
  };

  // redirect 分派三态：ready / pending 走 RedirectStep（「正在跳转…」；ready
  // 携 URL 由 effect 执行 location.replace）；failed 恢复图标墙可重点。
  if (redirect !== undefined) {
    if (redirect.phase === 'ready') {
      return <RedirectStep authorizeUrl={redirect.url} navigate={navigate} />;
    }
    if (redirect.phase === 'failed') {
      // 评审 P2-9：失败文案带 provider 展示名；图标墙保留可重点。
      return (
        <div>
          <p role="alert" className={styles.error}>
            {t('login.oauthRedirectFailed', {
              provider: providerDisplayName(providers, redirect.providerKey),
            })}
          </p>
          <ProviderWall
            providers={providers}
            onPick={pickRedirect}
            onPickQr={pickQr}
          />
        </div>
      );
    }
    // pending：空 authorizeUrl 的 RedirectStep（仅展示文案，effect 不跳转）。
    return <RedirectStep navigate={navigate} />;
  }

  // JSX 组件变量须大写开头（小写会被解析为字符串标签）。
  const QRStep = qrStep;

  /**
   * 扫码结论落地：面板结论（success 已跳转 / binding / 失败）上抛
   * 后关闭面板——分派归容器状态机（LoginContainer qrResultEvent）；图标墙
   * 恢复可重点（失败态重试 = 重新拉码，每次新 captcha，§2.8 行 703）。
   */
  const handleQrResult = (envelope: LoginFlowResponse) => {
    setQrProvider(undefined);
    onQrResult?.(envelope);
  };

  return (
    <div>
      <ProviderWall
        providers={providers}
        onPick={pickRedirect}
        onPickQr={pickQr}
      />
      {qrProvider !== undefined && QRStep !== null && (
        <QRStep providerKey={qrProvider} onResult={handleQrResult} />
      )}
    </div>
  );
}

/** 图标墙渲染态：uiGroup 分组 + sortOrder 排序（groupProviders）；图标经 ProviderIcon。 */
function ProviderWall({
  providers,
  onPick,
  onPickQr,
}: {
  providers: SnapshotProvider[];
  onPick: (providerKey: string) => void;
  onPickQr: (providerKey: string) => void;
}) {
  const groups = groupProviders(providers);
  if (groups.size === 0) {
    return null;
  }
  return (
    <div>
      {[...groups.entries()].map(([group, items]) => (
        <div key={group} data-group={group} className={styles.group}>
          {items
            .filter((p) => RENDER_CHANNELS.has(p.channel))
            .map((p) => (
              <button
                key={p.providerKey}
                type="button"
                className={styles.provider}
                title={p.displayName ?? p.providerKey}
                onClick={() =>
                  p.channel === 'qrcode'
                    ? onPickQr(p.providerKey)
                    : onPick(p.providerKey)
                }
              >
                <ProviderIcon
                  icon={p.icon}
                  alt={p.displayName ?? p.providerKey}
                />
                <span>{p.displayName ?? p.providerKey}</span>
              </button>
            ))}
        </div>
      ))}
    </div>
  );
}

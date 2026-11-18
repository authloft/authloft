/**
 * login entry 引导（docs/前端架构.md §4.1 行 375）：读 Go 空壳注入的
 * `window.__AUTHLOFT_INIT__`（注入白名单见接口文档 §8 唯一定义）。
 *
 * - `methods` 为 login 必填（§8）：缺失即服务端故障 → 调用方渲染错误态
 *   并提示刷新，没有回退接口（§1.5 行 98）；本模块纯同步读取，不阻塞渲染；
 * - 取出可选 `oidc`（§8：`/auth/authorize` 渲染空壳时注入）：首次请求的
 *   原样回传已由 api.ts 的 snapshotOidc 直接读注入实现（§2.2 行
 *   425），此处随引导结果带出，供页面层后续消费；
 * - 取出可选 `sso`（§2.1：client_id 命中 sso_client 行时注入，
 *   OIDC authorize 入口不注入）：缺席不阻塞（直登行为不变）；首签请求的
 *   ssoClientId 回传由 api.ts 直接读注入实现（§2.2），此处随引导结果带出
 *   供页面层后续消费（如应用名展示）；
 * - `static_base` 归一化（entry 首行赋 `__webpack_public_path__` 用，
 *   §1.5 行 99）：与 setup/bootstrap.ts 同口径；login 不跨 entry
 *   import setup 模块（三端 entry 独立演进）。
 */
import {
  getInit,
  type MethodsSnapshot,
  type OidcAccountContext,
  type OidcContext,
  type OidcMode,
  type SsoContext,
} from "../shared/types/init";

/** static_base 缺省回落值（接口文档 §8 行 1428：默认 /assets）。 */
const DEFAULT_STATIC_BASE = "/assets/";

/**
 * static_base 归一为以 `/` 结尾；空 / 缺省回落 `/assets/`（§1.5 行 99：
 * `__webpack_public_path__` = static_base + '/'）。可为 CDN 绝对地址，
 * 不得写死资源域名。
 */
export function normalizeStaticBase(base: string | undefined): string {
  if (base === undefined || base.trim() === "") {
    return DEFAULT_STATIC_BASE;
  }
  return base.endsWith("/") ? base : `${base}/`;
}

/**
 * OIDC 渲染视图（§4.2 三态在前端的分派输入）：从注入 oidc 提取 mode /
 * client_name / account，按只读快照返回；无 oidc 或 mode 未知 → plain（直登，
 * 形态 C 由后端 302 不渲染本页）。纯函数，node 可测。
 */
export interface OidcView {
  mode: OidcMode | "plain";
  clientName: string;
  account?: OidcAccountContext;
  ctx?: OidcContext;
}

/** 注入 oidc → 分派视图：mode 严格取 login/consent，其余（含 absent）归 plain。 */
export function oidcView(ctx: OidcContext | undefined): OidcView {
  if (ctx === undefined) {
    return { mode: "plain", clientName: "" };
  }
  const mode: OidcView["mode"] =
    ctx.mode === "login" || ctx.mode === "consent" ? ctx.mode : "plain";
  return {
    mode,
    clientName: ctx.client_name ?? "",
    ...(ctx.account !== undefined ? { account: ctx.account } : {}),
    ctx,
  };
}

/**
 * login 引导结果（§4.1 行 375）：methods 缺失（含注入块未下发）→ ok=false。
 * 例外：形态 B（oidc.mode=consent）不注入 methods（§二补充 / §8 收窄为 mode=login
 * 必填），左栏不渲染登录表单，故允许缺省并以空快照兜底。
 */
export type LoginBootstrapResult =
  | {
      ok: true;
      snapshot: MethodsSnapshot;
      oidc?: OidcContext;
      sso?: SsoContext;
    }
  | { ok: false };

/** 读注入快照（§8：methods 为 mode=login 必填、oidc / sso 可选）；同步纯读取，不阻塞渲染。 */
export function loadLoginBootstrap(): LoginBootstrapResult {
  const init = getInit();
  const snapshot = init?.methods;
  const oidc = init?.oidc;
  const sso = init?.sso;
  const isConsent = oidc?.mode === "consent";
  if ((snapshot === undefined || snapshot === null) && !isConsent) {
    return { ok: false };
  }
  return {
    ok: true,
    ...(snapshot !== undefined && snapshot !== null
      ? { snapshot }
      : { snapshot: { methods: [] } }),
    ...(oidc !== undefined ? { oidc } : {}),
    ...(sso !== undefined ? { sso } : {}),
  };
}

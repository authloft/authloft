/**
 * login entry 引导（docs/前端架构.md §4.1 行 375）：读 Go 空壳注入的
 * `window.__AUTHLOFT_INIT__`（注入白名单见接口文档 §8 唯一定义）。
 *
 * - `methods` 为 login 必填（§8）：缺失即服务端故障 → 调用方渲染错误态
 *   并提示刷新，没有回退接口（§1.5 行 98）；本模块纯同步读取，不阻塞渲染；
 * - 取出可选 `oidc`（§8：`/auth/authorize` 渲染空壳时注入）：首次请求的
 *   原样回传已由 api.ts 的 snapshotOidc 直接读注入实现（§2.2 行
 *   425），此处随引导结果带出，供页面层后续消费；
 * - `static_base` 归一化（entry 首行赋 `__webpack_public_path__` 用，
 *   §1.5 行 99）：与 setup/bootstrap.ts 同口径；login 不跨 entry
 *   import setup 模块（三端 entry 独立演进）。
 */
import {
  getInit,
  type MethodsSnapshot,
  type OidcContext,
} from '../shared/types/init';

/** static_base 缺省回落值（接口文档 §8 行 1428：默认 /assets）。 */
const DEFAULT_STATIC_BASE = '/assets/';

/**
 * static_base 归一为以 `/` 结尾；空 / 缺省回落 `/assets/`（§1.5 行 99：
 * `__webpack_public_path__` = static_base + '/'）。可为 CDN 绝对地址，
 * 不得写死资源域名。
 */
export function normalizeStaticBase(base: string | undefined): string {
  if (base === undefined || base.trim() === '') {
    return DEFAULT_STATIC_BASE;
  }
  return base.endsWith('/') ? base : `${base}/`;
}

/** login 引导结果（§4.1 行 375）：methods 缺失（含注入块未下发）→ ok=false。 */
export type LoginBootstrapResult =
  | {
      readonly ok: true;
      readonly snapshot: MethodsSnapshot;
      readonly oidc?: OidcContext;
    }
  | { readonly ok: false };

/** 读注入快照（§8：methods 必需、oidc 可选）；同步纯读取，不阻塞渲染。 */
export function loadLoginBootstrap(): LoginBootstrapResult {
  const init = getInit();
  const snapshot = init?.methods;
  if (snapshot === undefined || snapshot === null) {
    return { ok: false };
  }
  const oidc = init?.oidc;
  return oidc === undefined
    ? { ok: true, snapshot }
    : { ok: true, snapshot, oidc };
}

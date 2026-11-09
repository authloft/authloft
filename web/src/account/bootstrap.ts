/**
 * account entry 引导（docs/前端架构.md §5 行 478）：读 Go 空壳注入的
 * `window.__AUTHLOFT_INIT__`（注入白名单见接口文档 §8 唯一定义）。
 *
 * account 端不是登录流：无 login 的 methods 必需校验（§8：methods 仅
 * login 必填），`al_root` / `static_base` 三端适用、缺失即按缺省归一——
 * - `al_root`：Authloft 主域名（§8），用于拼登出跳转 `{al_root}/sso/logout`
 *   （§5 行 480）与 401 未登录跳登录 `{al_root}/sso/login`；
 *   归一口径与 shared/api/http.ts 的 resolveBaseUrl 一致（shared 层禁止
 *   import entry、entry 间禁止互引 §9 第 13 条——实现已收口 shared/urls.ts）；
 * - `static_base`：静态资源基址（§8），entry 首行赋 `__webpack_public_path__`，
 *   与 login/bootstrap.ts 同口径归一。
 */
import { getInit } from '../shared/types/init';
import { normalizeAlRoot } from '../shared/urls';

/** static_base 缺省回落值（接口文档 §8 行 1428：默认 /assets）。 */
const DEFAULT_STATIC_BASE = '/assets/';

/**
 * static_base 归一为以 `/` 结尾；空 / 缺省回落 `/assets/`
 * （§8：可为 CDN 绝对地址，不得写死资源域名）。
 */
export function normalizeStaticBase(base: string | undefined): string {
  if (base === undefined || base.trim() === '') {
    return DEFAULT_STATIC_BASE;
  }
  return base.endsWith('/') ? base : `${base}/`;
}

/** account 引导结果（§5 行 478）：归一后的注入值，无必需校验（恒 ok）。 */
export interface AccountBootstrapResult {
  ok: true;
  /** 归一后 al_root（登出 / 401 跳登录的前缀）。 */
  alRoot: string;
  /** 归一后 static_base（entry 首行 `__webpack_public_path__`）。 */
  staticBase: string;
}

/** 读注入变量并归一（§8 白名单 al_root / static_base）；同步纯读取，不阻塞渲染。 */
export function loadAccountBootstrap(): AccountBootstrapResult {
  const init = getInit();
  return {
    ok: true,
    alRoot: normalizeAlRoot(init?.al_root),
    staticBase: normalizeStaticBase(init?.static_base),
  };
}

// loginUrl / logoutUrl / normalizeAlRoot 实现收口 shared/urls.ts
//（URL 唯一真值），此处 re-export 保持既有引用面不变。
export { loginUrl, logoutUrl } from '../shared/urls';

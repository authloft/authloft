/**
 * account entry 引导（docs/前端架构.md §5 行 478）：读 Go 空壳注入的
 * `window.__AUTHLOFT_INIT__`（注入白名单见接口文档 §8 唯一定义）。
 *
 * account 端不是登录流：无 login 的 methods 必需校验（§8：methods 仅
 * login 必填），`al_root` / `static_base` 三端适用、缺失即按缺省归一——
 * - `al_root`：Authloft 主域名（§8），用于拼登出跳转 `{al_root}/sso/logout`
 *   （§5 行 480）与 401 未登录跳登录 `{al_root}/sso/login`；
 *   归一口径与 shared/api/http.ts 的 resolveBaseUrl 一致（shared 层禁止
 *   import entry、entry 间禁止互引 §9 第 13 条，故内联同款实现）；
 * - `static_base`：静态资源基址（§8），entry 首行赋 `__webpack_public_path__`，
 *   与 login/bootstrap.ts 同口径归一。
 */
import { getInit } from '../shared/types/init';

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

/**
 * al_root 归一：string 校验 → trim → 去尾斜杠；缺省回落当前站点源；
 * 非浏览器环境（单测 node）为空串（与 shared/api/http.ts 同口径）。
 */
function normalizeAlRoot(alRoot: unknown): string {
  const value =
    typeof alRoot === 'string' ? alRoot.trim().replace(/\/+$/, '') : '';
  if (value !== '') {
    return value;
  }
  return typeof location !== 'undefined' ? location.origin : '';
}

/** account 引导结果（§5 行 478）：归一后的注入值，无必需校验（恒 ok）。 */
export interface AccountBootstrapResult {
  readonly ok: true;
  /** 归一后 al_root（登出 / 401 跳登录的前缀）。 */
  readonly alRoot: string;
  /** 归一后 static_base（entry 首行 `__webpack_public_path__`）。 */
  readonly staticBase: string;
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

/** 401 未登录统一跳转的登录页地址（§5 行 480：跳 `{al_root}/sso/login`；Go 渲染，§8 行 1418）。 */
export function loginUrl(alRoot: string): string {
  return `${alRoot}/sso/login`;
}

/** 登出地址（§5 行 480 / 接口文档 §8 行 1420：`{al_root}/sso/logout`，Go 处理非 SPA）。 */
export function logoutUrl(alRoot: string): string {
  return `${alRoot}/sso/logout`;
}

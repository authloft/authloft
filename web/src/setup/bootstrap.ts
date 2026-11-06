/**
 * setup entry 引导：读 Go 空壳注入的 `window.__AUTHLOFT_INIT__`
 * （接口文档 §8 白名单；docs/前端架构.md §6b：只读 `static_base`，
 * 安装态无业务配置、不读 `methods`；`al_root` 用于跳转 /sso/login）。
 */
import { loginUrl, normalizeAlRoot } from '../shared/urls';

/** 空壳注入变量的最小形状（§8 白名单中 setup 页可用项）。 */
interface RawSetupInit {
  al_root?: unknown;
  static_base?: unknown;
}

export interface SetupInit {
  /** 站点根（形如 https://uc.example.com），末尾无斜杠。 */
  readonly alRoot: string;
  /** 静态资源基址，以 `/` 结尾（§1.5：`__webpack_public_path__` 用）。 */
  readonly staticBase: string;
}

/** static_base 缺省回落值（接口文档 §8：默认 /assets）。 */
export const DEFAULT_STATIC_BASE = '/assets/';

export function loadSetupInit(): SetupInit {
  const raw = (globalThis as { __AUTHLOFT_INIT__?: RawSetupInit })
    .__AUTHLOFT_INIT__;
  const alRootRaw = typeof raw?.al_root === 'string' ? raw.al_root : '';
  const staticBaseRaw =
    typeof raw?.static_base === 'string' ? raw.static_base : '';
  return {
    alRoot: normalizeAlRoot(alRootRaw),
    staticBase: normalizeStaticBase(staticBaseRaw),
  };
}

// normalizeAlRoot / 登录页地址实现收口 shared/urls.ts（URL
// 唯一真值）；此处再导出保持既有引用面（含测试）不变。
export { normalizeAlRoot };

/** static_base 归一为以 `/` 结尾；缺省回落 `/assets/`（§1.5 / §8）。 */
export function normalizeStaticBase(base: string): string {
  if (base.trim() === '') {
    return DEFAULT_STATIC_BASE;
  }
  return base.endsWith('/') ? base : `${base}/`;
}

/**
 * 跳转登录页：setup 完成 / 加载时已处于正常模式的统一出口（§6b / §13.4）。
 * 用 replace 避免回退键回到安装页。地址经 shared/urls.ts。
 */
export function redirectToLogin(alRoot: string): void {
  window.location.replace(loginUrl(alRoot));
}

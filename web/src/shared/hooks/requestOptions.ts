/**
 * 请求错误集中分派 options 工厂（docs/前端架构.md §3.2 useRequest 段；
 * 定稿 review/frontend-request-layer.md §5.4）：ahooks
 * useRequest 的错误统一进 onError，本模块只做 options / 回调集中，
 * 不重建请求机制。分派顺序：
 *   ① 401 / unauthenticated → loginUrl(alRoot, returnTo(...)) 跳登录
 *      （原先散在各域 effect / catch 内的 18 处内联分流收敛于此）；
 *   ② 字段级错误码（fieldByCode 命中且注入 onFieldError）→ 表单行内；
 *   ③ 其余 → Toast.error；首取页（错误帧呈现）传 toast:false 转静默，
 *      防 Toast + 错误帧双报。
 * al_root 取法与 shared/api/http.ts resolveBaseUrl 同口径（注入变量 →
 * location.origin），URL 拼装复用 shared/urls.ts（loginUrl 内含
 * returnTo 白名单校验，防开放重定向）。分派判定抽纯函数
 * classifyRequestError，node 可测；redirect / showToast 为测试注入点。
 */
import { Toast } from '@douyinfe/semi-ui-19';
import { ApiError, resolveCode } from '../api/errors';
import { t } from '../i18n';
import { loginUrl, normalizeAlRoot } from '../urls';

/**
 * 401 未登录判定：transport 归一后的 ApiError，HTTP 401 或 Connect
 * 标准码 unauthenticated（接口文档 §1.5 行 184-193 两者同源；与
 * account / admin 域 api.ts 的 isUnauthenticatedError 同口径，此处为
 * shared 层收敛点，域内定义随迁移收口后删除）。
 */
export function isUnauthenticatedError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.httpStatus === 401 || error.code === 'unauthenticated')
  );
}

/**
 * 错误 → 展示文案（§1.5 行 202：i18n 优先；未知异常兜底不透出内部信息）。
 * 与各域 apiErrorText 同口径的 shared 层实现。
 */
export function requestErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    return t(resolveCode(error).i18nKey);
  }
  return t('errors.code.unknown');
}

/** 集中分派的四种去处。 */
export type RequestErrorAction =
  /** 401：跳登录（URL 由工厂拼装，含 returnTo）。 */
  | { readonly kind: 'redirect' }
  /** 字段级错误码：行内呈现（用户需知道哪一栏错）。 */
  | { readonly kind: 'field'; readonly field: string; readonly message: string }
  /** 其余错误：Toast 弹出。 */
  | { readonly kind: 'toast'; readonly message: string }
  /** toast:false（首取页）：静默——错误态由页面错误帧呈现，防双报。 */
  | { readonly kind: 'silent' };

/**
 * 错误分派判定（纯函数）：401 优先于字段级与 toast 开关；字段级命中
 * 优先于 Toast（行内呈现不弹 Toast）；toast:false 仅作用于「其余」分支。
 */
export function classifyRequestError(
  error: unknown,
  options: {
    readonly toast?: boolean;
    readonly fieldByCode?: Readonly<Record<string, string>>;
    readonly onFieldError?: (field: string, message: string) => void;
  },
): RequestErrorAction {
  if (isUnauthenticatedError(error)) {
    return { kind: 'redirect' };
  }
  if (error instanceof ApiError && options.onFieldError !== undefined) {
    const field = options.fieldByCode?.[error.code];
    if (field !== undefined) {
      return { kind: 'field', field, message: requestErrorText(error) };
    }
  }
  if (options.toast === false) {
    return { kind: 'silent' };
  }
  return { kind: 'toast', message: requestErrorText(error) };
}

/** requestOptions 入参。 */
export interface RequestOptionsInput {
  /** 默认 true；首取页（错误帧呈现）传 false 防 Toast + 错误帧双报。 */
  readonly toast?: boolean;
  /** 字段级错误码 → 表单字段名（如 setup 的 INSTALL_FIELD_BY_CODE）。 */
  readonly fieldByCode?: Readonly<Record<string, string>>;
  /** 字段级错误的行内落点（如 formApi.setError）。 */
  readonly onFieldError?: (field: string, message: string) => void;
  /** 401 跳转的域内 returnTo 构造（accountReturnTo / adminReturnTo 分域注入）。 */
  readonly returnTo?: (path: string, search: string) => string;
  /** 测试注入点：默认 location.replace。 */
  readonly redirect?: (url: string) => void;
  /** 测试注入点：默认 Toast.error。 */
  readonly showToast?: (message: string) => void;
}

/** 工厂产出：可直接展开进 ahooks useRequest options。 */
export interface RequestOptionsResult {
  readonly onError: (error: Error) => void;
}

/** __AUTHLOFT_INIT__ 的最小形状（接口文档 §8 白名单中的 al_root）。 */
interface RawInit {
  al_root?: unknown;
}

/**
 * 生成 ahooks useRequest 的集中 onError 配置。用法：
 * `useRequest(fn, requestOptions({ toast: false }))`（首取）/
 * `useRequest(fn, { manual: true, ...requestOptions() })`（提交）。
 */
export function requestOptions(input: RequestOptionsInput = {}): RequestOptionsResult {
  const redirect =
    input.redirect ??
    ((url: string) => {
      location.replace(url);
    });
  const showToast = input.showToast ?? ((message: string) => Toast.error(message));
  return {
    onError: (error) => {
      const action = classifyRequestError(error, input);
      switch (action.kind) {
        case 'redirect': {
          const raw = (globalThis as { __AUTHLOFT_INIT__?: RawInit })
            .__AUTHLOFT_INIT__;
          const alRoot = normalizeAlRoot(raw?.al_root);
          const path = typeof location === 'undefined' ? '' : location.pathname;
          const search = typeof location === 'undefined' ? '' : location.search;
          redirect(loginUrl(alRoot, input.returnTo?.(path, search)));
          return;
        }
        case 'field':
          input.onFieldError?.(action.field, action.message);
          return;
        case 'toast':
          showToast(action.message);
          return;
        case 'silent':
          return;
      }
    },
  };
}

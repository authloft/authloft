/**
 * login entry 挂载（docs/前端架构.md §4.1 行 374 / §1.5 行 99）：
 * 首条执行语句读 `__AUTHLOFT_INIT__.static_base` 赋 `__webpack_public_path__`
 * （任何动态 import() 之前；缺省 `/assets/`）→ 注入 i18n（按浏览器语言
 * setLocale，zh-CN 默认）→ createRoot 挂载路由（错误边界包裹）。
 * 沿 setup/entry.tsx 同构模式：modern.config 注册 disableMount，
 * 不依赖 Modern.js 运行时路由 / SSR。
 */
// §1.7 行 120：全局样式由 entry 顶部 import 一次——tokens 只存变量（经组件
// reference 消费，本身无 CSS 产出），reset 为基础重置。
import '../shared/styles/tokens.less';
import '../shared/styles/reset.less';
import { Component, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { setLocale, t } from '../shared/i18n';
import { getInit } from '../shared/types/init';
import { normalizeStaticBase } from './bootstrap';
import { LoginApp } from './routes';

declare global {
  var __webpack_public_path__: string;
}

// §1.5 行 99 / §4.1 行 374：任何动态 import() 之前把
// `__webpack_public_path__` 设为 static_base + '/'（已归一），此后异步
// chunk 与图片按该前缀加载；static_base 可为 CDN 绝对地址，不写死资源
// 域名（本 entry 当前无动态 import，该值为异步扩展预留，同 setup 口径）。
__webpack_public_path__ = normalizeStaticBase(getInit()?.static_base);

// §4.1 行 374：注入 i18n（i18n/index.ts：模块级当前语言，zh-CN 默认）。
setLocale(navigator.language);

/** 渲染期异常兜底（§4.1 行 374：错误边界）。 */
class LoginErrorBoundary extends Component<
  { readonly children: ReactNode },
  { readonly error: unknown }
> {
  constructor(props: { readonly children: ReactNode }) {
    super(props);
    this.state = { error: undefined };
  }

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  render() {
    if (this.state.error !== undefined) {
      // 渲染期取 t()（setLocale 已在模块顶层执行，渲染时语言已就位）。
      return <p role="alert">{t('login.renderError')}</p>;
    }
    return this.props.children;
  }
}

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(
    <LoginErrorBoundary>
      <LoginApp />
    </LoginErrorBoundary>,
  );
}

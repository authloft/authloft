/**
 * reset entry（docs/前端架构.md §1.3 六 entry；/sso/reset 独立入口）：
 * 登录族按页拆入口——注入快照 `__AUTHLOFT_INIT__` 由服务端按 flow=reset
 * 口味注入本 entry 壳层（shell.go），页面间整页跳转（`<a href>`），不再经
 * 登录入口的 SPA 路由串用首开页快照。领域代码（pages/ResetPage 等）留在
 * `src/login` 由登录族入口共享 import，本文件只承载入口级装配（与 login
 * App.tsx 同构）：`__webpack_public_path__`（任何动态 import() 之前）→
 * i18n（会话内持久化值优先，缺省按浏览器语言）→ 错误边界包裹路由。
 */
import '../shared/styles/tokens.less';
import '../shared/styles/reset.less';
import { Component, type ReactNode } from 'react';
import { BrowserRouter } from '@modern-js/runtime/router';
import { initLocale, t } from '../shared/i18n';
import { getInit } from '../shared/types/init';
import { loadLoginBootstrap, normalizeStaticBase } from '../login/bootstrap';
import { ResetPage } from '../login/pages/ResetPage';

declare global {
  var __webpack_public_path__: string;
}

// §1.5 行 122：任何动态 import() 之前把 `__webpack_public_path__` 设为
// static_base 加尾斜杠（已归一）；static_base 可为 CDN 绝对地址。
__webpack_public_path__ = normalizeStaticBase(getInit()?.static_base);

// 注入 i18n（会话内持久化值优先，缺省按浏览器语言）。
initLocale(navigator.language);

/** 渲染期异常兜底（错误边界，与 login App.tsx 同款语义）。 */
class EntryErrorBoundary extends Component<
  { children: ReactNode },
  { error: unknown }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { error: undefined };
  }

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  render() {
    if (this.state.error !== undefined) {
      return <p role="alert">{t('login.renderError')}</p>;
    }
    return this.props.children;
  }
}

/** 重置端应用根：错误边界 + BrowserRouter（与入口族路由形态统一）+ 应用体。
 * 测试沿 login 入口同款缝：MemoryRouter 包裹命名导出的 ResetEntryApp 静态
 * 渲染（node 无 DOM，不渲染本默认导出）。 */
export default function App(): ReactNode {
  return (
    <EntryErrorBoundary>
      <BrowserRouter>
        <ResetEntryApp />
      </BrowserRouter>
    </EntryErrorBoundary>
  );
}

/** 重置端应用体：bootstrap 读注入快照 → 页面直渲染（本 entry 只服务
 * /sso/reset，无路由分派）。 */
export function ResetEntryApp(): ReactNode {
  // §1.5 行 98：methods 必需，缺失即服务端故障——错误态 + 提示刷新。
  const boot = loadLoginBootstrap();
  if (!boot.ok) {
    return <p role="alert">{t('login.initMissing')}</p>;
  }
  return <ResetPage snapshot={boot.snapshot} />;
}

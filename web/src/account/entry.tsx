/**
 * account entry 挂载（docs/前端架构.md §5 行 478 / §1.5 行 99）：
 * 沿 setup / login entry 同构模式——modern.config 注册
 * disableMount，不依赖 Modern.js 运行时路由 / SSR；首条执行语句读
 * `__AUTHLOFT_INIT__.static_base` 赋 `__webpack_public_path__`（任何动态
 * import() 之前；缺省 `/assets/`）→ 注入 i18n → createRoot 挂载路由
 * （错误边界包裹）。
 *
 * Semi UI 接入（§1.3 行 111：account 端用 Semi UI；本 entry 是全项目唯一
 * 引用点，login / setup 零引用）：
 * - 组件 JS 经官方包 exports 的 lib/es 子路径逐组件引入（见
 *   AppLayout.tsx 注释），组件样式随组件 JS 内部的 css import
 *   （semi-foundation 各组件 css）由构建链自动打包；
 * - 主题 css 变量（--semi-color-* 等）统一在 lib/es/_base/base.css 定义
 *   （exports 白名单内），与 tokens/reset 一起由 entry 顶部 import 一次——
 *   dist/css/semi.min.css 不在包 exports 白名单（Rspack 实测拒绝解析），
 *   且全量引入会引入未使用组件样式，弃用。
 *
 * 全局样式顺序（§1.7 行 120：由每个 entry 顶部 import 一次）：
 * tokens（只存变量）→ reset（基础重置）→ Semi 全量组件样式在后，
 * 组件级 .semi-* 类选择器特异度高于 reset 的元素选择器，两不冲突。
 */
// .css 副作用 import 的类型声明由 @modern-js/app-tools/types 提供
//（tsconfig types 字段），无需 global.d.ts 扩项（tsc 实测无 TS2307）。
import '../shared/styles/tokens.less';
import '../shared/styles/reset.less';
import '@douyinfe/semi-ui/lib/es/_base/base.css';
import { Component, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { setLocale } from '../shared/i18n';
import { getInit } from '../shared/types/init';
import { normalizeStaticBase } from './bootstrap';
import { AccountApp } from './routes';

declare global {
  var __webpack_public_path__: string;
}

// §1.5 行 99：任何动态 import() 之前把 `__webpack_public_path__` 设为
// static_base + '/'（已归一），此后异步 chunk 与图片按该前缀加载；
// static_base 可为 CDN 绝对地址，不写死资源域名（§9 第 14 条）。
__webpack_public_path__ = normalizeStaticBase(getInit()?.static_base);

// §4.1 行 374 同款：注入 i18n（模块级当前语言，zh-CN 默认）。
setLocale(navigator.language);

/** 渲染期异常兜底（§4.1 行 374：错误边界）。 */
class AccountErrorBoundary extends Component<
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
      // 文案无 i18n 键：最简中文字面量（归 i18n 收口卡）。
      return <p role="alert">页面出现异常，请刷新重试</p>;
    }
    return this.props.children;
  }
}

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(
    <AccountErrorBoundary>
      <AccountApp />
    </AccountErrorBoundary>,
  );
}

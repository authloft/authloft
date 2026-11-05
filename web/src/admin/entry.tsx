/**
 * admin entry 挂载（docs/前端架构.md §6 行 501/505 / §1.5 行 99）：
 * 沿 setup / login / account entry 同构模式——
 * modern.config 注册 disableMount，不依赖 Modern.js 运行时路由 / SSR；
 * 首条执行语句读 `__AUTHLOFT_INIT__.static_base` 赋 `__webpack_public_path__`
 * （任何动态 import() 之前；缺省 `/assets/`）→ 注入 i18n → createRoot
 * 挂载路由（错误边界包裹）。
 *
 * Semi UI 接入（§1.6 行 112/113：admin 端用 Semi UI，与 account 同底座
 * ——唯一包 @douyinfe/semi-ui-19，大包命名导入、禁子路径）：
 * - 组件一律从大包入口 import（lib/es/index.js，Rsbuild tree shaking
 *   按需裁剪）；组件样式随组件 JS 内部的 css import（semi-foundation
 *   各组件 css）由构建链自动打包；
 * - 主题 css 变量（--semi-color-* 等）在 lib/es/_base/base.css 定义，
 *   大包入口首行自带该 import 且包 sideEffects 标记 *.css——大包导入
 *   即自动引入，entry 无需显式 import；dist/css/semi.min.css 不在包
 *   exports 白名单（Rspack 拒绝解析），且全量引入会带上未使用组件
 *   样式，弃用。
 *
 * 全局样式顺序（§1.7 行 120：由每个 entry 顶部 import 一次）：
 * tokens（只存变量）→ reset（基础重置）→ Semi 主题变量 + 组件样式随
 * 大包导入链在后，组件级 .semi-* 类选择器特异度高于 reset 的元素选
 * 择器，两不冲突。
 */
// .less 副作用 import 的类型声明由 @modern-js/app-tools/types 提供
//（tsconfig types 字段），无需 global.d.ts 扩项（tsc 实测无 TS2307）。
import '../shared/styles/tokens.less';
import '../shared/styles/reset.less';
import { Component, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { setLocale, t } from '../shared/i18n';
import { getInit } from '../shared/types/init';
import { normalizeStaticBase } from './bootstrap';
import { AdminApp } from './routes';

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
class AdminErrorBoundary extends Component<
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
      // 渲染期 t()：错误边界文案经 i18n 字典。
      return <p role="alert">{t('admin.renderError')}</p>;
    }
    return this.props.children;
  }
}

const container = document.getElementById('root');
if (container) {
  createRoot(container).render(
    <AdminErrorBoundary>
      <AdminApp />
    </AdminErrorBoundary>,
  );
}

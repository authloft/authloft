/**
 * account entry（docs/前端架构.md §5 行 502 / §1.4 / §1.5 行 122）：
 * 去 `disableMount`——框架接管挂载（容器 `#root`，HTML 结构不变），
 * 本文件只默认导出根组件；原挂载前副作用留在本模块作用域（框架生成的
 * entry 静态 import 本模块，为首个自有执行点）：读
 * `__AUTHLOFT_INIT__.static_base` 赋 `__webpack_public_path__`（任何动态
 * import() 之前；缺省 `/assets/`）→ 注入 i18n → 根组件 = 错误边界包裹路由。
 *
 * Semi UI 接入（§1.6 行 112/113：account 端用 Semi UI——唯一包
 * @douyinfe/semi-ui-19，大包命名导入、禁子路径；本 entry 链是全项目唯一
 * 引用点，login / setup 零引用）：
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
import { HashRouter } from '@modern-js/runtime/router';
import { setLocale, t } from '../shared/i18n';
import { getInit } from '../shared/types/init';
import { normalizeStaticBase } from './bootstrap';
import { AccountApp } from './routes';

declare global {
  var __webpack_public_path__: string;
}

// §1.5 行 122：任何动态 import() 之前把 `__webpack_public_path__` 设为
// static_base 加尾斜杠（已归一），此后异步 chunk 与图片按该前缀加载；
// static_base 可为 CDN 绝对地址，不写死资源域名（§9 第 14 条）。
__webpack_public_path__ = normalizeStaticBase(getInit()?.static_base);

// 注入 i18n（模块级当前语言，zh-CN 默认）。
setLocale(navigator.language);

/** 渲染期异常兜底（错误边界，语义沿自行挂载时期不变）。 */
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
      // 兜底文案经 shared/i18n 域键（account.renderError）。
      return <p role="alert">{t('account.renderError')}</p>;
    }
    return this.props.children;
  }
}

/** 根组件（框架接管挂载，默认导出即挂载单元）：HashRouter
 *（hash 内路径 `/account#/profile` 等）包裹错误边界与路由表。 */
export default function App(): ReactNode {
  return (
    <HashRouter>
      <AccountErrorBoundary>
        <AccountApp />
      </AccountErrorBoundary>
    </HashRouter>
  );
}

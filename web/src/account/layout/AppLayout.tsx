/**
 * account 端应用布局（docs/前端架构.md §5 行 480）：侧边栏 + 顶栏 + 面包屑
 * + LogoutLink；未登录（401）统一跳登录由各页面消费 ./api 的
 * isUnauthenticatedError + ./bootstrap 的 loginUrl 实现（AppLayout 自身
 * 不发请求；shared/api/http 的错误归一层只产出 ApiError、无统一跳转，
 * 职责落在本 entry，后续页面复用同一对工具函数）。
 *
 * Semi UI 组件（§1.3 行 111：account 端用 Semi UI）：Layout / Nav /
 * Breadcrumb；登出跳 `{al_root}/sso/logout`（接口文档 §8 行 1420：Go
 * 处理，非 SPA），整页跳转走 <a href> 由浏览器原生完成。
 *
 * 样式（§1.7）：同目录同名 module.less，类名 camelCase；Semi 组件样式
 * 随组件 JS 内部 css import 自动打包，主题变量由大包入口自带的
 * _base/base.css 引入（见 entry.tsx 注释）。
 */
import type { ReactNode } from 'react';
// 大包命名导入（§1.6 行 112/113 硬性口径：唯一包 @douyinfe/semi-ui-19，
// 一律大包入口、禁子路径——此前 lib/es 子路径裁量已废止）。
// 组件样式随组件 JS 内部 css import 自动打包，主题变量由大包入口自带的
// _base/base.css 引入（见 entry.tsx 注释）。
import { Breadcrumb, Layout, Nav } from '@douyinfe/semi-ui-19';
import { t, type I18nKey } from '../../shared/i18n';
import { logoutUrl } from '../bootstrap';
import styles from './AppLayout.module.less';

const { Sider, Header, Content } = Layout;

/**
 * 侧边栏导航项（§5 行 478 路由清单的已交付子集）：
 * 安全中心（/account/security）已随 SecurityPage 长入；登录日志
 * （/account/audit）已随 AuditPage 长入；
 * itemKey 即路由路径，点击原生跳转。text 为 i18n 域键（account.*），
 * 渲染期经 t() 取文案（模块级求值会冻结在默认语言，故不在常量里调 t）。
 */
const NAV_ITEMS: { itemKey: string; textKey: I18nKey }[] = [
  { itemKey: '/account/profile', textKey: 'account.profileTitle' },
  { itemKey: '/account/security', textKey: 'account.securityTitle' },
  { itemKey: '/account/audit', textKey: 'account.auditTitle' },
];

/** 登出链接（§5 行 480）：跳 `{al_root}/sso/logout`，Go 处理（接口文档 §8 行 1420）。 */
function LogoutLink({ alRoot }: { readonly alRoot: string }) {
  return (
    <a className={styles.logoutLink} href={logoutUrl(alRoot)}>
      {t('account.logout')}
    </a>
  );
}

/** account 布局壳（§5 行 480）：Sider(Nav) + Header(面包屑 + 登出) + Content。 */
export function AppLayout(props: {
  /** 归一后 al_root（登出跳转前缀，见 ./bootstrap）。 */
  readonly alRoot: string;
  /** 侧边栏选中项（NAV_ITEMS 的 itemKey，同路由路径）。 */
  readonly activeKey: string;
  /** 顶栏面包屑层级（当前页标题链）。 */
  readonly breadcrumb: readonly string[];
  readonly children: ReactNode;
}) {
  return (
    <Layout className={styles.shell}>
      <Sider>
        <Nav
          className={styles.nav}
          items={NAV_ITEMS.map(({ itemKey, textKey }) => ({
            itemKey,
            text: t(textKey),
          }))}
          selectedKeys={[props.activeKey]}
          onClick={({ itemKey }) => {
            if (typeof itemKey === 'string') {
              window.location.assign(itemKey);
            }
          }}
          header={{ text: t('account.appTitle') }}
        />
      </Sider>
      <Layout>
        <Header className={styles.header}>
          <Breadcrumb routes={[...props.breadcrumb]} />
          <LogoutLink alRoot={props.alRoot} />
        </Header>
        <Content className={styles.content}>{props.children}</Content>
      </Layout>
    </Layout>
  );
}

/**
 * account 端布局包装层（docs/前端架构.md §5）：消费上层注入的自身权限点，
 * 构造右上 Dropdown 菜单（登出 + 条件跨端入口），与 NAV 项、面包屑、
 * Nav 标题、trigger 显示内容一并经 props 传入 shared/app-ui/ManageLayout
 * 基础布局壳；包装层自身不渲染 Sider/Header/Content、不发请求。
 * 登出跳 `{al_root}/sso/logout`（Go 处理，前端不发 fetch、不自行清 Cookie）。
 */
import { type ReactNode } from 'react';
import {
  matchRoutes,
  useLocation,
  type RouteObject,
} from '@modern-js/runtime/router';
import { ManageLayout, type HeaderMenu } from '@/shared/app-ui/ManageLayout';
import { ACCOUNT_NAV_ROUTES, toNavItems } from '../../shared/app-ui/nav-routes';
import { t } from '../../shared/i18n';
import { buildAccountHeaderMenu } from '../api';
import styles from './AppLayout.module.less';
import { getSiteName } from '@/shared/types/init';

const navItems = [...toNavItems(ACCOUNT_NAV_ROUTES)];

/** 子路由 handle 上面包屑字段（避免 any 扩散）。 */
interface BreadcrumbHandle {
  breadcrumb?: string[];
}

/** account 布局包装层：只构造 props，渲染委托共用基础布局壳。 */
export function AppLayout(props: {
  /** 归一后 al_root（登出 / 跨端跳转前缀，见 ./bootstrap）。 */
  alRoot: string;
  children: ReactNode;
  /** 上层注入的自身权限点：非空才显示跨端入口；取值由调用方提供，本层不发请求。 */
  permissions?: string[];
  /** 子路由表（各子路由 handle.breadcrumb 为面包屑来源），由父路由注入。 */
  routes: RouteObject[];
}) {
  // 非 data router 下 useMatches 不可用：按当前 location 从子路由表读命中
  // 子路由的 handle.breadcrumb；handle 缺失时兜底空数组（account 各路由均声明）。
  const location = useLocation();
  const matches = matchRoutes(props.routes, location) ?? [];
  const lastMatch = matches[matches.length - 1];
  const breadcrumb =
    (lastMatch?.route.handle as BreadcrumbHandle | undefined)?.breadcrumb ?? [];

  // 渲染期构造（CODE_GUIDE §4.6：模块级 t() 会冻结 locale）。
  // 菜单项由纯函数给出文案与注入的整页跳转动作，此处只补 Semi 需要的
  // node 形态；跨端切换经 location.replace，不经 Router。
  const headerMenu: HeaderMenu = buildAccountHeaderMenu(
    props.alRoot,
    props.permissions,
    (url) => window.location.replace(url),
  ).map(({ name, onClick }) => ({ node: 'item' as const, name, onClick }));
  return (
    <ManageLayout
      breadcrumb={breadcrumb}
      navItems={navItems}
      baseNavRoutes={ACCOUNT_NAV_ROUTES}
      navHeader={getSiteName()}
      headerLabel={
        <span className={styles.me}>{t('account.personalCenter')}</span>
      }
      headerMenu={headerMenu}
    >
      {props.children}
    </ManageLayout>
  );
}

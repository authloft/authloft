/**
 * account 端布局包装层（docs/前端架构.md §5）：消费上层注入的自身权限点，
 * 构造右上 Dropdown 菜单（登出 + 条件跨端入口），与 NAV 项、面包屑、
 * Nav 标题、trigger 显示内容一并经 props 传入 shared/app-ui/ManageLayout
 * 基础布局壳；包装层自身不渲染 Sider/Header/Content、不发请求。
 * 登出跳 `{al_root}/sso/logout`（Go 处理，前端不发 fetch、不自行清 Cookie）。
 */
import { type ReactNode } from 'react';
import { ManageLayout, type HeaderMenu } from '@/shared/app-ui/ManageLayout';
import { ACCOUNT_NAV_ROUTES, toNavItems } from '../../shared/app-ui/nav-routes';
import { t } from '../../shared/i18n';
import { buildAccountHeaderMenu } from '../api';
import styles from './AppLayout.module.less';

const navItems = [...toNavItems(ACCOUNT_NAV_ROUTES)];

/** account 布局包装层：只构造 props，渲染委托共用基础布局壳。 */
export function AppLayout(props: {
  /** 归一后 al_root（登出 / 跨端跳转前缀，见 ./bootstrap）。 */
  alRoot: string;
  /** 顶栏面包屑层级（当前页标题链）。 */
  breadcrumb: string[];
  children: ReactNode;
  /** 上层注入的自身权限点：非空才显示跨端入口；取值由调用方提供，本层不发请求。 */
  permissions?: string[];
}) {
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
      breadcrumb={props.breadcrumb}
      navItems={navItems}
      baseNavRoutes={ACCOUNT_NAV_ROUTES}
      navHeader={t('account.appTitle')}
      headerLabel={
        <span className={styles.me}>{t('account.personalCenter')}</span>
      }
      headerMenu={headerMenu}
    >
      {props.children}
    </ManageLayout>
  );
}

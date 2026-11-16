/**
 * admin 端布局包装层（docs/前端架构.md §6）：AdminService/GetMe 取管理员
 * 信息 + 404 掩护数据门（错误 / 加载态不渲染管理壳）留在包装层；NAV 项
 * （带 icons）、面包屑、右上 Dropdown 菜单（登出 + 跨端入口）、Nav 标题、
 * trigger 显示名经 props 传入 shared/app-ui/ManageLayout 基础布局壳。
 * 登出跳 `{al_root}/sso/logout`（Go 处理，前端不发 fetch、不自行清 Cookie）。
 */
import { type ReactNode } from 'react';
import { Banner, Spin, Typography } from '@douyinfe/semi-ui';
import {
  matchRoutes,
  useLocation,
  type RouteObject,
} from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { ADMIN_NAV_ROUTES, toNavItems } from '../../shared/app-ui/nav-routes';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { contextSwitchUrl } from '../../shared/urls';
import {
  ManageLayout,
  type HeaderMenu,
} from '../../shared/app-ui/ManageLayout';
import { logoutUrl } from '../bootstrap';
import { adminDisplayName, adminReturnTo, apiErrorText, getMe } from '../api';
import styles from './AdminLayout.module.less';
import {
  IconBox,
  IconConnectionPoint1,
  IconCustomize,
  IconGlobe,
  IconHome,
  IconSafe,
  IconSetting,
  IconUserList,
  IconWrench,
} from '@douyinfe/semi-icons';
import { getSiteName } from '@/shared/types/init';

const adminNavItems = toNavItems(ADMIN_NAV_ROUTES, {
  '/status': <IconHome />,
  '/providers': <IconGlobe />,
  '/users': <IconUserList />,
  '/clients/sso': <IconBox />,
  '/clients/oidc': <IconConnectionPoint1 />,
  '/settings': <IconSetting />,
  '/audit': <IconSafe />,
  '/decode': <IconWrench />,
  '/templates': <IconCustomize />,
});

/** 子路由 handle 上面包屑字段（避免 any 扩散）。 */
interface BreadcrumbHandle {
  breadcrumb?: string[];
}

/** admin 布局包装层：数据门留在此处，渲染委托共用基础布局壳。 */
export function AdminLayout(props: {
  /** 归一后 al_root（登出 / 401 跳登录的前缀，见 ./bootstrap）。 */
  alRoot: string;
  children: ReactNode;
  /** 读取子路由表的函数（延迟求值，规避路由表与布局构造期互相引用）。 */
  getRoutes: () => RouteObject[];
}) {
  // 导航与高亮取当前 hash 内路径（useLocation）；GetMe 的 401 跳登录
  // returnTo 取 HashRouter 内路径。
  const location = useLocation();
  // 非 data router 下 useMatches 不可用：按当前 location 从子路由表读命中
  // 子路由的 handle.breadcrumb；缺失时兜底 rootTitle（admin 各路由均声明）。
  const matches = matchRoutes(props.getRoutes(), location) ?? [];
  const lastMatch = matches[matches.length - 1];
  const breadcrumb = (lastMatch?.route.handle as BreadcrumbHandle | undefined)
    ?.breadcrumb ?? [t('admin.rootTitle')];
  // GetMe 改 ahooks 自动请求（§5.1）；401 由集中 onError 跳登录，
  // 404 掩护等其余错误不跳、走 error 态页面帧（toast:false 静默防双报）。
  const { data, error } = useRequest(
    getMe,
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );

  // 错误态（含 404 掩护）：不渲染管理壳（见文件头分流说明）；
  // 自绘文字换 Semi Banner（自带 role="alert"）。
  if (error !== undefined) {
    return <Banner type="danger" description={apiErrorText(error)} />;
  }
  // idle / loading：GetMe 未落地前不渲染管理壳（会话校验前置）。
  // 裸文字换 Semi Spin（居中容器为唯一布局自定义）。
  if (data === undefined) {
    return (
      <div className={styles.entryState} role="status">
        <Spin size="large" />
      </div>
    );
  }

  const displayName = adminDisplayName(data);
  // 渲染期构造菜单（CODE_GUIDE §4.6：模块级 t() 会冻结 locale）。
  const headerMenu: HeaderMenu = [
    {
      node: 'item',
      name: t('admin.logout'),
      onClick: () => window.location.replace(logoutUrl(props.alRoot)),
    },
    {
      node: 'item',
      name: t('admin.switchToAccount'),
      onClick: () =>
        window.location.replace(contextSwitchUrl(props.alRoot, 'account')),
    },
  ];
  return (
    <ManageLayout
      breadcrumb={breadcrumb}
      navItems={adminNavItems}
      baseNavRoutes={ADMIN_NAV_ROUTES}
      navHeader={getSiteName()}
      headerLabel={
        <span className={styles.me}>
          <Typography.Text className={styles.meName}>
            {displayName}
          </Typography.Text>
        </span>
      }
      headerMenu={headerMenu}
    >
      {props.children}
    </ManageLayout>
  );
}

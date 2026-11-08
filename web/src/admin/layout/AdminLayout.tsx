/**
 * admin 端应用布局（docs/前端架构.md §6 行 501/507）：侧边栏（由
 * ADMIN_NAV_ROUTES 单一来源派生）+ 顶栏（GetMe 管理员信息 +
 * LogoutLink）+ 面包屑 + Content。
 *
 * GetMe（§5.1 行 1159 管理员信息唯一来源）由布局层真调，渲染在顶栏；
 * 头像消费：avatarUrl 非空 → Semi Avatar src 渲染图片（alt 走
 * admin.meAvatarAlt）；空串 / 零值省略（§9 第 18 条兜底 → ''）→ 回退现状
 * 首字符文字头像，不新增占位图；失败分流（§6 行 523，判定纯函数
 * adminMeFailureAction 在 ./api）：
 * - 401（未携带有效会话）→ 统一跳登录 `{al_root}/sso/login`（replace：
 *   管理面不留回退占位，account/ProfilePage 同模式）；
 * - 404（会话有效但非管理员，掩护管理面存在）→ 归一化 ApiError 走统一
 *   错误处理（apiErrorText → errors.code.not_found 通用文案）显示错误态，
 *   **不跳登录**；错误 / 加载态不渲染管理壳（侧边栏 / 顶栏会泄露管理面
 *   存在，与掩护语义相悖）。
 *
 * Semi UI（§1.6 行 112/113：admin 端用 Semi UI，同 account 底座——唯一包
 * @douyinfe/semi-ui 大包命名导入，禁子路径）：Layout / Nav / Breadcrumb /
 * Avatar / Typography 均大包具名导入；入口加载 / 错误态（评审 V-6/
 * §9.3 映射）换 Semi Spin / Banner（Banner 自带 role="alert"）。
 * 登出跳 `{al_root}/sso/logout`（接口文档 §8 行 1420：Go 处理，非 SPA）。
 * 侧边栏：NAV 项与高亮均由 shared/app-ui/nav-routes.ts 的
 * ADMIN_NAV_ROUTES 派生（单一来源）；itemKey 即 hash 内路由路径，
 * selectedKeys 由 useLocation + matchActivePath 现算，点击经 router 导航。
 *
 * 样式（§1.7）：同目录同名 module.less，类名 camelCase，无内联布局样式。
 */
import { useState, type ReactNode } from "react";
import {
  Avatar,
  Banner,
  Breadcrumb,
  Dropdown,
  Layout,
  Nav,
  Spin,
  Typography,
} from "@douyinfe/semi-ui";
import { useLocation, useNavigate } from "@modern-js/runtime/router";
import { useRequest } from "ahooks";
import {
  ADMIN_NAV_ROUTES,
  matchActivePath,
  toNavItems,
} from "../../shared/app-ui/nav-routes";
import { requestOptions } from "../../shared/hooks/requestOptions";
import { t } from "../../shared/i18n";
import { logoutUrl } from "../bootstrap";
import { adminDisplayName, adminReturnTo, apiErrorText, getMe } from "../api";
import styles from "./AdminLayout.module.less";
import { SubNavProps } from "@douyinfe/semi-ui/lib/es/navigation";
import {
  IconBox,
  IconConnectionPoint1,
  IconGlobe,
  IconGlobeStroke,
  IconHome,
  IconSafe,
  IconSetting,
  IconUserList,
  IconWrench,
} from "@douyinfe/semi-icons";

const { Sider, Header, Content } = Layout;

/** 登出链接（§6 行 507 LogoutLink）：跳 `{al_root}/sso/logout`，Go 处理。 */
function LogoutLink({ alRoot }: { readonly alRoot: string }) {
  return (
    <a className={styles.logoutLink} href={logoutUrl(alRoot)}>
      {t("admin.logout")}
    </a>
  );
}

const adminNavItems = toNavItems(ADMIN_NAV_ROUTES, {
  "/status": <IconHome />,
  "/providers": <IconGlobe />,
  "/users": <IconUserList />,
  "/clients/sso": <IconBox />,
  "/clients/oidc": <IconConnectionPoint1 />,
  "/settings": <IconSetting />,
  "/audit": <IconSafe />,
  "/decode": <IconWrench />,
});

/** admin 布局壳（§6 行 507）：Sider(Nav) + Header(管理员信息 + 面包屑 + 登出) + Content。
 *  NAV 项与高亮均由 ADMIN_NAV_ROUTES 派生（单一来源，8 条字面量已删）；
 *  点击经 router 导航（HashRouter SPA 内跳，不再整页刷新）。 */
export function AdminLayout(props: {
  /** 归一后 al_root（登出 / 401 跳登录的前缀，见 ./bootstrap）。 */
  readonly alRoot: string;
  /** 顶栏面包屑层级（当前页标题链）。 */
  readonly breadcrumb: readonly string[];
  readonly children: ReactNode;
}) {
  // 窄屏侧栏折叠（评审 P0-4(c)）：用 Semi 自带响应式能力——Sider
  // breakpoint 注册 matchMedia（xs = max-width 575px，Semi 内置断点表），
  // onBreakpoint 驱动 Nav isCollapsed；不自写断点体系。初始窄屏由
  // registerMediaQuery 的 callInInit 立即回调覆盖，state 初值即正确。
  // 必须在所有提前 return 之前声明（hooks 顺序恒定）。
  const [navCollapsed, setNavCollapsed] = useState(false);
  // 导航与高亮取当前 hash 内路径（useLocation），命中经
  // matchActivePath（详情页归列表项高亮，如 /users/123 → /users）。
  const location = useLocation();
  const navigate = useNavigate();
  // GetMe 改 ahooks 自动请求（§5.1-①）；401 由集中 onError
  // 跳登录（returnTo 取 HashRouter 内路径，即上方导航用 location），
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
  return (
    <Layout className={styles.shell}>
      <Sider
        breakpoint={["xs"]}
        onBreakpoint={(_screen, matches) => setNavCollapsed(matches)}
      >
        <Nav
          className={`${styles.nav} semi-always-dark2`}
          isCollapsed={navCollapsed}
          // NAV 项由 ADMIN_NAV_ROUTES 派生（toNavItems 渲染期 t() 求值）。
          items={adminNavItems}
          // 高亮：当前 hash 内路径命中的导航 path（详情页归列表项）。
          selectedKeys={[matchActivePath(ADMIN_NAV_ROUTES, location.pathname)]}
          onClick={({ itemKey }) => {
            if (typeof itemKey === "string") {
              // itemKey 即 hash 内路由路径：SPA 内导航（HashRouter）。
              navigate(itemKey);
            }
          }}
          header={{ text: t("admin.appTitle") }}
        />
      </Sider>
      <Layout className={styles.layout}>
        <Header className={styles.header}>
          <Breadcrumb routes={[...props.breadcrumb]} />
          <Dropdown
            menu={[
              {
                node: "item",
                name: t("admin.logout"),
                onClick: () => navigate(logoutUrl(props.alRoot)),
              },
            ]}
            position="bottomRight"
          >
            <span className={styles.me}>
              <Typography.Text className={styles.meName}>
                {displayName}
              </Typography.Text>
            </span>
          </Dropdown>
        </Header>
        <Content className={styles.content}>{props.children}</Content>
      </Layout>
    </Layout>
  );
}

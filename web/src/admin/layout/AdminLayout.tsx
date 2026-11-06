/**
 * admin 端应用布局（docs/前端架构.md §6 行 501/507）：侧边栏（NAV_ITEMS，
 * 「提供方」随 ProvidersPage 长入、「用户」随 UsersPage 长入、「SSO 客户端」/
 * 「OIDC 客户端」随两页长入、「设置」随 SettingsPage 长入、「事件日志」/
 * 「监控」/「解码工具」随工具三页长入）+ 顶栏（GetMe 管理员信息 +
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
 * @douyinfe/semi-ui-19 大包命名导入，禁子路径）：Layout / Nav / Breadcrumb /
 * Avatar / Typography 均大包具名导入；
 * 登出跳 `{al_root}/sso/logout`（接口文档 §8 行 1420：Go 处理，非 SPA）。
 * 侧边栏选中 / 点击导航沿 account AppLayout 先例：itemKey 即路由
 * 路径，selectedKeys 受控于 activeKey prop，点击整页跳转。
 *
 * 样式（§1.7）：同目录同名 module.less，类名 camelCase，无内联布局样式。
 */
import { useEffect, type ReactNode } from 'react';
import { Avatar, Breadcrumb, Layout, Nav, Typography } from '@douyinfe/semi-ui-19';
import { useRequest } from '../../shared/hooks/useRequest';
import { t, type I18nKey } from '../../shared/i18n';
import { loginUrl, logoutUrl } from '../bootstrap';
import { adminDisplayName, adminMeFailureAction, apiErrorText, getMe } from '../api';
import styles from './AdminLayout.module.less';

const { Sider, Header, Content } = Layout;

/**
 * 侧边栏导航项（§6 行 515-525 页面路由清单的已交付子集）：「提供方」随
 * ProvidersPage 长入，「用户」随 UsersPage 长入；「SSO 客户端」
 * 「OIDC 客户端」随两页长入（需求 §4.6 行 257-258 两个独立模块，
 * 平铺两条目即两路由各自高亮）；「设置」随 SettingsPage 长入（需求
 * §4.6 行 259 系统配置）；「事件日志」「监控」随 AuditPage / StatusPage
 * 长入（需求 §4.6 行 260-261），「解码工具」随 DecodePage 长入
 * （§6 行 525 admin 排障工具，需求 §4.6 无对应模块条目故排最后）。
 * itemKey 即路由路径，点击整页跳转（account AppLayout 同约定）。
 * text 为 i18n 域键（admin.*），渲染期经 t() 取文案（模块级求值
 * 会冻结在默认语言，故不在常量里调 t）。
 */
const NAV_ITEMS: { itemKey: string; textKey: I18nKey }[] = [
  { itemKey: '/admin/providers', textKey: 'admin.navProviders' },
  { itemKey: '/admin/users', textKey: 'admin.navUsers' },
  { itemKey: '/admin/clients/sso', textKey: 'admin.navSsoClients' },
  { itemKey: '/admin/clients/oidc', textKey: 'admin.navOidcClients' },
  { itemKey: '/admin/settings', textKey: 'admin.navSettings' },
  { itemKey: '/admin/audit', textKey: 'admin.navAudit' },
  { itemKey: '/admin/status', textKey: 'admin.navStatus' },
  { itemKey: '/admin/decode', textKey: 'admin.navDecode' },
];

/** 登出链接（§6 行 507 LogoutLink）：跳 `{al_root}/sso/logout`，Go 处理。 */
function LogoutLink({ alRoot }: { readonly alRoot: string }) {
  return (
    <a className={styles.logoutLink} href={logoutUrl(alRoot)}>
      {t('admin.logout')}
    </a>
  );
}

/** admin 布局壳（§6 行 507）：Sider(Nav) + Header(管理员信息 + 面包屑 + 登出) + Content。 */
export function AdminLayout(props: {
  /** 归一后 al_root（登出 / 401 跳登录的前缀，见 ./bootstrap）。 */
  readonly alRoot: string;
  /** 侧边栏选中项（NAV_ITEMS 的 itemKey，同路由路径；account AppLayout 同约定）。 */
  readonly activeKey: string;
  /** 顶栏面包屑层级（当前页标题链）。 */
  readonly breadcrumb: readonly string[];
  readonly children: ReactNode;
}) {
  const { status, data, error, run } = useRequest(getMe);
  useEffect(() => {
    // §6 行 501：401 未携带有效会话 → 统一跳登录（adminMeFailureAction 分流，
    // 404 掩护等其余错误不跳，由渲染分支出错误态）。
    if (adminMeFailureAction(error) === 'redirect_login') {
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);
  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由上 effect + 渲染分支处理。
    run().catch(() => {});
  }, [run]);

  // 错误态（含 404 掩护）：朴素文案、不渲染管理壳（见文件头分流说明）。
  if (status === 'error') {
    return (
      <p role="alert" className={styles.entryError}>
        {apiErrorText(error)}
      </p>
    );
  }
  // idle / loading：GetMe 未落地前不渲染管理壳（会话校验前置）。
  if (data === undefined) {
    return (
      <p role="status" className={styles.entryLoading}>
        {t('admin.loading')}
      </p>
    );
  }

  const displayName = adminDisplayName(data);
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
              // itemKey 即路由路径：点击整页跳转（account AppLayout 同模式）。
              window.location.assign(itemKey);
            }
          }}
          header={{ text: t('admin.appTitle') }}
        />
      </Sider>
      <Layout>
        <Header className={styles.header}>
          <Breadcrumb routes={[...props.breadcrumb]} />
          <span className={styles.me}>
            {data.avatarUrl !== '' ? (
              <Avatar size="small" src={data.avatarUrl} alt={t('admin.meAvatarAlt')} />
            ) : (
              // 空串回退现状：首字符文字头像（§9 第 18 条零值兜底，无占位图）。
              <Avatar size="small">{displayName.slice(0, 1)}</Avatar>
            )}
            <Typography.Text className={styles.meName}>{displayName}</Typography.Text>
          </span>
          <LogoutLink alRoot={props.alRoot} />
        </Header>
        <Content className={styles.content}>{props.children}</Content>
      </Layout>
    </Layout>
  );
}

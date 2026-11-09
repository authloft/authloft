/**
 * 用户列表页（docs/前端架构.md §6 行 517；docs/接口文档.md §5.4 行 1245-1255；
 * docs/需求.md §4.6 行 256）——/admin/users。
 *
 * **admin 首个 DataTable 消费方**（§3.3 行 348：分页 / 筛选 / 行内开关经
 * shared/app-ui/DataTable，§1.7 服务端分页受控 TableQueryState）：
 * - 分页 / 排序 / 筛选：DataTable onQueryChange → setQuery → 重新取数；
 * - userStatus 筛选（§5.4 行 1249 筛选入参 {q, userStatus}）：状态列
 *   filters 下拉，wire 值映射见 buildListUsersRequest；
 * - 行内开关（禁用 / 启用，§5.4 行 1251 UpdateUserStatus）：DataTable
 *   switchColumn——onToggle reject 只回滚（runInlineToggle），**错误展示
 *   归消费方**：本页 catch 后 Toast 提示再 rethrow 触发回滚（ProvidersPage
 *   StatusSwitch 同口径）。
 *
 * q 搜索：后端 q 匹配 username / nickname / email / phone 四列，
 * draft / applied 两态——生效即回第 1 页（§1.7 服务端分页语义）。
 * 重置密码（§5.4 行 1252）：Modal 输入新密码 → ResetUserPassword → 仅成功
 * （OkResponse），新密码由管理员转交该用户；解除登录限制（§5.4 行 1254）：
 * UnlockUser，Popconfirm 确认。用户名 → /admin#/users/{id} 详情入口
 * （SPA 内 Link）。
 *
 * 401 统一跳登录（§6 行 501，ProvidersPage 同模式）；404 掩护等其余错误走
 * 页面错误态。组件壳 import Semi 后不可在 node 测试（工具链 blocker），
 * 可测逻辑全部收口在 ./api（请求构造 / 展示纯函数）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Empty,
  Input,
  Modal,
  Popconfirm,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { Link, useLocation } from '@modern-js/runtime/router';
import {
  DataTable,
  type DataTableColumn,
  type DataTableSwitchColumn,
} from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import { PasswordStrengthMeter } from '../../shared/components/PasswordStrengthMeter';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { AdminUser } from '../../gen/proto/api/admin/v1/user_pb';
import {
  adminReturnTo,
  USER_STATUS_DATA_INDEX,
  USER_STATUS_DISABLED,
  USER_STATUS_ENABLED,
  USER_STATUS_FILTERS,
  apiErrorText,
  buildListUsersRequest,
  buildResetUserPasswordRequest,
  buildUnlockUserRequest,
  buildUpdateUserStatusRequest,
  formatUnixTime,
  isUnauthenticatedError,
  listUsers,
  resetUserPassword,
  unlockUser,
  updateUserStatus,
  userStatusLabel,
} from '../api';
import { userDetailPath } from '../paths';
import styles from './UsersPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 行键（AdminUser.id int64 → 十进制字符串，§1.12）。 */
function userRowKey(row: AdminUser): string {
  return row.id.toString();
}

/** 用户列表页：搜索 + DataTable（状态筛选 / 行内禁用启停 / 排序 / 分页）+ 行内操作。 */
export function UsersPage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录收敛集中 onError，本页不再消费）。 */
  alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序 / 筛选全部由 DataTable 上报更新。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  // 搜索词两态：draft（输入框即时值）/ applied（已生效取数词）；生效即回第 1 页。
  const [qDraft, setQDraft] = useState('');
  const [appliedQ, setAppliedQ] = useState('');
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 列表取数改 ahooks 自动请求 + refreshDeps（query / appliedQ 变更
  // 重取，同原 effect 依赖）；401 由集中 onError 跳登录，其余错误走页面
  // 错误帧（toast:false 静默防双报）。
  const { data, error, loading } = useRequest(
    () => listUsers(buildListUsersRequest(appliedQ, query)),
    {
      refreshDeps: [appliedQ, query],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  // 写操作成功 / 失败反馈统一走 Semi Toast（原就地 notice/actionError
  // 文字已随 Semi 回归移除）；Modal 内表单错误（resetError）保持行内。
  // 重置密码弹窗（§5.4 行 1252）：resetTarget 即当前目标行；空即关闭。
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [resetConfirm, setResetConfirm] = useState('');
  const [resetMismatch, setResetMismatch] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);
  const [resetSubmitting, setResetSubmitting] = useState(false);

  /** 搜索生效：applied 词落地 + 回第 1 页（§1.7：筛选 / 搜索变化重置页码）。 */
  function applySearch(): void {
    setAppliedQ(qDraft.trim());
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /**
   * 行内禁用 / 启停（§5.4 行 1251）：失败 → Toast 提示后 rethrow，DataTable
   * 内部 runInlineToggle 捕获即回滚（错误展示归消费方，DataTable 契约）。
   */
  async function handleStatusToggle(
    row: AdminUser,
    next: boolean,
  ): Promise<void> {
    try {
      await updateUserStatus(buildUpdateUserStatusRequest(row.id, next));
    } catch (toggleError) {
      Toast.error(apiErrorText(toggleError));
      throw toggleError;
    }
  }

  /**
   * 解除登录限制（§5.4 行 1254 UnlockUser）：Popconfirm 确认后调用。
   * P0-2 防重：onConfirm 返回本 Promise——Semi Popconfirm 原生机制
   * （popconfirmFoundation.handleConfirm）在途期间确认钮 loading + 禁用
   * （连点不再触发），落地才关框；失败反馈仍走 Toast（catch 不抛出）。
   */
  async function handleUnlock(row: AdminUser): Promise<void> {
    try {
      await unlockUser(buildUnlockUserRequest(row.id));
      Toast.success(t('admin.unlockSuccess', { username: row.username }));
    } catch (unlockError) {
      Toast.error(apiErrorText(unlockError));
    }
  }

  /** 打开重置密码弹窗：清空上次输入 / 错误。 */
  function openReset(row: AdminUser): void {
    setResetTarget(row);
    setResetPassword('');
    setResetConfirm('');
    setResetMismatch(false);
    setResetError(null);
  }

  /**
   * 关闭重置弹窗（编辑未保存保护）：已输入新密码（dirty）时
   * 经 Semi Modal.confirm 二次确认；未输入（无改动可丢）直接关闭。
   */
  function closeReset(): void {
    if (resetPassword !== '' || resetConfirm !== '') {
      Modal.confirm({
        title: t('admin.unsavedChangesTitle'),
        content: t('admin.unsavedChangesContent'),
        onOk: () => setResetTarget(null),
      });
      return;
    }
    setResetTarget(null);
  }

  /** 提交重置（§5.4 行 1252）：确认密码不一致行内报错不发请求；password_weak 等策略错误由服务端权威判定展示。 */
  async function submitReset(): Promise<void> {
    const target = resetTarget;
    if (target === null || resetPassword === '' || resetSubmitting) {
      return;
    }
    if (resetPassword !== resetConfirm) {
      setResetMismatch(true);
      return;
    }
    setResetMismatch(false);
    setResetSubmitting(true);
    try {
      await resetUserPassword(
        buildResetUserPasswordRequest(target.id, resetPassword),
      );
      setResetTarget(null);
      Toast.success(
        t('admin.resetPasswordSuccess', { username: target.username }),
      );
    } catch (resetReqError) {
      setResetError(apiErrorText(resetReqError));
    } finally {
      setResetSubmitting(false);
    }
  }

  // 列口径（§6 行 517 用户列表）：用户名（详情链接）/ 昵称 / 手机号 / 邮箱 /
  // 状态（筛选下拉 + 文案）/ 最后登录 / 创建时间 / 操作；可排序列 dataIndex
  // 即 wire 字段名（§1.7 sort 前端限定，见 ./api USER_STATUS_DATA_INDEX 注）。
  const columns: DataTableColumn<AdminUser>[] = [
    {
      dataIndex: 'username',
      title: t('admin.usernameLabel'),
      render: (_text: unknown, row: AdminUser) => (
        // 去自绘主色装饰；改 SPA 内 Link（userDetailPath 构造，
        // 取代模板字符串直拼 /admin/users/{id}）。
        <Link to={userDetailPath(row.id)}>{row.username}</Link>
      ),
    },
    {
      dataIndex: 'nickname',
      title: t('admin.nicknameLabel'),
      render: (_text: unknown, row: AdminUser) => row.nickname || EMPTY_TEXT,
    },
    {
      dataIndex: 'phone',
      title: t('admin.phoneLabel'),
      render: (_text: unknown, row: AdminUser) => row.phone || EMPTY_TEXT,
    },
    {
      dataIndex: 'email',
      title: t('admin.emailLabel'),
      render: (_text: unknown, row: AdminUser) => row.email || EMPTY_TEXT,
    },
    {
      dataIndex: USER_STATUS_DATA_INDEX,
      title: t('admin.statusLabel'),
      // USER_STATUS_FILTERS 存 textKey，渲染期 t() 取当前语言。
      filters: USER_STATUS_FILTERS.map(({ value, textKey }) => ({
        value,
        text: t(textKey),
      })),
      render: (_text: unknown, row: AdminUser) =>
        userStatusLabel(row.userStatus),
    },
    {
      dataIndex: 'last_login_at',
      title: t('admin.lastLoginLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: AdminUser) =>
        formatUnixTime(row.lastLoginAt),
    },
    {
      dataIndex: 'created_at',
      title: t('admin.createdAtLabel'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: AdminUser) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'actions',
      title: t('admin.actionsLabel'),
      render: (_text: unknown, row: AdminUser) => (
        <span className={styles.actions}>
          <Button size="small" onClick={() => openReset(row)}>
            {t('admin.resetPasswordAction')}
          </Button>
          <Popconfirm
            title={t('admin.unlockConfirm', { username: row.username })}
            onConfirm={() => handleUnlock(row)}
          >
            <Button size="small">{t('admin.unlockAction')}</Button>
          </Popconfirm>
        </span>
      ),
    },
  ];

  // 行内开关列（§5.4 行 1251 禁用 / 启用）：DataTable 追加在列尾，乐观更新 +
  // 失败回滚由其内部 runInlineToggle 编排，错误展示归本页 onToggle。
  const switchColumn: DataTableSwitchColumn<AdminUser> = {
    dataIndex: USER_STATUS_DATA_INDEX,
    title: t('admin.userStatusToggleColumn'),
    width: 96,
    isOn: (row) => row.userStatus === USER_STATUS_ENABLED,
    toggleRow: (row, next) => ({
      ...row,
      userStatus: next ? USER_STATUS_ENABLED : USER_STATUS_DISABLED,
    }),
    onToggle: handleStatusToggle,
  };

  // 列表错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.usersLoadFailed')}
      />
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {t('admin.navUsers')}
      </Typography.Title>
      <div className={styles.toolbar}>
        <Input
          className={styles.searchInput}
          value={qDraft}
          onChange={(value) => setQDraft(value)}
          onEnterPress={applySearch}
          placeholder={t('admin.userSearchPlaceholder')}
          aria-label={t('admin.userSearchAriaLabel')}
        />
        <Button theme="solid" onClick={applySearch}>
          {t('admin.searchAction')}
        </Button>
      </div>
      <DataTable<AdminUser>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={userRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={loading}
        // 空态裸文字换 Semi Empty（默认插图 + 文案）；success 空态
        // 判定走 deriveRequestStatus 派生（§5.3，禁手写三条件）。
        empty={
          deriveRequestStatus(loading, error, data) === 'success' ? (
            <Empty description={t('admin.noUsers')} />
          ) : undefined
        }
        switchColumn={switchColumn}
      />
      <Modal
        title={
          resetTarget !== null
            ? t('admin.resetPasswordTitle', { username: resetTarget.username })
            : t('admin.resetPasswordAction')
        }
        visible={resetTarget !== null}
        onCancel={closeReset}
        maskClosable={false}
        footer={null}
      >
        <div className={styles.resetBody}>
          <p className={styles.resetHint}>{t('admin.resetPasswordHint')}</p>
          {/* Semi Input mode=password 自带显隐 eye；强度提示用 shared
              PasswordStrengthMeter（规则与接口文档 §5.6 默认策略同源，
              password_weak 服务端权威判定）。 */}
          <Input
            mode="password"
            value={resetPassword}
            onChange={(value) => {
              setResetPassword(value);
              setResetMismatch(false);
            }}
            aria-label={t('admin.newPasswordLabel')}
            placeholder={t('admin.newPasswordPlaceholder')}
            autoComplete="new-password"
          />
          <PasswordStrengthMeter
            password={resetPassword}
            username={resetTarget?.username}
            email={resetTarget?.email}
          />
          <Input
            mode="password"
            value={resetConfirm}
            onChange={(value) => {
              setResetConfirm(value);
              setResetMismatch(false);
            }}
            aria-label={t('admin.confirmPasswordLabel')}
            placeholder={t('admin.confirmPasswordPlaceholder')}
            autoComplete="new-password"
          />
          {resetMismatch ? (
            <p role="alert" className={styles.actionError}>
              {t('admin.passwordMismatchError')}
            </p>
          ) : null}
          {resetError !== null ? (
            <p role="alert" className={styles.actionError}>
              {resetError}
            </p>
          ) : null}
          <div className={styles.resetFooter}>
            <Button onClick={closeReset} disabled={resetSubmitting}>
              {t('admin.cancelAction')}
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitReset();
              }}
              disabled={
                resetSubmitting || resetPassword === '' || resetConfirm === ''
              }
              loading={resetSubmitting}
            >
              {t('admin.confirmResetAction')}
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}

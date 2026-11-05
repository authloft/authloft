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
 *   归消费方**：本页 catch 后就地提示再 rethrow 触发回滚（ProvidersPage
 *   StatusSwitch 同口径）。
 *
 * q 搜索：后端 q 匹配 username / nickname / email / phone 四列，
 * draft / applied 两态——生效即回第 1 页（§1.7 服务端分页语义）。
 * 重置密码（§5.4 行 1252）：Modal 输入新密码 → ResetUserPassword → 仅成功
 * （OkResponse），新密码由管理员转交该用户；解除登录限制（§5.4 行 1254）：
 * UnlockUser，Popconfirm 确认。用户名 → /admin/users/{id} 详情入口。
 *
 * 401 统一跳登录（§6 行 501，ProvidersPage 同模式）；404 掩护等其余错误走
 * 页面错误态。组件壳 import Semi 后不可在 node 测试（工具链 blocker），
 * 可测逻辑全部收口在 ./api（请求构造 / 展示纯函数）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Input, Modal, Popconfirm, Typography } from '@douyinfe/semi-ui-19';
import { DataTable, type DataTableColumn, type DataTableSwitchColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { AdminUser } from '../../gen/proto/api/admin/v1/user_pb';
import {
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
import { loginUrl } from '../bootstrap';
import styles from './UsersPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 行键（AdminUser.id int64 → 十进制字符串，§1.12）。 */
function userRowKey(row: AdminUser): string {
  return row.id.toString();
}

/** 用户列表页：搜索 + DataTable（状态筛选 / 行内禁用启停 / 排序 / 分页）+ 行内操作。 */
export function UsersPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序 / 筛选全部由 DataTable 上报更新。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  // 搜索词两态：draft（输入框即时值）/ applied（已生效取数词）；生效即回第 1 页。
  const [qDraft, setQDraft] = useState('');
  const [appliedQ, setAppliedQ] = useState('');
  const { status, data, error, run } = useRequest(listUsers);
  // 写操作反馈就地展示（行内开关 / 解锁 / 重置的失败与成功提示，消费方口径）。
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // 重置密码弹窗（§5.4 行 1252）：resetTarget 即当前目标行；空即关闭。
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [resetError, setResetError] = useState<string | null>(null);
  const [resetSubmitting, setResetSubmitting] = useState(false);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildListUsersRequest(appliedQ, query)).catch(() => {});
  }, [run, query, appliedQ]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  /** 搜索生效：applied 词落地 + 回第 1 页（§1.7：筛选 / 搜索变化重置页码）。 */
  function applySearch(): void {
    setAppliedQ(qDraft.trim());
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /**
   * 行内禁用 / 启停（§5.4 行 1251）：失败 → 就地提示后 rethrow，DataTable
   * 内部 runInlineToggle 捕获即回滚（错误展示归消费方，DataTable 契约）。
   */
  async function handleStatusToggle(row: AdminUser, next: boolean): Promise<void> {
    try {
      await updateUserStatus(buildUpdateUserStatusRequest(row.id, next));
    } catch (toggleError) {
      setActionError(apiErrorText(toggleError));
      throw toggleError;
    }
  }

  /** 解除登录限制（§5.4 行 1254 UnlockUser）：Popconfirm 确认后调用。 */
  async function handleUnlock(row: AdminUser): Promise<void> {
    try {
      await unlockUser(buildUnlockUserRequest(row.id));
      setNotice(`已解除「${row.username}」的登录限制`);
    } catch (unlockError) {
      setActionError(apiErrorText(unlockError));
    }
  }

  /** 打开重置密码弹窗：清空上次输入 / 错误。 */
  function openReset(row: AdminUser): void {
    setResetTarget(row);
    setResetPassword('');
    setResetError(null);
  }

  /** 提交重置（§5.4 行 1252）：password_weak 等策略错误由服务端权威判定展示。 */
  async function submitReset(): Promise<void> {
    const target = resetTarget;
    if (target === null || resetPassword === '' || resetSubmitting) {
      return;
    }
    setResetSubmitting(true);
    try {
      await resetUserPassword(buildResetUserPasswordRequest(target.id, resetPassword));
      setResetTarget(null);
      setNotice(`已重置「${target.username}」的密码，请将新密码转交该用户`);
    } catch (resetReqError) {
      setResetError(apiErrorText(resetReqError));
    } finally {
      setResetSubmitting(false);
    }
  }

  // 列口径（§6 行 517 用户列表）：用户名（详情链接）/ 昵称 / 手机号 / 邮箱 /
  // 状态（筛选下拉 + 文案）/ 最后登录 / 创建时间 / 操作；可排序列 dataIndex
  // 即 wire 字段名（§1.7 sort 前端限定，见 ./api USER_STATUS_DATA_INDEX 注）。
  const columns: readonly DataTableColumn<AdminUser>[] = [
    {
      dataIndex: 'username',
      title: '用户名',
      render: (_text: unknown, row: AdminUser) => (
        <a className={styles.detailLink} href={`/admin/users/${row.id}`}>
          {row.username}
        </a>
      ),
    },
    {
      dataIndex: 'nickname',
      title: '昵称',
      render: (_text: unknown, row: AdminUser) => row.nickname || EMPTY_TEXT,
    },
    {
      dataIndex: 'phone',
      title: '手机号',
      render: (_text: unknown, row: AdminUser) => row.phone || EMPTY_TEXT,
    },
    {
      dataIndex: 'email',
      title: '邮箱',
      render: (_text: unknown, row: AdminUser) => row.email || EMPTY_TEXT,
    },
    {
      dataIndex: USER_STATUS_DATA_INDEX,
      title: '状态',
      // USER_STATUS_FILTERS 存 textKey，渲染期 t() 取当前语言。
      filters: USER_STATUS_FILTERS.map(({ value, textKey }) => ({
        value,
        text: t(textKey),
      })),
      render: (_text: unknown, row: AdminUser) => userStatusLabel(row.userStatus),
    },
    {
      dataIndex: 'last_login_at',
      title: '最后登录',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: AdminUser) => formatUnixTime(row.lastLoginAt),
    },
    {
      dataIndex: 'created_at',
      title: '创建时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: AdminUser) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'actions',
      title: '操作',
      render: (_text: unknown, row: AdminUser) => (
        <span className={styles.actions}>
          <Button size="small" onClick={() => openReset(row)}>
            重置密码
          </Button>
          <Popconfirm
            title={`确定解除「${row.username}」的登录限制？`}
            onConfirm={() => {
              void handleUnlock(row);
            }}
          >
            <Button size="small">解除登录限制</Button>
          </Popconfirm>
        </span>
      ),
    },
  ];

  // 行内开关列（§5.4 行 1251 禁用 / 启用）：DataTable 追加在列尾，乐观更新 +
  // 失败回滚由其内部 runInlineToggle 编排，错误展示归本页 onToggle。
  const switchColumn: DataTableSwitchColumn<AdminUser> = {
    dataIndex: USER_STATUS_DATA_INDEX,
    title: '禁用/启用',
    width: 96,
    isOn: (row) => row.userStatus === USER_STATUS_ENABLED,
    toggleRow: (row, next) => ({
      ...row,
      userStatus: next ? USER_STATUS_ENABLED : USER_STATUS_DISABLED,
    }),
    onToggle: handleStatusToggle,
  };

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        用户列表加载失败，请刷新重试
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>用户</Typography.Title>
      <div className={styles.toolbar}>
        <Input
          className={styles.searchInput}
          value={qDraft}
          onChange={(value) => setQDraft(value)}
          onEnterPress={applySearch}
          placeholder="搜索用户名 / 昵称 / 手机号 / 邮箱"
          aria-label="搜索用户"
        />
        <Button theme="solid" onClick={applySearch}>
          搜索
        </Button>
      </div>
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}
      {notice !== null ? (
        <p role="status" className={styles.notice}>
          {notice}
        </p>
      ) : null}
      <DataTable<AdminUser>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={userRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? '暂无用户' : undefined}
        switchColumn={switchColumn}
      />
      <Modal
        title={resetTarget !== null ? `重置「${resetTarget.username}」的密码` : '重置密码'}
        visible={resetTarget !== null}
        onCancel={() => setResetTarget(null)}
        footer={null}
      >
        <div className={styles.resetBody}>
          <p className={styles.resetHint}>
            新密码需满足系统密码策略，重置成功后原会话全部失效，请将新密码转交该用户。
          </p>
          <Input
            mode="password"
            value={resetPassword}
            onChange={(value) => setResetPassword(value)}
            aria-label="新密码"
            placeholder="输入新密码"
            autoComplete="new-password"
          />
          {resetError !== null ? (
            <p role="alert" className={styles.actionError}>
              {resetError}
            </p>
          ) : null}
          <div className={styles.resetFooter}>
            <Button onClick={() => setResetTarget(null)} disabled={resetSubmitting}>
              取消
            </Button>
            <Button
              theme="solid"
              onClick={() => {
                void submitReset();
              }}
              disabled={resetSubmitting || resetPassword === ''}
              loading={resetSubmitting}
            >
              确认重置
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}

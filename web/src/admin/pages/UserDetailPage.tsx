/**
 * 用户详情页（docs/前端架构.md §6 行 518；docs/接口文档.md §5.4 行 1250/1253/
 * 1255；docs/需求.md §4.6 行 256）——/admin/users/{id}。
 *
 * GetUser（§5.4 行 1250：{id} 详情，含凭证概览 / 三方绑定 / MFA 状态）真调
 * （后端已实装）；解绑第三方（§5.4 行 1253 UnbindUserThirdparty
 * {id, providerKey}）Popconfirm 确认 → 成功后重取详情；Union 行不可单独解绑
 * 由服务端兜底（invalid_request）——admin 绑定视图 UserThirdpartyBinding 无
 * type 标记（§5.4 未定义），前端不预判置灰，失败文案就地展示。
 *
 * 登录日志（§5.4 行 1255 GetUserEvents {id} + 分页 §1.7）：DataTable 消费
 * （分页 / 排序受控 TableQueryState，初始 created_at desc——EventLogTable
 * 同构；列口径沿需求 §4.2 行 152：时间 / 事件 / 方式 / IP / 设备 UA）。
 *
 * 401 统一跳登录（§6 行 501，UsersPage 同模式）；404 掩护等其余错误走页面
 * 错误态。组件壳 import Semi 后不可在 node 测试（工具链 blocker），
 * 可测逻辑全部收口在 ./api（boundMfaFactors / credentialKindLabel /
 * userStatusLabel / formatUnixTime / 请求构造）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 子路径 import（同 AdminLayout 口径：避免全量入口，测试链 / 产物见其注释）。
import Button from '@douyinfe/semi-ui/lib/es/button';
import Popconfirm from '@douyinfe/semi-ui/lib/es/popconfirm';
import Typography from '@douyinfe/semi-ui/lib/es/typography';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { toCount } from '../../shared/utils/int';
import type { EventItem } from '../../gen/proto/api/admin/v1/events_pb';
import {
  apiErrorText,
  boundMfaFactors,
  buildGetUserEventsRequest,
  buildGetUserRequest,
  buildUnbindUserThirdpartyRequest,
  credentialKindLabel,
  formatUnixTime,
  getUser,
  getUserEvents,
  isUnauthenticatedError,
  unbindUserThirdparty,
  userStatusLabel,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './UserDetailPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 '' / 0n）。 */
const EMPTY_TEXT = '—';

/** 登录日志排序字段（§1.7 行 277 示例 created_at；sort 值域前端自律）。 */
const EVENTS_SORT_FIELD = 'created_at';

/** 详情页登录日志初始查询：第 1 页、每页 20、按时间倒序（EventLogTable 同构）。 */
const INITIAL_EVENTS_QUERY: TableQueryState = {
  ...initialTableQuery(),
  sort: EVENTS_SORT_FIELD,
  order: 'desc',
};

/** 登录日志列（需求 §4.2 行 152：时间 / 事件 / 方式 / IP / 设备 UA）。 */
const EVENTS_COLUMNS: readonly DataTableColumn<EventItem>[] = [
  {
    dataIndex: EVENTS_SORT_FIELD,
    title: '时间',
    width: 170,
    sorter: true,
    render: (_text: unknown, row: EventItem) => formatUnixTime(row.createdAt),
  },
  {
    dataIndex: 'event',
    title: '事件',
    width: 160,
    render: (_text: unknown, row: EventItem) => row.event || EMPTY_TEXT,
  },
  {
    dataIndex: 'amr',
    title: '方式',
    width: 140,
    render: (_text: unknown, row: EventItem) => row.amr || EMPTY_TEXT,
  },
  {
    dataIndex: 'ip',
    title: 'IP',
    width: 160,
    render: (_text: unknown, row: EventItem) => row.ip || EMPTY_TEXT,
  },
  {
    dataIndex: 'ua',
    title: '设备（UA）',
    render: (_text: unknown, row: EventItem) => row.ua || EMPTY_TEXT,
  },
];

/** 登录日志行键（EventItem.id）。 */
function eventRowKey(row: EventItem): string {
  return row.id.toString();
}

/** 用户详情页：基本信息 + 凭证概览 + MFA 状态 + 三方绑定（解绑）+ 登录日志。 */
export function UserDetailPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
  /** 目标用户 ID（路由 \d+ 段解析，见 ./routes）。 */
  readonly userId: bigint;
}): ReactNode {
  const { status, data, error, run } = useRequest(getUser);
  const [eventsQuery, setEventsQuery] = useState<TableQueryState>(INITIAL_EVENTS_QUERY);
  const { status: eventsStatus, data: eventsData, error: eventsError, run: runEvents } =
    useRequest(getUserEvents);
  // 解绑失败文案就地展示（成功经详情重取自然刷新）。
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildGetUserRequest(props.userId)).catch(() => {});
  }, [run, props.userId]);

  useEffect(() => {
    runEvents(buildGetUserEventsRequest(props.userId, eventsQuery)).catch(() => {});
  }, [runEvents, props.userId, eventsQuery]);

  useEffect(() => {
    const authError = isUnauthenticatedError(error) || isUnauthenticatedError(eventsError);
    if (authError) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, eventsError, props.alRoot]);

  /**
   * 解绑第三方（§5.4 行 1253）：Union 行不可单独解绑由服务端兜底
   * （invalid_request → 文案就地展示）；成功后重取详情刷新绑定列表。
   */
  async function handleUnbind(providerKey: string): Promise<void> {
    try {
      await unbindUserThirdparty(
        buildUnbindUserThirdpartyRequest(props.userId, providerKey),
      );
      await run(buildGetUserRequest(props.userId));
    } catch (unbindError) {
      setActionError(apiErrorText(unbindError));
    }
  }

  // 详情错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        用户详情加载失败，请刷新重试
      </p>
    );
  }
  if (data === undefined) {
    return (
      <p role="status" className={styles.loading}>
        加载中…
      </p>
    );
  }

  const user = data.user;
  const mfaBound = boundMfaFactors(data.mfa);

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>
        用户详情{user !== undefined ? `：${user.username}` : ''}
      </Typography.Title>
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>基本信息</h4>
        {user === undefined ? (
          // user 缺省（protojson 零值省略）：后端不该下发的防御分支。
          <p className={styles.muted}>无用户数据</p>
        ) : (
          <dl className={styles.infoGrid}>
            <dt>用户名</dt>
            <dd>{user.username || EMPTY_TEXT}</dd>
            <dt>昵称</dt>
            <dd>{user.nickname || EMPTY_TEXT}</dd>
            <dt>手机号</dt>
            <dd>
              {user.phone || EMPTY_TEXT}
              {user.phone !== '' && user.phoneVerified === BigInt(1) ? '（已验证）' : ''}
            </dd>
            <dt>邮箱</dt>
            <dd>
              {user.email || EMPTY_TEXT}
              {user.email !== '' && user.emailVerified === BigInt(1) ? '（已验证）' : ''}
            </dd>
            <dt>状态</dt>
            <dd>{userStatusLabel(user.userStatus)}</dd>
            <dt>强制两步验证</dt>
            <dd>{user.mfaRequired === BigInt(1) ? '是' : '否'}</dd>
            <dt>最后登录</dt>
            <dd>{formatUnixTime(user.lastLoginAt)}</dd>
            <dt>创建时间</dt>
            <dd>{formatUnixTime(user.createdAt)}</dd>
          </dl>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>MFA 状态</h4>
        {user !== undefined && user.mfaRequired === BigInt(1) ? (
          <p className={styles.mfaRequired}>系统强制启用两步验证</p>
        ) : null}
        <p className={styles.muted}>
          {mfaBound.length > 0 ? `已绑定：${mfaBound.join('、')}` : '未绑定任何二次因子'}
        </p>
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>凭证概览</h4>
        {data.credentials.length === 0 ? (
          <p className={styles.muted}>暂无凭证</p>
        ) : (
          <ul className={styles.list}>
            {data.credentials.map((credential) => (
              <li key={credential.id.toString()} className={styles.listRow}>
                <span className={styles.listMain}>
                  {credentialKindLabel(credential.kind)}
                  {credential.label !== '' ? `（${credential.label}）` : ''}
                </span>
                <span className={credential.isEnabled ? styles.enabled : styles.disabled}>
                  {credential.isEnabled ? '启用' : '禁用'}
                </span>
                <span className={styles.listMeta}>
                  绑定于 {formatUnixTime(credential.createdAt)}
                  {credential.lastUsedAt > BigInt(0)
                    ? ` · 最近使用 ${formatUnixTime(credential.lastUsedAt)}`
                    : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>三方绑定</h4>
        {data.bindings.length === 0 ? (
          <p className={styles.muted}>暂无第三方绑定</p>
        ) : (
          <ul className={styles.list}>
            {data.bindings.map((binding) => (
              <li key={binding.id.toString()} className={styles.listRow}>
                <span className={styles.listMain}>
                  {binding.providerKey}
                  {binding.nickname !== '' ? `（${binding.nickname}）` : ''}
                </span>
                <span className={styles.listMeta}>
                  OpenID {binding.openId || EMPTY_TEXT} · 绑定于{' '}
                  {formatUnixTime(binding.createdAt)}
                </span>
                <Popconfirm
                  title={`确定解绑「${binding.providerKey}」？解绑后无法再用它登录。`}
                  onConfirm={() => {
                    void handleUnbind(binding.providerKey);
                  }}
                >
                  <Button size="small" type="danger">
                    解绑
                  </Button>
                </Popconfirm>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>登录日志</h4>
        {eventsStatus === 'error' && !isUnauthenticatedError(eventsError) ? (
          <p role="alert" className={styles.actionError}>
            登录日志加载失败，请刷新重试
          </p>
        ) : (
          <DataTable<EventItem>
            columns={EVENTS_COLUMNS}
            rows={eventsData?.items ?? []}
            rowKey={eventRowKey}
            total={eventsData !== undefined ? toCount(eventsData.total) : 0}
            query={eventsQuery}
            onQueryChange={setEventsQuery}
            loading={eventsStatus === 'loading'}
            empty={eventsStatus === 'success' ? '暂无登录记录' : undefined}
          />
        )}
      </section>
    </section>
  );
}

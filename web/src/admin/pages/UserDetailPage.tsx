/**
 * 用户详情页（docs/前端架构.md §6 行 518；docs/接口文档.md §5.4 行 1250/1253/
 * 1255；docs/需求.md §4.6 行 256）——/admin/users/{id}。
 *
 * GetUser（§5.4 行 1250：{id} 详情，含凭证概览 / 三方绑定 / MFA 状态）真调
 * （后端已实装）；解绑第三方（§5.4 行 1253 UnbindUserThirdparty
 * {id, providerKey}）Popconfirm 确认 → 成功后重取详情；Union 行不可单独解绑
 * 由服务端兜底（invalid_request）——admin 绑定视图 UserThirdpartyBinding 无
 * type 标记（§5.4 未定义），前端不预判置灰，失败经 Semi Toast 展示
 * （原就地 actionError 文字已移除）；成功反馈接 Toast.success
 * （admin.unbindSuccess，P1-6 统一成功通道）。
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
import { useState, type ReactNode } from 'react';
import { Banner, Button, Popconfirm, Spin, Tag, Toast, Typography } from '@douyinfe/semi-ui-19';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { EventItem } from '../../gen/proto/api/admin/v1/events_pb';
import {
  adminReturnTo,
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

/**
 * 登录日志列（需求 §4.2 行 152：时间 / 事件 / 方式 / IP / 设备 UA）。
 * 渲染期函数求值，模块级 t() 会冻结在默认语言。
 */
function getEventsColumns(): readonly DataTableColumn<EventItem>[] {
  return [
    {
      dataIndex: EVENTS_SORT_FIELD,
      title: t('admin.timeColumn'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: EventItem) => formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'event',
      title: t('admin.eventColumn'),
      width: 160,
      render: (_text: unknown, row: EventItem) => row.event || EMPTY_TEXT,
    },
    {
      dataIndex: 'amr',
      title: t('admin.methodColumn'),
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
      title: t('admin.deviceUaColumn'),
      render: (_text: unknown, row: EventItem) => row.ua || EMPTY_TEXT,
    },
  ];
}

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
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 详情 / 登录日志双请求改 ahooks 自动请求 + refreshDeps；401 由
  // 集中 onError 跳登录，其余错误走错误帧（toast:false 静默防双报）。
  // refreshAsync 供解绑成功后串行重取（runAsync 正当场景①：await 结果串行
  // ——须待详情重取完成再报成功，沿旧 await run 语义）。
  const { data, error, refreshAsync } = useRequest(
    () => getUser(buildGetUserRequest(props.userId)),
    {
      refreshDeps: [props.userId],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const [eventsQuery, setEventsQuery] = useState<TableQueryState>(INITIAL_EVENTS_QUERY);
  const {
    data: eventsData,
    error: eventsError,
    loading: eventsLoading,
  } = useRequest(
    () => getUserEvents(buildGetUserEventsRequest(props.userId, eventsQuery)),
    {
      refreshDeps: [props.userId, eventsQuery],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  /**
   * 解绑第三方（§5.4 行 1253）：Union 行不可单独解绑由服务端兜底
   * （invalid_request → 失败经 Toast 展示）；成功后重取详情刷新
   * 绑定列表 + 成功反馈（P1-6 统一成功通道，新增 admin.unbindSuccess）。
   * P0-3 防重：onConfirm 返回本 Promise——Semi Popconfirm 原生机制
   * 在途期间确认钮 loading + 禁用（连点不再触发），落地才关框。
   */
  async function handleUnbind(providerKey: string): Promise<void> {
    try {
      await unbindUserThirdparty(
        buildUnbindUserThirdpartyRequest(props.userId, providerKey),
      );
      await refreshAsync();
      Toast.success(t('admin.unbindSuccess', { providerKey }));
    } catch (unbindError) {
      Toast.error(apiErrorText(unbindError));
    }
  }

  // 页级错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner type="danger" fullMode={false} description={t('admin.userDetailLoadFailed')} />
    );
  }
  // 裸文字换 Semi Spin。
  if (data === undefined) {
    return (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  }

  const user = data.user;
  const mfaBound = boundMfaFactors(data.mfa);

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>
        {t('admin.userDetailTitle')}
        {user !== undefined ? `：${user.username}` : ''}
      </Typography.Title>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>{t('admin.basicInfoSection')}</h4>
        {user === undefined ? (
          // user 缺省（protojson 零值省略）：后端不该下发的防御分支。
          <p className={styles.muted}>{t('admin.noUserData')}</p>
        ) : (
          <dl className={styles.infoGrid}>
            <dt>{t('admin.usernameLabel')}</dt>
            <dd>{user.username || EMPTY_TEXT}</dd>
            <dt>{t('admin.nicknameLabel')}</dt>
            <dd>{user.nickname || EMPTY_TEXT}</dd>
            <dt>{t('admin.phoneLabel')}</dt>
            <dd>
              {user.phone || EMPTY_TEXT}
              {user.phone !== '' && user.phoneVerified === BigInt(1)
                ? t('admin.verifiedTag')
                : ''}
            </dd>
            <dt>{t('admin.emailLabel')}</dt>
            <dd>
              {user.email || EMPTY_TEXT}
              {user.email !== '' && user.emailVerified === BigInt(1)
                ? t('admin.verifiedTag')
                : ''}
            </dd>
            <dt>{t('admin.statusLabel')}</dt>
            <dd>{userStatusLabel(user.userStatus)}</dd>
            <dt>{t('admin.mfaRequiredLabel')}</dt>
            <dd>{user.mfaRequired === BigInt(1) ? t('admin.yesText') : t('admin.noText')}</dd>
            <dt>{t('admin.lastLoginLabel')}</dt>
            <dd>{formatUnixTime(user.lastLoginAt)}</dd>
            <dt>{t('admin.createdAtLabel')}</dt>
            <dd>{formatUnixTime(user.createdAt)}</dd>
          </dl>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>{t('admin.mfaStatusSection')}</h4>
        {user !== undefined && user.mfaRequired === BigInt(1) ? (
          <p className={styles.mfaRequired}>{t('admin.mfaRequiredNotice')}</p>
        ) : null}
        <p className={styles.muted}>
          {mfaBound.length > 0
            ? t('admin.mfaBoundSummary', { factors: mfaBound.join('、') })
            : t('admin.mfaNoneBound')}
        </p>
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>{t('admin.credentialsSection')}</h4>
        {data.credentials.length === 0 ? (
          <p className={styles.muted}>{t('admin.noCredentials')}</p>
        ) : (
          <ul className={styles.list}>
            {data.credentials.map((credential) => (
              <li key={credential.id.toString()} className={styles.listRow}>
                <span className={styles.listMain}>
                  {credentialKindLabel(credential.kind)}
                  {credential.label !== '' ? `（${credential.label}）` : ''}
                </span>
                {/* 自绘状态徽章（主色蓝代偿）换 Semi Tag，语义色交 Semi。 */}
                {credential.isEnabled ? (
                  <Tag color="green">{t('admin.credentialEnabled')}</Tag>
                ) : (
                  <Tag>{t('admin.credentialDisabled')}</Tag>
                )}
                <span className={styles.listMeta}>
                  {t('admin.boundAt', { time: formatUnixTime(credential.createdAt) })}
                  {credential.lastUsedAt > BigInt(0)
                    ? t('admin.credentialLastUsed', {
                        time: formatUnixTime(credential.lastUsedAt),
                      })
                    : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>{t('admin.bindingsSection')}</h4>
        {data.bindings.length === 0 ? (
          <p className={styles.muted}>{t('admin.noBindings')}</p>
        ) : (
          <ul className={styles.list}>
            {data.bindings.map((binding) => (
              <li key={binding.id.toString()} className={styles.listRow}>
                <span className={styles.listMain}>
                  {binding.providerKey}
                  {binding.nickname !== '' ? `（${binding.nickname}）` : ''}
                </span>
                <span className={styles.listMeta}>
                  OpenID {binding.openId || EMPTY_TEXT} ·{' '}
                  {t('admin.boundAt', { time: formatUnixTime(binding.createdAt) })}
                </span>
                <Popconfirm
                  title={t('admin.unbindConfirm', { providerKey: binding.providerKey })}
                  onConfirm={() => handleUnbind(binding.providerKey)}
                >
                  <Button size="small" type="danger">
                    {t('admin.unbindAction')}
                  </Button>
                </Popconfirm>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={styles.block}>
        <h4 className={styles.blockTitle}>{t('admin.loginLogSection')}</h4>
        {eventsError !== undefined && !isUnauthenticatedError(eventsError) ? (
          // 区块级错误态换 Semi Banner（自带 role="alert"）。
          <Banner type="danger" fullMode={false} description={t('admin.loginLogLoadFailed')} />
        ) : (
          <DataTable<EventItem>
            columns={getEventsColumns()}
            rows={eventsData?.items ?? []}
            rowKey={eventRowKey}
            total={eventsData !== undefined ? toCount(eventsData.total) : 0}
            query={eventsQuery}
            onQueryChange={setEventsQuery}
            loading={eventsLoading}
            // success 空态判定走 deriveRequestStatus 派生（§5.3）。
            empty={
              deriveRequestStatus(eventsLoading, eventsError, eventsData) === 'success'
                ? t('admin.noLoginRecords')
                : undefined
            }
          />
        )}
      </section>
    </section>
  );
}

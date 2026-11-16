/**
 * 用户详情抽屉内容（UsersPage 点击用户名打开；组件常驻挂载，仅切 visible，
 * 不随 URL 变化）：
 *
 * GetUser（{id} 详情，含凭证概览 / 三方绑定 / MFA 状态）真调
 * （后端已实装）；解绑第三方（UnbindUserThirdparty {id, providerKey}）
 * Popconfirm 确认 → 成功后重取详情；Union 行不可单独解绑
 * 由服务端兜底（invalid_request）——admin 绑定视图 UserThirdpartyBinding 无
 * type 标记，前端不预判置灰，失败经 Semi Toast 展示
 * （原就地 actionError 文字已移除）；成功反馈接 Toast.success
 * （admin.unbindSuccess，P1-6 统一成功通道）。
 *
 * 登录日志（GetUserEvents {id} + 分页）：DataTable 消费
 * （分页 / 排序受控 TableQueryState，初始 created_at desc——EventLogTable
 * 同构；列口径沿需求：时间 / 事件 / 方式 / IP / 设备 UA）。
 *
 * 401 统一跳登录（UsersPage 同模式）；404 掩护等其余错误走错误态。
 * 组件壳 import Semi 后不可在 node 测试（工具链 blocker），
 * 可测逻辑全部收口在 ./api（boundMfaFactors / credentialKindLabel /
 * userStatusLabel / formatUnixTime / 请求构造）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Popconfirm,
  SideSheet,
  Spin,
  Tag,
  Toast,
} from '@douyinfe/semi-ui';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
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
function getEventsColumns(): DataTableColumn<EventItem>[] {
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

/** 用户详情抽屉：基本信息 + 凭证概览 + MFA 状态 + 三方绑定（解绑）+ 登录日志。 */
export function UserDetail(props: {
  /** 归一后 al_root（透传，保持与列表页路由参数一致）。 */
  alRoot: string;
  /** 目标用户 ID；抽屉关闭期间保留上次 id，避免关闭动画闪空。 */
  userId: bigint | null;
  visible: boolean;
  onClose: () => void;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 抽屉常驻挂载：仅在可见且有目标 id 时才发请求——ready 拦截关闭后的
  // 残余请求，id 切换经 refreshDeps 重取；0n 仅作未 ready 时的入参兜底。
  // refreshAsync 供解绑成功后串行重取（须待详情重取完成再报成功）。
  const ready = props.visible && props.userId !== null;
  const { data, error, refreshAsync } = useRequest(
    () => getUser(buildGetUserRequest(props.userId ?? BigInt(0))),
    {
      ready,
      refreshDeps: [props.userId],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );
  const [eventsQuery, setEventsQuery] =
    useState<TableQueryState>(INITIAL_EVENTS_QUERY);
  const {
    data: eventsData,
    error: eventsError,
    loading: eventsLoading,
  } = useRequest(
    () =>
      getUserEvents(
        buildGetUserEventsRequest(props.userId ?? BigInt(0), eventsQuery),
      ),
    {
      ready,
      refreshDeps: [props.userId, eventsQuery],
      ...requestOptions({
        toast: false,
        returnTo: () => adminReturnTo(location.pathname, location.search),
      }),
    },
  );

  /**
   * 解绑第三方：Union 行不可单独解绑由服务端兜底
   * （invalid_request → 失败经 Toast 展示）；成功后重取详情刷新
   * 绑定列表 + 成功反馈（P1-6 统一成功通道，新增 admin.unbindSuccess）。
   * P0-3 防重：onConfirm 返回本 Promise——Semi Popconfirm 原生机制
   * 在途期间确认钮 loading + 禁用（连点不再触发），落地才关框。
   */
  async function handleUnbind(providerKey: string): Promise<void> {
    try {
      await unbindUserThirdparty(
        buildUnbindUserThirdpartyRequest(
          props.userId ?? BigInt(0),
          providerKey,
        ),
      );
      await refreshAsync();
      Toast.success(t('admin.unbindSuccess', { providerKey }));
    } catch (unbindError) {
      Toast.error(apiErrorText(unbindError));
    }
  }

  // 抽屉内容：错误态 / 加载态 / 五个区块均落在 SideSheet 内，标题由外层
  // title 承载（避免旧独立页的 section 壳与 page-title 重复）。
  let content: ReactNode;
  if (error !== undefined && !isUnauthenticatedError(error)) {
    content = (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.userDetailLoadFailed')}
      />
    );
  } else if (data === undefined) {
    content = (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  } else {
    const user = data.user;
    const mfaBound = boundMfaFactors(data.mfa);
    content = (
      <>
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
              <dd>
                {user.mfaRequired === BigInt(1)
                  ? t('admin.yesText')
                  : t('admin.noText')}
              </dd>
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
                    {t('admin.boundAt', {
                      time: formatUnixTime(credential.createdAt),
                    })}
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
                    {t('admin.boundAt', {
                      time: formatUnixTime(binding.createdAt),
                    })}
                  </span>
                  <Popconfirm
                    title={t('admin.unbindConfirm', {
                      providerKey: binding.providerKey,
                    })}
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
            <Banner
              type="danger"
              fullMode={false}
              description={t('admin.loginLogLoadFailed')}
            />
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
                deriveRequestStatus(eventsLoading, eventsError, eventsData) ===
                'success'
                  ? t('admin.noLoginRecords')
                  : undefined
              }
            />
          )}
        </section>
      </>
    );
  }

  const titleUser = data?.user;
  const title =
    titleUser !== undefined
      ? `${t('admin.userDetailTitle')}：${titleUser.username}`
      : t('admin.userDetailTitle');

  return (
    <SideSheet
      title={title}
      visible={props.visible}
      maskClosable={false}
      onCancel={props.onClose}
      size="medium"
    >
      {content}
    </SideSheet>
  );
}

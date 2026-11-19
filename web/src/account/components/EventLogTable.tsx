/**
 * 本人安全日志表（docs/前端架构.md §5；docs/接口文档.md §3.7）：
 * AccountService/GetEvents 分页展示本人全部安全事件（登录成功 + 改密 /
 * 重置密码 / 换绑 / 两步验证开关 / 通行密钥 / 三方绑定解绑等，事件类型
 * 口径与后台 admin 事件日志一致）；前端只展示、不发筛选参数（§3.7 的
 * event 入参系预留，本页未接线筛选）；列口径：事件类型、时间、方式、
 * IP、设备 UA。
 *
 * 取数：受控 TableQueryState（初始 created_at desc，§1.7 示例排序）
 * → buildGetEventsRequest → getEvents；翻页 / 排序经 DataTable 的
 * onQueryChange 上报（dataTableLogic.resolveTableQuery 归一）重新取数。
 * 401 统一跳登录（§5，沿 ProfilePage 模式）；其余错误就地提示。
 * 文案经 shared/i18n（account.* 域键）；事件类型文案经
 * shared/utils/eventLabels（与 admin 同源一份，不复制第二份映射）。
 *
 * 展示帧 EventLogTableView 与取数壳分离（ProfilePageView 同口径）：前者
 * 纯 props 渲染、node 可测（多事件类型渲染用例），后者管取数与错误分流。
 */
import { useState, type ReactNode } from 'react';
import { Banner } from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import {
  accountReturnTo,
  buildGetEventsRequest,
  formatUnixTime,
  getEvents,
  isUnauthenticatedError,
} from '../api';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import type { UserEventItem } from '../../gen/proto/api/account/v1/thirdparty_pb';
import { eventTypeLabel } from '../../shared/utils/eventLabels';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import styles from './EventLogTable.module.less';

/** 排序字段（§1.7 示例 created_at；sort 值域前端自律）。 */
const LOG_SORT_FIELD = 'created_at';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 初始查询：第 1 页、每页 20（§1.7 缺省）、按时间倒序。 */
const INITIAL_LOG_QUERY: TableQueryState = {
  ...initialTableQuery(),
  sort: LOG_SORT_FIELD,
  order: 'desc',
};

/**
 * 行键：安全事件条目无 id 字段（§3.7），以业务复合键充当——event 必入键，
 * 否则同秒同源的两类事件（如 login_success 与 change_password）键碰撞。
 * 导出供测试锚定（ProfilePageView 纯逻辑落位同口径）。
 */
export function logRowKey(row: UserEventItem): string {
  return `${row.createdAt}:${row.event}:${row.ip}:${row.amr}`;
}

/**
 * 列口径：事件类型 / 时间 / 方式 / IP / 设备 UA。函数形态供渲染期构造
 * （t() 于渲染期调用，防模块级 locale 冻结）。
 */
function logColumns(): DataTableColumn<UserEventItem>[] {
  return [
    {
      dataIndex: 'event',
      title: t('account.logEventColumn'),
      width: 160,
      render: (_text: unknown, row: UserEventItem) => eventTypeLabel(row.event),
    },
    {
      dataIndex: 'createdAt',
      title: t('account.logTimeColumn'),
      width: 180,
      sorter: true,
      render: (_text: unknown, row: UserEventItem) =>
        formatUnixTime(row.createdAt),
    },
    {
      dataIndex: 'amr',
      title: t('account.logMethodColumn'),
      width: 160,
      render: (_text: unknown, row: UserEventItem) => row.amr || EMPTY_TEXT,
    },
    {
      dataIndex: 'ip',
      title: 'IP',
      width: 180,
      render: (_text: unknown, row: UserEventItem) => row.ip || EMPTY_TEXT,
    },
    {
      dataIndex: 'ua',
      title: t('account.logUaColumn'),
      render: (_text: unknown, row: UserEventItem) => row.ua || EMPTY_TEXT,
    },
  ];
}

/** 展示帧：纯 props 渲染（ProfilePageView 同口径；零副作用、node 可测）。 */
export function EventLogTableView(props: {
  /** 受控查询状态（分页 / 排序）。 */
  query: TableQueryState;
  onQueryChange: (next: TableQueryState) => void;
  rows: UserEventItem[];
  /** 服务端权威 total（§1.7）。 */
  total: number;
  loading: boolean;
  /** 空态文案；undefined 用 DataTable 内置空态（错误 / 加载态）。 */
  empty: string | undefined;
}): ReactNode {
  return (
    <div className={styles.tableWrap}>
      <DataTable<UserEventItem>
        columns={logColumns()}
        rows={props.rows}
        rowKey={logRowKey}
        total={props.total}
        query={props.query}
        onQueryChange={props.onQueryChange}
        loading={props.loading}
        empty={props.empty}
      />
    </div>
  );
}

/** 安全日志表状态壳：query 受控 → GetEvents 取数 → 展示帧渲染。 */
export function EventLogTable(): ReactNode {
  const [query, setQuery] = useState<TableQueryState>(INITIAL_LOG_QUERY);
  // 自动请求 + refreshDeps（query 变化重取，替代 effect 模板）；401
  // 集中 onError 跳登录带 returnTo，其余静默（错误帧呈现防双报）。
  const location = useLocation();
  const { data, error, loading } = useRequest(
    () => getEvents(buildGetEventsRequest(query)),
    {
      refreshDeps: [query],
      ...requestOptions({
        toast: false,
        returnTo: () => accountReturnTo(location.pathname, location.search),
      }),
    },
  );
  const status = deriveRequestStatus(loading, error, data);

  if (status === 'error' && !isUnauthenticatedError(error)) {
    // 区块级加载失败裸文本 → Semi Banner（自带 role="alert"）。
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('account.logLoadFailed')}
      />
    );
  }
  return (
    <EventLogTableView
      query={query}
      onQueryChange={setQuery}
      rows={data?.items ?? []}
      total={data !== undefined ? toCount(data.total) : 0}
      loading={status === 'loading'}
      empty={status === 'success' ? t('account.logEmpty') : undefined}
    />
  );
}

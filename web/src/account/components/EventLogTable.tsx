/**
 * 本人登录记录表（docs/前端架构.md §5 行 490；docs/接口文档.md §3.7 行 1041）：
 * AccountService/GetEvents 分页展示——「仅成功记录」由服务端过滤（行 1041
 * 响应口径），前端只展示、不发筛选参数；列口径取需求 §4.2 行 152：时间、
 * 方式、IP、设备 UA。
 *
 * 取数：受控 TableQueryState（初始 created_at desc，§1.7 行 277 示例排序）
 * → buildGetEventsRequest → getEvents；翻页 / 排序经 DataTable 的
 * onQueryChange 上报（dataTableLogic.resolveTableQuery 归一）重新取数。
 * 401 统一跳登录（§5 行 480，沿 ProfilePage 模式）；其余错误就地提示。
 * 后端本接口系桩——测试走 msw，联调待后端实装解锁。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { buildGetEventsRequest, formatUnixTime, getEvents, isUnauthenticatedError } from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import {
  initialTableQuery,
  type TableQueryState,
} from '../../shared/app-ui/dataTableLogic';
import type { UserEventItem } from '../../gen/proto/api/account/v1/thirdparty_pb';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import styles from './EventLogTable.module.less';

/** 排序字段（§1.7 行 277 示例 created_at；sort 值域前端自律）。 */
const LOG_SORT_FIELD = 'created_at';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 初始查询：第 1 页、每页 20（§1.7 缺省）、按时间倒序。 */
const INITIAL_LOG_QUERY: TableQueryState = {
  ...initialTableQuery(),
  sort: LOG_SORT_FIELD,
  order: 'desc',
};

/** 行键：登录记录条目无 id 字段（§3.7 行 1041），以业务复合键充当。 */
function logRowKey(row: UserEventItem): string {
  return `${row.createdAt}:${row.ip}:${row.amr}`;
}

/**
 * 列口径（需求 §4.2 行 152）：时间 / 方式 / IP / 设备 UA。
 * 函数形态供渲染期构造（t() 于渲染期调用，防模块级 locale 冻结）。
 */
function logColumns(): readonly DataTableColumn<UserEventItem>[] {
  return [
    {
      dataIndex: 'createdAt',
      title: t('account.logTimeColumn'),
      width: 180,
      sorter: true,
      render: (_text: unknown, row: UserEventItem) => formatUnixTime(row.createdAt),
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

/** 登录记录表状态壳：query 受控 → GetEvents 取数 → DataTable 渲染。 */
export function EventLogTable(): ReactNode {
  const [query, setQuery] = useState<TableQueryState>(INITIAL_LOG_QUERY);
  const { status, data, error, run } = useRequest(getEvents);
  const alRoot = loadAccountBootstrap().alRoot;

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防 unhandled rejection；
    // 错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(buildGetEventsRequest(query)).catch(() => {});
  }, [run, query]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §5 行 480：401 统一跳登录（replace：日志页不可回退占位）。
      window.location.replace(loginUrl(alRoot));
    }
  }, [error, alRoot]);

  if (status === 'error' && !isUnauthenticatedError(error)) {
    return <p role="alert">{t('account.logLoadFailed')}</p>;
  }
  return (
    <div className={styles.tableWrap}>
      <DataTable<UserEventItem>
        columns={logColumns()}
        rows={data?.items ?? []}
        rowKey={logRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? t('account.logEmpty') : undefined}
      />
    </div>
  );
}

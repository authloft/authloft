/**
 * 事件日志统一视图页（docs/前端架构.md §6 行 523 AuditPage；docs/接口文档.md
 * §5.6 行 1288 ListEvents；docs/需求.md §4.6 行 260）——/admin/audit。
 *
 * 预设视图（§5.6 行 1288「预设视图『登录记录』『敏感操作』」）：
 * - 「登录记录」：event 强制 login_success（《后端架构》§4.6 行 807 记录范围
 *   ——记录成功登录 + 各类敏感操作，登录记录即 login_success 单值）；
 * - 「敏感操作」：事件类型集合文档未定义封闭集（《后端架构》§4.6 event 值域
 *   以 `|...` 收尾开放 + ListEvents 的 event 系单值正向精确过滤、无排除语义）
 *   ——故停报该项，未建该预设（依据见 ./api 段头注）；
 *   手动「事件类型」筛选可按已知 17 类逐类型过滤（需求 §4.6「可按类型筛选」）。
 *
 * DataTable 消费分页（UsersPage 同模式）：§1.7 服务端分页受控
 * TableQueryState；created_at 可排序（dataIndex 即 wire 名口径）；预设 /
 * 筛选变更即回第 1 页重取。buildListEventsRequest 六筛选全支持
 * （§5.6 行 1288），actorId / userId / from / to 的 UI 暴露归后续增强——
 * 本页交付口径 = OUTCOME（预设 + 类型筛选 + DataTable 分页）。
 *
 * 401 统一跳登录（§6 行 501，UsersPage 同模式）；其余错误页面错误态。
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑全部收口
 * ./api（请求构造 / 预设映射 / 展示纯函数）。样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { RadioGroup, Select, Typography } from '@douyinfe/semi-ui-19';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { toCount } from '../../shared/utils/int';
import type { EventItem } from '../../gen/proto/api/admin/v1/events_pb';
import {
  ACTOR_TYPE_FILTERS,
  EVENT_TYPE_FILTERS,
  actorText,
  bigIdText,
  buildListEventsRequest,
  eventDetailText,
  eventTypeLabel,
  formatUnixTime,
  isUnauthenticatedError,
  listEvents,
  type AuditPreset,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './AuditPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** 预设视图选项（§5.6 行 1288；「敏感操作」停报见文件头注）。 */
const PRESET_OPTIONS: readonly { readonly value: AuditPreset; readonly label: string }[] = [
  { value: 'all', label: '全部事件' },
  { value: 'login_records', label: '登录记录' },
];

/** 行键（EventItem.id int64 → 十进制字符串，§1.12）。 */
function eventRowKey(row: EventItem): string {
  return row.id.toString();
}

/** 事件日志统一视图页：预设 + 类型筛选 + DataTable 服务端分页。 */
export function AuditPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  // §1.7 受控查询状态：分页 / 排序由 DataTable 上报更新；筛选 / 预设变更回第 1 页。
  const [query, setQuery] = useState<TableQueryState>(initialTableQuery);
  const [preset, setPreset] = useState<AuditPreset>('all');
  const [eventFilter, setEventFilter] = useState('');
  const [actorTypeFilter, setActorTypeFilter] = useState('');
  const { status, data, error, run } = useRequest(listEvents);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(
      buildListEventsRequest(
        preset,
        { event: eventFilter, actorType: actorTypeFilter },
        query,
      ),
    ).catch(() => {});
  }, [run, query, preset, eventFilter, actorTypeFilter]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  /** 预设变更（§5.6 行 1288）：回第 1 页重取（§1.7 语义）。 */
  function changePreset(next: AuditPreset): void {
    setPreset(next);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 事件类型筛选变更（仅 all 预设生效；login_records 下已禁用）：回第 1 页重取。 */
  function changeEventFilter(value: string): void {
    setEventFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 操作者类型筛选变更：回第 1 页重取。 */
  function changeActorTypeFilter(value: string): void {
    setActorTypeFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  // 列口径（EventItem 全字段投影，《后端架构》§4.6；dataIndex 即 wire 名——
  // created_at 可排序走后端 orderClause ^[a-z0-9_]+$，既定口径）。
  const columns: readonly DataTableColumn<EventItem>[] = [
    {
      dataIndex: 'event',
      title: '事件类型',
      render: (_text: unknown, row: EventItem) => eventTypeLabel(row.event),
    },
    {
      dataIndex: 'actor_type',
      title: '操作者',
      render: (_text: unknown, row: EventItem) => actorText(row.actorType, row.actorId),
    },
    {
      dataIndex: 'user_id',
      title: '对象用户',
      render: (_text: unknown, row: EventItem) => bigIdText(row.userId),
    },
    {
      dataIndex: 'client_id',
      title: '客户端',
      render: (_text: unknown, row: EventItem) => row.clientId || EMPTY_TEXT,
    },
    {
      dataIndex: 'amr',
      title: '认证方法',
      render: (_text: unknown, row: EventItem) => row.amr || EMPTY_TEXT,
    },
    {
      dataIndex: 'ip',
      title: '来源 IP',
      render: (_text: unknown, row: EventItem) => row.ip || EMPTY_TEXT,
    },
    {
      dataIndex: 'ua',
      title: 'User-Agent',
      render: (_text: unknown, row: EventItem) => (
        <span className={styles.ellipsis} title={row.ua}>
          {row.ua || EMPTY_TEXT}
        </span>
      ),
    },
    {
      dataIndex: 'target',
      title: '操作目标',
      render: (_text: unknown, row: EventItem) => row.target || EMPTY_TEXT,
    },
    {
      dataIndex: 'detail',
      title: '详情',
      render: (_text: unknown, row: EventItem) => (
        <span className={styles.ellipsis} title={eventDetailText(row.detail)}>
          {eventDetailText(row.detail)}
        </span>
      ),
    },
    {
      dataIndex: 'created_at',
      title: '发生时间',
      width: 170,
      sorter: true,
      render: (_text: unknown, row: EventItem) => formatUnixTime(row.createdAt),
    },
  ];

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        事件日志加载失败，请刷新重试
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>事件日志</Typography.Title>
      <div className={styles.filterBar}>
        <RadioGroup
          type="button"
          value={preset}
          onChange={(event) => changePreset(event.target.value as AuditPreset)}
          options={PRESET_OPTIONS.map((option) => ({
            value: option.value,
            label: option.label,
          }))}
        />
        <Select
          className={styles.filterSelect}
          value={eventFilter}
          onChange={(value) => changeEventFilter(typeof value === 'string' ? value : '')}
          placeholder="事件类型：全部"
          showClear
          optionList={EVENT_TYPE_FILTERS.map((option) => ({
            value: option.value,
            label: option.text,
          }))}
          disabled={preset === 'login_records'}
          aria-label="按事件类型筛选"
        />
        <Select
          className={styles.filterSelect}
          value={actorTypeFilter}
          onChange={(value) => changeActorTypeFilter(typeof value === 'string' ? value : '')}
          placeholder="操作者类型：全部"
          showClear
          optionList={ACTOR_TYPE_FILTERS.map((option) => ({
            value: option.value,
            label: option.text,
          }))}
          aria-label="按操作者类型筛选"
        />
      </div>
      <DataTable<EventItem>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={eventRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? '暂无事件记录' : undefined}
      />
    </section>
  );
}

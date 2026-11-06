/**
 * 事件日志统一视图页（docs/前端架构.md §6 行 543 AuditPage；docs/接口文档.md
 * §5.6 行 1297 ListEvents；docs/需求.md §4.6 行 260）——/admin/audit。
 *
 * 预设视图（§5.6 行 1297「预设视图『登录记录』『敏感操作』」）：
 * - 「登录记录」：event 强制 login_success（《后端架构》§4.6 行 807 记录范围
 *   ——记录成功登录 + 各类敏感操作，登录记录即 login_success 单值）；
 * - 「敏感操作」（2026-11-06 定稿五类封闭集）：改密 / 重置
 *   密码 / 解绑 / 启用/停用两步验证五类——ListEvents 的 event 系 optional
 *   string 单值正向过滤（预设为前端组装概念）→ event 下拉限定五类单选
 *   （eventTypeFilterOptions）、进预设出集现值默认 change_password
 *   （resolveEventFilterOnPreset，列表立即有数据）、入集保留；切其余预设
 *   保留现值（预设切换不清筛选惯例）；四项筛选在该预设下照常叠加
 *   （与 login_records 下行为一致）。
 *
 * DataTable 消费分页（UsersPage 同模式）：§1.7 服务端分页受控
 * TableQueryState；created_at 可排序（dataIndex 即 wire 名口径）；预设 /
 * 筛选变更即回第 1 页重取。六筛选 UI 全暴露（§5.6 行 1297）：event /
 * actorType 下拉（既有）+ actorId / userId 数值输入（InputNumber，空即
 * 不过滤）+ from / to 时间选择（DatePicker type=dateTime，本地时间 →
 * Unix 秒）。数值口径（§1.12）：ID 输入经 ^\d+$ 校验后 BigInt()（InputNumber
 * 超精度时以 string 原样承载，不经 Number）；时间戳秒级经 Number 换算无
 * 精度问题后转 bigint。换算内联本文件（入方向 BigInt() 先例同
 * buildSetSettingsRequest / SettingsPage onChange 归一），构造函数零改动
 * （buildListEventsRequest 既有语义，login_records 预设下 event 让位、
 * 其余五项照常叠加 → 四项筛选在预设下不禁用）。
 *
 * 401 统一跳登录（§6 行 523，UsersPage 同模式）；其余错误页面错误态。
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑（请求
 * 构造 / 预设映射 / 展示纯函数）收口 ./api；四项筛选的 UI 输入换算因
 * 换算处紧贴 Semi 控件值形态内联本文件（见上）。样式（§1.7）：同目录
 * 同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { DatePicker, InputNumber, RadioGroup, Select, Typography } from '@douyinfe/semi-ui-19';
import { DataTable, type DataTableColumn } from '../../shared/app-ui/DataTable';
import { initialTableQuery, type TableQueryState } from '../../shared/app-ui/dataTableLogic';
import { useRequest } from '../../shared/hooks/useRequest';
import { t, type I18nKey } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import type { EventItem } from '../../gen/proto/api/admin/v1/events_pb';
import {
  ACTOR_TYPE_FILTERS,
  actorText,
  bigIdText,
  buildListEventsRequest,
  eventDetailText,
  eventTypeFilterOptions,
  eventTypeLabel,
  formatUnixTime,
  isUnauthenticatedError,
  listEvents,
  resolveEventFilterOnPreset,
  type AuditPreset,
} from '../api';
import { loginUrl } from '../bootstrap';
import styles from './AuditPage.module.less';

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/**
 * ID 数值输入（InputNumber 值，number | string，空态 ''）→ bigint 筛选值
 * （§1.12：ID 全程字符串换算，禁 Number 运算）：^\d+$ 保证 BigInt() 无精度
 * 损失——超 2^53 输入由 InputNumber 以 string 原样承载；空态 / 非十进制
 * 中间态一律 undefined = 不过滤（与构造函数 optional 语义对齐）。
 */
function idInputToFilter(value: number | string | undefined): bigint | undefined {
  if (value === undefined || value === '') {
    return undefined;
  }
  const text = String(value).trim();
  return /^\d+$/.test(text) ? BigInt(text) : undefined;
}

/**
 * DatePicker 本地时间 → Unix 秒（§12.9 时间口径，§1.12 bigint 承载）：
 * 秒级时间戳 < 2^53，getTime() 经 Number 换算无精度问题；未选择 → undefined。
 */
function dateToUnixFilter(value: Date | undefined): bigint | undefined {
  if (value === undefined) {
    return undefined;
  }
  return BigInt(Math.floor(value.getTime() / 1000));
}

/**
 * 预设视图选项（§5.6 行 1297：全部 / 登录记录 / 敏感操作三项）。
 * textKey 字段化——模块级只存键，消费方渲染期 t(textKey)。
 */
const PRESET_OPTIONS: readonly { readonly value: AuditPreset; readonly textKey: I18nKey }[] = [
  { value: 'all', textKey: 'admin.auditPresetAll' },
  { value: 'login_records', textKey: 'admin.auditPresetLoginRecords' },
  { value: 'sensitive_records', textKey: 'admin.auditPresetSensitiveRecords' },
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
  // 四项筛选 UI 原始输入：ID 类承载 Semi InputNumber 值
  // （number | string，空态 ''）；时间类承载 DatePicker 本地时间（未选 = undefined）。
  const [actorIdFilter, setActorIdFilter] = useState<number | string>('');
  const [userIdFilter, setUserIdFilter] = useState<number | string>('');
  const [fromFilter, setFromFilter] = useState<Date | undefined>(undefined);
  const [toFilter, setToFilter] = useState<Date | undefined>(undefined);
  const { status, data, error, run } = useRequest(listEvents);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run(
      buildListEventsRequest(
        preset,
        {
          event: eventFilter,
          actorType: actorTypeFilter,
          actorId: idInputToFilter(actorIdFilter),
          userId: idInputToFilter(userIdFilter),
          from: dateToUnixFilter(fromFilter),
          to: dateToUnixFilter(toFilter),
        },
        query,
      ),
    ).catch(() => {});
  }, [
    run,
    query,
    preset,
    eventFilter,
    actorTypeFilter,
    actorIdFilter,
    userIdFilter,
    fromFilter,
    toFilter,
  ]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

  /** 预设变更（§5.6 行 1297）：回第 1 页重取（§1.7 语义）。 */
  function changePreset(next: AuditPreset): void {
    setPreset(next);
    // 「敏感操作」：event 下拉限定五类，进预设出集现值默认 change_password
    // （列表立即有数据）、入集保留；切其余预设保留现值（预设切换不清筛选惯例）。
    setEventFilter(resolveEventFilterOnPreset(next, eventFilter));
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 事件类型筛选变更（sensitive_records 下限定五类单选；login_records 下已禁用）：回第 1 页重取。 */
  function changeEventFilter(value: string): void {
    setEventFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 操作者类型筛选变更：回第 1 页重取。 */
  function changeActorTypeFilter(value: string): void {
    setActorTypeFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 操作者 ID 筛选变更（空即不过滤）：回第 1 页重取。 */
  function changeActorIdFilter(value: number | string): void {
    setActorIdFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 用户 ID 筛选变更（空即不过滤）：回第 1 页重取。 */
  function changeUserIdFilter(value: number | string): void {
    setUserIdFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 起始时间筛选变更（未选即不过滤）：回第 1 页重取。 */
  function changeFromFilter(value: Date | undefined): void {
    setFromFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  /** 结束时间筛选变更（未选即不过滤）：回第 1 页重取。 */
  function changeToFilter(value: Date | undefined): void {
    setToFilter(value);
    setQuery((prev) => ({ ...prev, page: 1 }));
  }

  // 列口径（EventItem 全字段投影，《后端架构》§4.6；dataIndex 即 wire 名——
  // created_at 可排序走后端 orderClause ^[a-z0-9_]+$，既定口径）。
  const columns: readonly DataTableColumn<EventItem>[] = [
    {
      dataIndex: 'event',
      title: t('admin.eventTypeColumn'),
      render: (_text: unknown, row: EventItem) => eventTypeLabel(row.event),
    },
    {
      dataIndex: 'actor_type',
      title: t('admin.actorColumn'),
      render: (_text: unknown, row: EventItem) => actorText(row.actorType, row.actorId),
    },
    {
      dataIndex: 'user_id',
      title: t('admin.targetUserColumn'),
      render: (_text: unknown, row: EventItem) => bigIdText(row.userId),
    },
    {
      dataIndex: 'client_id',
      title: t('admin.clientColumn'),
      render: (_text: unknown, row: EventItem) => row.clientId || EMPTY_TEXT,
    },
    {
      dataIndex: 'amr',
      title: t('admin.authMethodColumn'),
      render: (_text: unknown, row: EventItem) => row.amr || EMPTY_TEXT,
    },
    {
      dataIndex: 'ip',
      title: t('admin.sourceIpColumn'),
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
      title: t('admin.actionTargetColumn'),
      render: (_text: unknown, row: EventItem) => row.target || EMPTY_TEXT,
    },
    {
      dataIndex: 'detail',
      title: t('admin.detailColumn'),
      render: (_text: unknown, row: EventItem) => (
        <span className={styles.ellipsis} title={eventDetailText(row.detail)}>
          {eventDetailText(row.detail)}
        </span>
      ),
    },
    {
      dataIndex: 'created_at',
      title: t('admin.occurredAtColumn'),
      width: 170,
      sorter: true,
      render: (_text: unknown, row: EventItem) => formatUnixTime(row.createdAt),
    },
  ];

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        {t('admin.auditLoadFailed')}
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('admin.navAudit')}</Typography.Title>
      <div className={styles.filterBar}>
        <RadioGroup
          type="button"
          value={preset}
          onChange={(event) => changePreset(event.target.value as AuditPreset)}
          options={PRESET_OPTIONS.map((option) => ({
            value: option.value,
            label: t(option.textKey),
          }))}
        />
        <Select
          className={styles.filterSelect}
          value={eventFilter}
          onChange={(value) => changeEventFilter(typeof value === 'string' ? value : '')}
          placeholder={t('admin.eventFilterPlaceholder')}
          showClear
          optionList={eventTypeFilterOptions(preset).map((option) => ({
            value: option.value,
            // FILTERS 存 textKey，渲染期 t() 取当前语言。
            label: t(option.textKey),
          }))}
          disabled={preset === 'login_records'}
          aria-label={t('admin.eventFilterAriaLabel')}
        />
        <Select
          className={styles.filterSelect}
          value={actorTypeFilter}
          onChange={(value) => changeActorTypeFilter(typeof value === 'string' ? value : '')}
          placeholder={t('admin.actorFilterPlaceholder')}
          showClear
          optionList={ACTOR_TYPE_FILTERS.map((option) => ({
            value: option.value,
            label: t(option.textKey),
          }))}
          aria-label={t('admin.actorFilterAriaLabel')}
        />
        <InputNumber
          className={styles.filterInput}
          value={actorIdFilter}
          onChange={(value) => changeActorIdFilter(value)}
          placeholder={t('admin.actorIdFilterPlaceholder')}
          min={0}
          precision={0}
          showClear
          aria-label={t('admin.actorIdFilterAriaLabel')}
        />
        <InputNumber
          className={styles.filterInput}
          value={userIdFilter}
          onChange={(value) => changeUserIdFilter(value)}
          placeholder={t('admin.userIdFilterPlaceholder')}
          min={0}
          precision={0}
          showClear
          aria-label={t('admin.userIdFilterAriaLabel')}
        />
        <DatePicker
          className={styles.filterDate}
          type="dateTime"
          value={fromFilter}
          onChange={(date) => changeFromFilter(date instanceof Date ? date : undefined)}
          placeholder={t('admin.fromFilterPlaceholder')}
          showClear
        />
        <DatePicker
          className={styles.filterDate}
          type="dateTime"
          value={toFilter}
          onChange={(date) => changeToFilter(date instanceof Date ? date : undefined)}
          placeholder={t('admin.toFilterPlaceholder')}
          showClear
        />
      </div>
      {preset === 'sensitive_records' ? (
        <p className={styles.presetHint}>{t('admin.auditPresetSensitiveHint')}</p>
      ) : null}
      <DataTable<EventItem>
        columns={columns}
        rows={data?.items ?? []}
        rowKey={eventRowKey}
        total={data !== undefined ? toCount(data.total) : 0}
        query={query}
        onQueryChange={setQuery}
        loading={status === 'loading'}
        empty={status === 'success' ? t('admin.noEvents') : undefined}
      />
    </section>
  );
}

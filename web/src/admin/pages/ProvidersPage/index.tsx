/**
 * 提供商列表页（docs/前端架构.md §6 行 515；docs/接口文档.md §5.2 行
 * 1164-1177；docs/需求.md §4.6 行 255）——/admin/providers。
 *
 * 列表用 Semi Table：显示名 / provider_key（可复制，shared CopyButton）/
 * 类别 / 类型（内置图标——shared ProviderIcon；§5.2 列表行集不含 icon_url
 * （该字段在 AdminProvider 详情，§5.3 行 1210），故列表恒渲染内置占位图形）/
 * 状态（StatusSwitch 行内启停；storage 类恒可用不渲染开关，见
 * providerStatusSwitchable）/ 策略标签（api.policyTags）/ 排序（sort_order
 * 值）/ 操作（编辑、删除）。编辑复用 ProviderEdit 侧栏（providerKey 定位）；
 * 删除经 ConfirmActionButton 二次确认后调 DeleteProvider，成功后 Toast +
 * 重新取数。工具栏「新建提供商」入口指向 PROVIDER_NEW_PATH（需求 §4.6）。
 *
 * 工具栏类别筛选：对已载入行集本地过滤（单页全量取数，不接后端 category
 * 入参）；筛选态与拖拽排序互斥——过滤行集是全量子集、重排会把子集当
 * 全量提交，故筛选中停用拖拽，清空筛选恢复全量。
 *
 * 拖拽排序从行内移出：右上角「排序」按钮展开 SideSheet，内嵌 SortableList
 * 承载原拖拽逻辑；行集截断（超 100）时停用拖拽并给出提示（见
 * buildListProvidersRequest）。启停 / 排序均乐观更新 + 失败回滚，错误文案
 * Toast 展示（错误展示归消费方——DataTable 行内开关同口径）。
 *
 * 取数：ListProviders **真调**（后端已实装）——全量取数
 * （buildListProvidersRequest：第 1 页 × 100，拖拽排序需全量行集，见其
 * 注释）；超限兜底停用拖拽（数据仍展示）。写路径 SetProviderEnabled /
 * SortProviders / DeleteProvider 后端已实装，单测走 msw。
 *
 * 401 统一跳登录（§6 行 501，account EventLogTable 同模式：会话在 GetMe
 * 之后过期等场景）；404 掩护等其余错误走页面错误态（AdminLayout 已对
 * GetMe 同口径分流，本页对列表请求补齐）。
 *
 * 组件壳 import Semi 后模块图不可在 node 测试（工具链 blocker）——
 * 可测逻辑全部收口在 ./api（请求构造 / 策略标签）与 SortableList /
 * ProviderCallbackHint（各自导出纯函数，零 Semi）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { create } from '@bufbuild/protobuf';
import {
  Banner,
  Button,
  Empty,
  Select,
  SideSheet,
  Space,
  Table,
  Tag,
  Toast,
} from '@douyinfe/semi-ui';
// ColumnProps 类型导入例外（CODE_GUIDE §4.1 第 21 条）：仅类型导入
// （编译期擦除、零运行时痕迹）+ 子路径在包 exports 白名单 + 大包入口确未
// 转出该类型，与 shared/app-ui/DataTable.tsx 同款用法。
import type { ColumnProps } from '@douyinfe/semi-ui/lib/es/table';
import { useLocation } from '@modern-js/runtime/router';
import { patchRowByKey } from '../../../shared/app-ui/dataTableLogic';
import { CopyButton } from '../../../shared/components/CopyButton';
import { ProviderIcon } from '../../../shared/components/ProviderIcon';
import { PageLayout } from '../../../shared/components/PageLayout';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../../shared/hooks/requestOptions';
import { hasKey, t } from '../../../shared/i18n';
import { toCount } from '../../../shared/utils/int';
import { SetProviderEnabledRequestSchema } from '../../../gen/proto/api/admin/v1/provider_pb';
import type { Provider } from '../../../gen/proto/api/admin/v1/provider_pb';
import {
  adminReturnTo,
  apiErrorText,
  buildDeleteProviderRequest,
  buildListProvidersRequest,
  buildSortProvidersRequest,
  deleteProvider,
  isUnauthenticatedError,
  listProviders,
  policyTags,
  setProviderEnabled,
  sortProviders,
} from '../../api';
import { ConfirmActionButton } from '../../components/ConfirmActionButton';
import { SortableList } from '../../components/SortableList';
import { StatusSwitch } from '../../components/StatusSwitch';
import styles from './index.module.less';
import { ProviderEdit } from './edit';

/** 行键（§5.3 行 1192：provider_key 创建后不可改，天然行键）。 */
function providerRowKey(row: Provider): string {
  return row.providerKey;
}

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/** storage 类别（恒可用：存储配置存在即可用，行内启停不适用）。 */
const STORAGE_CATEGORY = 'storage';

/**
 * 行内启停开关可见性：storage 类 Provider 恒可用（存储配置存在即可用，
 * 后端解析不消费 is_enabled，schema 亦不再下发该字段），不渲染开关、
 * 落零值占位；其余类别（含空类别零值行）行为不变。
 */
export function providerStatusSwitchable(category: string): boolean {
  return category !== STORAGE_CATEGORY;
}

/**
 * 类型 / 类别展示名（接口文档 §5.3 文案口径：admin.providerType.* /
 * admin.providerCategory.* 前缀键；字典缺键原样显示 wire 值不猜译名，
 * 空串落零值占位）。
 */
export function providerTypeDisplayName(type: string): string {
  if (type === '') {
    return EMPTY_TEXT;
  }
  const key = `admin.providerType.${type}`;
  return hasKey(key) ? t(key) : type;
}

export function providerCategoryDisplayName(category: string): string {
  if (category === '') {
    return EMPTY_TEXT;
  }
  const key = `admin.providerCategory.${category}`;
  return hasKey(key) ? t(key) : category;
}

/**
 * 按类别本地过滤已载入行集（''=不限，返回原行集引用）。不接线后端
 * category 入参：本页单页全量取数，数据量小、本地过滤即可。
 */
export function filterProvidersByCategory(
  rows: Provider[],
  category: string,
): Provider[] {
  if (category === '') {
    return rows;
  }
  return rows.filter((row) => row.category === category);
}

/**
 * 类别筛选下拉选项：「不限」置顶 + 已载入行集 distinct category（首现序）。
 * 空串类别是 protojson 零值占位、不构成可筛维度，跳过；选项名走
 * providerCategoryDisplayName（字典缺键回显 wire 值）。
 */
export function providerCategoryFilterOptions(
  rows: Provider[],
): { value: string; label: string }[] {
  const categories: string[] = [];
  for (const row of rows) {
    if (row.category !== '' && !categories.includes(row.category)) {
      categories.push(row.category);
    }
  }
  return [
    { value: '', label: t('admin.filterAnyOption') },
    ...categories.map((category) => ({
      value: category,
      label: providerCategoryDisplayName(category),
    })),
  ];
}

/**
 * 拖拽排序可用性：排序提交依赖全量行集（部分行集重排会与未载入行冲突），
 * 筛选态行集是全量子集、重排会把子集当全量提交——筛选与拖拽互斥，
 * 行集截断与筛选态任一命中即停用。
 */
export function sortDragEnabled(
  rowCount: number,
  total: number,
  categoryFilter: string,
): boolean {
  return rowCount === total && categoryFilter === '';
}

/** 提供商列表页：回调提示 + 类别筛选表格（行内启停 + 侧栏拖拽排序 + 编辑删除）。 */
export function ProvidersPage(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  alRoot: string;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 列表取数改 ahooks 自动请求；401 由集中 onError 跳登录，其余
  // 错误走页面错误帧（toast:false 静默防双报）。
  const { data, error, loading, refresh } = useRequest(
    () => listProviders(buildListProvidersRequest()),
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );
  // 行集本地态：列表载入同步 + 启停 / 排序写操作成功后就地补丁（乐观）。
  const [rows, setRows] = useState<Provider[]>([]);
  // 写操作失败反馈走 Semi Toast；成功反馈接 Toast.success。
  const [showEdit, setShowEdit] = useState(false);
  const [editProvider, setEditProvider] = useState<Provider | null>(null);
  // 排序 SideSheet 显隐（拖拽排序从行内移入）。
  const [showSort, setShowSort] = useState(false);
  // 类别筛选（工具栏 Select 本地过滤已载入行集；''=不限）。
  const [categoryFilter, setCategoryFilter] = useState('');

  // 列表数据落地 → 同步行集（引用更换即覆盖本地补丁，DataTable 同模式）。
  useEffect(() => {
    if (data !== undefined) {
      setRows(data.items);
    }
  }, [data]);

  const total = data !== undefined ? toCount(data.total) : 0;
  // 表格行集：类别筛选本地过滤（''=不限即原行集）。
  const visibleRows = filterProvidersByCategory(rows, categoryFilter);
  // 拖拽排序需全量行集且非筛选态（互斥，见 sortDragEnabled）；「超单页
  // 上限」提示只认行集截断，筛选态停用不冒充该文案。
  const fullRowset = rows.length === total;
  const canDrag = sortDragEnabled(rows.length, total, categoryFilter);

  function openCreate(): void {
    setEditProvider(null);
    setShowEdit(true);
  }

  function openEdit(row: Provider): void {
    setEditProvider(row);
    setShowEdit(true);
  }

  async function handleToggle(row: Provider, next: boolean): Promise<void> {
    try {
      await setProviderEnabled(
        create(SetProviderEnabledRequestSchema, {
          providerKey: row.providerKey,
          isEnabled: next,
        }),
      );
      // 成功：行数据追上乐观态（StatusSwitch 覆盖清除依赖此更新）+
      // 成功反馈（displayName 空串兜底 providerKey，§9 第 18 条零值口径）。
      setRows((prev) =>
        patchRowByKey(prev, providerRowKey, row.providerKey, (r) => ({
          ...r,
          isEnabled: next,
        })),
      );
      Toast.success(
        t(
          next ? 'admin.providerEnableSuccess' : 'admin.providerDisableSuccess',
          {
            name: row.displayName || row.providerKey,
          },
        ),
      );
    } catch (toggleError) {
      // 失败：错误展示归消费方 + rethrow 触发 StatusSwitch 回滚。
      Toast.error(apiErrorText(toggleError));
      throw toggleError;
    }
  }

  function handleSort(next: Provider[]): void {
    const prev = rows;
    setRows(next); // 乐观：新序先行。
    sortProviders(buildSortProvidersRequest(next))
      .then(() => {
        // 拖拽排序成功反馈（P1-6 统一成功通道）。
        Toast.success(t('admin.providerSortSuccess'));
      })
      .catch((sortError) => {
        setRows(prev); // 失败回滚原序。
        Toast.error(apiErrorText(sortError));
      });
  }

  // 表格列（渲染期构造，t() 不在模块级求值——CODE_GUIDE §4.6）。
  const columns: ColumnProps<Provider>[] = [
    {
      title: t('admin.providerColumnDisplayName'),
      dataIndex: 'displayName',
      render: (_text: unknown, row: Provider) => row.displayName || EMPTY_TEXT,
    },
    {
      title: t('admin.providerColumnKey'),
      dataIndex: 'providerKey',
      render: (_text: unknown, row: Provider) => (
        <span className={styles.keyCell}>
          <code className={styles.keyText}>{row.providerKey}</code>
          <CopyButton text={row.providerKey} />
        </span>
      ),
    },
    {
      title: t('admin.providerColumnCategory'),
      dataIndex: 'category',
      render: (_text: unknown, row: Provider) =>
        providerCategoryDisplayName(row.category),
    },
    {
      title: t('admin.providerColumnType'),
      dataIndex: 'type',
      render: (_text: unknown, row: Provider) => (
        <span className={styles.typeCell}>
          <ProviderIcon alt={row.type} />
          <span>{providerTypeDisplayName(row.type)}</span>
        </span>
      ),
    },
    {
      title: t('admin.statusLabel'),
      dataIndex: 'isEnabled',
      render: (_text: unknown, row: Provider) =>
        providerStatusSwitchable(row.category) ? (
          <StatusSwitch
            isEnabled={row.isEnabled}
            onToggle={(next) => handleToggle(row, next)}
          />
        ) : (
          EMPTY_TEXT
        ),
    },
    {
      title: t('admin.providerColumnPolicyTags'),
      dataIndex: 'policyTags',
      render: (_text: unknown, row: Provider) => {
        const tags = policyTags(row);
        return tags.length > 0 ? (
          <Space>
            {tags.map((tag) => (
              <Tag key={tag} size="small">
                {tag}
              </Tag>
            ))}
          </Space>
        ) : (
          EMPTY_TEXT
        );
      },
    },
    {
      title: t('admin.providerColumnSortOrder'),
      dataIndex: 'sortOrder',
      width: 80,
      render: (_text: unknown, row: Provider) => toCount(row.sortOrder),
    },
    {
      title: t('admin.actionsLabel'),
      dataIndex: 'actions',
      render: (_text: unknown, row: Provider) => (
        <span className={styles.actions}>
          <Button onClick={() => openEdit(row)}>{t('admin.editAction')}</Button>
          <ConfirmActionButton
            title={t('admin.providerDeleteConfirm', {
              name: row.displayName || row.providerKey,
            })}
            action={() =>
              deleteProvider(buildDeleteProviderRequest(row.providerKey))
            }
            onSuccess={() => {
              Toast.success(
                t('admin.providerDeleteSuccess', {
                  name: row.displayName || row.providerKey,
                }),
              );
              refresh();
            }}
          >
            {t('admin.removeAction')}
          </ConfirmActionButton>
        </span>
      ),
    },
  ];

  // 列表错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return (
      <Banner
        type="danger"
        fullMode={false}
        description={t('admin.providersLoadFailed')}
      />
    );
  }

  return (
    <PageLayout
      title={t('admin.navProviders')}
      filter={
        <Select
          className={styles.categoryFilter}
          // ''（不限）映射 undefined 让 placeholder 显示（UsersPage 同款）。
          value={categoryFilter === '' ? undefined : categoryFilter}
          onChange={(value) =>
            setCategoryFilter(typeof value === 'string' ? value : '')
          }
          placeholder={t('admin.providerColumnCategory')}
          showClear
          optionList={providerCategoryFilterOptions(rows)}
          aria-label={t('admin.providerColumnCategory')}
        />
      }
      actions={
        <Space>
          <Button onClick={() => setShowSort(true)}>
            {t('admin.providerSortAction')}
          </Button>
          <Button theme="solid" onClick={openCreate}>
            {t('admin.createProviderAction')}
          </Button>
        </Space>
      }
    >
      <Table<Provider>
        columns={columns}
        dataSource={visibleRows}
        rowKey={(record) =>
          record === undefined ? '' : providerRowKey(record)
        }
        loading={loading}
        pagination={false}
        // 空态判定走 deriveRequestStatus 派生（§5.3，禁手写三条件）。
        empty={
          deriveRequestStatus(loading, error, data) === 'success' ? (
            <Empty description={t('admin.noProviders')} />
          ) : undefined
        }
      />
      {/* 拖拽排序从行内移入侧栏：复用 SortableList + handleSort，行集/回滚同源。 */}
      <SideSheet
        title={t('admin.providerSortTitle')}
        visible={showSort}
        onCancel={() => setShowSort(false)}
        size="small"
      >
        {!fullRowset && total > 0 ? (
          <p className={styles.dragNote}>
            {t('admin.providersDragDisabledNote')}
          </p>
        ) : null}
        <SortableList
          items={rows}
          itemKey={providerRowKey}
          onSort={handleSort}
          disabled={!canDrag}
          handleLabel={t('admin.providerDragSortLabel')}
          renderItem={(row) => (
            <div className={styles.sortRow}>
              <span className={styles.sortName}>
                {row.displayName || EMPTY_TEXT}
              </span>
              <code className={styles.sortKey}>{row.providerKey}</code>
              <span className={styles.sortOrder}>{toCount(row.sortOrder)}</span>
            </div>
          )}
        />
      </SideSheet>
      <ProviderEdit
        alRoot={props.alRoot}
        providerKey={editProvider?.providerKey}
        onSave={() => {
          setShowEdit(false);
          refresh();
        }}
        visible={showEdit}
        onClose={() => setShowEdit(false)}
      />
    </PageLayout>
  );
}

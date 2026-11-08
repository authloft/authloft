/**
 * 提供方列表页（docs/前端架构.md §6 行 515；docs/接口文档.md §5.2 行
 * 1164-1177；docs/需求.md §4.6 行 255）——/admin/providers。
 *
 * 列口径（§6 行 515）：显示名 / provider_key（可复制，shared CopyButton）/
 * 类别 / 类型（内置图标——shared ProviderIcon；§5.2 列表行集不含 icon_url
 * （该字段在 AdminProvider 详情，§5.3 行 1210），故列表恒渲染内置占位图形）/
 * 状态（StatusSwitch 行内启停）/ 策略标签（api.policyTags）/ 排序
 * （sort_order 值 + SortableList 拖拽）。顶部 ProviderCallbackHint：回调
 * 地址模板只读提示 + 复制（§5.3 行 1193）。工具栏「新建提供方」入口指向
 * PROVIDER_NEW_PATH（需求 §4.6 列表/新建/编辑/启用/排序补全）。
 *
 * 取数：ListProviders **真调**（后端已实装）——全量取数
 * （buildListProvidersRequest：第 1 页 × 100，拖拽排序需全量行集，见其
 * 注释）；超限兜底停用拖拽（数据仍展示）。写路径 SetProviderEnabled /
 * SortProviders 后端已实装，单测走 msw；启停 / 拖拽均乐观更新 +
 * 失败回滚，错误文案 Toast 展示（错误展示归消费方——DataTable 行内开关同口径）。
 *
 * 401 统一跳登录（§6 行 501，account EventLogTable 同模式：会话在 GetMe
 * 之后过期等场景）；404 掩护等其余错误走页面错误态（AdminLayout 已对
 * GetMe 同口径分流，本页对列表请求补齐）。
 *
 * 组件壳 import Semi 后模块图不可在 node 测试（工具链 blocker）——
 * 可测逻辑全部收口在 ./api（请求构造 / 策略标签）与 SortableList /
 * ProviderCallbackHint（各自导出纯函数，零 Semi）。
 * 样式（§1.7）：同目录同名 module less；列布局经与表头同构的 grid 模板对齐。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { create } from '@bufbuild/protobuf';
import { Banner, Button, Empty, Spin, Tag, Toast, Typography } from '@douyinfe/semi-ui';
import { Link, useLocation, useNavigate } from '@modern-js/runtime/router';
import { patchRowByKey } from '../../shared/app-ui/dataTableLogic';
import { CopyButton } from '../../shared/components/CopyButton';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { useRequest } from 'ahooks';
import { deriveRequestStatus } from '../../shared/hooks/deriveRequestStatus';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t, type I18nKey } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { SetProviderEnabledRequestSchema } from '../../gen/proto/api/admin/v1/provider_pb';
import type { Provider } from '../../gen/proto/api/admin/v1/provider_pb';
import {
  adminReturnTo,
  apiErrorText,
  buildListProvidersRequest,
  buildSortProvidersRequest,
  isUnauthenticatedError,
  listProviders,
  policyTags,
  setProviderEnabled,
  sortProviders,
} from '../api';
import { ProviderCallbackHint } from '../components/ProviderCallbackHint';
import { SortableList } from '../components/SortableList';
import { StatusSwitch } from '../components/StatusSwitch';
import { PROVIDER_NEW_PATH, providerEditPath } from '../paths';
import styles from './ProvidersPage.module.less';

/** 行键（§5.3 行 1192：provider_key 创建后不可改，天然行键）。 */
function providerRowKey(row: Provider): string {
  return row.providerKey;
}

/** 零值占位（§9 第 18 条：protojson 省略零值 → 解码为 ''）。 */
const EMPTY_TEXT = '—';

/**
 * 表头列（与 .row 网格列一一对应；首列为 SortableList 拖拽手柄，无标题）。
 * 列序沿 §6 行 515：显示名 / 标识 / 类别 / 类型 / 状态 / 策略标签 / 排序。
 * textKey 字段化——模块级只存键（'' 为拖拽手柄空占位），渲染期 t()。
 */
const HEADER_CELL_KEYS: readonly (I18nKey | '')[] = [
  '',
  'admin.providerColumnDisplayName',
  'admin.providerColumnKey',
  'admin.providerColumnCategory',
  'admin.providerColumnType',
  'admin.statusLabel',
  'admin.providerColumnPolicyTags',
  'admin.providerColumnSortOrder',
];

/** 提供方列表页：回调提示 + 全量列表（行内启停 + 拖拽排序）。 */
export function ProvidersPage(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 列表取数改 ahooks 自动请求；401 由集中 onError 跳登录，其余
  // 错误走页面错误帧（toast:false 静默防双报）。
  const { data, error, loading } = useRequest(
    () => listProviders(buildListProvidersRequest()),
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );
  // 页内跳转换 router 导航（HashRouter SPA 内跳，不再整页刷新）。
  const navigate = useNavigate();
  // 行集本地态：列表载入同步 + 启停 / 排序写操作成功后就地补丁（乐观）。
  const [rows, setRows] = useState<readonly Provider[]>([]);
  // 写操作（启停 / 排序）失败反馈改走 Semi Toast（原就地 actionError
  // 文字已随 Semi 回归移除）；成功反馈接 Toast.success（P1-6 统一成功
  // 通道，新增最小键集 admin.provider{Enable,Disable,Sort}Success）。

  // 列表数据落地 → 同步行集（引用更换即覆盖本地补丁，DataTable 同模式）。
  useEffect(() => {
    if (data !== undefined) {
      setRows(data.items);
    }
  }, [data]);

  const total = data !== undefined ? toCount(data.total) : 0;
  // 拖拽排序需全量行集（部分行集重排会与未载入行冲突，见 buildListProvidersRequest）。
  const canDrag = rows.length === total;

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
        t(next ? 'admin.providerEnableSuccess' : 'admin.providerDisableSuccess', {
          name: row.displayName || row.providerKey,
        }),
      );
    } catch (toggleError) {
      // 失败：错误展示归消费方 + rethrow 触发 StatusSwitch 回滚。
      Toast.error(apiErrorText(toggleError));
      throw toggleError;
    }
  }

  function handleSort(next: readonly Provider[]): void {
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

  // 列表错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return <Banner type="danger" fullMode={false} description={t('admin.providersLoadFailed')} />;
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">{t('admin.navProviders')}</Typography.Title>
      {/* 新建入口（需求 §4.6 列表/新建/编辑/启用/排序；对照 OidcClientsPage 工具栏写法）。 */}
      <div className={styles.toolbar}>
        <Button theme="solid" onClick={() => void navigate(PROVIDER_NEW_PATH)}>
          {t('admin.createProviderAction')}
        </Button>
      </div>
      <ProviderCallbackHint alRoot={props.alRoot} />
      {!canDrag && total > 0 ? (
        <p className={styles.dragNote}>{t('admin.providersDragDisabledNote')}</p>
      ) : null}
      <div className={styles.headerRow}>
        {HEADER_CELL_KEYS.map((cell) => (
          <span key={cell}>{cell === '' ? '' : t(cell)}</span>
        ))}
      </div>
      <SortableList
        items={rows}
        itemKey={providerRowKey}
        onSort={handleSort}
        disabled={!canDrag}
        handleLabel={t('admin.providerDragSortLabel')}
        renderItem={(row) => {
          const tags = policyTags(row);
          return (
            <div className={styles.row}>
              <span className={styles.cellName}>
                {/* 编辑入口（§6 行 516 ProviderEditPage；去自绘主色装饰，
                    改 SPA 内 Link，路径经 providerEditPath 编码拼接）。 */}
                <Link to={providerEditPath(row.providerKey)}>
                  {row.displayName || EMPTY_TEXT}
                </Link>
              </span>
              <span className={styles.cellKey}>
                <code className={styles.keyText}>{row.providerKey}</code>
                <CopyButton text={row.providerKey} />
              </span>
              <span className={styles.cellCategory}>{row.category || EMPTY_TEXT}</span>
              <span className={styles.cellType}>
                <ProviderIcon alt={row.type} />
                <span>{row.type || EMPTY_TEXT}</span>
              </span>
              <span className={styles.cellStatus}>
                <StatusSwitch
                  isEnabled={row.isEnabled}
                  onToggle={(next) => handleToggle(row, next)}
                />
              </span>
              <span className={styles.cellTags}>
                {/* 自绘徽章换 Semi Tag（默认语义色）。 */}
                {tags.length > 0
                  ? tags.map((tag) => (
                      <Tag key={tag} size="small">
                        {tag}
                      </Tag>
                    ))
                  : EMPTY_TEXT}
              </span>
              <span className={styles.cellOrder}>{toCount(row.sortOrder)}</span>
            </div>
          );
        }}
      />
      {loading && rows.length === 0 ? (
        // 整页加载态裸文字换 Semi Spin。
        <div className={styles.stateCenter} role="status">
          <Spin size="large" />
        </div>
      ) : null}
      {/* success 空态判定走 deriveRequestStatus 派生（§5.3）。 */}
      {deriveRequestStatus(loading, error, data) === 'success' && rows.length === 0 ? (
        // 空态裸文字换 Semi Empty（默认插图 + 文案）。
        <Empty description={t('admin.noProviders')} />
      ) : null}
    </section>
  );
}

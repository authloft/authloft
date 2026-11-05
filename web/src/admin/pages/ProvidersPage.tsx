/**
 * 提供方列表页（docs/前端架构.md §6 行 515；docs/接口文档.md §5.2 行
 * 1164-1177；docs/需求.md §4.6 行 255）——/admin/providers。
 *
 * 列口径（§6 行 515）：显示名 / provider_key（可复制，shared CopyButton）/
 * 类别 / 类型（内置图标——shared ProviderIcon；§5.2 列表行集不含 icon_url
 * （该字段在 AdminProvider 详情，§5.3 行 1210），故列表恒渲染内置占位图形）/
 * 状态（StatusSwitch 行内启停）/ 策略标签（api.policyTags）/ 排序
 * （sort_order 值 + SortableList 拖拽）。顶部 ProviderCallbackHint：回调
 * 地址模板只读提示 + 复制（§5.3 行 1193）。
 *
 * 取数：ListProviders **真调**（后端已实装）——全量取数
 * （buildListProvidersRequest：第 1 页 × 100，拖拽排序需全量行集，见其
 * 注释）；超限兜底停用拖拽（数据仍展示）。写路径 SetProviderEnabled /
 * SortProviders 后端已实装，单测走 msw；启停 / 拖拽均乐观更新 +
 * 失败回滚，错误文案就地展示（错误展示归消费方——DataTable 行内开关同口径）。
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
import { Typography } from '@douyinfe/semi-ui-19';
import { patchRowByKey } from '../../shared/app-ui/dataTableLogic';
import { CopyButton } from '../../shared/components/CopyButton';
import { ProviderIcon } from '../../shared/components/ProviderIcon';
import { useRequest } from '../../shared/hooks/useRequest';
import { toCount } from '../../shared/utils/int';
import { SetProviderEnabledRequestSchema } from '../../gen/proto/api/admin/v1/provider_pb';
import type { Provider } from '../../gen/proto/api/admin/v1/provider_pb';
import {
  apiErrorText,
  buildListProvidersRequest,
  buildSortProvidersRequest,
  isUnauthenticatedError,
  listProviders,
  policyTags,
  setProviderEnabled,
  sortProviders,
} from '../api';
import { loginUrl } from '../bootstrap';
import { ProviderCallbackHint } from '../components/ProviderCallbackHint';
import { SortableList } from '../components/SortableList';
import { StatusSwitch } from '../components/StatusSwitch';
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
 */
const HEADER_CELLS: readonly string[] = [
  '',
  '显示名',
  '标识',
  '类别',
  '类型',
  '状态',
  '策略标签',
  '排序',
];

/** 提供方列表页：回调提示 + 全量列表（行内启停 + 拖拽排序）。 */
export function ProvidersPage(props: {
  /** 归一后 al_root（401 跳登录前缀 / 回调地址前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  const { status, data, error, run } = useRequest(listProviders);
  // 行集本地态：列表载入同步 + 启停 / 排序写操作成功后就地补丁（乐观）。
  const [rows, setRows] = useState<readonly Provider[]>([]);
  // 写操作（启停 / 排序）失败文案，就地展示；成功不清除由下次失败覆盖。
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下方 effect 与错误分支处理。
    run(buildListProvidersRequest()).catch(() => {});
  }, [run]);

  // 列表数据落地 → 同步行集（引用更换即覆盖本地补丁，DataTable 同模式）。
  useEffect(() => {
    if (data !== undefined) {
      setRows(data.items);
    }
  }, [data]);

  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(loginUrl(props.alRoot));
    }
  }, [error, props.alRoot]);

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
      // 成功：行数据追上乐观态（StatusSwitch 覆盖清除依赖此更新）。
      setRows((prev) =>
        patchRowByKey(prev, providerRowKey, row.providerKey, (r) => ({
          ...r,
          isEnabled: next,
        })),
      );
    } catch (toggleError) {
      // 失败：错误展示归消费方 + rethrow 触发 StatusSwitch 回滚。
      setActionError(apiErrorText(toggleError));
      throw toggleError;
    }
  }

  function handleSort(next: readonly Provider[]): void {
    const prev = rows;
    setRows(next); // 乐观：新序先行。
    sortProviders(buildSortProvidersRequest(next)).catch((sortError) => {
      setRows(prev); // 失败回滚原序。
      setActionError(apiErrorText(sortError));
    });
  }

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
    return (
      <p role="alert" className={styles.loadError}>
        提供方列表加载失败，请刷新重试
      </p>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>提供方</Typography.Title>
      <ProviderCallbackHint alRoot={props.alRoot} />
      {actionError !== null ? (
        <p role="alert" className={styles.actionError}>
          {actionError}
        </p>
      ) : null}
      {!canDrag && total > 0 ? (
        <p className={styles.dragNote}>提供方数量超过单页上限（100），拖拽排序已停用</p>
      ) : null}
      <div className={styles.headerRow}>
        {HEADER_CELLS.map((cell) => (
          <span key={cell}>{cell}</span>
        ))}
      </div>
      <SortableList
        items={rows}
        itemKey={providerRowKey}
        onSort={handleSort}
        disabled={!canDrag}
        handleLabel="拖拽调整提供方排序"
        renderItem={(row) => {
          const tags = policyTags(row);
          return (
            <div className={styles.row}>
              <span className={styles.cellName}>
                {/* 编辑入口（§6 行 516 ProviderEditPage；最小改动：显示名作链接）。 */}
                <a className={styles.editLink} href={`/admin/providers/${row.providerKey}/edit`}>
                  {row.displayName || EMPTY_TEXT}
                </a>
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
                {tags.length > 0
                  ? tags.map((tag) => (
                      <span key={tag} className={styles.tag}>
                        {tag}
                      </span>
                    ))
                  : EMPTY_TEXT}
              </span>
              <span className={styles.cellOrder}>{toCount(row.sortOrder)}</span>
            </div>
          );
        }}
      />
      {status === 'loading' && rows.length === 0 ? (
        <p role="status" className={styles.empty}>
          加载中…
        </p>
      ) : null}
      {status === 'success' && rows.length === 0 ? (
        <p role="status" className={styles.empty}>
          暂无提供方
        </p>
      ) : null}
    </section>
  );
}

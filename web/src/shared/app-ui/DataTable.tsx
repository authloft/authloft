/**
 * 通用数据表（docs/前端架构.md §3.3 行 348：分页、排序、筛选、行内开关；
 * docs/接口文档.md §1.7 分页约定）——shared/app-ui 首件，admin 与 account
 * 日志页共用设计；依赖 Semi UI，仅 account / admin 可 import（§9 第 13 条，
 * login / setup 禁）。
 *
 * 受控组件：行集 / 总数 / 查询状态全部由消费方持有，本组件只把 Semi Table
 * 的 onChange 载荷经 dataTableLogic.resolveTableQuery 归一成 TableQueryState
 * 上报（onQueryChange），消费方据此向服务端取数（§1.7 服务端分页）——回调
 * 参数归一点与行内开关的乐观更新 / 回滚编排在 dataTableLogic.ts（零 Semi
 * 依赖、node 可测；组件壳含 Semi import，渲染测试受工具链 blocker，
 * 见 account.test.tsx 头注）。
 *
 * 行内开关：switchColumn 指定一列 Semi Switch，点击后先对本地行集乐观打补丁
 * （runInlineToggle），onToggle reject 即回滚原行集；rows prop 引用更换
 * （消费方重新取数）时清除本地乐观覆盖。错误提示不在本组件：onToggle 的
 * reject 只承担「触发回滚」语义，展示归消费方在自身 onToggle 内处理。
 *
 * 样式（§1.7）：同目录同名 module less；Semi 组件样式随组件 JS 自动打包
 * （见 AppLayout 注释），此处只承载容器对接。
 */
import { useEffect, useState, type ReactNode } from 'react';
// 大包命名导入（§1.6 行 113 硬性口径：一律大包入口、禁子路径）。
import { Switch, Table } from '@douyinfe/semi-ui-19';
// ColumnProps 类型导入例外：大包入口（lib/es/index.d.ts）仅转出组件值，
// 未转出该类型——经官方 exports 白名单内的 table 子路径做纯类型导入
// （import type，编译期擦除、零运行时痕迹）。
import type { ColumnProps } from '@douyinfe/semi-ui-19/lib/es/table';
import {
  MAX_PAGE_SIZE,
  resolveTableQuery,
  runInlineToggle,
  type TableQueryState,
} from './dataTableLogic';
import styles from './DataTable.module.less';

/** 数据列规格：Semi ColumnProps 的结构化子集（受控排序 / 筛选开关）。 */
export interface DataTableColumn<T> {
  readonly dataIndex: string;
  readonly title: ReactNode;
  readonly width?: string | number;
  readonly align?: 'left' | 'center' | 'right';
  /** 单元格渲染；缺省按 dataIndex 原样展示。 */
  readonly render?: (text: unknown, row: T, index: number) => ReactNode;
  /** 服务端排序：受控（当前方向取 query.sort / query.order）。 */
  readonly sorter?: boolean;
  /** 服务端筛选下拉选项；选中值经 onQueryChange 的 filters 上报。 */
  readonly filters?: readonly { readonly value: string; readonly text: string }[];
}

/** 行内开关列规格（§3.3 行 348）：追加在列尾；乐观更新 + 失败回滚。 */
export interface DataTableSwitchColumn<T> {
  readonly dataIndex: string;
  readonly title: ReactNode;
  readonly width?: string | number;
  readonly isOn: (row: T) => boolean;
  /** 行数据不可变更新（乐观 patch 的构造点；消费方按行类型展开）。 */
  readonly toggleRow: (row: T, next: boolean) => T;
  /** 持久化；reject 即触发回滚（错误展示归消费方，见文件头）。 */
  readonly onToggle: (row: T, next: boolean) => Promise<void>;
}

export interface DataTableProps<T> {
  readonly columns: readonly DataTableColumn<T>[];
  readonly rows: readonly T[];
  /** 行键（Semi rowKey 同构；乐观覆盖的清除依赖 rows 引用比较）。 */
  readonly rowKey: (row: T) => string;
  /** 总条数（§1.7 行 278：服务端权威 total）。 */
  readonly total: number;
  readonly query: TableQueryState;
  readonly onQueryChange: (next: TableQueryState) => void;
  readonly loading?: boolean;
  /** 空态文案（Semi empty）；缺省用 Semi 内置空态。 */
  readonly empty?: ReactNode;
  /** 行内开关列；缺省无开关列。 */
  readonly switchColumn?: DataTableSwitchColumn<T>;
}

/** 页码条选项（§1.7 行 277：pageSize 上限 100）。 */
const PAGE_SIZE_OPTS: readonly number[] = [10, 20, 50, MAX_PAGE_SIZE];

/** 受控排序方向：query.order → Semi sortOrder；未激活 / 未命中列恒 false。 */
function sortOrderOf(dataIndex: string, query: TableQueryState): 'ascend' | 'descend' | false {
  if (dataIndex !== query.sort || query.order === '') {
    return false;
  }
  return query.order === 'asc' ? 'ascend' : 'descend';
}

/** 通用数据表（受控）：分页 / 排序 / 筛选 / 行内开关的共用封装。 */
export function DataTable<T extends Record<string, unknown>>(
  props: DataTableProps<T>,
): ReactNode {
  const { rows, rowKey, query, onQueryChange, switchColumn } = props;
  // 行内开关乐观覆盖：rows prop 引用更换（消费方重新取数）→ 清除，让位真值。
  const [overrideRows, setOverrideRows] = useState<readonly T[] | null>(null);
  useEffect(() => {
    setOverrideRows(null);
  }, [rows]);
  const displayRows = overrideRows ?? rows;

  async function handleToggle(row: T, next: boolean): Promise<void> {
    if (switchColumn === undefined) {
      return;
    }
    const outcome = await runInlineToggle(
      displayRows,
      rowKey,
      rowKey(row),
      (r) => switchColumn.toggleRow(r, next),
      async (patched) => {
        await switchColumn.onToggle(patched, next);
      },
    );
    // 成功 → 保留打补丁行集（乐观生效）；失败 → 原 rows（回滚）；未变更 → 清空覆盖。
    setOverrideRows(outcome.rows === rows ? null : outcome.rows);
  }

  const columns: ColumnProps<T>[] = props.columns.map((column) => ({
    dataIndex: column.dataIndex,
    title: column.title,
    width: column.width,
    align: column.align,
    render: column.render,
    sorter: column.sorter === true ? true : undefined,
    sortOrder: column.sorter === true ? sortOrderOf(column.dataIndex, query) : undefined,
    filters: column.filters !== undefined ? [...column.filters] : undefined,
    filteredValue: [...(query.filters[column.dataIndex] ?? [])],
  }));
  if (switchColumn !== undefined) {
    columns.push({
      dataIndex: switchColumn.dataIndex,
      title: switchColumn.title,
      width: switchColumn.width,
      render: (_text: unknown, row: T) => (
        <Switch
          checked={switchColumn.isOn(row)}
          onChange={(checked) => {
            void handleToggle(row, checked);
          }}
        />
      ),
    });
  }

  return (
    // 滚动容器（评审 P0-4(d)）：窄屏下表格保持可读最小宽度、
    // 列不再无限压缩，由本容器横向滚动（样式见 DataTable.module.less）。
    <div className={styles.scroll}>
      <Table<T>
        className={styles.table}
        columns={columns}
        dataSource={[...displayRows]}
        rowKey={(record) => (record === undefined ? '' : rowKey(record))}
        loading={props.loading}
        empty={props.empty}
        pagination={{
          currentPage: query.page,
          pageSize: query.pageSize,
          total: props.total,
          pageSizeOpts: [...PAGE_SIZE_OPTS],
        }}
        onChange={(changeInfo) => {
          onQueryChange(resolveTableQuery(changeInfo, query));
        }}
      />
    </div>
  );
}

/**
 * DataTable 可测纯逻辑（docs/前端架构.md §3.3 行 348 职责 / §8 行 621 测试
 * 约束；docs/接口文档.md §1.7 分页约定）。
 *
 * 落位说明（沿实测 blocker 口径，见 account/api.ts 头注）：组件壳
 * DataTable.tsx import Semi UI 后，任何含其模块图的测试文件都在 rstest
 * 0.12.5 加载期崩（lib/es 无扩展名 import 被 externalize）——分页 / 排序 /
 * 筛选回调参数的归一点与行内开关的乐观更新 / 回滚编排（§8 行 621 的被测
 * 对象）全部收口在本模块：零 Semi 依赖、node 可测；DataTable.tsx 只做受控
 * 渲染接线。admin 消费方落地时同样经本模块复用。
 *
 * 分页口径（§1.7 行 275-278）：page 从 1 开始、pageSize 默认 20 上限 100；
 * sort / order 取值由前端限定（后端不做白名单强制校验）。
 */

/** §1.7 行 277：pageSize 缺省值。 */
export const DEFAULT_PAGE_SIZE = 20;

/** §1.7 行 277：pageSize 上限。 */
export const MAX_PAGE_SIZE = 100;

/** §1.7 行 277：page 从 1 开始。 */
export const FIRST_PAGE = 1;

/** 排序方向 wire 值（§1.7 行 277：asc / desc；'' 表示当前无排序）。 */
export type TableSortOrder = 'asc' | 'desc' | '';

/**
 * 受控查询状态（§1.7 分页 + 排序 + 筛选）：消费方持有并随 onQueryChange
 * 更新，换页 / 换排序 / 换筛选后按新状态向服务端取数。filters 为筛选列
 * dataIndex → 选中值集合（Semi 筛选下拉多选语义）。
 */
export interface TableQueryState {
  readonly page: number;
  readonly pageSize: number;
  readonly sort: string;
  readonly order: TableSortOrder;
  readonly filters: Readonly<Record<string, readonly string[]>>;
}

/**
 * Semi Table onChange 载荷的结构化子集（零 Semi import；形状对齐
 * semi-foundation 的 BaseChangeInfoSorter / BaseChangeInfoFilter）：受控
 * 渲染下只消费这三段，其余字段忽略。
 */
export interface TableChangePayload {
  readonly pagination?: { readonly currentPage?: number; readonly pageSize?: number };
  readonly sorter?: { readonly dataIndex?: string; readonly sortOrder?: string | boolean };
  readonly filters?: readonly {
    readonly dataIndex?: string;
    readonly filteredValue?: readonly unknown[];
  }[];
}

/** pageSize 归一（§1.7 行 277）：缺省 20；越界夹取 [1, 100]。 */
export function clampPageSize(pageSize: number): number {
  if (!Number.isFinite(pageSize) || pageSize < 1) {
    return DEFAULT_PAGE_SIZE;
  }
  return Math.min(Math.floor(pageSize), MAX_PAGE_SIZE);
}

/** page 归一（§1.7 行 277：从 1 开始）：非有限数 / <1 夹取到 1。 */
export function clampPage(page: number): number {
  if (!Number.isFinite(page) || page < FIRST_PAGE) {
    return FIRST_PAGE;
  }
  return Math.floor(page);
}

/** 初始查询状态（§1.7 缺省：第 1 页、每页 20、无排序、无筛选）。 */
export function initialTableQuery(pageSize: number = DEFAULT_PAGE_SIZE): TableQueryState {
  return {
    page: FIRST_PAGE,
    pageSize: clampPageSize(pageSize),
    sort: '',
    order: '',
    filters: {},
  };
}

/** Semi 排序方向 → §1.7 wire 值：ascend→asc、descend→desc、其余（false / undefined）→ ''。 */
function semiOrderToWire(sortOrder: string | boolean | undefined): TableSortOrder {
  if (sortOrder === 'ascend') {
    return 'asc';
  }
  if (sortOrder === 'descend') {
    return 'desc';
  }
  return '';
}

/**
 * Semi Table onChange 载荷 → 受控查询状态（§8 行 621「分页 / 排序 / 筛选
 * 回调参数」的归一点）：
 * - 分页：currentPage / pageSize 就地归一（§1.7 夹取），缺省保持 prev
 *   （排序 / 筛选变化时 Semi 仍回传当前分页，缺省段为防御）；
 * - 排序：sorter.dataIndex + sortOrder → sort / order；清除排序（sortOrder
 *   非 ascend / descend）→ order=''（sort 保留最近排序列，受控渲染与 wire
 *   均只认非空 order）；
 * - 筛选：filters 数组 → dataIndex → 选中值映射（值收窄为 string；空 /
 *   缺省 → 空数组）；无筛选列 → {}。
 */
export function resolveTableQuery(
  payload: TableChangePayload,
  prev: TableQueryState,
): TableQueryState {
  const page =
    payload.pagination?.currentPage !== undefined
      ? clampPage(payload.pagination.currentPage)
      : prev.page;
  const pageSize =
    payload.pagination?.pageSize !== undefined
      ? clampPageSize(payload.pagination.pageSize)
      : prev.pageSize;
  const sort = payload.sorter?.dataIndex ?? '';
  const order = sort === '' ? '' : semiOrderToWire(payload.sorter?.sortOrder);
  const filters: Record<string, readonly string[]> = {};
  for (const column of payload.filters ?? []) {
    if (column.dataIndex !== undefined) {
      filters[column.dataIndex] = (column.filteredValue ?? []).map((value) => String(value));
    }
  }
  return { page, pageSize, sort, order, filters };
}

/**
 * 行内开关行集的不可变更新（§3.3 行 348 行内开关 / §8 行 621 乐观更新）：
 * update 只作用于命中行（keyOf(row) === key）；未命中任何行 → 原数组引用原样
 * 返回。原数组与行对象永不改动（不可变），调用方保留旧引用即回滚依据。
 */
export function patchRowByKey<T>(
  rows: readonly T[],
  keyOf: (row: T) => string,
  key: string,
  update: (row: T) => T,
): readonly T[] {
  let hit = false;
  const next = rows.map((row) => {
    if (keyOf(row) === key) {
      hit = true;
      return update(row);
    }
    return row;
  });
  return hit ? next : rows;
}

/** 行内开关编排结果：ok=false（persist 失败）时 rows 为回滚后的行集。 */
export interface InlineToggleOutcome<T> {
  readonly ok: boolean;
  readonly rows: readonly T[];
}

/**
 * 行内开关编排（§8 行 621「乐观更新与回滚」）：
 * 1. 乐观更新：立即对命中行应用 update（UI 随行集先行反映新状态）；
 * 2. persist 成功 → { ok: true, rows: 打补丁行集 }；
 * 3. persist 失败 → { ok: false, rows: 原 rows 引用 }——回滚 = 恢复未打补丁
 *    的原数组（不可变前提保证其完好）；
 * 4. key 未命中任何行 → 不调 persist、原样返回（无可变更项）。
 * persist 收到的参数为打补丁后的行（消费方据此发持久化请求）。
 */
export async function runInlineToggle<T>(
  rows: readonly T[],
  keyOf: (row: T) => string,
  key: string,
  update: (row: T) => T,
  persist: (patched: T) => Promise<void>,
): Promise<InlineToggleOutcome<T>> {
  const next = patchRowByKey(rows, keyOf, key, update);
  const patched = next === rows ? undefined : next.find((row) => keyOf(row) === key);
  if (patched === undefined) {
    return { ok: true, rows };
  }
  try {
    await persist(patched);
    return { ok: true, rows: next };
  } catch {
    return { ok: false, rows };
  }
}

/**
 * 行内开关 per-row 防重守卫（P0-1，定稿 §6.1）：tryEnter 首次返回
 * true 并登记在途；同 key 在途期间再次 tryEnter 返回 false——调用方据此
 * no-op（连点两次只发一次 persist）；leave 解除登记（finally 中调用，
 * 成功 / 失败均放行下一次）。判定必须同步（React state 异步更新挡不住
 * 同一拍内的连续点击），故状态封装在闭包内、组件以 useRef 持有跨渲染
 * 存活；零 Semi 依赖，node 可测。
 */
export interface InflightGuard {
  /** 进入在途：已在途 → false（重复触发应 no-op）。 */
  tryEnter(key: string): boolean;
  /** 离开在途（成功 / 失败均须调用，否则该行永久锁死）。 */
  leave(key: string): void;
  /** 当前在途判定（渲染行内 Switch loading 用）。 */
  has(key: string): boolean;
}

/** 创建 per-row 防重守卫（每组件实例一个，useRef 持有）。 */
export function createInflightGuard(): InflightGuard {
  const inflight = new Set<string>();
  return {
    tryEnter(key) {
      if (inflight.has(key)) {
        return false;
      }
      inflight.add(key);
      return true;
    },
    leave(key) {
      inflight.delete(key);
    },
    has(key) {
      return inflight.has(key);
    },
  };
}

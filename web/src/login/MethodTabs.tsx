/**
 * 登录方式列表（docs/前端架构.md §4.1 行 384、§8.2 行 582）：
 * tab（普通主因子方式）+ 图标墙（thirdparty providers）两种形态（§4.1 行 384
 * 「tab / 图标墙」，实现取最简）。
 *
 * - 数据只来自注入快照 methods（§2.1）：服务端生成快照时已按 sort_order /
 *   ui_group 排序（后端架构 §3 methods.go「方式列表快照生成」），method 级
 *   顺序即数组顺序、前端不重排、不另发请求（页面存活期内不刷新，§2.1 行 410）；
 * - 不展示未启用项（快照本身不注入未启用 / usage 不匹配的方式，§2.1 行 406；
 *   此处再按 usage 含 primary 防御过滤——login 页只展示主因子方式，§2.1）；
 * - ui_group 分组与 sort_order 排序在 wire 上仅存在于 thirdparty.providers
 *   （§2.7.1 行 566-572 的 uiGroup / sortOrder，快照类型 shared/types/init.ts
 *   SnapshotProvider）——图标墙按 uiGroup 分组、组内按 sortOrder 升序
 *   （int64 十进制字符串，§1.12，BigInt 解析后比较、非法串兜底 0）；
 * - capability 不满足的方法自动隐藏（需求 §4.1.6 行 105：不展示「不支持」
 *   提示；消费 useCapability——逐条目在子组件内调用，遵守 hook 规则）；
 * - thirdparty 中 channel=api 的 provider 不渲染（§4.3 行 440：wx.login 由
 *   宿主承载，Authloft 前端不实现）；图标墙的点击分派（redirect 取
 *   authorize_url / qrcode 打开面板）归 ProviderButtons 因子实现（后续），本实现
 *   仅渲染展示。
 *
 * 文案：方式名取 i18n 字典 factors.*（§1.10 因子全集，缺键回显键本身可见
 * 可排查）；空状态 / 引导提示在字典无键，中文字面量 + 注释声明，扩键归
 * 后续 i18n 实现。
 */
import { t } from '../shared/i18n';
import { useCapability } from '../shared/hooks/useCapability';
import type { LoginMethodEntry, SnapshotProvider } from '../shared/types/init';

export interface MethodTabsProps {
  /** 注入快照的登录方式列表（§2.1）。 */
  methods: readonly LoginMethodEntry[];
  /** 当前方式（空串 = 未选择）。 */
  current: string;
  /** 选择方式（容器推导 firstStep 后 dispatch select_method）。 */
  onSelect: (method: string) => void;
}

/** 空状态文案（i18n 无键，字面量声明见文件头）。 */
const EMPTY_TEXT = '暂无可用登录方式';

/** 未选择方式时的引导文案（同上）。 */
const SELECT_HINT_TEXT = '请选择登录方式';

/** 图标墙不渲染的 channel（§4.3 行 440：api 由宿主承载）。 */
const HIDDEN_CHANNELS: ReadonlySet<string> = new Set(['api']);

/**
 * sortOrder 排序键：int64 十进制字符串（§1.12）→ bigint 比较基准（不转
 * number，防超 2^53 丢精度）；缺失 / 空串 / 非法串兜底 0（§9 第 18 条）。
 */
function sortOrderKey(provider: SnapshotProvider): bigint {
  try {
    return BigInt(provider.sortOrder ?? '');
  } catch {
    return BigInt(0);
  }
}

/** 组内按 sortOrder 升序（bigint 比较，无精度损失）。 */
function compareBySortOrder(
  a: SnapshotProvider,
  b: SnapshotProvider,
): number {
  const x = sortOrderKey(a);
  const y = sortOrderKey(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * 图标墙分组（纯函数，可测）：过滤 channel=api → 按 sortOrder 升序 → 按
 * uiGroup 分组（Map 保插入序，组序 = 排序后首元素的出现顺序；uiGroup 缺省
 * 归空串组）。
 */
export function groupProviders(
  providers: readonly SnapshotProvider[],
): ReadonlyMap<string, SnapshotProvider[]> {
  const sorted = providers
    .filter((p) => !HIDDEN_CHANNELS.has(p.channel))
    .sort(compareBySortOrder);
  const groups = new Map<string, SnapshotProvider[]>();
  for (const p of sorted) {
    const key = p.uiGroup ?? '';
    const bucket = groups.get(key);
    if (bucket === undefined) {
      groups.set(key, [p]);
    } else {
      bucket.push(p);
    }
  }
  return groups;
}

export function MethodTabs({ methods, current, onSelect }: MethodTabsProps) {
  const tabs = methods.filter(
    (m) => m.method !== 'thirdparty' && (m.usage ?? []).includes('primary'),
  );
  const thirdparty = methods.find((m) => m.method === 'thirdparty');
  const empty = tabs.length === 0 && thirdparty === undefined;

  return (
    <nav>
      {empty && <p role="status">{EMPTY_TEXT}</p>}
      <ul style={listStyle}>
        {tabs.map((entry) => (
          <MethodTabItem
            key={entry.method}
            entry={entry}
            current={current}
            onSelect={onSelect}
          />
        ))}
      </ul>
      {thirdparty !== undefined && <ProviderWall entry={thirdparty} />}
    </nav>
  );
}

/** 单个方式 tab：capability 检测在子组件内消费 useCapability（hook 规则）。 */
function MethodTabItem({
  entry,
  current,
  onSelect,
}: {
  entry: LoginMethodEntry;
  current: string;
  onSelect: (method: string) => void;
}) {
  const capable = useCapability(entry.capability);
  if (!capable) {
    // 需求 §4.1.6 行 105：浏览器 / 设备不支持时自动不展示（无「不支持」提示）。
    return null;
  }
  const selected = entry.method === current;
  return (
    <li>
      <button
        type="button"
        style={selected ? activeTabStyle : tabStyle}
        aria-current={selected ? 'true' : undefined}
        onClick={() => onSelect(entry.method)}
      >
        {t(`factors.${entry.method}`)}
      </button>
    </li>
  );
}

/**
 * thirdparty 图标墙（§4.1 行 384「图标墙」形态）：uiGroup 分组 + sortOrder
 * 排序（见 groupProviders）；点击分派归 ProviderButtons 因子实现（后续），
 * 本实现仅渲染（按钮不绑定行为）。
 */
function ProviderWall({ entry }: { entry: LoginMethodEntry }) {
  const groups = groupProviders(entry.providers ?? []);
  if (groups.size === 0) {
    return null;
  }
  return (
    <div>
      {[...groups.entries()].map(([group, providers]) => (
        <div key={group} data-group={group} style={groupStyle}>
          {providers.map((p) => (
            <button
              key={p.providerKey}
              type="button"
              style={providerStyle}
              title={p.displayName ?? p.providerKey}
            >
              {p.icon ? <img src={p.icon} alt="" style={iconStyle} /> : null}
              <span>{p.displayName ?? p.providerKey}</span>
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

/** 供视图层复用的引导文案（与 EMPTY_TEXT 同源声明）。 */
export const SELECT_HINT = SELECT_HINT_TEXT;

const listStyle = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '0.5rem',
  listStyle: 'none',
  margin: 0,
  padding: 0,
} as const;

const tabStyle = {
  padding: '0.375rem 0.875rem',
} as const;

const activeTabStyle = {
  ...tabStyle,
  fontWeight: 700,
  textDecoration: 'underline',
} as const;

const groupStyle = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '0.5rem',
  marginTop: '0.75rem',
} as const;

const providerStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.375rem',
  padding: '0.375rem 0.625rem',
} as const;

const iconStyle = {
  width: '1.25rem',
  height: '1.25rem',
} as const;

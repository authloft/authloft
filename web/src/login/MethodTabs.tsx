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
 * - thirdparty 图标墙（uiGroup 分组 / sortOrder 排序 / 点击分派）归
 *   factors/ProviderButtons 渲染（§4.3 行 454「图标墙 + 按 channel 分派」
 *   的唯一实现，防双份渲染）：本组件只负责安放
 *   （传入 providers），不再自带图标墙实现；groupProviders 纯函数随之迁至
 *   ProviderButtons，此处 re-export 保持既有导入面（login-container.test）；
 * - capability 不满足的方法自动隐藏（需求 §4.1.6 行 105：不展示「不支持」
 *   提示）；可见性口径与首屏默认选中共用纯函数 primaryTabMethods（唯一定义，
 *   供 LoginContainer 复用），能力检测走 resolveCapability（非 hook，可在
 *   filter 内逐条目求值；页面存活期内能力视为恒定）。
 *
 * 文案：方式名取 i18n 字典 factors.*（§1.10 因子全集，缺键回显键本身可见
 * 可排查）；空状态 / 引导提示经 i18n 字典 login.* 键取用。
 */
import type { LoginFlowResponse } from '../gen/proto/api/sso/v1/envelope_pb';
import { resolveCapability } from '../shared/hooks/useCapability';
import { t } from '../shared/i18n';
import type { LoginMethodEntry } from '../shared/types/init';
import { Tabs } from './components/Tabs';
import { ProviderButtons } from './factors/ProviderButtons';

/** 图标墙分组纯函数自 ProviderButtons 迁入，re-export 保持既有导入面。 */
export { groupProviders } from './factors/ProviderButtons';

/**
 * 可见的主因子 tab（登录页 tab 的唯一口径）：MethodTabs 渲染与
 * LoginContainer 首屏默认选中共同消费，避免「选中了但页面上没有」的错位。
 *
 * - 排除 thirdparty（图标墙由 ProviderButtons 承载，§4.1 行 384）；
 * - 仅 usage 含 primary（§2.1：login 页只展示主因子方式）；
 * - capability 不满足自动隐藏（需求 §4.1.6 行 105）：resolveCapability
 *   纯函数求值（非 hook，可在 filter 内逐条目调用）；
 * - 顺序沿用注入快照数组序（后端 sort_order / ui_group 已排序，§2.1）。
 */
export function primaryTabMethods(
  methods: LoginMethodEntry[],
): LoginMethodEntry[] {
  return methods.filter(
    (m) =>
      m.method !== 'thirdparty' &&
      (m.usage ?? []).includes('primary') &&
      resolveCapability(m.capability),
  );
}

export interface MethodTabsProps {
  /** 注入快照的登录方式列表（§2.1）。 */
  methods: LoginMethodEntry[];
  /** 当前方式（空串 = 未选择）。 */
  current: string;
  /** 选择方式（容器推导 firstStep 后 dispatch select_method）。 */
  onSelect: (method: string) => void;
  /**
   * 扫码登录结论上抛：透传 ProviderButtons → QRCodeStep——
   * binding_required / 失败态交容器状态机分派（§2.8 行 739-743）。
   */
  onQrResult?: (envelope: LoginFlowResponse) => void;
}

export function MethodTabs({
  methods,
  current,
  onSelect,
  onQrResult,
}: MethodTabsProps) {
  const tabs = primaryTabMethods(methods);
  const thirdparty = methods.find((m) => m.method === 'thirdparty');
  const empty = tabs.length === 0 && thirdparty === undefined;

  if (empty) {
    return <p role="status">{t('login.noMethods')}</p>;
  }

  return (
    <>
      <Tabs
        tabList={tabs.map((entry) => ({
          itemKey: entry.method,
          title: t(`factors.${entry.method}`),
        }))}
        activeKey={current}
        onChange={onSelect}
      />
      {thirdparty !== undefined && (
        <ProviderButtons
          providers={thirdparty.providers ?? []}
          onQrResult={onQrResult}
        />
      )}
    </>
  );
}

/**
 * i18n 取文案入口（docs/前端架构.md §3.4 行 343）：按 key 取文案 + 最简语言
 * 选择（模块级当前语言，zh-CN 默认；entry 挂载时按需 setLocale）。
 *
 * - 缺译不许静默回退 undefined：当前语言缺键 → zh-CN（默认语言）→ 键本身
 *   回显（可见、可排查），绝不返回 undefined；
 * - zh / en 两套 key 全量对齐由类型系统强制（en-US 以 I18nMessages 约束），
 *   另有运行时键集对齐测试兜底；
 * - 插值：`{name}` 占位，params 提供则替换，未提供的占位保留原样。
 */
import { zhCN, type I18nMessages } from './zh-CN';
import { enUS } from './en-US';

export type Locale = 'zh-CN' | 'en-US';
export type I18nKey = keyof I18nMessages;

/** 当前支持的语言包；键集互为镜像（I18nMessages 编译期强制）。 */
const DICTIONARIES: Readonly<Record<Locale, I18nMessages>> = {
  'zh-CN': zhCN,
  'en-US': enUS,
};

const DEFAULT_LOCALE: Locale = 'zh-CN';

let currentLocale: Locale = DEFAULT_LOCALE;

/**
 * 任意输入（如 navigator.language）归一到受支持语言：en 前缀 → en-US，
 * 其余（含空串 / 未知值）→ zh-CN（默认）。
 */
export function normalizeLocale(input: string): Locale {
  return input.toLowerCase().startsWith('en') ? 'en-US' : 'zh-CN';
}

/** 当前语言（默认 zh-CN）。 */
export function getLocale(): Locale {
  return currentLocale;
}

/** 切换语言（最简实现：模块级变量；未知取值归一到 zh-CN）。 */
export function setLocale(locale: string): void {
  currentLocale = normalizeLocale(locale);
}

/** key 在当前语言或默认语言中可译。 */
export function hasKey(key: string): boolean {
  const dict = DICTIONARIES[currentLocale] as Record<string, string>;
  const fallback = DICTIONARIES[DEFAULT_LOCALE] as Record<string, string>;
  return (
    Object.prototype.hasOwnProperty.call(dict, key) ||
    Object.prototype.hasOwnProperty.call(fallback, key)
  );
}

/** `模板 {name}` 插值：params 命中则替换为字符串，未命中保留占位原样。 */
export function interpolate(
  template: string,
  params: Readonly<Record<string, string | number>>,
): string {
  return template.replace(/\{(\w+)\}/g, (placeholder, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name)
      ? String(params[name])
      : placeholder,
  );
}

/**
 * 按 key 取文案：当前语言 → zh-CN（默认语言）→ 键本身回显（缺译可见，
 * 绝不 undefined）；params 提供则做 `{name}` 插值。
 */
export function t(
  key: string,
  params?: Readonly<Record<string, string | number>>,
): string {
  const dict = DICTIONARIES[currentLocale] as Record<string, string>;
  const fallback = DICTIONARIES[DEFAULT_LOCALE] as Record<string, string>;
  const raw = Object.prototype.hasOwnProperty.call(dict, key)
    ? dict[key]
    : Object.prototype.hasOwnProperty.call(fallback, key)
      ? fallback[key]
      : key;
  return params === undefined ? raw : interpolate(raw, params);
}

export type { I18nMessages } from './zh-CN';

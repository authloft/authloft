/**
 * Provider 动态表单 schema 驱动纯逻辑（docs/前端架构.md §6 行 508-510；
 * docs/接口文档.md §5.3 行 1181-1243）。
 *
 * 渲染壳（SchemaForm / FieldRegistry / fields）import Semi 后模块图不可在
 * node 测试（工具链 blocker）——schema 驱动逻辑全部收口在本模块
 * （零 Semi 依赖，node 可测）：五区块分组 / 默认值应用 / 详情回填 /
 * 提交前校验 / 提交体构造 / provider_key 唯一性预检。
 *
 * 值模型（§5.3 行 1183「提交体即 {"<key>": <value>}」）：
 * - text / secret / select → string；checkbox → boolean；number → number；
 * - json → string（编辑文本态：回填 stringify、提交前 parse 回对象，
 *   合法性由 validateSchemaValues 前置保证）。
 */
import type { JsonObject, JsonValue } from '@bufbuild/protobuf';
import type { Value } from '@bufbuild/protobuf/wkt';
import type {
  SchemaField,
  SchemaResponse,
} from '../../gen/proto/api/admin/v1/schema_pb';
import type {
  AdminProvider,
  Provider,
} from '../../gen/proto/api/admin/v1/provider_pb';

/**
 * 表单五区块（§5.3 行 1185 封闭值域：basic / credential / endpoint（整块
 * 默认折叠）/ display / policy）；渲染序固定按本数组。
 */
export const SECTION_ORDER: readonly string[] = [
  'basic',
  'credential',
  'endpoint',
  'display',
  'policy',
];

/** 区块标题（§5.3 行 1185 括注逐字）。 */
export const SECTION_TITLES: Readonly<Record<string, string>> = {
  basic: '基础信息',
  credential: '凭证',
  endpoint: '端点',
  display: '展示与排序',
  policy: '策略开关',
};

/** 六种字段类型（§5.3 行 1229 唯一定义：管理后台只用到这六个）。 */
export const FIELD_TYPES: readonly string[] = [
  'text',
  'secret',
  'checkbox',
  'number',
  'select',
  'json',
];

/**
 * 按五区块分组（§5.3 行 1185：同一字段在五区块中的顺序沿用 fields[]
 * 数组顺序）——返回与 SECTION_ORDER 对齐的五个组（空区块为空数组，
 * 消费方自行跳过）。**section 缺失 / 非法即 throw**（前端架构 §6 行 508：
 * 不维护 key → 区块映射表，section 缺失即报错；§5.3 行 1185「每个字段都
 * 必须带 section」——protojson 零值省略下缺失即空串）。
 */
export function groupFieldsBySection(
  fields: readonly SchemaField[],
): readonly (readonly SchemaField[])[] {
  const groups: SchemaField[][] = SECTION_ORDER.map(() => []);
  for (const field of fields) {
    const index = SECTION_ORDER.indexOf(field.section);
    if (index < 0) {
      throw new Error(
        `provider schema 字段 ${JSON.stringify(field.key)} 的 section 缺失或非法：${JSON.stringify(field.section)}`,
      );
    }
    groups[index].push(field);
  }
  return groups;
}

/**
 * google.protobuf.Value → JSON 值（§5.3 行 1183 default 为任意 JSON 值）。
 * 后端 dto 构造集（dto/admin.go：NewStringValue / NewNumberValue /
 * NewBoolValue）之外的结构仅防御性覆盖，不额外造语义。
 */
function valueToJson(value: Value | undefined): JsonValue {
  if (value === undefined) {
    return null;
  }
  const kind = value.kind;
  switch (kind.case) {
    case 'boolValue':
    case 'numberValue':
    case 'stringValue':
      return kind.value;
    case 'nullValue':
      return null;
    case 'listValue':
      return kind.value.values.map((item) => valueToJson(item));
    case 'structValue': {
      const out: JsonObject = {};
      for (const [key, item] of Object.entries(kind.value.fields)) {
        out[key] = valueToJson(item);
      }
      return out;
    }
    default:
      return null;
  }
}

/** 类型零值（schema 未下发 default 时的初始态）。 */
function zeroValueFor(field: SchemaField): unknown {
  switch (field.type) {
    case 'checkbox':
      return false;
    case 'number':
      return 0;
    default:
      // text / secret / select / json 及未知类型（§12.9 行 1754：type 跨版本
      // 可能新增，string 承载）统一按文本零值兜底。
      return '';
  }
}

/**
 * Ext / json 字段值归一：对象 / 数组 → 格式化 JSON 文本（json 字段的编辑
 * 文本态）；其余原样。回填（adminProviderToValues）与默认值
 * （applySchemaDefaults）共用。
 */
function normalizeForForm(field: SchemaField, value: unknown): unknown {
  if (field.type === 'json' && typeof value === 'object' && value !== null) {
    return JSON.stringify(value, null, 2);
  }
  return value;
}

/**
 * 新建初始值（§5.3 行 1183 default 修饰）：default 有值按 default（json
 * 字段 stringify 为编辑文本），未下发按类型零值。
 */
export function applySchemaDefaults(
  fields: readonly SchemaField[],
): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const field of fields) {
    const fallback = valueToJson(field.default);
    values[field.key] =
      fallback !== null
        ? normalizeForForm(field, fallback)
        : zeroValueFor(field);
  }
  return values;
}

/**
 * 新建表单初始值（新建链路 category 死锁修正）。死锁链路：
 * category 字段无 default 修饰 → applySchemaDefaults 落零值 ''，而该字段
 * 恒在锁定键（§5.3 行 1195「由注册表按 type 决定，只读」）禁用无法编辑，
 * required:true 又必拦「此项为必填」→ 新建 Provider 无法保存；即便放行，
 * 提交 category:'' 也会被后端一致性校验拒绝（c != meta.Category）。
 * 修正：category 以 SchemaResponse 顶层 category 预填（注册表权威，
 * §5.3 行 1183 输出结构 / 行 1195），其余字段沿用 default / 零值口径。
 * 编辑链路不经过本函数（adminProviderToValues 从行现值回填）。
 */
export function initialCreateValues(
  schema: SchemaResponse,
): Record<string, unknown> {
  const values = applySchemaDefaults(schema.fields);
  values.category = schema.category;
  return values;
}

/**
 * provider 表列 wire 名 → AdminProvider typed 属性的机械映射（§5.3 行
 * 1241：表列封闭集，created_at / updated_at / ext 不进表单；type 由页面级
 * 下拉持有不在 schema fields 内）。**这不是 key → 区块映射**（§6 行 508
 * 禁令针对的是 section 归属；本表是 wire 名 ↔ 生成物属性名的恒等换名）。
 */
const TABLE_COLUMN_GETTERS: Readonly<
  Record<string, (provider: AdminProvider) => unknown>
> = {
  provider_key: (p) => p.providerKey,
  display_name: (p) => p.displayName,
  category: (p) => p.category,
  union_provider: (p) => p.unionProvider,
  is_enabled: (p) => p.isEnabled,
  enable_signin: (p) => p.enableSignin,
  enable_signup: (p) => p.enableSignup,
  auto_bind: (p) => p.autoBind,
  auto_bind_fields: (p) => p.autoBindFields,
  ui_group: (p) => p.uiGroup,
  // int64 → number：sort_order 值域 1..n（§5.2 行 1174 拖拽重排），安全。
  sort_order: (p) => Number(p.sortOrder),
  icon_url: (p) => p.iconUrl,
  remark: (p) => p.remark,
};

/**
 * 编辑回填（§5.2 行 1170 GetProvider → AdminProvider）：表列字段取 typed
 * 属性，其余（Ext 字段）取 ext JsonObject（键即 schema 的 key，§5.3 行
 * 1183）；缺失键按类型零值。category / provider_key 等锁定键的禁用态由
 * 消费方（SchemaForm lockedKeys）决定，本函数只管值。
 */
export function adminProviderToValues(
  fields: readonly SchemaField[],
  provider: AdminProvider,
): Record<string, unknown> {
  const ext: JsonObject = provider.ext ?? {};
  const values: Record<string, unknown> = {};
  for (const field of fields) {
    const getter = TABLE_COLUMN_GETTERS[field.key];
    if (getter !== undefined) {
      values[field.key] = normalizeForForm(field, getter(provider));
      continue;
    }
    const raw = Object.prototype.hasOwnProperty.call(ext, field.key)
      ? ext[field.key]
      : undefined;
    values[field.key] =
      raw === undefined ? zeroValueFor(field) : normalizeForForm(field, raw);
  }
  return values;
}

/**
 * 提交前校验（§5.3 修饰 required / pattern + 类型合法性）→ 字段键 →
 * 文案（消费方按键定位渲染在字段下方）：
 * - required：空值（undefined / null / ''）即拦截（checkbox 不适用——
 *   false 是合法值，§5.3 开关字段均无 required）；
 * - pattern：非空字符串不匹配即拦截（空值交 required；icon_url 等
 *   非必填字段留空放行，§5.3 行 1213「留空时渲染占位」）；
 * - number：非 number 即拦截（受控态由渲染器保证，此处兜底）；
 * - json：非空文本 JSON.parse 失败即拦截（空文本 = 未设置，放行）。
 */
export function validateSchemaValues(
  fields: readonly SchemaField[],
  values: Readonly<Record<string, unknown>>,
): Record<string, string> {
  const issues: Record<string, string> = {};
  for (const field of fields) {
    const value = values[field.key];
    if (field.type !== 'checkbox' && field.required && isEmptyValue(value)) {
      issues[field.key] = '此项为必填';
      continue;
    }
    if (
      field.pattern !== '' &&
      typeof value === 'string' &&
      value !== '' &&
      !new RegExp(field.pattern).test(value)
    ) {
      issues[field.key] = '格式不正确';
      continue;
    }
    if (field.type === 'number' && !isEmptyValue(value) && typeof value !== 'number') {
      issues[field.key] = '必须是数字';
      continue;
    }
    if (
      field.type === 'json' &&
      typeof value === 'string' &&
      value.trim() !== ''
    ) {
      try {
        JSON.parse(value);
      } catch {
        issues[field.key] = '不是合法的 JSON';
      }
    }
  }
  return issues;
}

function isEmptyValue(value: unknown): boolean {
  return value === undefined || value === null || value === '';
}

/**
 * provider_key 唯一性预检数据源判定（前端架构 §6 行 516「保存前校验
 * provider_key 唯一性与字符集」）：列表行集（buildListProvidersRequest
 * 全量取数）中已存在同 key 即冲突。预检失败（列表请求不可用）时消费方
 * 直接提交，由后端 uk 冲突 already_exists（§5.2 行 1179 写操作口径）兜底。
 */
export function isProviderKeyTaken(
  providerKey: string,
  rows: readonly Provider[],
): boolean {
  return (
    providerKey !== '' && rows.some((row) => row.providerKey === providerKey)
  );
}

/**
 * 提交体构造（§5.3 行 1183：提交体即 {"<key>": <value>}；后端
 * service/admin/provider.go CreateProvider 从提交体取 type 定位注册表，
 * 故顶层恒带 type）。json 字段文本 parse 回对象（合法性由
 * validateSchemaValues 前置保证——先校验后构造是本模块的消费契约）；
 * 空 json 文本省略键（未设置）。Create 全量提交；Update 同一构造
 * （后端 PATCH over schema 键集，缺省保留）。
 */
export function buildProviderStruct(
  providerType: string,
  fields: readonly SchemaField[],
  values: Readonly<Record<string, unknown>>,
): JsonObject {
  const out: JsonObject = { type: providerType };
  for (const field of fields) {
    const value = values[field.key];
    if (field.type === 'json') {
      const text = typeof value === 'string' ? value : '';
      if (text.trim() === '') {
        continue;
      }
      out[field.key] = JSON.parse(text) as JsonValue;
      continue;
    }
    out[field.key] = value as JsonValue;
  }
  return out;
}

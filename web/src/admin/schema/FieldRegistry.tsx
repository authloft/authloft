/**
 * 字段类型 → 渲染器注册表（docs/前端架构.md §6 行 509）：六种字段类型与
 * 三个修饰的**唯一定义在接口文档 §5.3 行 1229**——本模块只做 type → 渲染
 * 组件的分派，语义（section 分组 / 默认值 / 校验）全部在 schemaLogic。
 * 新增渠道类型不改前端（§5.3 行 1185/1229）：未知 type 走占位渲染。
 */
import type { ReactNode } from 'react';
import type { SchemaField } from '../../gen/proto/api/admin/v1/schema_pb';
import {
  CheckboxField,
  JsonField,
  NumberField,
  SecretField,
  SelectField,
  TextField,
  UnsupportedField,
} from './fields/FieldRenderers';

/** 字段渲染器入参（值模型见 schemaLogic 文件头）。 */
export interface FieldRendererProps {
  field: SchemaField;
  /** 当前值（json → string 文本态；text/secret/select → string；checkbox → boolean；number → number）。 */
  value: unknown;
  onChange: (value: unknown) => void;
  /** 禁用（提交中 / 锁定键，如 category 只读、provider_key 编辑锁）。 */
  disabled: boolean;
  /** 该字段的校验文案（validateSchemaValues 产物按键定位；undefined = 无问题）。 */
  issue: string | undefined;
  /** 字段扩展位（SchemaForm fieldExtra 注入，如 icon_url 预览）。 */
  extra: ReactNode;
}

export type FieldRenderer = (props: FieldRendererProps) => ReactNode;

/** 六种类型的渲染器注册表（§5.3 行 1229）。 */
export const FIELD_RENDERERS: Readonly<Record<string, FieldRenderer>> = {
  text: TextField,
  secret: SecretField,
  checkbox: CheckboxField,
  number: NumberField,
  select: SelectField,
  json: JsonField,
};

/** 分派：已知六类型 → 对应渲染器；未知 type → 占位渲染（不丢值不崩）。 */
export function resolveFieldRenderer(type: string): FieldRenderer {
  return FIELD_RENDERERS[type] ?? UnsupportedField;
}

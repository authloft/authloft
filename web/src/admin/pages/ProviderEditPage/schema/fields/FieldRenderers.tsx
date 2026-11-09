/**
 * 六种字段类型的渲染实现（docs/前端架构.md §6 行 510；docs/接口文档.md
 * §5.3 行 1229 唯一定义：text / secret / checkbox / number / select / json；
 * 修饰三个：advanced / pattern / default 的语义在 schemaLogic，本文件只管
 * 字段装配）。
 *
 * 【Semi Form 化】全部改用 `Form.*` 字段组件：值、onChange、label 关联、
 * 必填星号、help / extra 与校验文案由外层 `<Form>` 托管（CODE_GUIDE §2.4
 * 「admin 用 Semi UI 自带表单校验」），本文件零受控 state。字段必须挂在
 * `<Form>` 内渲染（FormApiContext / FormStateContext 由 Form 提供）。
 *
 * Semi UI 经大包入口命名导入（§1.6 行 113 硬性口径）；未知 type 渲染
 * 禁用占位不崩（§12.9 行 1754：fields[].type 跨版本可能新增）。
 * 样式复用 ../SchemaForm.module.less（字段装配属表单布局；跨文件共享
 * 同一 CSS Modules 映射，§1.7）。
 */
import type { ReactNode } from 'react';
import { Form } from '@douyinfe/semi-ui';
import type { SchemaField } from '@/gen/proto/api/admin/v1/schema_pb';
import { t } from '@/shared/i18n';
import type { FieldRendererProps } from '../FieldRegistry';
import styles from '../SchemaForm.module.less';

/** 字段 label（Semi LabelProps：required 驱动必填星号 + 自动关联控件）。 */
function fieldLabel(field: SchemaField): {
  text: string;
  required: boolean;
} {
  return { text: field.label, required: field.required };
}

/** help 文案（空串不传，避免渲染空占位）。 */
function fieldHelp(field: SchemaField): string | undefined {
  return field.help !== '' ? field.help : undefined;
}

/**
 * 文本类字段保留空串：Semi Form 默认把清空值转 undefined 并从 formState
 * 删键，会让 buildProviderStruct 提交 undefined（原受控实现是 ''）。
 */
const KEEP_EMPTY_STRING = true;

/** text：单行文本（扩展位如 icon_url 预览挂 suffix，保持输入框内联）。 */
export function TextField(props: FieldRendererProps): ReactNode {
  return (
    <Form.Input
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      suffix={props.extra}
      allowEmptyString={KEEP_EMPTY_STRING}
      disabled={props.disabled}
    />
  );
}

/** secret：密码态输入（Semi Input 自带可见性切换）。 */
export function SecretField(props: FieldRendererProps): ReactNode {
  return (
    <Form.Input
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      suffix={props.extra}
      mode="password"
      autoComplete="new-password"
      allowEmptyString={KEEP_EMPTY_STRING}
      disabled={props.disabled}
    />
  );
}

/** checkbox：开关（Form 托管 checked 布尔值）。 */
export function CheckboxField(props: FieldRendererProps): ReactNode {
  return (
    <Form.Checkbox
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      extraText={props.extra}
      disabled={props.disabled}
    />
  );
}

/** number：数字（InputNumber 的 onChange 可能回 string，convert 归一为 number）。 */
export function NumberField(props: FieldRendererProps): ReactNode {
  return (
    <Form.InputNumber
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      extraText={props.extra}
      convert={(value: unknown) =>
        typeof value === 'number' ? value : Number(value) || 0
      }
      disabled={props.disabled}
    />
  );
}

/** select：取值集合即 options（§5.3 行 1229 与 §1.11 同名同义）。 */
export function SelectField(props: FieldRendererProps): ReactNode {
  return (
    <Form.Select
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      extraText={props.extra}
      optionList={props.field.options.map((option) => ({
        value: option,
        label: option,
      }))}
      placeholder={t('common.selectPlaceholder')}
      convert={(value: unknown) =>
        value === undefined || value === null ? '' : String(value)
      }
      disabled={props.disabled}
    />
  );
}

/** json：JSON 文本域（值模型 string，提交前 parse，schemaLogic 口径）。 */
export function JsonField(props: FieldRendererProps): ReactNode {
  return (
    <Form.TextArea
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={fieldHelp(props.field)}
      extraText={props.extra}
      className={styles.jsonEditor}
      rows={6}
      placeholder='{"key": "value"}'
      allowEmptyString={KEEP_EMPTY_STRING}
      disabled={props.disabled}
      aria-label={props.field.label}
    />
  );
}

/** 未知 type 占位（§12.9 行 1754：跨版本新增类型渲染占位不丢值不崩）。 */
export function UnsupportedField(props: FieldRendererProps): ReactNode {
  return (
    <Form.Input
      field={props.field.key}
      label={fieldLabel(props.field)}
      helpText={t('admin.unsupportedFieldType', { type: props.field.type })}
      extraText={props.extra}
      allowEmptyString={KEEP_EMPTY_STRING}
      disabled
    />
  );
}

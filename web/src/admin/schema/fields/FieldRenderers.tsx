/**
 * 六种字段类型的渲染实现（docs/前端架构.md §6 行 510；docs/接口文档.md
 * §5.3 行 1229 唯一定义：text / secret / checkbox / number / select / json；
 * 修饰三个：advanced / pattern / default 的语义在 schemaLogic，本文件只管
 * 受控渲染）。六渲染器共享 FieldShell 装配（label / required 星号 / help /
 * issue），故合一个文件（既定口径授权合并轻量类型）。
 *
 * Semi UI 经 lib/es 子路径引入（AdminLayout 口径）；未知 type 渲染占位
 * 不崩（§12.9 行 1754：fields[].type 跨版本可能新增）——分派在
 * ../FieldRegistry。样式复用 ../SchemaForm.module.less（字段装配属表单
 * 布局；跨文件共享同一 CSS Modules 映射，§1.7）。
 */
import type { ReactNode } from 'react';
import Checkbox from '@douyinfe/semi-ui/lib/es/checkbox';
import Input from '@douyinfe/semi-ui/lib/es/input';
import InputNumber from '@douyinfe/semi-ui/lib/es/inputNumber';
import Select from '@douyinfe/semi-ui/lib/es/select';
import type { SchemaField } from '../../../gen/proto/api/admin/v1/schema_pb';
import { JsonEditor } from '../../components/JsonEditor';
import type { FieldRendererProps } from '../FieldRegistry';
import styles from '../SchemaForm.module.less';

/** 字段控件 id（key 字符集 [a-z0-9_]，§5.3 行 1219——天然安全作 id 片段）。 */
function fieldDomId(field: SchemaField): string {
  return `provider-field-${field.key}`;
}

/**
 * 字段装配壳：label（required 星号）+ 控件 + 可选扩展位（icon_url 预览等，
 * SchemaForm fieldExtra）+ help + issue（校验文案按键定位渲染）。
 */
function FieldShell(props: {
  readonly field: SchemaField;
  readonly issue: string | undefined;
  readonly extra?: ReactNode;
  readonly children: ReactNode;
}): ReactNode {
  const { field } = props;
  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={fieldDomId(field)}>
        {field.label}
        {field.required ? (
          <span className={styles.requiredMark} aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      <div className={styles.control}>
        {props.children}
        {props.extra !== undefined && props.extra !== null ? (
          <span className={styles.fieldExtra}>{props.extra}</span>
        ) : null}
      </div>
      {field.help !== '' ? <p className={styles.help}>{field.help}</p> : null}
      {props.issue !== undefined ? (
        <p role="alert" className={styles.issue}>
          {props.issue}
        </p>
      ) : null}
    </div>
  );
}

/** text：单行文本。 */
export function TextField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <Input
        id={fieldDomId(props.field)}
        value={typeof props.value === 'string' ? props.value : ''}
        onChange={(value) => props.onChange(value)}
        disabled={props.disabled}
      />
    </FieldShell>
  );
}

/** secret：密码态输入（Semi Input 自带可见性切换）。 */
export function SecretField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <Input
        id={fieldDomId(props.field)}
        mode="password"
        value={typeof props.value === 'string' ? props.value : ''}
        onChange={(value) => props.onChange(value)}
        disabled={props.disabled}
        autoComplete="new-password"
      />
    </FieldShell>
  );
}

/** checkbox：开关。 */
export function CheckboxField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <Checkbox
        id={fieldDomId(props.field)}
        checked={props.value === true}
        onChange={(event) => props.onChange(event.target.checked)}
        disabled={props.disabled}
      />
    </FieldShell>
  );
}

/** number：数字（Semi InputNumber 的 onChange 可能回 string，归一为 number）。 */
export function NumberField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <InputNumber
        id={fieldDomId(props.field)}
        value={typeof props.value === 'number' ? props.value : 0}
        onChange={(value) =>
          props.onChange(typeof value === 'number' ? value : Number(value) || 0)
        }
        disabled={props.disabled}
      />
    </FieldShell>
  );
}

/** select：取值集合即 options（§5.3 行 1229 与 §1.11 同名同义）。 */
export function SelectField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <Select
        id={fieldDomId(props.field)}
        value={typeof props.value === 'string' ? props.value : ''}
        optionList={props.field.options.map((option) => ({
          value: option,
          label: option,
        }))}
        onChange={(value) => props.onChange(String(value))}
        disabled={props.disabled}
        placeholder="请选择"
      />
    </FieldShell>
  );
}

/** json：JsonEditor 文本域（值模型 string，提交前 parse，schemaLogic 口径）。 */
export function JsonField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <JsonEditor
        value={typeof props.value === 'string' ? props.value : ''}
        onChange={props.onChange}
        disabled={props.disabled}
        ariaLabel={props.field.label}
      />
    </FieldShell>
  );
}

/** 未知 type 占位（§12.9 行 1754：跨版本新增类型渲染占位不丢值不崩）。 */
export function UnsupportedField(props: FieldRendererProps): ReactNode {
  return (
    <FieldShell field={props.field} issue={props.issue} extra={props.extra}>
      <p role="note" className={styles.unsupported}>
        暂不支持的字段类型：{props.field.type}
      </p>
    </FieldShell>
  );
}

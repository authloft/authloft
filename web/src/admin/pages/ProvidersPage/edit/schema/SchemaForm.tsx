/**
 * 通用 Schema 驱动表单（docs/前端架构.md §6 行 508；docs/接口文档.md
 * §5.3 行 1181-1243）：按 fields[].section 分五区块（basic / credential /
 * endpoint（整块默认折叠）/ display / policy），区块内按数组顺序渲染
 * （§5.3 行 1185）——**不维护任何 key → 区块映射表，section 缺失即报错**
 * （groupFieldsBySection throw，本组件就地捕获渲染错误帧，防整页崩）。
 *
 * 【Semi Form 化】本组件必须挂在外层 `<Form>` 内：字段控件全部是
 * Form.* 字段组件（值 / 校验文案 / label 关联 / 必填星号由 Form 托管，
 * 本组件零 state），区块标题用 `Form.Section`（替代手写 section + h4），
 * `advanced` 字段组与 endpoint 整块折叠改用 Semi `Collapse`（替代原生
 * details / summary；`keepDOM` 保证折叠区字段始终注册，校验错误与
 * initValues 中的默认值都能落到字段 / 提交体），字段按 `Row + Col`
 * （span=12）两栏排布。
 *
 * 渲染壳薄（工具链 blocker 口径）：分组 / 校验 / 值构造逻辑全在
 * schemaLogic（node 可测）；本组件与 fields/ 渲染器只做装配。
 * 样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import { Col, Collapse, Form, Row } from '@douyinfe/semi-ui';
import type {
  SchemaField,
  SchemaResponse,
} from '@/gen/proto/api/admin/v1/schema_pb';
import { t } from '@/shared/i18n';
import { resolveFieldRenderer } from './FieldRegistry';
import {
  groupFieldsBySection,
  SECTION_ORDER,
  SECTION_TITLES,
} from './schemaLogic';
import styles from './SchemaForm.module.less';

export interface SchemaFormProps {
  /** GetProviderSchema 响应（§5.3 行 1183：{type, category, fields}）。 */
  schema: SchemaResponse;
  /** 锁定键（渲染禁用：category 只读 §5.3 行 1195、provider_key 编辑锁）。 */
  lockedKeys: string[];
  /** 字段扩展位注入（如 icon_url 的 ProviderIcon 实时预览）。 */
  fieldExtra?: (field: SchemaField) => ReactNode;
}

/** 单字段装配：分派渲染器（FieldRegistry）+ 锁定 / 禁用 / 扩展位。 */
function SchemaFieldControl(props: {
  field: SchemaField;
  owner: SchemaFormProps;
}): ReactNode {
  const { field, owner } = props;
  const Renderer = resolveFieldRenderer(field.type);
  return (
    <Renderer
      field={field}
      disabled={owner.lockedKeys.includes(field.key)}
      extra={owner.fieldExtra !== undefined ? owner.fieldExtra(field) : null}
    />
  );
}

/** 两栏字段栅格（每字段 span=12，窄屏整行）。 */
function FieldRow(props: {
  fields: SchemaField[];
  owner: SchemaFormProps;
}): ReactNode {
  return (
    <>
      {props.fields.map((field) => (
        <SchemaFieldControl key={field.key} field={field} owner={props.owner} />
      ))}
    </>
  );
}

/** 区块内一组字段的装配（普通字段直渲染，advanced 收进 Collapse）。 */
function FieldsGroup(props: {
  section: string;
  fields: SchemaField[];
  owner: SchemaFormProps;
}): ReactNode {
  const plain = props.fields.filter((field) => !field.advanced);
  const advanced = props.fields.filter((field) => field.advanced);
  return (
    <>
      {plain.length > 0 ? (
        <FieldRow fields={plain} owner={props.owner} />
      ) : null}
      {advanced.length > 0 ? (
        <Collapse className={styles.collapse} defaultActiveKey={[]} keepDOM>
          <Collapse.Panel
            itemKey={`advanced-${props.section}`}
            header={t('admin.advancedOptions')}
          >
            <FieldRow fields={advanced} owner={props.owner} />
          </Collapse.Panel>
        </Collapse>
      ) : null}
    </>
  );
}

/** Schema 驱动表单：五区块（SECTION_ORDER 序），endpoint 整块默认折叠。 */
export function SchemaForm(props: SchemaFormProps): ReactNode {
  let groups: SchemaField[][] | null = null;
  let sectionError: string | null = null;
  try {
    groups = groupFieldsBySection(props.schema.fields);
  } catch (error) {
    sectionError = error instanceof Error ? error.message : String(error);
  }
  if (sectionError !== null || groups === null) {
    return (
      <p role="alert" className={styles.schemaError}>
        {t('admin.sectionErrorPrefix')}
        {sectionError}
      </p>
    );
  }
  return (
    <div className={styles.form}>
      {groups.map((fields, index) => {
        if (fields.length === 0) {
          return null; // 空区块不渲染（如 sms/email 无 endpoint 基线字段）。
        }
        const section = SECTION_ORDER[index];
        return (
          <div key={section} className={styles.section}>
            <Form.Section text={t(SECTION_TITLES[section])} />
            <FieldsGroup section={section} fields={fields} owner={props} />
          </div>
        );
      })}
    </div>
  );
}

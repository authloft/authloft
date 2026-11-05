/**
 * 通用 Schema 驱动表单（docs/前端架构.md §6 行 508；docs/接口文档.md
 * §5.3 行 1181-1243）：按 fields[].section 分五区块（basic / credential /
 * endpoint（整块默认折叠）/ display / policy），区块内按数组顺序渲染
 * （§5.3 行 1185）——**不维护任何 key → 区块映射表，section 缺失即报错**
 * （groupFieldsBySection throw，本组件就地捕获渲染错误帧，防整页崩）。
 *
 * advanced 修饰（§5.3 行 1229：只管单个字段在区块内是否折叠，与 endpoint
 * 整块折叠正交）：区块内 advanced 字段统一收进「高级选项」折叠组（原生
 * details，零 Semi 依赖，语义即默认折叠）。受控表单：值 / 校验文案 /
 * 锁定键全部由消费方（ProviderEditPage）持有，本组件零状态。
 *
 * 渲染壳薄（工具链 blocker 口径）：分组 / 校验 / 值构造逻辑全在
 * schemaLogic（node 可测）；本组件与 fields/ 渲染器只做装配。
 * 样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import type {
  SchemaField,
  SchemaResponse,
} from '../../gen/proto/api/admin/v1/schema_pb';
import { resolveFieldRenderer } from './FieldRegistry';
import {
  groupFieldsBySection,
  SECTION_ORDER,
  SECTION_TITLES,
} from './schemaLogic';
import styles from './SchemaForm.module.less';

/** endpoint 区块折叠组标题（§5.3 行 1205「端点（高级折叠）」）。 */
const ENDPOINT_SUMMARY = '端点配置';

/** 区块内 advanced 字段折叠组标题。 */
const ADVANCED_SUMMARY = '高级选项';

/** section 违规错误帧前缀（groupFieldsBySection 的报错信息随文案展示）。 */
const SECTION_ERROR_PREFIX = '表单结构异常：';

export interface SchemaFormProps {
  /** GetProviderSchema 响应（§5.3 行 1183：{type, category, fields}）。 */
  readonly schema: SchemaResponse;
  /** 表单值（schemaLogic 值模型；由消费方持有）。 */
  readonly values: Readonly<Record<string, unknown>>;
  /** 校验文案（validateSchemaValues 产物，键定位）。 */
  readonly issues: Readonly<Record<string, string>>;
  /** 锁定键（渲染禁用：category 只读 §5.3 行 1195、provider_key 编辑锁）。 */
  readonly lockedKeys: readonly string[];
  /** 全表单禁用（提交中）。 */
  readonly disabled: boolean;
  /** 值变更（键级上抛）。 */
  readonly onChange: (key: string, value: unknown) => void;
  /** 字段扩展位注入（如 icon_url 的 ProviderIcon 实时预览）。 */
  readonly fieldExtra?: (field: SchemaField) => ReactNode;
}

/** 区块内一组字段的装配（普通字段直渲染，advanced 收折叠组）。 */
function FieldsGroup(props: {
  readonly fields: readonly SchemaField[];
  readonly owner: SchemaFormProps;
}): ReactNode {
  const plain = props.fields.filter((field) => !field.advanced);
  const advanced = props.fields.filter((field) => field.advanced);
  return (
    <>
      {plain.map((field) => (
        <SchemaFieldControl key={field.key} field={field} owner={props.owner} />
      ))}
      {advanced.length > 0 ? (
        <details className={styles.collapsible}>
          <summary className={styles.collapsibleSummary}>{ADVANCED_SUMMARY}</summary>
          <div className={styles.collapsibleBody}>
            {advanced.map((field) => (
              <SchemaFieldControl
                key={field.key}
                field={field}
                owner={props.owner}
              />
            ))}
          </div>
        </details>
      ) : null}
    </>
  );
}

/** 单字段装配：分派渲染器（FieldRegistry）+ 锁定 / 禁用 / issue / 扩展位。 */
function SchemaFieldControl(props: {
  readonly field: SchemaField;
  readonly owner: SchemaFormProps;
}): ReactNode {
  const { field, owner } = props;
  const Renderer = resolveFieldRenderer(field.type);
  return (
    <Renderer
      field={field}
      value={owner.values[field.key]}
      onChange={(value) => owner.onChange(field.key, value)}
      disabled={owner.disabled || owner.lockedKeys.includes(field.key)}
      issue={owner.issues[field.key]}
      extra={owner.fieldExtra !== undefined ? owner.fieldExtra(field) : null}
    />
  );
}

/** Schema 驱动表单：五区块（SECTION_ORDER 序），endpoint 整块默认折叠。 */
export function SchemaForm(props: SchemaFormProps): ReactNode {
  let groups: readonly (readonly SchemaField[])[] | null = null;
  let sectionError: string | null = null;
  try {
    groups = groupFieldsBySection(props.schema.fields);
  } catch (error) {
    sectionError = error instanceof Error ? error.message : String(error);
  }
  if (sectionError !== null || groups === null) {
    return (
      <p role="alert" className={styles.schemaError}>
        {SECTION_ERROR_PREFIX}
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
          <section key={section} className={styles.section}>
            <h4 className={styles.sectionTitle}>{SECTION_TITLES[section]}</h4>
            {section === 'endpoint' ? (
              // 整块默认折叠（§5.3 行 1185；details 默认收起）。
              <details className={styles.collapsible}>
                <summary className={styles.collapsibleSummary}>
                  {ENDPOINT_SUMMARY}
                </summary>
                <div className={styles.collapsibleBody}>
                  <FieldsGroup fields={fields} owner={props} />
                </div>
              </details>
            ) : (
              <FieldsGroup fields={fields} owner={props} />
            )}
          </section>
        );
      })}
    </div>
  );
}

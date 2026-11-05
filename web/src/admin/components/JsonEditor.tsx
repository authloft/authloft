/**
 * JSON 字段编辑器（docs/前端架构.md §6 行 514；docs/接口文档.md §5.3
 * 行 1229 json 类型）：user_mapping / metadata 等字段的纯文本域编辑，
 * 合法性校验在提交前统一进行（schemaLogic.validateSchemaValues 的
 * JSON.parse 分支；既定口径：不引第三方 JSON 编辑器库，用
 * 纯文本域 + JSON.parse 校验的最简实现）。
 *
 * 零 Semi 依赖（原生 textarea）——node 静态渲染可测（components.test
 * 同模式）；invalid 反馈不落本组件（issue 文案由 SchemaForm 渲染在
 * 字段下方，键定位）。
 * 样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import styles from './JsonEditor.module.less';

/** 空值占位提示（JSON 对象字面形态示例）。 */
const PLACEHOLDER = '{"key": "value"}';

export interface JsonEditorProps {
  /** 编辑文本态的 JSON 值（schemaLogic 值模型：json → string）。 */
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** 禁用（提交中 / 锁定键）。 */
  readonly disabled: boolean;
  /** 无障碍标签（字段 label）。 */
  readonly ariaLabel: string;
}

/** JSON 文本域编辑器：受控、等宽字体、关闭拼写检查。 */
export function JsonEditor(props: JsonEditorProps): ReactNode {
  return (
    <textarea
      className={styles.editor}
      value={props.value}
      onChange={(event) => props.onChange(event.target.value)}
      disabled={props.disabled}
      aria-label={props.ariaLabel}
      rows={6}
      spellCheck={false}
      placeholder={PLACEHOLDER}
    />
  );
}

/**
 * 字符串列表编辑器（docs/前端架构.md §6 行 519 客户端页「回调白名单 /
 * scopes」字段编辑；docs/接口文档.md §5.5 行 1262/1264）：redirectUris /
 * scopes 等 repeated string 字段的逐条输入 + 添加 / 删除。
 *
 * 零 Semi 依赖（原生 input / button）——node 静态渲染可测（JsonEditor /
 * SortableList 同模式）；条目去空白与合法性校验不在本组件（提交前经
 * api.cleanStringList / redirectUrisIssue / scopesIssue 统一收口）。
 * onChange 编排收口在纯函数 replaceListItem / removeListItem /
 * appendListItem（moveItem 同口径，node 可测），组件只做受控接线。
 * 样式（§1.7）：同目录同名 module less。
 */
import type { ReactNode } from 'react';
import { t } from '../../shared/i18n';
import styles from './StringListEditor.module.less';

/**
 * 条目就地更新（不可变）：命中 index 换值，其余原样；越界 → 原引用返回
 * （无变更即无新引用，受控 state 相等短路）。
 */
export function replaceListItem(
  values: readonly string[],
  index: number,
  value: string,
): readonly string[] {
  if (index < 0 || index >= values.length) {
    return values;
  }
  return [...values.slice(0, index), value, ...values.slice(index + 1)];
}

/** 条目按位剔除（不可变）：越界 → 原引用返回。 */
export function removeListItem(values: readonly string[], index: number): readonly string[] {
  if (index < 0 || index >= values.length) {
    return values;
  }
  return [...values.slice(0, index), ...values.slice(index + 1)];
}

/** 追加空条目（添加按钮；焦点随受控输入落新行）。 */
export function appendListItem(values: readonly string[]): readonly string[] {
  return [...values, ''];
}

export interface StringListEditorProps {
  /** 编辑值（受控；中间态允许空串条目）。 */
  readonly values: readonly string[];
  readonly onChange: (next: readonly string[]) => void;
  /** 禁用（提交中）。 */
  readonly disabled: boolean;
  /** 无障碍标签（字段名，条目 / 删除按钮按序号派生）。 */
  readonly ariaLabel: string;
  /** 添加按钮文案（如「添加回调地址」）。 */
  readonly addText: string;
  /** 条目输入占位提示（如「https://example.com/callback 或 *」）。 */
  readonly placeholder: string;
  /** 空表提示文案；缺省不渲染（非空表恒不渲染）。 */
  readonly emptyHint?: string;
}

/** 字符串列表编辑器：受控、逐条输入 + 添加 / 删除。 */
export function StringListEditor(props: StringListEditorProps): ReactNode {
  return (
    <div className={styles.editor}>
      {props.values.length === 0 && props.emptyHint !== undefined ? (
        <p className={styles.emptyHint}>{props.emptyHint}</p>
      ) : null}
      {props.values.map((value, index) => (
        <div className={styles.row} key={index}>
          <input
            className={styles.input}
            value={value}
            onChange={(event) =>
              props.onChange(replaceListItem(props.values, index, event.target.value))
            }
            disabled={props.disabled}
            aria-label={`${props.ariaLabel} ${index + 1}`}
            placeholder={props.placeholder}
            spellCheck={false}
          />
          <button
            type="button"
            className={styles.remove}
            onClick={() => props.onChange(removeListItem(props.values, index))}
            disabled={props.disabled}
            aria-label={`${props.ariaLabel} ${index + 1} ${t('admin.removeAction')}`}
          >
            {t('admin.removeAction')}
          </button>
        </div>
      ))}
      <button
        type="button"
        className={styles.add}
        onClick={() => props.onChange(appendListItem(props.values))}
        disabled={props.disabled}
      >
        {props.addText}
      </button>
    </div>
  );
}

/**
 * 拖拽排序列表（docs/前端架构.md §6 行 512；docs/接口文档.md §5.2 行 1174
 * SortProviders `{items:[{providerKey, sortOrder}]}`）——admin 端 Provider
 * 列表行集的拖拽容器。
 *
 * 拖拽实现：**原生 HTML5 Drag and Drop**（draggable + dragover + drop），
 * 零第三方 dnd 依赖——Semi UI 不自带拖拽排序能力、工程内亦无既有 dnd 库
 * （本实现禁止引新依赖，既定口径）；单列纵向拖拽的列表
 * 场景原生实现足够。
 *
 * 受控组件：行集顺序由消费方持有，拖拽落定经 onSort 上报**不可变新数组**
 * （moveItem）；持久化与失败回滚归消费方（ProvidersPage 乐观更新 + 回滚，
 * 与启停开关同模式）。拖拽态以 itemKey 追踪（行集重排后 key 不漂移）。
 *
 * 顺序重排纯函数 moveItem 单独导出（零 Semi 依赖，node 可测）；本组件零
 * Semi import，渲染可经 renderToStaticMarkup 静态验证（components.test.ts
 * 同模式；组件交互边界在 moveItem 覆盖）。
 * 样式（§1.7）：同目录同名 module less。
 */
import { useState, type ReactNode } from 'react';
import { t } from '../../shared/i18n';
import styles from './SortableList.module.less';

/**
 * 不可变重排（node 可测纯函数）：把 from 位元素移到 to 位；越界 / 同位 →
 * **原数组引用**原样返回（无变更即无新引用——消费方回滚语义依赖此约定）。
 */
export function moveItem<T>(items: readonly T[], from: number, to: number): readonly T[] {
  if (from < 0 || from >= items.length || to < 0 || to >= items.length || from === to) {
    return items;
  }
  const next = [...items];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next;
}

export interface SortableListProps<T> {
  /** 行集（受控：顺序由消费方持有，onSort 只上报新序）。 */
  readonly items: readonly T[];
  /** 行键（拖拽态追踪与列表 key；Provider 列表为 provider_key）。 */
  readonly itemKey: (item: T) => string;
  /** 行内容渲染（列布局归消费方，本组件只包拖拽壳与手柄）。 */
  readonly renderItem: (item: T) => ReactNode;
  /** 拖拽落定 → 新顺序（不可变新数组；持久化 / 失败回滚归消费方）。 */
  readonly onSort: (next: readonly T[]) => void;
  /** 停用拖拽（行集截断等）；缺省可拖。 */
  readonly disabled?: boolean;
  /** 拖拽手柄无障碍标签。 */
  readonly handleLabel?: string;
}

/** 拖拽进行态：拖起行 + 悬停行（key 追踪，防行集重排后索引漂移）。 */
interface DragState {
  readonly dragKey: string;
  readonly overKey: string;
}

/** 拖拽排序容器：每行 = 手柄 + renderItem；落定即 onSort(moveItem(...))。 */
export function SortableList<T>(props: SortableListProps<T>): ReactNode {
  const {
    items,
    itemKey,
    renderItem,
    onSort,
    disabled = false,
    handleLabel = t('admin.dragSortHandle'),
  } = props;
  const [drag, setDrag] = useState<DragState | null>(null);

  function handleDrop(targetKey: string): void {
    if (drag === null || drag.dragKey === targetKey) {
      setDrag(null);
      return;
    }
    const from = items.findIndex((item) => itemKey(item) === drag.dragKey);
    const to = items.findIndex((item) => itemKey(item) === targetKey);
    if (from !== -1 && to !== -1) {
      onSort(moveItem(items, from, to));
    }
    setDrag(null);
  }

  return (
    <ul className={styles.list}>
      {items.map((item) => {
        const key = itemKey(item);
        const isDragging = drag !== null && drag.dragKey === key;
        const isOver = drag !== null && drag.overKey === key && drag.dragKey !== key;
        const itemClass = [styles.item, isDragging ? styles.itemDragging : '', isOver ? styles.itemOver : '']
          .join(' ')
          .trim();
        return (
          <li
            key={key}
            className={itemClass}
            draggable={!disabled}
            onDragStart={(event) => {
              setDrag({ dragKey: key, overKey: key });
              event.dataTransfer.effectAllowed = 'move';
              // Firefox 要求 dataTransfer 有载荷才启动拖拽；载荷无消费方，仅手柄语义。
              event.dataTransfer.setData('text/plain', key);
            }}
            onDragOver={(event) => {
              if (drag === null) {
                // 非本列表发起的拖拽（如外部文件）不响应、不作落点。
                return;
              }
              // 允许落点（preventDefault 后 drop 才会触发）。
              event.preventDefault();
              event.dataTransfer.dropEffect = 'move';
              if (drag.overKey !== key) {
                setDrag({ ...drag, overKey: key });
              }
            }}
            onDrop={(event) => {
              event.preventDefault();
              handleDrop(key);
            }}
            onDragEnd={() => setDrag(null)}
          >
            <span className={styles.handle} role="img" aria-label={handleLabel}>
              ⠿
            </span>
            {renderItem(item)}
          </li>
        );
      })}
    </ul>
  );
}

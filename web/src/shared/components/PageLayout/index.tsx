import { Typography } from '@douyinfe/semi-ui';
import { type ReactNode } from 'react';
import styles from './index.module.less';

export function PageLayout(props: {
  title: string;
  /** 搜索 / 筛选合并后的单一插槽，位于标题下方左侧。 */
  filter?: ReactNode;
  /** 右侧动作区，flex-shrink:0；窄屏与 filter 上下堆叠。 */
  actions?: ReactNode;
  children: ReactNode;
}): ReactNode {
  const hasToolbar = props.filter !== undefined || props.actions !== undefined;
  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className={styles.title}>
        {props.title}
      </Typography.Title>
      {hasToolbar ? (
        <div className={styles.toolbar}>
          {props.filter !== undefined ? (
            <div className={styles.filter}>{props.filter}</div>
          ) : null}
          {props.actions !== undefined ? (
            <div className={styles.actions}>{props.actions}</div>
          ) : null}
        </div>
      ) : null}
      <div className={styles.content}>{props.children}</div>
    </section>
  );
}

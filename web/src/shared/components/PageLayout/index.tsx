import { Typography } from '@douyinfe/semi-ui';
import { type ReactNode } from 'react';
import styles from './index.module.less';

export function PageLayout(props: {
  title: string;
  children: ReactNode;
}): ReactNode {
  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">
        {props.title}
      </Typography.Title>
      {props.children}
    </section>
  );
}

import { ReactNode } from 'react';
import styles from './AppLayout.module.less';

export interface AppLayoutProps {
  title: string;
  children: ReactNode;
  footer?: ReactNode;
}

export function AppLayout({ title, children, footer }: AppLayoutProps) {
  return (
    <main className={styles.page}>
      <div className={styles.card}>
        <h1 className={styles.title}>{title}</h1>
        {children}
        <footer className={styles.footer}>{footer}</footer>
      </div>
    </main>
  );
}

/**
 * 登录日志页（docs/前端架构.md §5 行 493；docs/接口文档.md §3.7 行 1041）：
 * 审计入口页，数据与 401 / 错误处理在 EventLogTable（§5 行 490），本页只做
 * 标题安放；AppLayout 包裹见 routes.tsx（/account/audit）。
 * 文案经 shared/i18n（复用 account.auditTitle）。
 */
import type { ReactNode } from 'react';
import { Typography } from '@douyinfe/semi-ui';
import { EventLogTable } from '../components/EventLogTable';
import { t } from '../../shared/i18n';
import styles from './AuditPage.module.less';

/** 登录日志页：标题 + 本人登录记录表（仅成功记录，服务端过滤）。 */
export function AuditPage(): ReactNode {
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('account.auditTitle')}</Typography.Title>
      <EventLogTable />
    </section>
  );
}

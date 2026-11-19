/**
 * 安全日志页（docs/前端架构.md §5；docs/接口文档.md §3.7）：审计入口页，
 * 数据与 401 / 错误处理在 EventLogTable（§5），本页只做标题安放；
 * AppLayout 包裹见 routes.tsx（/account/audit）。
 * 文案经 shared/i18n（复用 account.auditTitle）。
 */
import type { ReactNode } from 'react';
import { PageLayout } from '@/shared/components/PageLayout';
import { EventLogTable } from '../components/EventLogTable';
import { t } from '../../shared/i18n';

/** 安全日志页：标题 + 本人全部安全事件表（安全事件口径见 EventLogTable）。 */
export function AuditPage(): ReactNode {
  return (
    <PageLayout title={t('account.auditTitle')}>
      <EventLogTable />
    </PageLayout>
  );
}

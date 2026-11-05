/**
 * 登录日志页（docs/前端架构.md §5 行 493；docs/接口文档.md §3.7 行 1041）：
 * 审计入口页，数据与 401 / 错误处理在 EventLogTable（§5 行 490），本页只做
 * 标题安放；AppLayout 包裹见 routes.tsx（/account/audit）。
 * 文案中文字面量：沿 account 既有模式，扩 i18n 键归后续 i18n 实现。
 */
import type { ReactNode } from 'react';
import { Typography } from '@douyinfe/semi-ui-19';
import { EventLogTable } from '../components/EventLogTable';
import styles from './AuditPage.module.less';

/** 登录日志页：标题 + 本人登录记录表（仅成功记录，服务端过滤）。 */
export function AuditPage(): ReactNode {
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>登录日志</Typography.Title>
      <EventLogTable />
    </section>
  );
}

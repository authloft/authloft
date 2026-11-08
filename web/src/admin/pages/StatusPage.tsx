/**
 * 监控页（docs/前端架构.md §6 行 524 StatusPage；docs/接口文档.md §5.6 行 1290
 * GetStatus；docs/需求.md §4.6 行 261）——/admin/status。
 *
 * 三指标只读 + 手动刷新（GetStatus 无入参；轮询文档未规定，不自行发挥）：
 * 队列长度 / 累计丢弃条数 / 最近 flush 耗时（毫秒——与设置项 queue_flush_ms
 * 攒批时间窗不同名不同义，生成物 StatusResponse 头注）。零值语义（后端
 * 只读透传口径）：flush 耗时 0 = 自启动以来尚未发生过批量落库；
 * 队列长度不含已取出、尚未落库的批次。int64 计数类经 toCount 收窄（§1.12）。
 *
 * 401 统一跳登录（§6 行 501，UsersPage 同模式）；其余错误页面错误态。
 * 组件壳 import Semi 后不可 node 测试（既有 Blocker），可测逻辑收口
 * ./api（三方法 msw + 展示纯函数）。样式（§1.7）：同目录同名 module less。
 */
import { type ReactNode } from 'react';
import { Banner, Button, Card, Spin, Typography } from '@douyinfe/semi-ui';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { requestOptions } from '../../shared/hooks/requestOptions';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { adminReturnTo, getStatus, isUnauthenticatedError } from '../api';
import styles from './StatusPage.module.less';

/** 监控页：GetStatus 三指标卡片 + 手动刷新。 */
export function StatusPage(_props: {
  /** 归一后 al_root（路由传参保留；401 跳登录收敛集中 onError，本页不再消费）。 */
  readonly alRoot: string;
}): ReactNode {
  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  // 首取改 ahooks 自动请求；401 由集中 onError 跳登录，其余错误
  // 走页面错误帧（toast:false 静默防双报）；手动刷新走 ahooks refresh
  // （按末次入参重发，错误同样进集中 onError）。
  const { data, error, loading, refresh } = useRequest(
    getStatus,
    requestOptions({
      toast: false,
      returnTo: () => adminReturnTo(location.pathname, location.search),
    }),
  );

  // 列表错误态（404 掩护等其余错误；401 由集中 onError 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (error !== undefined && !isUnauthenticatedError(error)) {
    return <Banner type="danger" fullMode={false} description={t('admin.statusLoadFailed')} />;
  }
  // idle / loading：数据未落地前的过渡态（裸文字换 Semi Spin）。
  if (data === undefined) {
    return (
      <div className={styles.stateCenter} role="status">
        <Spin size="large" />
      </div>
    );
  }

  return (
    <section className={styles.page}>
      <Typography.Title heading={3} className="page-title">{t('admin.navStatus')}</Typography.Title>
      <div className={styles.stats}>
        <Card className={styles.statCard} title={t('admin.statusQueueLength')}>
          <Typography.Text className={styles.statValue}>
            {toCount(data.queueLength)}
          </Typography.Text>
        </Card>
        <Card className={styles.statCard} title={t('admin.statusDropped')}>
          <Typography.Text className={styles.statValue}>
            {toCount(data.dropped)}
          </Typography.Text>
        </Card>
        <Card className={styles.statCard} title={t('admin.statusFlushMs')}>
          <Typography.Text className={styles.statValue}>
            {toCount(data.flushMs)}
          </Typography.Text>
        </Card>
      </div>
      <p className={styles.hint}>{t('admin.statusHint')}</p>
      <Button
        theme="solid"
        loading={loading}
        onClick={() => {
          refresh();
        }}
      >
        {t('admin.refreshAction')}
      </Button>
    </section>
  );
}

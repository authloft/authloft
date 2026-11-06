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
import { useEffect, type ReactNode } from 'react';
import { Banner, Button, Card, Spin, Typography } from '@douyinfe/semi-ui-19';
import { useLocation } from '@modern-js/runtime/router';
import { useRequest } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import { adminReturnTo, getStatus, isUnauthenticatedError } from '../api';
import { loginUrl } from '../bootstrap';
import styles from './StatusPage.module.less';

/** 监控页：GetStatus 三指标卡片 + 手动刷新。 */
export function StatusPage(props: {
  /** 归一后 al_root（401 跳登录前缀）。 */
  readonly alRoot: string;
}): ReactNode {
  const { status, data, error, run } = useRequest(getStatus);

  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由下 effect 与错误分支处理。
    run().catch(() => {});
  }, [run]);

  // 401 跳登录带 returnTo（/admin# + hash 内路径，登录后跳回本页）。
  const location = useLocation();
  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §6 行 501：401 统一跳登录（replace：管理面不留回退占位）。
      window.location.replace(
        loginUrl(props.alRoot, adminReturnTo(location.pathname, location.search)),
      );
    }
  }, [error, props.alRoot, location]);

  // 列表错误态（404 掩护等其余错误；401 由上方 effect 跳登录）。
  // 自绘文字换 Semi Banner（自带 role="alert"；fullMode=false 为内容区形态）。
  if (status === 'error' && !isUnauthenticatedError(error)) {
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
      <Typography.Title heading={3}>{t('admin.navStatus')}</Typography.Title>
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
        loading={status === 'loading'}
        onClick={() => {
          run().catch(() => {});
        }}
      >
        {t('admin.refreshAction')}
      </Button>
    </section>
  );
}

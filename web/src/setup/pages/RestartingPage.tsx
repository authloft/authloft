/**
 * 重启中页（docs/前端架构.md §6b / 接口文档 §13.4）：两条安装路径
 * （上传配置 / 全新安装）成功后共用本页——同一文案 + 同一轮询。
 * 轮询口径（已定稿）：**2s 间隔 / 120s 超时 /
 * GetStatus 404 视为完成**（重启后正常模式下 setup 路由不注册 → 404 即完成）；
 * 轮询实现在 ../wizard（零 Semi 依赖，rstest 可加载）。
 * §9 第 13 条 setup 例外：Semi Spin/Banner 化 + 120s 超时
 * 补「重新探测」（重置计时重新轮询）。
 */
import { useEffect, useState } from 'react';
import { Banner, Button, Spin, Typography } from '@douyinfe/semi-ui';
import { fetchSetupStatus } from '../api';
import { pollRestart } from '../wizard';
import { redirectToLogin } from '../bootstrap';
import { t } from '../../shared/i18n';
import styles from './RestartingPage.module.less';

/** 两条路径共用的重启页：文案 + 轮询；完成跳 /sso/login，超时给「重新探测」。 */
export default function RestartingPage({ alRoot }: { alRoot: string }) {
  const [timedOut, setTimedOut] = useState(false);
  // 「重新探测」递增轮次 → effect 重跑 pollRestart，deadline 从新一轮
  // 起点重算（pollRestart 在调用时刻取 now() + timeoutMs）。
  const [round, setRound] = useState(0);

  useEffect(() => {
    const handle = pollRestart({ check: fetchSetupStatus });
    let unmounted = false;
    handle.done.then((result) => {
      if (unmounted) {
        return;
      }
      if (result === 'restarted') {
        // §13.4：服务恢复（status 404）后跳 /sso/login。
        redirectToLogin(alRoot);
      } else if (result === 'timeout') {
        // §6b：超时只提示检查服务状态，不自动重试安装；另设手动「重新探测」。
        setTimedOut(true);
      }
    });
    return () => {
      unmounted = true;
      handle.cancel();
    };
  }, [alRoot, round]);

  return (
    <section className={styles.block}>
      <Typography.Title heading={3}>
        {t('setup.restartingTitle')}
      </Typography.Title>
      {/* §13.4 两条路径共用的重启提示文案（逐字取自契约，键：setup.restartingNotice）。 */}
      <Typography.Paragraph type="secondary">
        {t('setup.restartingNotice')}
      </Typography.Paragraph>
      {timedOut ? (
        <>
          <Banner type="warning" description={t('setup.restartTimeoutNotice')} />
          <Button
            theme="solid"
            onClick={() => {
              setTimedOut(false);
              setRound((value) => value + 1);
            }}
          >
            {t('setup.reprobe')}
          </Button>
        </>
      ) : (
        <>
          <Spin size="large" />
          <Typography.Paragraph type="secondary" role="status">
            {t('setup.waitingRestart')}
          </Typography.Paragraph>
        </>
      )}
    </section>
  );
}

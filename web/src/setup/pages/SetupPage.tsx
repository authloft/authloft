/**
 * 安装入口页（docs/前端架构.md §6b）：模式判定 + 两条路径入口。
 * 加载即调 SetupService/GetStatus（§13.1）：正常返回 → setup 模式，展示
 * 两条路径入口；404 / 连接失败 → 已处于正常模式，直接跳 /sso/login。
 * 页面内部用状态切换（安装端前端路由仅 /setup，接口文档 §8 / §1.4）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { fetchSetupStatus } from '../api';
import { redirectToLogin } from '../bootstrap';
import { t } from '../../shared/i18n';
import InstallPage from './InstallPage';
import RestartingPage from './RestartingPage';
import UploadConfigPage from './UploadConfigPage';
import styles from './SetupPage.module.less';

type Phase = 'checking' | 'choice' | 'upload' | 'install' | 'restarting';

export default function SetupPage({ alRoot }: { alRoot: string }) {
  const [phase, setPhase] = useState<Phase>('checking');

  useEffect(() => {
    let cancelled = false;
    fetchSetupStatus().then((result) => {
      if (cancelled) {
        return;
      }
      if (result.kind === 'setup') {
        setPhase('choice');
      } else {
        // §6b：返回 404 / 连接失败即已处于正常模式，直接跳 /sso/login。
        redirectToLogin(alRoot);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [alRoot]);

  const body: ReactNode = (() => {
    switch (phase) {
      case 'checking':
        return <p>{t('setup.checkingMode')}</p>;
      case 'choice':
        return (
          <>
            <h1>{t('setup.initTitle')}</h1>
            <p>{t('setup.setupModeDetected')}</p>
            <button type="button" onClick={() => setPhase('upload')}>
              {t('setup.uploadConfigTitle')}
            </button>
            <button type="button" onClick={() => setPhase('install')}>
              {t('setup.installTitle')}
            </button>
          </>
        );
      case 'upload':
        return (
          <UploadConfigPage
            onRestarting={() => setPhase('restarting')}
            onSwitchToInstall={() => setPhase('install')}
          />
        );
      case 'install':
        return <InstallPage onRestarting={() => setPhase('restarting')} />;
      case 'restarting':
        return <RestartingPage alRoot={alRoot} />;
    }
  })();

  return (
    <section className={styles.page}>
      {body}
    </section>
  );
}

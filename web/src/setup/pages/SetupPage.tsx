/**
 * 安装入口页（docs/前端架构.md §6b）：模式判定 + 两条路径入口。
 * 加载即调 SetupService/GetStatus（§13.1）：正常返回 → setup 模式，展示
 * 两条路径入口；404 / 连接失败 → 已处于正常模式，直接跳 /sso/login。
 * 页面内部用状态切换（安装端前端路由仅 /setup，接口文档 §8 / §1.4）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { fetchSetupStatus } from '../api';
import { redirectToLogin } from '../bootstrap';
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
        return <p>正在检测运行模式…</p>;
      case 'choice':
        return (
          <>
            <h1>Authloft 初始化</h1>
            <p>检测到首次启动（setup 模式），请选择初始化方式：</p>
            <button type="button" onClick={() => setPhase('upload')}>
              上传已有配置
            </button>
            <button type="button" onClick={() => setPhase('install')}>
              全新安装
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

/**
 * 安装入口页（docs/前端架构.md §6b）：模式判定 + 两条路径入口。
 * 加载即调 SetupService/GetStatus（§13.1）：正常返回 → setup 模式，展示
 * 两条路径入口；404 → 已完成安装（Banner info + 引导登录，不静默
 * 跳转）；连接失败 → 按 §6b 原口径跳 /sso/login。页面内部用状态切换
 * （安装端前端路由仅 /setup，接口文档 §8 / §1.4）。
 * §9 第 13 条 setup 例外：外壳 Semi 化——Steps 步骤条
 * + Typography/RadioGroup/Spin/Banner 默认样式，不造卡片外壳与装饰样式。
 */
import { useEffect, useState, type ReactNode } from 'react';
import {
  Banner,
  Button,
  Radio,
  RadioGroup,
  Spin,
  Steps,
  Typography,
} from '@douyinfe/semi-ui-19';
import { fetchSetupStatus } from '../api';
import { redirectToLogin } from '../bootstrap';
import { t } from '../../shared/i18n';
import InstallPage from './InstallPage';
import RestartingPage from './RestartingPage';
import UploadConfigPage from './UploadConfigPage';
import styles from './SetupPage.module.less';

type Phase = 'checking' | 'installed' | 'choice' | 'upload' | 'install' | 'restarting';

/** Steps 步序（§11.3 目标形态）：提交中视为「执行安装」步。 */
function stepCurrent(phase: Phase, submitting: boolean): number {
  switch (phase) {
    case 'choice':
      return 0;
    case 'upload':
    case 'install':
      return submitting ? 2 : 1;
    case 'restarting':
      return 3;
    default:
      return 0;
  }
}

export default function SetupPage({ alRoot }: { alRoot: string }) {
  const [phase, setPhase] = useState<Phase>('checking');
  // 子页提交态上抛（Steps current 推进到「执行安装」，并锁步骤跳转）。
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchSetupStatus().then((result) => {
      if (cancelled) {
        return;
      }
      if (result.kind === 'setup') {
        // 安装中刷新经 GetStatus 恢复——契约只给到模式，回到选择步
        //（纯前端恢复，不动契约；安装进度百分比缺口见评审报告）。
        setPhase('choice');
      } else if (result.kind === 'gone') {
        // setup 路由 404 = 已完成安装 → Banner info + 引导登录。
        setPhase('installed');
      } else {
        // §6b：连接失败维持原口径，跳 /sso/login。
        redirectToLogin(alRoot);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [alRoot]);

  // Steps 只允许点回「选择安装方式」（已完成步）；提交中 / 重启中禁止跳转。
  function handleStepChange(index: number): void {
    if (submitting || phase === 'restarting') {
      return;
    }
    if (index === 0 && (phase === 'upload' || phase === 'install')) {
      setPhase('choice');
    }
  }

  const showSteps =
    phase === 'choice' ||
    phase === 'upload' ||
    phase === 'install' ||
    phase === 'restarting';

  const body: ReactNode = (() => {
    switch (phase) {
      case 'checking':
        return (
          <div className={styles.center}>
            <Spin size="large" />
            <Typography.Paragraph type="secondary">
              {t('setup.checkingMode')}
            </Typography.Paragraph>
          </div>
        );
      case 'installed':
        return (
          <>
            <Banner type="info" description={t('setup.alreadyInstalled')} />
            <Button
              theme="solid"
              block
              onClick={() => {
                redirectToLogin(alRoot);
              }}
            >
              {t('setup.goToLogin')}
            </Button>
          </>
        );
      case 'choice':
        return (
          <>
            <Typography.Title heading={3}>{t('setup.initTitle')}</Typography.Title>
            <Typography.Paragraph type="secondary">
              {t('setup.setupModeDetected')}
            </Typography.Paragraph>
            <RadioGroup
              direction="vertical"
              onChange={(event) => setPhase(event.target.value as Phase)}
            >
              <Radio value="upload" extra={t('setup.uploadConfigDesc')}>
                {t('setup.uploadConfigTitle')}
              </Radio>
              <Radio value="install" extra={t('setup.installDesc')}>
                {t('setup.installTitle')}
              </Radio>
            </RadioGroup>
          </>
        );
      case 'upload':
        return (
          <UploadConfigPage
            onRestarting={() => setPhase('restarting')}
            onSwitchToInstall={() => setPhase('install')}
            onSubmittingChange={setSubmitting}
          />
        );
      case 'install':
        return (
          <InstallPage
            onRestarting={() => setPhase('restarting')}
            onSubmittingChange={setSubmitting}
          />
        );
      case 'restarting':
        return <RestartingPage alRoot={alRoot} />;
    }
  })();

  return (
    <section className={styles.page}>
      <div className={styles.content}>
        {showSteps ? (
          <Steps
            current={stepCurrent(phase, submitting)}
            onChange={handleStepChange}
            aria-label={t('setup.initTitle')}
          >
            <Steps.Step title={t('setup.stepChoice')} />
            <Steps.Step title={t('setup.stepFill')} />
            <Steps.Step title={t('setup.stepRun')} />
            <Steps.Step title={t('setup.stepRestart')} />
          </Steps>
        ) : null}
        {body}
      </div>
    </section>
  );
}

/**
 * 上传已有配置页（路径 A，docs/前端架构.md §6b / 接口文档 §13.2）：
 * 上传 config.yaml 全文；失败按 error.code 反馈（校验 / 连接 / 初始化），
 * 可修正后重试；成功（restarting:true）进入与全新安装一致的重启流程。
 * 约束（§6b）：不解析、不回显配置内容（可能含密钥）——文件只按纯文本读入
 * 编辑框，此外不渲染、不日志输出配置内容。
 * §9 第 13 条 setup 例外：Semi 化——Upload（点击 / 拖拽）
 * + TextArea 预览 + Banner 反馈；admin_missing → Banner warning + Modal
 * 确认「改走全新安装」（S-4 分支动作）。
 */
import { useState } from 'react';
import {
  Banner,
  Button,
  Modal,
  TextArea,
  Typography,
  Upload,
} from '@douyinfe/semi-ui-19';
import { requestUploadConfig, setupMessage } from '../api';
import { ApiError } from '../../shared/api/errors';
import { t } from '../../shared/i18n';
import styles from './UploadConfigPage.module.less';

interface UploadConfigPageProps {
  onRestarting: () => void;
  onSwitchToInstall: () => void;
  /** S-2：提交态上抛给 SetupPage 推进 Steps「执行安装」步并锁步骤跳转。 */
  onSubmittingChange?: (submitting: boolean) => void;
}

export default function UploadConfigPage({
  onRestarting,
  onSwitchToInstall,
  onSubmittingChange,
}: UploadConfigPageProps) {
  const [configText, setConfigText] = useState('');
  const [errorText, setErrorText] = useState<string | null>(null);
  const [adminMissing, setAdminMissing] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const canSubmit = configText.trim() !== '' && !submitting;

  function setSubmittingBoth(value: boolean): void {
    setSubmitting(value);
    onSubmittingChange?.(value);
  }

  async function handleSubmit(): Promise<void> {
    setSubmittingBoth(true);
    setErrorText(null);
    setAdminMissing(false);
    try {
      // §13.2：成功响应 restarting:true，进入与全新安装一致的重启流程。
      await requestUploadConfig(configText);
      onRestarting();
    } catch (error) {
      if (error instanceof ApiError) {
        setErrorText(setupMessage(error.code));
        // §13.2 ④：版本已最新但管理员缺失 → Banner warning + Modal 确认后改走全新安装。
        setAdminMissing(error.code === 'admin_missing');
      } else {
        setErrorText(setupMessage('internal'));
      }
    } finally {
      setSubmittingBoth(false);
    }
  }

  return (
    <div className={styles.stack}>
      <Typography.Title heading={3}>
        {t('setup.uploadConfigTitle')}
      </Typography.Title>
      <Typography.Paragraph type="secondary">
        {t('setup.uploadConfigIntro')}
      </Typography.Paragraph>
      <Upload
        action=""
        draggable
        accept=".yaml,.yml,text/yaml,text/plain"
        limit={1}
        dragMainText={t('setup.uploadDragMain')}
        dragSubText={t('setup.uploadDragSub')}
        customRequest={({ fileInstance, onSuccess, onError }) => {
          // 只按纯文本读入编辑框，供用户核对后提交；不解析内容（§6b）。
          // customRequest 语义仅为本地读入，不发任何网络请求。
          fileInstance
            .text()
            .then((text) => {
              setConfigText(text);
              onSuccess({});
            })
            .catch(() => {
              setErrorText(t('setup.unreadableFile'));
              onError({});
            });
        }}
      />
      <TextArea
        rows={14}
        value={configText}
        placeholder={t('setup.uploadConfigPlaceholder')}
        onChange={(value) => setConfigText(value)}
      />
      {errorText ? (
        <Banner type="danger" description={errorText} />
      ) : null}
      {adminMissing ? (
        <>
          <Banner type="warning" description={t('setup.adminMissingHint')} />
          <Button
            block
            onClick={() => {
              setConfirmOpen(true);
            }}
          >
            {t('setup.switchToInstall')}
          </Button>
        </>
      ) : null}
      <Button
        theme="solid"
        block
        disabled={!canSubmit}
        loading={submitting}
        onClick={() => void handleSubmit()}
      >
        {submitting ? t('setup.initializing') : t('setup.startInitialize')}
      </Button>
      <Modal
        title={t('setup.adminMissingConfirmTitle')}
        visible={confirmOpen}
        okText={t('setup.switchToInstall')}
        cancelText={t('setup.cancel')}
        onOk={() => {
          setConfirmOpen(false);
          onSwitchToInstall();
        }}
        onCancel={() => {
          setConfirmOpen(false);
        }}
      >
        {t('setup.adminMissingConfirmContent')}
      </Modal>
    </div>
  );
}

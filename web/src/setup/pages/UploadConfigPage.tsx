/**
 * 上传已有配置页（路径 A，docs/前端架构.md §6b / 接口文档 §13.2）：
 * 上传 config.yaml 全文；失败按 error.code 反馈（校验 / 连接 / 初始化），
 * 可修正后重试；成功（restarting:true）进入与全新安装一致的重启流程。
 * 约束（§6b）：不解析、不回显配置内容（可能含密钥）——文件只按纯文本读入
 * 编辑框，此外不渲染、不日志输出配置内容。
 */
import { useState, type ChangeEvent } from 'react';
import { requestUploadConfig, setupMessage } from '../api';
import { ApiError } from '../../shared/api/errors';
import { t } from '../../shared/i18n';
import styles from './UploadConfigPage.module.less';

interface UploadConfigPageProps {
  onRestarting: () => void;
  onSwitchToInstall: () => void;
}

export default function UploadConfigPage({
  onRestarting,
  onSwitchToInstall,
}: UploadConfigPageProps) {
  const [configText, setConfigText] = useState('');
  const [errorText, setErrorText] = useState<string | null>(null);
  const [adminMissing, setAdminMissing] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const canSubmit = configText.trim() !== '' && !submitting;

  async function handleSubmit(): Promise<void> {
    setSubmitting(true);
    setErrorText(null);
    setAdminMissing(false);
    try {
      // §13.2：成功响应 restarting:true，进入与全新安装一致的重启流程。
      await requestUploadConfig(configText);
      onRestarting();
    } catch (error) {
      if (error instanceof ApiError) {
        setErrorText(setupMessage(error.code));
        // §13.2 ④：版本已最新但管理员缺失 → 改走全新安装。
        setAdminMissing(error.code === 'admin_missing');
      } else {
        setErrorText(setupMessage('internal'));
      }
    } finally {
      setSubmitting(false);
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    // 只按纯文本读入编辑框，供用户核对后提交；不解析内容。
    file
      .text()
      .then((text) => {
        setConfigText(text);
      })
      .catch(() => {
        setErrorText(t('setup.unreadableFile'));
      });
  }

  return (
    <>
      <h1 className={styles.title}>{t('setup.uploadConfigTitle')}</h1>
      <p className={styles.intro}>{t('setup.uploadConfigIntro')}</p>
      <div className={styles.fileRow}>
        <input
          type="file"
          className={styles.fileInput}
          accept=".yaml,.yml,text/yaml,text/plain"
          onChange={handleFileChange}
        />
      </div>
      <div>
        <textarea
          rows={14}
          cols={80}
          spellCheck={false}
          className={styles.textarea}
          placeholder={t('setup.uploadConfigPlaceholder')}
          value={configText}
          onChange={(event) => setConfigText(event.target.value)}
        />
      </div>
      {errorText ? (
        <p role="alert" className={styles.error}>
          {errorText}
        </p>
      ) : null}
      {adminMissing ? (
        <p className={styles.hint}>{t('setup.adminMissingHint')}</p>
      ) : null}
      <div className={styles.actions}>
        <button
          type="button"
          className={styles.primaryButton}
          disabled={!canSubmit}
          onClick={handleSubmit}
        >
          {submitting ? t('setup.initializing') : t('setup.startInitialize')}
        </button>
        {adminMissing ? (
          <button
            type="button"
            className={styles.secondaryButton}
            onClick={onSwitchToInstall}
          >
            {t('setup.switchToInstall')}
          </button>
        ) : null}
      </div>
    </>
  );
}

/**
 * 头像上传组件（docs/前端架构.md §5 行 503 / §3.2 行 344；docs/接口文档.md
 * §3.2 行 831-868 / §10.8 流程唯一定义）：内部仅调 useUpload()，不感知
 * proxy / direct——模式差异收敛在 hook（文档位 shared/hooks/useUpload.ts，
 * 迁移落位；编排纯逻辑 uploadAvatarFile 亦在彼处）；零值投影（§3.2
 * 行 842：avatar_storage_provider 未配置时 {mode:"proxy",maxSize:0,
 * allowedTypes:[]}）时隐藏上传入口（渲染 null）。
 * 挂载点 ProfilePage（§5 行 513）：上传成功经 onUploaded 上抛
 * url（§10.8 流程终点 {url}），由页面刷新头像展示；持久化到用户资料归
 * UpdateProfile（后端仍为桩，随其实装接线）。
 */
import { useRef, useState, type ReactNode } from 'react';
import { Avatar, Button } from '@douyinfe/semi-ui';
import { apiErrorText } from '../api';
import { useUpload } from '../../shared/hooks/useUpload';
import { t } from '../../shared/i18n';
import styles from './AvatarUploader.module.less';

/**
 * 头像上传组件：预览 + 选文件 + 进度 + 错误；上传成功经 onUploaded 上抛
 * url（§10.8 流程终点 {url}），调用方（ProfilePage）刷新头像展示。
 */
export function AvatarUploader(props: {
  /** 当前头像地址（预览底图；上传成功后预览切换为新 url）。 */
  readonly currentUrl?: string;
  /** 上传成功回调（§10.8 流程终点 {url}）。 */
  readonly onUploaded?: (url: string) => void;
}): ReactNode {
  const { hidden, config, upload } = useUpload();
  const [uploading, setUploading] = useState(false);
  const [progressText, setProgressText] = useState<string | undefined>(undefined);
  const [error, setError] = useState<unknown>(undefined);
  const [uploadedUrl, setUploadedUrl] = useState<string | undefined>(undefined);
  // 评审 P2-2：上传失败保留原文件供「重试」——不必重新选择文件；
  // 成功或选择新文件时清除。
  const [retryFile, setRetryFile] = useState<File | undefined>(undefined);
  const inputRef = useRef<HTMLInputElement | null>(null);

  if (hidden) {
    // §3.2 行 842：零值投影 / 配置未加载 → 隐藏上传入口。
    return null;
  }

  const handleFile = (file: File | undefined) => {
    if (file === undefined || uploading) {
      return;
    }
    setUploading(true);
    setError(undefined);
    setRetryFile(undefined);
    setProgressText(undefined);
    upload(file, (progress) => {
      // proxy 分支经 XHR upload 事件（前端架构 §3.2 行 349）；direct 的 PUT
      // 无进度事件、不回调（§3.2 行 350），进度文案仅在 proxy 分支出现。
      if (progress.total > 0) {
        setProgressText(
          t('account.uploadProgress', {
            percent: Math.round((progress.loaded / progress.total) * 100),
          }),
        );
      }
    })
      .then((url) => {
        setUploadedUrl(url);
        props.onUploaded?.(url);
      })
      .catch((uploadError: unknown) => {
        setRetryFile(file); // 失败：留存原文件，错误文案旁给「重试」入口。
        setError(uploadError);
      })
      .finally(() => {
        setUploading(false);
        setProgressText(undefined);
      });
  };

  const previewUrl = uploadedUrl ?? props.currentUrl;
  return (
    <div className={styles.uploader}>
      <Avatar size="large" src={previewUrl || undefined} alt={t('account.avatarAlt')} />
      <div className={styles.controls}>
        <input
          ref={inputRef}
          type="file"
          accept={config?.allowedTypes.join(',')}
          className={styles.fileInput}
          onChange={(event) => {
            handleFile(event.target.files?.[0]);
            // 清空 value 允许重复选择同一文件再次触发 onChange。
            event.target.value = '';
          }}
          aria-label={t('account.avatarChooseFileAria')}
        />
        <Button
          onClick={() => inputRef.current?.click()}
          loading={uploading}
          disabled={uploading}
        >
          {t('account.avatarUploadAction')}
        </Button>
        {progressText !== undefined ? (
          <p role="status" className={styles.progress}>
            {progressText}
          </p>
        ) : null}
        {error !== undefined ? (
          <p role="alert" className={styles.error}>
            {apiErrorText(error)}
          </p>
        ) : null}
        {error !== undefined && retryFile !== undefined ? (
          // 评审 P2-2：失败重试——以上次选择的文件重走上传链。
          <Button
            size="small"
            onClick={() => handleFile(retryFile)}
            disabled={uploading}
          >
            {t('common.retry')}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

/**
 * 头像上传入口（docs/前端架构.md §5 / §3.2；docs/接口文档.md
 * §3.2 / §10.8 流程唯一定义）：内部仅调 useUpload()，不感知
 * proxy / direct——模式差异收敛在 hook（文档位 shared/hooks/useUpload.ts，
 * 迁移落位；编排纯逻辑 uploadAvatarFile 亦在彼处）。入口可见性按 hook
 * status 区分：配置加载中 / 加载失败（尚不能确定存储配置）渲染禁用的
 * 上传按钮，仅配置就绪且零值投影（§3.2：avatar_storage_provider 未配置时
 * {mode:"proxy",maxSize:0,allowedTypes:[]}）才隐藏上传入口（渲染 null）。
 * 大头像展示归挂载点 ProfilePage（组件内不再重复渲染 Avatar），本组件
 * 只出「更换头像」单行入口（按钮 + 尺寸 / 类型提示）；上传成功经
 * onUploaded 上抛 url（§10.8 流程终点 {url}），持久化到用户资料归
 * UpdateProfile {avatarUrl}（页面壳接线）。
 */
import { useRef, useState, type ReactNode } from 'react';
import { Button } from '@douyinfe/semi-ui';
import { apiErrorText } from '../api';
import { useUpload } from '../../shared/hooks/useUpload';
import { t } from '../../shared/i18n';
import styles from './AvatarUploader.module.less';

/** MIME 子类型短名（image/jpeg → JPEG），提示文案用。 */
function avatarTypeShortName(mime: string): string {
  return (mime.split('/')[1] ?? mime).toUpperCase();
}

/** 字节数上限的可读文案（≥1MB 取 MB，一位小数兜非整；不足取 KB）。 */
function avatarMaxSizeText(maxSize: bigint): string {
  const mb = Number(maxSize) / (1024 * 1024);
  if (mb >= 1) {
    return `${Number.isInteger(mb) ? mb : mb.toFixed(1)} MB`;
  }
  const kb = Number(maxSize) / 1024;
  return `${Number.isInteger(kb) ? kb : kb.toFixed(1)} KB`;
}

/**
 * 头像上传入口：选文件 + 进度 + 错误；上传成功经 onUploaded 上抛
 * url（§10.8 流程终点 {url}），调用方（ProfilePage）刷新头像展示。
 */
export function AvatarUploader(props: {
  /** 上传成功回调（§10.8 流程终点 {url}）。 */
  onUploaded?: (url: string) => void;
}): ReactNode {
  const { status, hidden, config, upload } = useUpload();
  const [uploading, setUploading] = useState(false);
  const [progressText, setProgressText] = useState<string | undefined>(
    undefined,
  );
  const [error, setError] = useState<unknown>(undefined);
  // 上传失败保留原文件供「重试」——不必重新选择文件；选择新文件时清除。
  const [retryFile, setRetryFile] = useState<File | undefined>(undefined);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // 入口可见性：仅「配置就绪且零值投影」= 确定未配存储才隐藏；加载中 /
  // 加载失败（无法确定配置）渲染禁用按钮，不闪隐藏。
  if (status === 'success' && hidden) {
    return null;
  }
  const entryActive = status === 'success' && !hidden;

  const handleFile = (file: File | undefined) => {
    if (file === undefined || uploading) {
      return;
    }
    setUploading(true);
    setError(undefined);
    setRetryFile(undefined);
    setProgressText(undefined);
    upload(file, (progress) => {
      // proxy 分支经 XHR upload 事件（前端架构 §3.2）；direct 的 PUT
      // 无进度事件、不回调（§3.2），进度文案仅在 proxy 分支出现。
      if (progress.total > 0) {
        setProgressText(
          t('account.uploadProgress', {
            percent: Math.round((progress.loaded / progress.total) * 100),
          }),
        );
      }
    })
      .then((url) => {
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

  // 尺寸 / 类型提示随配置下发（entryActive 时 config 必已就绪且非零值）。
  const typesText = (config?.allowedTypes ?? [])
    .map(avatarTypeShortName)
    .join(' / ');
  const hintText =
    entryActive && config !== undefined && typesText !== ''
      ? t('account.avatarUploadHint', {
          types: typesText,
          size: avatarMaxSizeText(config.maxSize),
        })
      : undefined;

  return (
    <div className={styles.controls}>
      <div className={styles.uploader}>
        <input
          ref={inputRef}
          type="file"
          accept={config?.allowedTypes.join(',')}
          className={styles.fileInput}
          disabled={!entryActive}
          onChange={(event) => {
            handleFile(event.target.files?.[0]);
            // 清空 value 允许重复选择同一文件再次触发 onChange。
            event.target.value = '';
          }}
          aria-label={t('account.avatarChooseFileAria')}
        />
        <Button
          theme="borderless"
          type="primary"
          onClick={() => inputRef.current?.click()}
          loading={uploading}
          disabled={!entryActive || uploading}
        >
          {t('account.avatarUploadAction')}
        </Button>
        {hintText !== undefined ? (
          // 提示小字复用 .progress 弱化样式（muted / sm），不新增类。
          <span className={styles.progress}>{hintText}</span>
        ) : null}
      </div>
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
        // 失败重试——以上次选择的文件重走上传链。
        <Button
          size="small"
          onClick={() => handleFile(retryFile)}
          disabled={uploading}
        >
          {t('common.retry')}
        </Button>
      ) : null}
    </div>
  );
}

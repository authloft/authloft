/**
 * 头像上传组件（docs/前端架构.md §5 行 481 / §3.2 行 322；docs/接口文档.md
 * §3.2 行 815-852 / §10.8 流程唯一定义）：内部仅调 useUpload()，不感知
 * proxy / direct——模式差异收敛在 hook（编排纯逻辑在 ./api 的
 * uploadAvatarFile）；零值投影（§3.2 行 826：avatar_storage_provider 未配置
 * 时 {mode:"proxy",maxSize:0,allowedTypes:[]}）时隐藏上传入口（渲染 null）。
 *
 * 【useUpload 落位说明】按文档 useUpload 属 shared/hooks/useUpload.ts、读配置
 * 经 shared/api/account（前端架构 §2 行 152 / §3.2 行 322）——本次不碰
 * shared/**，按约定落 account/components 同目录（本文件内
 * 导出，契约以文档为准）；迁往 shared/hooks 归后续 shared 扩展（需
 * 批准 shared/ 改动）。文档签名的 scene 参数不引入——关键约束「仅用于头像」，
 * 单场景无分派。
 * 挂载点为 ProfilePage（§5 行 491「资料：头像」），不在本次交付范围——本次交付
 * 组件与逻辑层测试，挂载 + UpdateProfile 持久化 avatarUrl 归 profile 后续增强。
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Avatar, Button } from '@douyinfe/semi-ui-19';
import type { AvatarUploadConfig } from '../../gen/proto/api/account/v1/profile_pb';
import { ApiError } from '../../shared/api/errors';
import type { UploadProgress } from '../../shared/api/http';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import {
  apiErrorText,
  avatarUploadDeps,
  getConfig,
  isUploadEntryHidden,
  uploadAvatarFile,
} from '../api';
import styles from './AvatarUploader.module.less';

/** useUpload 对外形态（§3.2 行 322 契约：config + upload(file) → url）。 */
export interface UseUploadResult {
  /** GetConfig 加载态（配置未就绪时入口隐藏、不可上传）。 */
  readonly status: RequestStatus;
  /** §3.2 行 826：零值投影 / 配置未加载 → true（隐藏上传入口）。 */
  readonly hidden: boolean;
  /** 当前 avatarUpload 投影（未加载 / 缺省为 undefined，§3.1 零值兜底）。 */
  readonly config: AvatarUploadConfig | undefined;
  /** 上传（§10.8）：预校验失败与服务端错误统一抛 ApiError（文案走 i18n 字典）。 */
  upload(
    file: File,
    onUploadProgress?: (progress: UploadProgress) => void,
  ): Promise<string>;
}

/**
 * 头像上传 hook（§3.2 行 322 契约、§10.8 流程）：读 GetConfig 的
 * avatarUpload.{mode,maxSize,allowedTypes}（mfaPolicy 不由本 hook 消费，
 * 安全中心按 §3.2 读取），在 proxy / direct 间切换——分支只在
 * uploadAvatarFile（./api）内，hook 壳零模式感知。
 */
export function useUpload(): UseUploadResult {
  const { status, data, run } = useRequest(getConfig);
  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 state），吞掉防 unhandled rejection。
    run().catch(() => {});
  }, [run]);
  const config = data?.avatarUpload;
  const upload = useCallback(
    (file: File, onUploadProgress?: (progress: UploadProgress) => void) => {
      if (config === undefined) {
        // 入口已按 hidden 隐藏，此处防御性兜底（§3.1 零值兜底，不透出细节）。
        return Promise.reject(
          new ApiError({ httpStatus: 0, code: 'internal', message: '', requestId: '' }),
        );
      }
      return uploadAvatarFile(config, file, avatarUploadDeps, onUploadProgress);
    },
    [config],
  );
  return { status, hidden: isUploadEntryHidden(config), config, upload };
}

/**
 * 头像上传组件：预览 + 选文件 + 进度 + 错误；上传成功经 onUploaded 上抛
 * url（§10.8 流程终点 {url}；持久化到用户资料归调用方 / profile 增强卡）。
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
  const inputRef = useRef<HTMLInputElement | null>(null);

  if (hidden) {
    // §3.2 行 826：零值投影 / 配置未加载 → 隐藏上传入口。
    return null;
  }

  const handleFile = (file: File | undefined) => {
    if (file === undefined || uploading) {
      return;
    }
    setUploading(true);
    setError(undefined);
    setProgressText(undefined);
    upload(file, (progress) => {
      // proxy 分支经 XHR upload 事件（前端架构 §3.2 行 327）；direct 的 PUT
      // 无进度事件、不回调（§3.2 行 328），进度文案仅在 proxy 分支出现。
      if (progress.total > 0) {
        setProgressText(`上传中 ${Math.round((progress.loaded / progress.total) * 100)}%`);
      }
    })
      .then((url) => {
        setUploadedUrl(url);
        props.onUploaded?.(url);
      })
      .catch((uploadError: unknown) => {
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
      <Avatar size="large" src={previewUrl || undefined} alt="用户头像" />
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
          aria-label="选择头像文件"
        />
        <Button
          onClick={() => inputRef.current?.click()}
          loading={uploading}
          disabled={uploading}
        >
          上传头像
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
      </div>
    </div>
  );
}

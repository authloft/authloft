/**
 * 统一头像上传 hook（docs/前端架构.md §3.2 行 344；docs/接口文档.md §3.2
 * 行 831-868 / §10.8 流程唯一定义）：读 AccountService/GetConfig 的
 * avatarUpload.{mode,maxSize,allowedTypes}（经 shared/api/account；mfaPolicy
 * 不由本 hook 消费——安全中心按接口文档 §3.2 读取），在 proxy / direct 间
 * 切换，模式差异只收敛在本模块（前端架构 §3.2 行 347-350：前端分支只有两处
 * ——proxy 走 postForm 的 onUploadProgress；direct 经 presign 取 uploadUrl 与
 * headers 后 fetch PUT 直传、不带 Cookie，CommitAvatar 回填 url）。
 * 上传前做体积 / 类型预校验，返回码与后端一致（file_too_large /
 * file_type_not_allowed，§1.6 封闭集；服务端仍按同口径权威校验，行 868）。
 * 仅用于头像（渠道图标不允许在 Authloft 内上传）；upload(file) 签名 +
 * scene 参数为多场景预留——当前仅头像单场景（接口文档 §3.2），引入第二
 * 上传场景时再扩展（既定定稿口径；前端架构 §3.2
 * 行 344）。
 *
 * 零值投影（§3.2 行 842）：avatar_storage_provider 未配置时 GetConfig 下发
 * {mode:"proxy", maxSize:0, allowedTypes:[]}，前端据零值隐藏上传入口；配置
 * 未加载（undefined）同样隐藏。
 *
 * 【落位说明】头像上传自 account/api.ts + AvatarUploader.tsx（内联）迁文档位
 * 本模块；编排 / 预校验等可测纯函数随 hook 落此（纯函数本身零 Semi 依赖、
 * node 可测——工具链 blocker 见 account.test.tsx 头注；前端架构 §8.2
 * 行 648 的被测对象在此）。hook 壳改 ahooks useRequest +
 * requestOptions 集中 onError，模块 import 链因此含
 * ahooks / Semi（Toast）——测试链 bundleDependencies 已覆盖，
 * ahooks 无 CSS 不需新增配置（ahooks-probe.test.ts 绊线）。
 */
import { useCallback } from 'react';
import { useRequest } from 'ahooks';
import { create } from '@bufbuild/protobuf';
import type {
  AvatarPresignResponse,
  AvatarResponse,
  AvatarUploadConfig,
  CommitAvatarRequest,
  PresignAvatarRequest,
} from '../../gen/proto/api/account/v1/profile_pb';
import {
  CommitAvatarRequestSchema,
  PresignAvatarRequestSchema,
} from '../../gen/proto/api/account/v1/profile_pb';
import { ApiError } from '../api/errors';
import type { UploadProgress } from '../api/http';
import {
  commitAvatar,
  getConfig,
  presignAvatar,
  uploadAvatarProxy,
} from '../api/account';
import { deriveRequestStatus, type RequestStatus } from './deriveRequestStatus';
import { requestOptions } from './requestOptions';

/**
 * §3.2 行 842：零值投影 {mode:"proxy", maxSize:0, allowedTypes:[]} 时
 * GetConfig 不发 avatarUpload 语义（protojson 省略零值 → 解码为 0n / []），
 * 前端据此隐藏上传入口；配置未加载（undefined）同样隐藏。
 * 两信号任一为零即视为不可上传（零值投影两者同时为零，此处保守取或）。
 */
export function isUploadEntryHidden(config: AvatarUploadConfig | undefined): boolean {
  if (config === undefined) {
    return true;
  }
  return config.maxSize <= BigInt(0) || config.allowedTypes.length === 0;
}

/**
 * 上传前体积 / 类型预校验（§3.2 行 868 / 前端架构 §3.2 行 344 关键约束）：
 * 返回码与后端一致（file_too_large / file_type_not_allowed，§1.6 封闭集），
 * 文案经 shared/i18n 的 errors.code.<code> 同一份字典（§8.2 行 648「文案与
 * 后端一致」）；服务端仍是权威（PresignAvatar 同口径校验）。
 */
export function validateAvatarFile(
  config: AvatarUploadConfig,
  file: Pick<File, 'size' | 'type'>,
): 'file_too_large' | 'file_type_not_allowed' | undefined {
  if (config.maxSize > BigInt(0) && BigInt(file.size) > config.maxSize) {
    return 'file_too_large';
  }
  if (config.allowedTypes.length > 0 && !config.allowedTypes.includes(file.type)) {
    return 'file_type_not_allowed';
  }
  return undefined;
}

/** 头像上传依赖（proxy 一支 / direct 三支）；测试可注入假实现。 */
export interface AvatarUploadDeps {
  uploadProxy(
    formData: FormData,
    onUploadProgress?: (progress: UploadProgress) => void,
  ): Promise<AvatarResponse>;
  presignAvatar(request: PresignAvatarRequest): Promise<AvatarPresignResponse>;
  commitAvatar(request: CommitAvatarRequest): Promise<AvatarResponse>;
  putToStorage(url: string, headers: Record<string, string>, file: File): Promise<void>;
}

/**
 * direct 模式对象存储直传（前端架构 §3.2 行 350 / §10.8）：PUT uploadUrl 携带
 * presign 下发的 headers（如 Content-Type）、不带 Cookie（不用 credentials）；
 * 非 2xx 按 §3.2 行 842 映射 internal（未知异常，不新增错误码）。
 */
async function putAvatarToStorage(
  url: string,
  headers: Record<string, string>,
  file: File,
): Promise<void> {
  const response = await fetch(url, { method: 'PUT', headers, body: file });
  if (!response.ok) {
    throw new ApiError({ httpStatus: 0, code: 'internal', message: '', requestId: '' });
  }
}

/** 真实依赖（生产与 msw 集成测试共用），薄封装取自 shared/api/account。 */
export const avatarUploadDeps: AvatarUploadDeps = {
  uploadProxy: uploadAvatarProxy,
  presignAvatar,
  commitAvatar,
  putToStorage: putAvatarToStorage,
};

/**
 * 头像上传编排（§10.8 唯一流程，前端架构 §8.2 行 648 用例的被测对象）：
 * 预校验 → 按 mode 分支——proxy 一支（postForm multipart）；direct 三步
 * （PresignAvatar → PUT uploadUrl → CommitAvatar）。预校验失败抛 code 与
 * 后端一致的 ApiError（文案归 apiErrorText / i18n 字典）；mode 取值域
 * proxy｜direct（§3.2 行 842 闭合），非 direct 一律走 proxy 分支（保守）。
 */
export async function uploadAvatarFile(
  config: AvatarUploadConfig,
  file: File,
  deps: AvatarUploadDeps = avatarUploadDeps,
  onUploadProgress?: (progress: UploadProgress) => void,
): Promise<string> {
  const invalid = validateAvatarFile(config, file);
  if (invalid !== undefined) {
    throw new ApiError({ httpStatus: 400, code: invalid, message: '', requestId: '' });
  }
  if (config.mode === 'direct') {
    const presigned = await deps.presignAvatar(
      create(PresignAvatarRequestSchema, {
        filename: file.name,
        contentType: file.type,
        size: BigInt(file.size),
      }),
    );
    await deps.putToStorage(presigned.uploadUrl, presigned.headers, file);
    const committed = await deps.commitAvatar(
      create(CommitAvatarRequestSchema, { key: presigned.key }),
    );
    return committed.url;
  }
  const formData = new FormData();
  formData.append('file', file);
  return (await deps.uploadProxy(formData, onUploadProgress)).url;
}

/** useUpload 对外形态（前端架构 §3.2 行 344 契约：config + upload(file) → url）。 */
export interface UseUploadResult {
  /** GetConfig 加载态（配置未就绪时入口隐藏、不可上传）。 */
  readonly status: RequestStatus;
  /** §3.2 行 842：零值投影 / 配置未加载 → true（隐藏上传入口）。 */
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
 * 头像上传 hook（§3.2 行 344 契约、§10.8 流程）：读 GetConfig 的
 * avatarUpload.{mode,maxSize,allowedTypes}（mfaPolicy 不由本 hook 消费），
 * 在 proxy / direct 间切换——分支只在 uploadAvatarFile 内，hook 壳零模式感知。
 */
export function useUpload(): UseUploadResult {
  // 配置读取改 ahooks 自动请求（§5.1-①）；集中 onError——401 跳登录，
  // 其余静默（toast:false：失败仅 hidden=true 隐藏入口，沿用旧行为不弹 Toast）。
  const { data, error, loading } = useRequest(getConfig, requestOptions({ toast: false }));
  const status = deriveRequestStatus(loading, error, data);
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

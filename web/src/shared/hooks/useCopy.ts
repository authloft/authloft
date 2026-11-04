/**
 * 剪贴板复制 + 短暂成功态（docs/前端架构.md §3.2 useCopy 行 307）：用于
 * provider_key、回调地址、恢复码复制（§3.3 CopyButton 一族复用）。
 *
 * 复制控制器（createCopyController）不依赖 React，可独立测试；hook 壳只做
 * 状态绑定与卸载清理。
 */
import { useCallback, useEffect, useState } from 'react';

/** copied 成功态持续时间。 */
export const COPY_FEEDBACK_MS = 2000;

export interface CopyControllerOptions {
  /** 剪贴板写入；默认 navigator.clipboard.writeText（注入以便测试）。 */
  writeText?: (text: string) => Promise<void>;
  /** 成功态持续时间（默认 COPY_FEEDBACK_MS）。 */
  durationMs?: number;
}

export interface CopyController {
  /**
   * 复制：成功（并触发短暂成功态）→ true；剪贴板不可用（非安全上下文 /
   * 权限拒绝）或写入失败 → false，不抛错（体验性功能，失败静默）。
   */
  copy(text: string): Promise<boolean>;
  isCopied(): boolean;
  /** 清掉计时器（hook 卸载时调用；成功态由回调方自行复位）。 */
  dispose(): void;
}

/**
 * 复制控制器：成功 → copied=true，durationMs 后回落 false；期间再次复制成功
 * 则重新计时；失败不改成功态。onChanged 只在成功态翻转时收到 true / false。
 */
export function createCopyController(
  onChanged: (copied: boolean) => void,
  options: CopyControllerOptions = {},
): CopyController {
  const writeText =
    options.writeText ??
    ((text: string) => navigator.clipboard.writeText(text));
  const durationMs = options.durationMs ?? COPY_FEEDBACK_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const clearTimer = () => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
  };

  return {
    async copy(text: string): Promise<boolean> {
      try {
        await writeText(text);
      } catch {
        return false;
      }
      clearTimer();
      onChanged(true);
      timer = setTimeout(() => {
        timer = undefined;
        onChanged(false);
      }, durationMs);
      return true;
    },
    isCopied: () => timer !== undefined,
    dispose: clearTimer,
  };
}

export interface UseCopyResult {
  /** 最近一次复制是否处于成功态窗口内。 */
  readonly copied: boolean;
  /** 复制（语义同 CopyController.copy）。 */
  readonly copy: (text: string) => Promise<boolean>;
}

/** @param durationMs 成功态持续时间（默认 COPY_FEEDBACK_MS）。 */
export function useCopy(durationMs?: number): UseCopyResult {
  const [copied, setCopied] = useState(false);
  const [controller] = useState(() =>
    createCopyController(setCopied, { durationMs }),
  );
  useEffect(() => controller.dispose, [controller]);
  const copy = useCallback((text: string) => controller.copy(text), [controller]);
  return { copied, copy };
}

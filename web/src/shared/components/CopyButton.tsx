/**
 * 复制按钮（docs/前端架构.md §3.3 行 330）：复用 shared/hooks 的 useCopy
 * （provider_key、回调地址、恢复码复制），文案走 shared/i18n。
 */
import { Button } from '@douyinfe/semi-ui';
import { useCopy } from '../hooks/useCopy';
import { t } from '../i18n';

export interface CopyButtonProps {
  /** 待复制文本。 */
  text: string;
  /** 成功态持续时间（默认 useCopy 的 2s）。 */
  durationMs?: number;
}

export function CopyButton({ text, durationMs }: CopyButtonProps) {
  const { copied, copy } = useCopy(durationMs);
  return (
    <Button type="tertiary" theme="outline" onClick={() => void copy(text)}>
      {copied ? t('common.copied') : t('common.copy')}
    </Button>
  );
}

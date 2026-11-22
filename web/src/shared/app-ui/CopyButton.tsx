/**
 * 复制按钮（docs/前端架构.md §3.3）：复用 shared/hooks 的 useCopy
 * （provider_key、回调地址、恢复码复制），文案走 shared/i18n。
 *
 * 落位 shared/app-ui（Semi 组件领地）：本组件消费 @douyinfe/semi-ui 大包
 * 入口（semi-ui 的 sideEffects 把 lib/es/index.js 标记为有副作用，tree-shaking
 * 摇不掉）——放 shared/components 桶导出曾把整包 semi 夹带进 login 族三张
 * 壳（桶 → CopyButton → semi-ui 大包入口 → cacheGroup semi 进 initial chunks），
 * 故禁止经 shared/components 桶 re-export 任何依赖 Semi 的模块。
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

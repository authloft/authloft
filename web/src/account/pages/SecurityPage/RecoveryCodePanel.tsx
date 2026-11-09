/**
 * 恢复码面板（docs/前端架构.md §5 行 486；docs/接口文档.md §3.5 行 907-908）：
 * 一次性展示 10 个恢复码（GetRecoveryCodes 与 BindTotp verify 同格式，行 906）
 * + 重新生成（RegenerateRecoveryCodes，action=regenerate，全量作废后
 * 一次性下发新码，行 908）。纯展示组件：码数据与重新生成动作由调用方注入——
 * - TotpBindDialog 成功帧：verify 响应的 recoveryCodes 直接传入一次性展示
 *   （§5 行 485「直接交给 RecoveryCodePanel」；无 createdAt / 重新生成入口）；
 * - MfaSetting 查看场景：GetRecoveryCodes 结果 + 重新生成回调。
 * 复制走 shared CopyButton（useCopy，剪贴板不可用静默失败）。
 * 评审 P2-3：「下载为文本」——纯前端 Blob 下载（非请求，§9 第 16 条
 * 仅禁手拼 Blob 发请求），文件名固定 authloft-recovery-codes.txt。
 * 文案经 shared/i18n（account.* 域键）。
 */
import type { ReactNode } from 'react';
import { Button, Popconfirm } from '@douyinfe/semi-ui';
import { CopyButton } from '../../../shared/components/CopyButton';
import { t } from '../../../shared/i18n';
import { formatUnixTime } from '../../api';
import styles from './RecoveryCodePanel.module.less';

export function RecoveryCodePanel(props: {
  /** 恢复码列表（xxxx-xxxx，§3.5 行 907）。 */
  codes: string[];
  /** 签发时间（Unix 秒，§3.5 行 907 createdAt）；bind 一次性展示场景无该值 → 省略行。 */
  createdAt?: bigint;
  /** 重新生成回调（§3.5 行 908 全量作废）；不传则不渲染重新生成入口。 */
  onRegenerate?: () => void;
  /** 重新生成进行中（按钮 loading，调用方维护）。 */
  regenerateBusy?: boolean;
}): ReactNode {
  return (
    <div className={styles.panel}>
      <p className={styles.notice}>{t('account.recoveryNotice')}</p>
      <ul className={styles.codes}>
        {props.codes.map((code) => (
          <li key={code} className={styles.code}>
            {code}
          </li>
        ))}
      </ul>
      <div className={styles.meta}>
        {props.createdAt !== undefined ? (
          <span>
            {t('account.recoveryIssuedAt', {
              time: formatUnixTime(props.createdAt),
            })}
          </span>
        ) : null}
        <CopyButton text={props.codes.join('\n')} />
        {/* 评审 P2-3：下载为文本（纯前端 Blob 下载，对齐 Casdoor）。 */}
        <Button
          type="tertiary"
          onClick={() => {
            const url = URL.createObjectURL(
              new Blob([props.codes.join('\n')], {
                type: 'text/plain;charset=utf-8',
              }),
            );
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = 'authloft-recovery-codes.txt';
            anchor.click();
            URL.revokeObjectURL(url);
          }}
        >
          {t('account.recoveryDownload')}
        </Button>
      </div>
      {props.onRegenerate !== undefined ? (
        <Popconfirm
          title={t('account.recoveryRegenerateConfirm')}
          onConfirm={props.onRegenerate}
        >
          <Button type="tertiary" loading={props.regenerateBusy ?? false}>
            {t('account.recoveryRegenerate')}
          </Button>
        </Popconfirm>
      ) : null}
    </div>
  );
}

/**
 * 恢复码面板（docs/前端架构.md §5 行 486；docs/接口文档.md §3.5 行 907-908）：
 * 一次性展示 10 个恢复码（GetRecoveryCodes 与 BindTotp verify 同格式，行 906）
 * + 重新生成（RegenerateRecoveryCodes，action=regenerate，全量作废后
 * 一次性下发新码，行 908）。纯展示组件：码数据与重新生成动作由调用方注入——
 * - TotpBindDialog 成功帧：verify 响应的 recoveryCodes 直接传入一次性展示
 *   （§5 行 485「直接交给 RecoveryCodePanel」；无 createdAt / 重新生成入口）；
 * - MfaMethodList 查看场景：GetRecoveryCodes 结果 + 重新生成回调。
 * 复制走 shared CopyButton（useCopy，剪贴板不可用静默失败）。
 * 文案经 shared/i18n（account.* 域键）。
 */
import type { ReactNode } from 'react';
import { Button, Popconfirm } from '@douyinfe/semi-ui-19';
import { CopyButton } from '../../shared/components/CopyButton';
import { t } from '../../shared/i18n';
import { formatUnixTime } from '../api';
import styles from './RecoveryCodePanel.module.less';

export function RecoveryCodePanel(props: {
  /** 恢复码列表（xxxx-xxxx，§3.5 行 907）。 */
  readonly codes: readonly string[];
  /** 签发时间（Unix 秒，§3.5 行 907 createdAt）；bind 一次性展示场景无该值 → 省略行。 */
  readonly createdAt?: bigint;
  /** 重新生成回调（§3.5 行 908 全量作废）；不传则不渲染重新生成入口。 */
  readonly onRegenerate?: () => void;
  /** 重新生成进行中（按钮 loading，调用方维护）。 */
  readonly regenerateBusy?: boolean;
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
          <span>{t('account.recoveryIssuedAt', { time: formatUnixTime(props.createdAt) })}</span>
        ) : null}
        <CopyButton text={props.codes.join('\n')} />
      </div>
      {props.onRegenerate !== undefined ? (
        <Popconfirm title={t('account.recoveryRegenerateConfirm')} onConfirm={props.onRegenerate}>
          <Button type="tertiary" loading={props.regenerateBusy ?? false}>
            {t('account.recoveryRegenerate')}
          </Button>
        </Popconfirm>
      ) : null}
    </div>
  );
}

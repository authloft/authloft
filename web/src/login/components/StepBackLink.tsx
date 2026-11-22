/**
 * 「返回上一步」文字按钮（登录族页族共用）：原地回退一步、不发请求。
 *
 * 状态回退由消费方各自实现，口径一致（原地回退、清一次性输入、已提交值
 * 回填、loginToken 不动）：
 * - 登录页（LoginFlowView）：select_method 重选当前方式 = 回该方式第一步
 *   （token 保留，重发 / 重走同 tid）；
 * - 注册 / 重置页：复用重发路径的回退预处理（backToChallenge）。
 */
import { t } from '../../shared/i18n';
import styles from './StepBackLink.module.less';

export function StepBackLink({ onBack }: { onBack: () => void }) {
  return (
    <button type="button" className={styles.back} onClick={onBack}>
      {t('login.backToPrevious')}
    </button>
  );
}

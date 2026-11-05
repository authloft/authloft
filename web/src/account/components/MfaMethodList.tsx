/**
 * MFA 因子列表（docs/前端架构.md §5 行 484；docs/接口文档.md §3.2 行 828-848 /
 * §3.5 行 884-909 + §5 行 495 数据分工）：系统开放二次因子逐行渲染（摘要与
 * 明细同集合、数组序即渲染序，§3.2 行 845）——
 * - 勾选启用 / 取消启用走 SetMfa {methods:[...]}（§3.5 行 904：空数组=关闭；
 *   required=true 不可关闭 → 本地拒绝不发包，§3.2 行 833）；成功后只刷新
 *   mfaPolicy（父级 onPolicyRefresh 重取 GetConfig，§5 行 495）；
 * - 启用勾选仅对已绑定因子开放（bound=false 置灰；绑定入口在对应区块：
 *   totp → TotpBindDialog（本组件挂载）、otp_sms / otp_email → 联系方式
 *   ContactBindForm（§3.4）、webauthn → 通行密钥 WebauthnList）；
 * - 绑定明细展开时才请求 GetMfa（§5 行 495：mfaPolicy 一次请求渲染摘要）；
 * - 恢复码查看（GetRecoveryCodes）与重新生成（RegenerateRecoveryCodes，
 *   全量作废）经 RecoveryCodePanel 呈现；重新生成失败保留旧码（作废与
 *   新码下发在服务端同事务原子发生）。
 * 文案经 shared/i18n（account.* 域键 + factors.* 因子名复用）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Checkbox, Modal, Spin, Tag } from '@douyinfe/semi-ui-19';
import type { MfaPolicyMethod } from '../../gen/proto/api/account/v1/profile_pb';
import type { MfaFactor } from '../../gen/proto/api/account/v1/mfa_pb';
import { useRequest } from '../../shared/hooks/useRequest';
import { t, type I18nKey } from '../../shared/i18n';
import {
  apiErrorText,
  buildRegenerateRecoveryCodesRequest,
  buildSetMfaRequest,
  formatUnixTime,
  getMfa,
  getRecoveryCodes,
  mfaFactorDetail,
  regenerateRecoveryCodes,
  setMfa,
} from '../api';
import { RecoveryCodePanel } from './RecoveryCodePanel';
import { TotpBindDialog } from './TotpBindDialog';
import styles from './MfaMethodList.module.less';

/** 因子展示名 i18n 键（§3.2 行 835-841 因子全集；未知因子回显原文，§9 第 18 条零值兜底）。 */
const FACTOR_LABEL_KEYS: Readonly<Record<string, I18nKey>> = {
  totp: 'account.factorTotp',
  otp_sms: 'factors.otp_sms',
  otp_email: 'factors.otp_email',
  webauthn: 'factors.webauthn',
  recovery_code: 'factors.recovery_code',
};

function factorLabel(factor: string): string {
  const key = FACTOR_LABEL_KEYS[factor];
  return key !== undefined ? t(key) : factor;
}

/** 未绑定因子的指引文案键（绑定入口在对应区块，本列表不重复实现）。 */
const UNBOUND_HINT_KEYS: Readonly<Record<string, I18nKey>> = {
  otp_sms: 'account.mfaBindPhoneHint',
  otp_email: 'account.mfaBindEmailHint',
  webauthn: 'account.mfaBindWebauthnHint',
};

/** 未绑定因子的指引文案（渲染期 t()，防模块级 locale 冻结）。 */
function unboundHint(factor: string): string | undefined {
  const key = UNBOUND_HINT_KEYS[factor];
  return key !== undefined ? t(key) : undefined;
}

export function MfaMethodList(props: {
  /** 系统开放因子摘要（GetConfig mfaPolicy.methods，§3.2 行 834-845）。 */
  readonly methods: MfaPolicyMethod[];
  /** 策略强制（§3.2 行 833：true 时不可关闭两步验证）。 */
  readonly required: boolean;
  /** 父级递增（如通行密钥增删后）触发已展开明细重取（GetMfa 与凭据数联动）。 */
  readonly detailVersion: number;
  /** 开关 / 绑定成功回调：父级重取 GetConfig 刷新 mfaPolicy（§5 行 495 只刷摘要）。 */
  readonly onPolicyRefresh: () => void;
}): ReactNode {
  const [expanded, setExpanded] = useState(false);
  const [lockedNotice, setLockedNotice] = useState(false);
  const [totpOpen, setTotpOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  const { status: toggleStatus, error: toggleError, run: runToggle } = useRequest(setMfa);
  const { data: mfa, status: detailStatus, error: detailError, run: runDetails } = useRequest(getMfa);
  const {
    data: recoveryData,
    status: recoveryStatus,
    error: recoveryError,
    run: runRecovery,
  } = useRequest(getRecoveryCodes);
  const {
    data: regenData,
    status: regenStatus,
    error: regenError,
    run: runRegen,
    reset: resetRegen,
  } = useRequest(regenerateRecoveryCodes);

  // 展开时才请求 GetMfa（§5 行 495）；detailVersion 变化（通行密钥增删）重取。
  useEffect(() => {
    if (expanded) {
      runDetails().catch(() => {});
    }
  }, [expanded, props.detailVersion, runDetails]);

  // 打开查看恢复码 → 重取（服务端最新为准）；上次重新生成结果在关框时已清。
  useEffect(() => {
    if (recoveryOpen) {
      runRecovery().catch(() => {});
    }
  }, [recoveryOpen, runRecovery]);

  const handleToggle = (factor: string, next: boolean) => {
    const built = buildSetMfaRequest(props.methods, factor, next, props.required);
    if (!built.ok) {
      setLockedNotice(true);
      return;
    }
    setLockedNotice(false);
    // 成功只刷 mfaPolicy（§5 行 495：明细无绑定变化，不重取 GetMfa）。
    runToggle(built.request)
      .then((result) => {
        if (result !== undefined) {
          props.onPolicyRefresh();
        }
      })
      .catch(() => {});
  };

  const toggling = toggleStatus === 'loading';
  // 摘要 factors 与 GetMfa 明细同集合（§3.5 行 886 / §3.2 行 845），按 factor 关联。
  const factorMap = new Map<string, MfaFactor>(
    (mfa?.factors ?? []).map((factor) => [factor.factor, factor]),
  );

  // 恢复码视图：重新生成成功后以新码为准；失败保留旧码（服务端原子作废）。
  const codesView = regenData ?? recoveryData;
  const recoveryBusy = regenStatus === 'loading';
  const recoveryLoading =
    recoveryStatus === 'loading' && recoveryData === undefined && regenData === undefined;

  return (
    <div className={styles.wrap}>
      <ul className={styles.list}>
        {props.methods.map((method) => (
          <li key={method.factor} className={styles.row}>
            <Checkbox
              checked={method.enabled}
              disabled={toggling || !method.bound}
              onChange={(e) => handleToggle(method.factor, e.target.checked ?? false)}
              aria-label={t('account.mfaEnableFactorAria', { factor: factorLabel(method.factor) })}
            />
            <span className={styles.factor}>{factorLabel(method.factor)}</span>
            <Tag size="small" color={method.bound ? 'green' : 'grey'}>
              {method.bound ? t('account.factorBoundTag') : t('account.factorUnboundTag')}
            </Tag>
            {method.factor === 'totp' && !method.bound ? (
              <Button size="small" onClick={() => setTotpOpen(true)}>
                {t('account.bindAction')}
              </Button>
            ) : null}
            {method.factor === 'recovery_code' && method.bound ? (
              <Button size="small" onClick={() => setRecoveryOpen(true)}>
                {t('account.viewRecoveryCodes')}
              </Button>
            ) : null}
            {!method.bound && unboundHint(method.factor) !== undefined ? (
              <span className={styles.unboundHint}>{unboundHint(method.factor)}</span>
            ) : null}
          </li>
        ))}
      </ul>
      {lockedNotice ? (
        <p role="alert" className={styles.notice}>
          {t('account.mfaLocked')}
        </p>
      ) : null}
      {toggleStatus === 'error' ? (
        <p role="alert" className={styles.notice}>
          {apiErrorText(toggleError)}
        </p>
      ) : null}
      <div className={styles.detailsBlock}>
        <Button type="tertiary" size="small" onClick={() => setExpanded(!expanded)}>
          {expanded ? t('account.mfaHideDetails') : t('account.mfaShowDetails')}
        </Button>
        {expanded ? (
          detailStatus === 'loading' ? (
            <Spin size="small" />
          ) : detailStatus === 'error' ? (
            <p role="alert" className={styles.notice}>
              {t('account.mfaDetailsLoadFailed', { error: apiErrorText(detailError) })}
            </p>
          ) : (
            <ul className={styles.detailList}>
              {props.methods.map((method) => {
                const factor = factorMap.get(method.factor);
                return (
                  <li key={method.factor} className={styles.detailRow}>
                    <span className={styles.detailFactor}>{factorLabel(method.factor)}</span>
                    <span className={styles.detailText}>
                      {factor !== undefined ? mfaFactorDetail(factor) : t('account.mfaNotBound')}
                    </span>
                  </li>
                );
              })}
              <li className={styles.detailRow}>
                <span className={styles.detailFactor}>{t('account.recoveryIssuedAtLabel')}</span>
                <span className={styles.detailText}>
                  {formatUnixTime(mfa?.recoveryIssuedAt ?? BigInt(0))}
                </span>
              </li>
            </ul>
          )
        ) : null}
      </div>
      <TotpBindDialog
        visible={totpOpen}
        onCancel={() => setTotpOpen(false)}
        onDone={() => {
          setTotpOpen(false);
          // 绑定改变 mfaPolicy（totp / recovery_code 翻转）与 GetMfa 明细。
          props.onPolicyRefresh();
          if (expanded) {
            runDetails().catch(() => {});
          }
        }}
      />
      <Modal
        title={t('factors.recovery_code')}
        visible={recoveryOpen}
        onCancel={() => {
          // 关框即清上次重新生成结果，防重开时闪现旧码一帧（重开走 GetRecoveryCodes）。
          resetRegen();
          setRecoveryOpen(false);
        }}
        footer={null}
      >
        {recoveryLoading ? (
          <Spin />
        ) : codesView === undefined ? (
          <p role="alert" className={styles.notice}>
            {recoveryStatus === 'error' ? apiErrorText(recoveryError) : t('account.recoveryLoadFailed')}
          </p>
        ) : (
          <RecoveryCodePanel
            codes={codesView.codes}
            createdAt={codesView.createdAt}
            onRegenerate={() => {
              runRegen(buildRegenerateRecoveryCodesRequest()).catch(() => {});
            }}
            regenerateBusy={recoveryBusy}
          />
        )}
        {regenStatus === 'error' ? (
          <p role="alert" className={styles.notice}>
            {apiErrorText(regenError)}
          </p>
        ) : null}
      </Modal>
    </div>
  );
}

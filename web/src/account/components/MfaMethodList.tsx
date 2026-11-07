/**
 * MFA 因子列表（交互重构；docs/前端架构.md §5 行 484；docs/接口文档.md
 * §3.2 行 828-848 / §3.5 行 884-909 + §5 行 495 数据分工）：
 * - **状态一律 Tag / 文本承载**（已绑定 / 未绑定 / 已停用），删除 Checkbox
 *   启用开关（勾选即发包误触成本高，且「启用」与「已绑定」是两回事）；
 *   动作按状态分派——未绑定 →「绑定」（totp 进 TotpBindDialog；otp_sms /
 *   otp_email / webauthn 的绑定入口在对应区块，给指引不出按钮）；已停用
 *   （bound && !enabled）→「启用」；已启用 →「停用」（danger + Popconfirm
 *   二次确认）；required=true 时停用走 buildSetMfaRequest 本地拒绝不发包
 *   （§3.2 行 833）。契约无「重新绑定」路径（BindTotp 已绑即拒，§3.5 行
 *   905-906 未定义重绑语义），不放该入口；
 * - **行内常显摘要**：挂载即取一次 GetMfa（原「显示明细」展开才取，展开
 *   入口已删）——设备数 / 添加时间 / 恢复码剩余经 mfaFactorDetail 直显行内，
 *   无逐行请求、无需用户点开；
 * - **恢复码剩余 ≤ 2**（api.isRecoveryLow / RECOVERY_LOW_THRESHOLD）→
 *   warning Tag + 行内「重新生成」入口（成功即开恢复码弹窗展示新码并重取
 *   GetMfa 刷新剩余数）；
 * - **成功反馈**（P1-6 统一通道）：启用 / 停用 / 重新生成成功 Toast.success；
 *   行状态更新选「重新取数」（onPolicyRefresh 刷 GetConfig 摘要 + runDetails
 *   重取 GetMfa——服务端权威，变动面小，不手写本地补丁）。
 * 视觉保持 Semi 默认（§9.3 口径：不加卡片外壳与自造装饰）。
 * 文案经 shared/i18n（account.* 域键 + factors.* 因子名复用）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Modal, Popconfirm, Spin, Tag, Toast } from '@douyinfe/semi-ui-19';
import type { MfaPolicyMethod } from '../../gen/proto/api/account/v1/profile_pb';
import type { MfaFactor } from '../../gen/proto/api/account/v1/mfa_pb';
import { useRequest } from '../../shared/hooks/useRequest';
import { t, type I18nKey } from '../../shared/i18n';
import { toCount } from '../../shared/utils/int';
import {
  apiErrorText,
  buildRegenerateRecoveryCodesRequest,
  buildSetMfaRequest,
  getMfa,
  getRecoveryCodes,
  isRecoveryLow,
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
  /** 父级递增（如通行密钥增删后）触发明细重取（GetMfa 与凭据数联动）。 */
  readonly detailVersion: number;
  /** 开关 / 绑定成功回调：父级重取 GetConfig 刷新 mfaPolicy（§5 行 495 只刷摘要）。 */
  readonly onPolicyRefresh: () => void;
}): ReactNode {
  const [lockedNotice, setLockedNotice] = useState(false);
  const [totpOpen, setTotpOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  const { status: toggleStatus, error: toggleError, run: runToggle } = useRequest(setMfa);
  const { data: mfa, status: detailStatus, error: detailError, run: runDetails } =
    useRequest(getMfa);
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

  // 挂载即取一次 GetMfa（行内常显摘要）；detailVersion 变化（通行密钥
  // 增删）重取。原「显示明细」展开入口删除，不再按需拉取。
  useEffect(() => {
    runDetails().catch(() => {});
  }, [props.detailVersion, runDetails]);

  // 打开查看恢复码 → 重取（服务端最新为准）；上次重新生成结果在关框时已清。
  useEffect(() => {
    if (recoveryOpen) {
      runRecovery().catch(() => {});
    }
  }, [recoveryOpen, runRecovery]);

  /** 启用 / 停用（§3.5 行 904 SetMfa 全量集合）：成功 Toast + 双链重取。 */
  const handleSetEnabled = (factor: string, next: boolean) => {
    const built = buildSetMfaRequest(props.methods, factor, next, props.required);
    if (!built.ok) {
      setLockedNotice(true);
      return;
    }
    setLockedNotice(false);
    runToggle(built.request)
      .then((result) => {
        if (result !== undefined) {
          Toast.success(
            t(next ? 'account.mfaEnabledSuccess' : 'account.mfaDisabledSuccess', {
              factor: factorLabel(factor),
            }),
          );
          props.onPolicyRefresh();
          runDetails().catch(() => {});
        }
      })
      .catch(() => {});
  };

  /** 低余量行内「重新生成」：成功开弹窗展示新码 + 重取剩余数。 */
  const handleRegenerateInline = () => {
    runRegen(buildRegenerateRecoveryCodesRequest())
      .then((result) => {
        if (result !== undefined) {
          Toast.success(t('account.recoveryRegenerateSuccess'));
          setRecoveryOpen(true);
          runDetails().catch(() => {});
        }
      })
      .catch(() => {});
  };

  const toggling = toggleStatus === 'loading';
  // 摘要 methods 与 GetMfa 明细同集合（§3.5 行 886 / §3.2 行 845），按 factor 关联。
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
        {props.methods.map((method) => {
          const factor = factorMap.get(method.factor);
          const recoveryLow = factor !== undefined && isRecoveryLow(factor);
          return (
            <li key={method.factor} className={styles.row}>
              <div className={styles.rowMain}>
                <span className={styles.factor}>{factorLabel(method.factor)}</span>
                {/* 状态一律 Tag 承载（不用可点勾选框承载状态）。 */}
                {!method.bound ? (
                  <Tag size="small" color="grey">
                    {t('account.factorUnboundTag')}
                  </Tag>
                ) : method.enabled ? (
                  <Tag size="small" color="green">
                    {t('account.factorBoundTag')}
                  </Tag>
                ) : (
                  <Tag size="small" color="orange">
                    {t('account.factorDisabledTag')}
                  </Tag>
                )}
                {/* 行内常显摘要：设备数 / 添加时间 / 恢复码剩余（挂载一次取）。 */}
                {detailStatus === 'loading' && mfa === undefined ? (
                  <Spin size="small" />
                ) : detailStatus === 'error' && mfa === undefined ? (
                  <span className={styles.unboundHint}>
                    {t('account.mfaDetailsLoadFailed', { error: apiErrorText(detailError) })}
                  </span>
                ) : method.bound && factor !== undefined ? (
                  <span className={styles.summary}>{mfaFactorDetail(factor)}</span>
                ) : !method.bound && unboundHint(method.factor) !== undefined ? (
                  <span className={styles.unboundHint}>{unboundHint(method.factor)}</span>
                ) : null}
                {recoveryLow && factor !== undefined ? (
                  <Tag size="small" color="yellow">
                    {t('account.recoveryLowWarning', { count: toCount(factor.remaining) })}
                  </Tag>
                ) : null}
              </div>
              <div className={styles.rowActions}>
                {!method.bound && method.factor === 'totp' ? (
                  <Button size="small" onClick={() => setTotpOpen(true)}>
                    {t('account.bindAction')}
                  </Button>
                ) : null}
                {method.bound && !method.enabled ? (
                  <Button
                    size="small"
                    theme="solid"
                    disabled={toggling}
                    onClick={() => handleSetEnabled(method.factor, true)}
                  >
                    {t('account.mfaEnableAction')}
                  </Button>
                ) : null}
                {method.bound && method.enabled ? (
                  <Popconfirm
                    title={t('account.mfaDisableConfirm', {
                      factor: factorLabel(method.factor),
                    })}
                    onConfirm={() => handleSetEnabled(method.factor, false)}
                  >
                    <Button size="small" type="danger" disabled={toggling}>
                      {t('account.mfaDisableAction')}
                    </Button>
                  </Popconfirm>
                ) : null}
                {method.factor === 'recovery_code' && method.bound ? (
                  <>
                    {recoveryLow ? (
                      <Button
                        size="small"
                        onClick={handleRegenerateInline}
                        loading={recoveryBusy}
                        disabled={recoveryBusy}
                      >
                        {t('account.recoveryRegenerate')}
                      </Button>
                    ) : null}
                    <Button size="small" onClick={() => setRecoveryOpen(true)}>
                      {t('account.viewRecoveryCodes')}
                    </Button>
                  </>
                ) : null}
              </div>
            </li>
          );
        })}
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
      <TotpBindDialog
        visible={totpOpen}
        onCancel={() => setTotpOpen(false)}
        onDone={() => {
          setTotpOpen(false);
          // 绑定成功（P1-6 统一通道）：Toast + 双链重取（totp / recovery_code 翻转）。
          Toast.success(
            t('account.mfaEnabledSuccess', { factor: factorLabel('totp') }),
          );
          props.onPolicyRefresh();
          runDetails().catch(() => {});
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
            {recoveryStatus === 'error'
              ? apiErrorText(recoveryError)
              : t('account.recoveryLoadFailed')}
          </p>
        ) : (
          <RecoveryCodePanel
            codes={codesView.codes}
            createdAt={codesView.createdAt}
            onRegenerate={() => {
              runRegen(buildRegenerateRecoveryCodesRequest())
                .then((result) => {
                  if (result !== undefined) {
                    Toast.success(t('account.recoveryRegenerateSuccess'));
                    runDetails().catch(() => {});
                  }
                })
                .catch(() => {});
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

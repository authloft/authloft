/**
 * 安全中心页（docs/前端架构.md §5 行 492；docs/接口文档.md §3）：GetConfig
 * （§3.2 行 819，后端已实装）驱动四个区块——
 * - 两步验证摘要 + 因子明细：mfaPolicy（§3.2 行 828-848：enabled / required /
 *   trustedDeviceDays 预留恒 0 / methods 因子投影）渲染摘要卡片；明细与开关
 *   归 MfaMethodList（§3.5：SetMfa 开关、展开才请求 GetMfa、TotpBindDialog /
 *   RecoveryCodePanel 挂载；数据分工 §5 行 495：开关成功只刷新 mfaPolicy）；
 * - 登录密码：PasswordChangeForm（hasPassword 驱动，§3.3）；
 * - 联系方式：ContactBindForm ×2（phone / email，§3.4；captcha 配置取
 *   GetConfig 的 captcha 对象——account entry 的配置读取处，§3.2 行 819）；
 * - 通行密钥：WebauthnList（§3.6 / 需求 §4.1.6：注册 resident key / 重命名 /
 *   删除；增删会翻转 mfaPolicy.webauthn.bound → onChanged 时重取 GetConfig
 *   并递增 detailVersion 驱动已展开的 GetMfa 明细重取）；
 * - 第三方账号：ThirdPartyList（§3.7 / §3.7.1：双列表 + redirect / qrcode
 *   通道绑定 + 解绑置灰）。
 * 头像上传入口已挂载 ProfilePage（§5 行 513；本页无头像区块——
 * SecurityPage 不渲染 AvatarUploader）。
 *
 * 【redirect 绑定回调落地（§3.7.1 A 行 969-971）】OAuthCallbackPage b 分支
 * 完成后 location.replace('/account/security?bind={success|ErrorInfo.code}')
 * 回到本页——挂载时读取 ?bind= 出成功 / 失败横幅（bindParamMessage：target_
 * taken 出绑定语境文案「该账号已被其他账号绑定」），
 * 随即 replaceState 清参防刷新复读（不新增历史项）。
 *
 * 401 处理沿 ProfilePage 模式（§5 行 480）：isUnauthenticatedError +
 * loginUrl 由页面层统一实现。文案经 shared/i18n（account.* 域键；
 * 「通行密钥」卡片题复用 factors.webauthn）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button, Card, Spin, Typography } from '@douyinfe/semi-ui-19';
import { create } from '@bufbuild/protobuf';
import type {
  AccountConfigResponse,
  MfaPolicy,
} from '../../gen/proto/api/account/v1/profile_pb';
import { MfaPolicySchema } from '../../gen/proto/api/account/v1/profile_pb';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import { t } from '../../shared/i18n';
import {
  bindParamMessage,
  getConfig,
  isUnauthenticatedError,
  readBindParam,
} from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import { ContactBindForm } from '../components/ContactBindForm';
import { MfaMethodList } from '../components/MfaMethodList';
import { PasswordChangeForm } from '../components/PasswordChangeForm';
import { ThirdPartyList } from '../components/ThirdPartyList';
import { WebauthnList } from '../components/WebauthnList';
import styles from './SecurityPage.module.less';

/** mfaPolicy 零值兜底（§3.1：缺失字段按零值；protojson 省略未置字段时）。 */
const ZERO_MFA_POLICY: MfaPolicy = create(MfaPolicySchema, {});

/** captcha 零值兜底（§3.1）：GetConfig 未下发 captcha 时 CaptchaWidget 走其兜底错误态。 */
const ZERO_CAPTCHA_CONFIG = create(CaptchaConfigSchema, {});

/** redirect 绑定回调横幅（§3.7.1 A 行 969-971）：success / ErrorInfo.code 两态。 */
export interface BindNotice {
  readonly kind: 'success' | 'error';
  readonly text: string;
}

/**
 * 安全中心帧视图（纯渲染，无请求）：
 * 配置未就绪 → 401 以外的错误提示 / 加载态；就绪 → 摘要 + 明细 + 密码 +
 * 联系方式 + 通行密钥 + 第三方。
 */
export function SecurityPageView(props: {
  readonly status: RequestStatus;
  readonly config: AccountConfigResponse | undefined;
  readonly error: unknown;
  /** MFA 明细重取信号（递增触发已展开明细重取 GetMfa，见 MfaMethodList props）。 */
  readonly detailVersion: number;
  /** 重取 GetConfig（刷新 mfaPolicy 摘要，§5 行 495 数据分工）。 */
  readonly onRefreshConfig: () => void;
  /** 通行密钥增删成功：重取 GetConfig + 递增 detailVersion。 */
  readonly onWebauthnChanged: () => void;
  /** redirect 绑定回调横幅（?bind= 参数消费；无 → 不渲染）。 */
  readonly bindNotice: BindNotice | undefined;
  /** 关闭横幅。 */
  readonly onDismissBindNotice: () => void;
}): ReactNode {
  const { config, error } = props;
  if (config === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      return <p role="alert">{t('account.configLoadFailed')}</p>;
    }
    return <Spin />;
  }
  const policy = config.mfaPolicy ?? ZERO_MFA_POLICY;
  const captcha = config.captcha ?? ZERO_CAPTCHA_CONFIG;
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>{t('account.securityTitle')}</Typography.Title>
      {props.bindNotice !== undefined ? (
        <div
          role={props.bindNotice.kind === 'success' ? 'status' : 'alert'}
          className={props.bindNotice.kind === 'success' ? styles.bindOk : styles.bindError}
        >
          <span>{props.bindNotice.text}</span>
          <Button size="small" type="tertiary" onClick={props.onDismissBindNotice}>
            {t('account.close')}
          </Button>
        </div>
      ) : null}
      <Card title={t('account.twoFactorTitle')} className={styles.card}>
        <p className={styles.mfaStatus}>
          {policy.enabled ? t('account.mfaEnabledStatus') : t('account.mfaDisabledStatus')}
          {policy.required ? t('account.mfaRequiredNote') : ''}
        </p>
        {/* §3.2 行 847：trustedDeviceDays 预留恒 0——本期无「信任此设备」。 */}
        <p className={styles.mfaTrust}>{t('account.trustDeviceNote')}</p>
        {/* 因子列表 + 开关 + 绑定明细（§3.5），占位提示随之替换。 */}
        <MfaMethodList
          methods={policy.methods}
          required={policy.required}
          detailVersion={props.detailVersion}
          onPolicyRefresh={props.onRefreshConfig}
        />
      </Card>
      <Card title={t('account.passwordCardTitle')} className={styles.card}>
        <PasswordChangeForm hasPassword={config.hasPassword} />
      </Card>
      <Card title={t('account.contactCardTitle')} className={styles.card}>
        <div className={styles.contactStack}>
          <ContactBindForm kind="phone" captcha={captcha} />
          <ContactBindForm kind="email" captcha={captcha} />
        </div>
      </Card>
      <Card title={t('factors.webauthn')} className={styles.card}>
        <WebauthnList onChanged={props.onWebauthnChanged} />
      </Card>
      <Card title={t('account.thirdpartyCardTitle')} className={styles.card}>
        <ThirdPartyList hasPassword={config.hasPassword} captcha={captcha} />
      </Card>
    </section>
  );
}

/** 安全中心状态壳：首次进入请求 GetConfig；401 统一跳登录（§5 行 480）。 */
export function SecurityPage(): ReactNode {
  const { status, data, error, run } = useRequest(getConfig);
  const [detailVersion, setDetailVersion] = useState(0);
  const [bindNotice, setBindNotice] = useState<BindNotice | undefined>(undefined);
  const alRoot = loadAccountBootstrap().alRoot;
  useEffect(() => {
    if (isUnauthenticatedError(error)) {
      // §5 行 480：401 统一跳登录（replace：安全中心不可回退占位）。
      window.location.replace(loginUrl(alRoot));
    }
  }, [error, alRoot]);
  useEffect(() => {
    // useRequest.run 失败会 rethrow（状态已入 reducer），此处吞掉防
    // unhandled rejection；错误呈现 / 401 跳转由上 effect + View 帧处理。
    run().catch(() => {});
  }, [run]);
  // redirect 绑定回调落地（§3.7.1 A 行 969-971）：挂载时消费 ?bind= 出横幅，
  // 随即清参（replaceState 不新增历史项，防刷新复读；readBindParam 纯函数在
  // ./api，node 可测）。仅挂载时执行一次（[] 空依赖，pathname 固定本页）。
  useEffect(() => {
    const code = readBindParam(window.location.search);
    if (code !== undefined) {
      setBindNotice({
        kind: code === 'success' ? 'success' : 'error',
        text: bindParamMessage(code),
      });
      window.history.replaceState(null, '', window.location.pathname);
    }
  }, []);
  const refreshConfig = () => {
    // 开关 / 绑定成功只刷 mfaPolicy（§5 行 495：重取 GetConfig 摘要）。
    run().catch(() => {});
  };
  const handleWebauthnChanged = () => {
    // webauthn.bound 可能翻转 → 刷摘要 + 已展开明细重取。
    setDetailVersion((v) => v + 1);
    run().catch(() => {});
  };
  return (
    <SecurityPageView
      status={status}
      config={data}
      error={error}
      detailVersion={detailVersion}
      onRefreshConfig={refreshConfig}
      onWebauthnChanged={handleWebauthnChanged}
      bindNotice={bindNotice}
      onDismissBindNotice={() => setBindNotice(undefined)}
    />
  );
}

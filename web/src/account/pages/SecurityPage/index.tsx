/**
 * 安全中心页（SettingList 行式布局）：GetConfig 驱动三个区块——
 * - 登录方式：密码（hasPassword 区分设置 / 修改）、手机号 / 邮箱（未设密码
 *   显示「请先设置密码」）、通行密钥（useWebauthnSetting：已绑定 X 个 +
 *   查看已绑定 / 新增）；
 * - 双因素认证：useMfaSetting（MFA + 恢复码合并单行）；
 * - 第三方账号：ThirdPartyList（redirect / qrcode 通道绑定 + 解绑置灰）。
 *
 * 【redirect 绑定回调落地（§3.7.1 A 行 969-971）】OAuthCallbackPage b 分支
 * 完成后 location.replace('/account#/security?bind={success|ErrorInfo.code}')
 * 回到本页——挂载时读取 ?bind= 出 Toast（bindParamMessage：target_taken
 * 出绑定语境文案），随即清参防刷新复读（setSearchParams replace，保 hash
 * 清 query）。
 *
 * 401 处理（§5 行 480）：统一走 shared/hooks/requestOptions 的集中
 * onError（跳登录带 returnTo）。文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { useLocation, useSearchParams } from '@modern-js/runtime/router';
import { useRequest } from 'ahooks';
import { Button, Modal, Spin, Toast, Typography } from '@douyinfe/semi-ui';
import { create } from '@bufbuild/protobuf';
import type {
  AccountConfigResponse,
  MfaPolicy,
} from '@/gen/proto/api/account/v1/profile_pb';
import { MfaPolicySchema } from '@/gen/proto/api/account/v1/profile_pb';
import { CaptchaConfigSchema } from '@/gen/proto/api/common/v1/captcha_pb';
import {
  deriveRequestStatus,
  type RequestStatus,
} from '@/shared/hooks/deriveRequestStatus';
import { requestOptions } from '@/shared/hooks/requestOptions';
import { t } from '@/shared/i18n';
import { PageLayout } from '@/shared/components/PageLayout';
import { SettingListSections } from '@/shared/components/SettingList';
import {
  accountReturnTo,
  bindParamMessage,
  getConfig,
  getProfile,
  isUnauthenticatedError,
  readBindParam,
} from '../../api';
import { ContactBindForm } from './ContactBindForm';
import { useMfaSetting } from './MfaSetting';
import { PasswordChangeForm } from './PasswordChangeForm';
import { ThirdPartyList } from './ThirdPartyList';
import { useWebauthnSetting } from './WebauthnSetting';

/** mfaPolicy 零值兜底（§3.1：缺失字段按零值；protojson 省略未置字段时）。 */
const ZERO_MFA_POLICY: MfaPolicy = create(MfaPolicySchema, {});

/** captcha 零值兜底（§3.1）：GetConfig 未下发 captcha 时 CaptchaWidget 走其兜底错误态。 */
const ZERO_CAPTCHA_CONFIG = create(CaptchaConfigSchema, {});

/** 安全中心帧视图：配置未就绪 → 错误提示 / 加载态。 */
export function SecurityPageView(props: {
  status: RequestStatus;
  config: AccountConfigResponse | undefined;
  error: unknown;
  /** 重取 GetConfig（刷新 mfaPolicy 摘要）。 */
  onRefreshConfig: () => void;
}): ReactNode {
  // 当前已绑定值回显（GetProfile 服务端脱敏字段）——挂载即取，绑定成功后刷新。
  const { data: profile, refresh: refreshProfile } = useRequest(getProfile);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showBindPhoneModal, setShowBindPhoneModal] = useState(false);
  const [showBindEmailModal, setShowBindEmailModal] = useState(false);
  const { config, error } = props;
  const policy = config?.mfaPolicy ?? ZERO_MFA_POLICY;
  const mfaField = useMfaSetting({
    methods: policy.methods,
    required: policy.required,
    onPolicyRefresh: props.onRefreshConfig,
  });
  const webauthnField = useWebauthnSetting();
  if (config === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      return <p role="alert">{t('account.configLoadFailed')}</p>;
    }
    return <Spin />;
  }
  const captcha = config.captcha ?? ZERO_CAPTCHA_CONFIG;
  const hasPassword = config.hasPassword;
  const contactExtra = (kind: 'phone' | 'email', bound: boolean) =>
    hasPassword ? (
      <Button
        type="tertiary"
        onClick={() =>
          kind === 'phone'
            ? setShowBindPhoneModal(true)
            : setShowBindEmailModal(true)
        }
      >
        {bound ? t('account.rebindAction') : t('account.goBindAction')}
      </Button>
    ) : (
      <Typography.Text type="tertiary">
        {t('account.setPasswordFirst')}
      </Typography.Text>
    );
  return (
    <PageLayout title={t('account.securityTitle')}>
      <SettingListSections
        sections={[
          {
            key: 'login',
            title: t('account.loginMethodTitle'),
            fields: [
              {
                key: 'password',
                title: t('account.passwordLabel'),
                help: hasPassword
                  ? t('account.passwordChangeHint')
                  : t('account.passwordNotSet'),
                extra: (
                  <Button
                    type="tertiary"
                    onClick={() => setShowPasswordModal(true)}
                  >
                    {hasPassword
                      ? t('account.changePasswordAction')
                      : t('account.setPasswordAction')}
                  </Button>
                ),
              },
              {
                key: 'phone',
                title: t('account.phoneLabel'),
                help: profile?.phone || t('account.factorUnboundTag'),
                extra: contactExtra('phone', Boolean(profile?.phone)),
              },
              {
                key: 'email',
                title: t('account.emailLabel'),
                help: profile?.email || t('account.factorUnboundTag'),
                extra: contactExtra('email', Boolean(profile?.email)),
              },
              webauthnField,
            ],
          },
          {
            key: 'mfa',
            title: t('account.mfaSectionTitle'),
            fields: [mfaField],
          },
          {
            key: 'thirdparty',
            title: t('account.thirdpartyCardTitle'),
            children: (
              <ThirdPartyList hasPassword={hasPassword} captcha={captcha} />
            ),
          },
        ]}
      />
      <Modal
        visible={showPasswordModal}
        title={
          hasPassword
            ? t('account.changePasswordAction')
            : t('account.setPasswordAction')
        }
        footer={null}
        onCancel={() => setShowPasswordModal(false)}
      >
        <PasswordChangeForm hasPassword={hasPassword} />
      </Modal>
      <Modal
        visible={showBindPhoneModal}
        title={t('account.bindPhoneTitle')}
        footer={null}
        onCancel={() => setShowBindPhoneModal(false)}
      >
        <ContactBindForm
          kind="phone"
          captcha={captcha}
          onBound={refreshProfile}
        />
      </Modal>
      <Modal
        visible={showBindEmailModal}
        title={t('account.bindEmailTitle')}
        footer={null}
        onCancel={() => setShowBindEmailModal(false)}
      >
        <ContactBindForm
          kind="email"
          captcha={captcha}
          onBound={refreshProfile}
        />
      </Modal>
    </PageLayout>
  );
}

/** 安全中心状态壳：首次进入请求 GetConfig；401 集中 onError 跳登录（§5 行 480）。 */
export function SecurityPage(): ReactNode {
  // 错误统一走集中 onError——401 跳登录带 returnTo，其余静默
  // （toast:false：错误帧呈现，防 Toast + 行内双报）。
  const location = useLocation();
  const { data, error, loading, refresh } = useRequest(
    getConfig,
    requestOptions({
      toast: false,
      returnTo: () => accountReturnTo(location.pathname, location.search),
    }),
  );
  const status = deriveRequestStatus(loading, error, data);
  // redirect 绑定回调落地（§3.7.1 A 行 969-971）：挂载时消费 ?bind= 出 Toast，
  // 随即清参（不新增历史项，防刷新复读）。**hash 路由已知坑**：query 在
  // hash 内（`/account#/security?bind=…`），必须经 useSearchParams 读、
  // setSearchParams(replace) 清（保留 hash 路径只清 query）。
  const [searchParams, setSearchParams] = useSearchParams();
  useEffect(() => {
    const code = readBindParam(searchParams.toString());
    if (code !== undefined) {
      const text = bindParamMessage(code);
      if (code === 'success') {
        Toast.success(text);
      } else {
        Toast.error(text);
      }
      setSearchParams({}, { replace: true });
    }
    // 仅挂载时执行一次；setSearchParams 引用稳定，不入依赖（防清参后重触发）。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <SecurityPageView
      status={status}
      config={data}
      error={error}
      onRefreshConfig={refresh}
    />
  );
}

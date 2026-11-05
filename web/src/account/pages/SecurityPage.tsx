/**
 * 安全中心页（docs/前端架构.md §5 行 492；docs/接口文档.md §3）：GetConfig
 * （§3.2 行 819，后端已实装——「先 mock」口径按 msw 单测覆盖，
 * 页面真调）驱动三个区块——
 * - 两步验证摘要卡片：mfaPolicy（§3.2 行 828-848：enabled / required /
 *   trustedDeviceDays 预留恒 0 / methods 因子投影；绑定明细归后续实现，此处
 *   仅摘要 + 占位提示，不实现明细 / 开关）；
 * - 登录密码：PasswordChangeForm（hasPassword 驱动，§3.3）；
 * - 联系方式：ContactBindForm ×2（phone / email，§3.4；captcha 配置取
 *   GetConfig 的 captcha 对象——account entry 的配置读取处，§3.2 行 819）。
 * 头像上传挂载点为 ProfilePage（§5 行 491），AvatarUploader 组件本次
 * 交付但不落本页（doc 优先：SecurityPage 无头像区块）。
 *
 * 401 处理沿 ProfilePage 模式（§5 行 480）：isUnauthenticatedError +
 * loginUrl 由页面层统一实现。文案无 i18n 键：中文字面量 + 注释声明。
 */
import { useEffect, type ReactNode } from 'react';
// 子路径 import（同 ProfilePage 口径：避免全量入口，测试链 / 产物见其注释）。
import Card from '@douyinfe/semi-ui/lib/es/card';
import Spin from '@douyinfe/semi-ui/lib/es/spin';
import Tag from '@douyinfe/semi-ui/lib/es/tag';
import Typography from '@douyinfe/semi-ui/lib/es/typography';
import { create } from '@bufbuild/protobuf';
import type {
  AccountConfigResponse,
  MfaPolicy,
} from '../../gen/proto/api/account/v1/profile_pb';
import { MfaPolicySchema } from '../../gen/proto/api/account/v1/profile_pb';
import { CaptchaConfigSchema } from '../../gen/proto/api/common/v1/captcha_pb';
import { useRequest, type RequestStatus } from '../../shared/hooks/useRequest';
import { getConfig, isUnauthenticatedError } from '../api';
import { loadAccountBootstrap, loginUrl } from '../bootstrap';
import { ContactBindForm } from '../components/ContactBindForm';
import { PasswordChangeForm } from '../components/PasswordChangeForm';
import styles from './SecurityPage.module.less';

/** mfaPolicy 因子展示名（§3.2 行 835-841 因子全集；未知因子回显原文，§9 第 18 条零值兜底）。 */
const MFA_FACTOR_LABELS: Readonly<Record<string, string>> = {
  totp: 'TOTP 动态码',
  otp_sms: '短信验证码',
  otp_email: '邮箱验证码',
  webauthn: '通行密钥',
  recovery_code: '恢复码',
};

function mfaFactorLabel(factor: string): string {
  return MFA_FACTOR_LABELS[factor] ?? factor;
}

/** mfaPolicy 零值兜底（§3.1：缺失字段按零值；protojson 省略未置字段时）。 */
const ZERO_MFA_POLICY: MfaPolicy = create(MfaPolicySchema, {});

/** captcha 零值兜底（§3.1）：GetConfig 未下发 captcha 时 CaptchaWidget 走其兜底错误态。 */
const ZERO_CAPTCHA_CONFIG = create(CaptchaConfigSchema, {});

/**
 * 安全中心帧视图（纯渲染，无请求）：
 * 配置未就绪 → 401 以外的错误提示 / 加载态；就绪 → 摘要 + 密码 + 联系方式。
 */
export function SecurityPageView(props: {
  readonly status: RequestStatus;
  readonly config: AccountConfigResponse | undefined;
  readonly error: unknown;
}): ReactNode {
  const { config, error } = props;
  if (config === undefined) {
    if (props.status === 'error' && !isUnauthenticatedError(error)) {
      return <p role="alert">配置加载失败，请刷新重试</p>;
    }
    return <Spin />;
  }
  const policy = config.mfaPolicy ?? ZERO_MFA_POLICY;
  const captcha = config.captcha ?? ZERO_CAPTCHA_CONFIG;
  return (
    <section className={styles.page}>
      <Typography.Title heading={3}>安全中心</Typography.Title>
      <Card title="两步验证" className={styles.card}>
        <p className={styles.mfaStatus}>
          {policy.enabled ? '已开启两步验证' : '未开启两步验证'}
          {policy.required ? '（策略强制开启，不可关闭）' : ''}
        </p>
        {/* §3.2 行 847：trustedDeviceDays 预留恒 0——本期无「信任此设备」。 */}
        <p className={styles.mfaTrust}>信任设备：暂不支持（每次登录均需二次验证）</p>
        <ul className={styles.mfaMethods}>
          {policy.methods.map((method) => (
            <li key={method.factor} className={styles.mfaMethod}>
              <span className={styles.mfaFactor}>{mfaFactorLabel(method.factor)}</span>
              <Tag size="small" color={method.bound ? 'green' : 'grey'}>
                {method.bound ? '已绑定' : '未绑定'}
              </Tag>
              <Tag size="small" color={method.enabled ? 'blue' : 'grey'}>
                {method.enabled ? '已启用' : '未启用'}
              </Tag>
            </li>
          ))}
        </ul>
        {/* MFA 绑定明细 / 开关不在本次范围，此处仅摘要卡片。 */}
        <Typography.Text type="secondary" className={styles.mfaHint}>
          因子绑定明细与开关管理即将开放
        </Typography.Text>
      </Card>
      <Card title="登录密码" className={styles.card}>
        <PasswordChangeForm hasPassword={config.hasPassword} />
      </Card>
      <Card title="联系方式" className={styles.card}>
        <div className={styles.contactStack}>
          <ContactBindForm kind="phone" captcha={captcha} />
          <ContactBindForm kind="email" captcha={captcha} />
        </div>
      </Card>
    </section>
  );
}

/** 安全中心状态壳：首次进入请求 GetConfig；401 统一跳登录（§5 行 480）。 */
export function SecurityPage(): ReactNode {
  const { status, data, error, run } = useRequest(getConfig);
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
  return <SecurityPageView status={status} config={data} error={error} />;
}

/**
 * 扫码绑定对话框（docs/前端架构.md §5；docs/接口文档.md §3.7.1 B）：
 * shared/components/QRCodeDialog 的绑定包装——窗体与四态面板归 shared 通用壳
 * （modal 注入 account 域窗体 shared/app-ui/Modal），本组件只做域内接线：
 * requestQR 经 shared/api/sso 调 SsoService/CreateQrcode{providerKey,
 * scene:'bind', captcha}（§2.8，captcha 配置取自 §3.2 的 GetConfig、由调用方
 * 注入；每次拉码都要新的凭据），pollUrl 轮询
 * AccountService/GetThirdpartyTicket{ticket, poll}（§3.7.1 B），onResult
 * success → onDone（成功 → 关闭面板并刷新列表）；expired → 面板「重试」重拉码
 * （requestQR 每轮经弹窗现取新凭据）；卸载中断轮询（§3.3）。不触碰登录状态机：
 * onResult 不做 completeLogin 类终点跳转，绑定不改登录态（§3.7.1 B）。
 *
 * 【target_taken 文案落地】通用字典 target_taken 系联系方式语境；绑定语境
 * （§3.7.1 B 服务端 message 示例）为「该账号已被其他账号绑定」。经
 * QRCodeDialog 的 resolveFailureText(envelope) 注入 bindFailureText（./api
 * 纯函数）按信封顶层 status 出文案；最近一次轮询信封的保存与「拉码失败 /
 * 连续轮询超错无落定信封不改文案」由壳的守卫负责。
 *
 * 【captcha 门控】按 provider need_captcha 分派（§2.5 触发表）：true 走
 * upfront——面板挂载即弹窗问凭据再发请求；false 走 reactive——先裸发，命中
 * captcha_required 才弹窗；captcha_invalid 在窗内换凭据重试；用户取消则卸下
 * 面板、留「获取二维码」按钮原地重入（panelKey 重挂 = 新一轮拉码，凭据一次性
 * 不可复用）。signal 忽略——api 薄封装不支持中断，结果丢弃由壳 disposed 检查
 * 兜底。文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Button } from '@douyinfe/semi-ui';
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../../gen/proto/api/sso/v1/login_pb';
import type { LoginFlowResponse } from '../../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../../gen/proto/api/sso/v1/ticket_pb';
import { Modal as AppModal } from '../../../shared/app-ui/Modal';
import { CaptchaDialog } from '../../../shared/captcha/CaptchaDialog';
import { errorCaptchaOutcome } from '../../../shared/captcha/captchaGate';
import { useCaptchaGate } from '../../../shared/captcha/useCaptchaGate';
import { QRCodeDialog } from '../../../shared/components/QRCodeDialog';
import { createQrcode } from '../../../shared/api/sso';
import { t } from '../../../shared/i18n';
import {
  bindFailureText,
  buildCreateQrcodeBindRequest,
  buildGetThirdpartyTicketRequest,
  getThirdpartyTicket,
} from '../../api';
import styles from './ThirdPartyBindDialog.module.less';

/**
 * 扫码绑定窗体：visible 即挂 QRCodeDialog（挂载即拉码，卸载即 dispose 中断
 * 轮询）；X / Esc / 底部「关闭」统一路由 onCancel（未完成不刷新列表）。
 * captcha 弹窗由本组件持有（gate），经 children 挂进壳内。用户取消 captcha
 * 则卸下面板、留「获取二维码」按钮原地重入——重入窗体直接由注入的 AppModal
 * 承载（壳挂载即拉码，表达不了「等用户点了再拉」），footer 与壳同一口径：
 * 仅「关闭」、X / Esc / 遮罩不误触，关窗动作一律 onCancel。
 */
export function ThirdPartyBindDialog(props: {
  /** 打开态（父级 ThirdPartyList 控制）。 */
  visible: boolean;
  /** 扫码类 Provider 标识（§3.7.1 B：channel=qrcode 的 available 条目）。 */
  providerKey: string;
  /** Provider 展示名（Modal 标题）。 */
  displayName: string;
  /** 拉码需人机校验（§2.5 模式分派，随 available 条目透传）。 */
  needCaptcha: boolean;
  /** captcha 配置（§3.2 GetConfig 注入，§5）。 */
  captcha: CaptchaConfig;
  /** 未完成绑定的关闭（父级仅关框）。 */
  onCancel: () => void;
  /** 绑定成功（§3.7.1 B）：父级关框 + 刷新列表。 */
  onDone: () => void;
}): ReactNode {
  const gate = useCaptchaGate(AppModal);
  const [cancelled, setCancelled] = useState(false);
  // 取消后重入：新 key 重挂壳体 → 再次走 upfront 弹窗（凭据一次性，不可复用）。
  const [panelKey, setPanelKey] = useState(0);

  // 关闭后重置：选关闭沿（非打开沿）——壳随 visible=false 已卸载、controller
  // 已 dispose，重置发生在卸载之后，避免「打开帧先挂旧面板再重置」的一帧闪挂
  // （旧凭据拉错码）。
  useEffect(() => {
    if (!props.visible) {
      setCancelled(false);
    }
  }, [props.visible]);

  const title =
    props.displayName === ''
      ? t('account.scanBindTitle')
      : t('account.bindNameTitle', { name: props.displayName });

  const requestQR = async (
    _signal: AbortSignal,
  ): Promise<CreateQrcodeResponse> => {
    // signal 忽略——api 薄封装不支持中断（pollUrl 同）。
    const outcome = await gate.run({
      // 模式分派（§2.5）：provider need_captcha=true 先问再发，false 先
      // 裸发命中 captcha_required 才问；服务端按同一配置 fail-closed 兜底。
      mode: props.needCaptcha ? 'upfront' : 'reactive',
      config: props.captcha,
      // 凭据一律交请求组装（reactive 首探不带 captcha 字段，§2.5）。
      request: (token: CaptchaPayload | undefined) =>
        createQrcode(buildCreateQrcodeBindRequest(props.providerKey, token)),
      // CreateQrcode 响应无 status 字段（§12.9 生成物）：结论只在错误侧。
      readOutcome: () => ({ action: 'message' }),
      readError: errorCaptchaOutcome,
    });
    if (outcome.kind === 'result') {
      return outcome.result;
    }
    if (outcome.kind === 'cancelled') {
      // 面板壳随即卸载，其 disposed 检查会吞掉这次 reject 的 failed 态。
      setCancelled(true);
      throw new Error(t('account.qrNeedCaptcha'));
    }
    throw outcome.error;
  };

  const pollUrl = (
    ticket: string,
    _signal: AbortSignal,
  ): Promise<LoginFlowResponse> =>
    getThirdpartyTicket(buildGetThirdpartyTicketRequest(ticket));

  if (!props.visible) {
    return null;
  }

  if (cancelled) {
    return (
      <AppModal
        title={title}
        visible
        hasCancel={false}
        okText={t('common.close')}
        closable
        closeOnEsc
        maskClosable={false}
        onOk={props.onCancel}
        onCancel={props.onCancel}
      >
        <div className={styles.body}>
          {/* 面板上明示「扫码后将绑定到当前账号」（§5）。 */}
          <p className={styles.hint}>{t('account.qrBindHint')}</p>
          <Button
            theme="solid"
            onClick={() => {
              setCancelled(false);
              setPanelKey((key) => key + 1);
            }}
          >
            {t('account.fetchQrcodeAction')}
          </Button>
        </div>
      </AppModal>
    );
  }

  return (
    <QRCodeDialog
      key={panelKey}
      modal={AppModal}
      title={title}
      requestQR={requestQR}
      pollUrl={pollUrl}
      // success 即绑定完成，关闭面板并刷新列表；bind.ok 不作判据（protojson
      // 省略零值），不读 .login（绑定不触碰登录状态机）。
      onResult={props.onDone}
      resolveFailureText={bindFailureText}
      onClose={props.onCancel}
    >
      <div className={styles.body}>
        <p className={styles.hint}>{t('account.qrBindHint')}</p>
        <CaptchaDialog {...gate.dialogProps} />
      </div>
    </QRCodeDialog>
  );
}

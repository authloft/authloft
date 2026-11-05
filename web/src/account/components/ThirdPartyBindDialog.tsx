/**
 * 扫码绑定对话框（docs/前端架构.md §5 行 489；docs/接口文档.md §3.7.1 B）：
 * shared/QRCodePanel 的绑定包装——requestQR 经 shared/api/sso 调
 * SsoService/CreateQrcode{providerKey, scene:'bind', captcha}（§2.8 行 688-703，
 * captcha 配置取自 §3.2 的 GetConfig、由调用方注入；每次拉码都要新的凭据，
 * 行 703），pollUrl 轮询 AccountService/GetThirdpartyTicket{ticket, poll}（§3.7.1
 * B 行 996），onResult success → onDone（成功 → 关闭面板并刷新列表，行 1007）；
 * expired → 面板「重试」重拉码（requestQR 实时取新 captcha 凭据）；卸载中断
 * 轮询（§3.3 行 345）。不触碰登录状态机（§5 行 489）：onResult 不做
 * completeLogin 类终点跳转，绑定不改登录态（§3.7.1 B 行 1033）。
 *
 * 【target_taken 文案落地】QRCodePanel 组件壳把 onPhase
 * 硬接 setPhase、failed 帧文案固定走 §1.6 通用字典（errors.status.target_taken
 * 系联系方式语境）；绑定语境（§3.7.1 B 行 1028 服务端 message 示例）为
 * 「该账号已被其他账号绑定」。本组件以 createQRPanelController +
 * QRCodePanelView 组合消费（四态面板机与纯展示仍是 shared 唯一实现，§3.3 行
 * 345；组件壳 QRCodePanel 仅 15 行胶水，此处等价重组以注入 onPhase），经
 * bindPollPhase（./api 纯函数）替换 target_taken 的 failed 帧文案——两组
 * props 下四态流转仍一致（面板四态流转测试约束不破，仅该帧文案按语境覆盖）。
 *
 * 【captcha 门控】CreateQrcode 必须携带 captcha（§2.8 行 690/703）：先渲染
 * CaptchaWidget +「获取二维码」，凭据就绪才挂面板（挂载即拉码，面板
 * 契约；login 端 QRCodeStep 同款门控模式，§2.8 行 490-497 取图链在
 * CaptchaWidget 内）。signal 忽略——api 薄封装不支持中断，结果丢弃由面板
 * disposed 检查兜底。
 * 文案经 shared/i18n（account.* 域键）。
 */
import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { Button, Modal } from '@douyinfe/semi-ui-19';
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { CreateQrcodeResponse } from '../../gen/proto/api/sso/v1/ticket_pb';
import { CaptchaWidget, type CaptchaWidgetHandle } from '../../shared/captcha/CaptchaWidget';
import {
  createQRPanelController,
  MAX_POLL_SECONDS,
  QRCodePanelView,
  type QRPanelController,
  type QRPanelPhase,
} from '../../shared/components/QRCodePanel';
import { createQrcode } from '../../shared/api/sso';
import { t } from '../../shared/i18n';
import {
  bindPollPhase,
  buildCreateQrcodeBindRequest,
  buildGetThirdpartyTicketRequest,
  getThirdpartyTicket,
} from '../api';
import styles from './ThirdPartyBindDialog.module.less';

/** 面板体 props（started 后挂载；controller 生命周期与卸载中断绑定）。 */
interface PanelBodyProps {
  /** 扫码类 Provider 标识（§3.7.1 B 行 993）。 */
  readonly providerKey: string;
  /** CaptchaWidget 句柄（useRef<CaptchaWidgetHandle>(null) 产物；实时取拉码凭据，§2.8 行 703）。 */
  readonly captchaRef: RefObject<CaptchaWidgetHandle | null>;
  /** 绑定成功（§3.7.1 B 行 1007）：父级关框 + 刷新列表。 */
  readonly onDone: () => void;
}

/**
 * 面板体：createQRPanelController + QRCodePanelView 组合（见文件头 target_taken
 * 落地说明）。lastPollStatus 记录最近一次轮询信封顶层 status，供 failed 帧
 * 文案映射（bindPollPhase）；propsRef 模式与 shared 面板组件壳一致（闭包内
 * 读最新 props）。
 */
function BindPanelBody({ providerKey, captchaRef, onDone }: PanelBodyProps): ReactNode {
  const [phase, setPhase] = useState<QRPanelPhase>({ kind: 'fetching' });
  const lastPollStatusRef = useRef('');
  const propsRef = useRef({ providerKey, captchaRef, onDone });
  propsRef.current = { providerKey, captchaRef, onDone };
  const [controller] = useState<QRPanelController>(() =>
    createQRPanelController({
      requestQR: (_signal: AbortSignal): Promise<CreateQrcodeResponse> => {
        const captcha = propsRef.current.captchaRef.current?.getToken();
        if (captcha === undefined) {
          return Promise.reject(new Error(t('account.qrNeedCaptcha')));
        }
        return createQrcode(
          buildCreateQrcodeBindRequest(propsRef.current.providerKey, captcha),
        );
      },
      pollUrl: async (ticket: string, _signal: AbortSignal): Promise<LoginFlowResponse> => {
        const envelope = await getThirdpartyTicket(
          buildGetThirdpartyTicketRequest(ticket),
        );
        lastPollStatusRef.current = envelope.status;
        return envelope;
      },
      onResult: () => {
        // §3.7.1 B 行 1007 / 行 1024：success 即绑定完成，关闭面板并刷新
        // 列表；bind.ok 不作判据（protojson 省略零值，行 1024 示例 bind 无
        // ok 字段），不读 .login（绑定不触碰登录状态机）。
        propsRef.current.onDone();
      },
      onPhase: (next) => {
        setPhase(bindPollPhase(next, lastPollStatusRef.current));
      },
      pollSeconds: MAX_POLL_SECONDS,
    }),
  );

  // 挂载即拉码；卸载中断轮询与在途拉码（§3.3 行 345）。
  useEffect(() => {
    controller.refresh();
    return () => controller.dispose();
  }, [controller]);

  return <QRCodePanelView phase={phase} onRefresh={() => controller.refresh()} />;
}

/**
 * 扫码绑定状态壳（TotpBindDialog 挂载模式）：打开（visible 翻转）→ 重置本地
 * 态重走 captcha 门控；关闭即卸载面板体（visible 条件渲染）中断轮询，重开
 * 重走门控。Modal 的 X / 遮罩关闭一律路由到 onCancel（未完成不刷新列表）。
 */
export function ThirdPartyBindDialog(props: {
  /** 打开态（父级 ThirdPartyList 控制）。 */
  readonly visible: boolean;
  /** 扫码类 Provider 标识（§3.7.1 B 行 993：channel=qrcode 的 available 条目）。 */
  readonly providerKey: string;
  /** Provider 展示名（Modal 标题）。 */
  readonly displayName: string;
  /** captcha 配置（§3.2 GetConfig 注入，§5 行 489）。 */
  readonly captcha: CaptchaConfig;
  /** 未完成绑定的关闭（父级仅关框）。 */
  readonly onCancel: () => void;
  /** 绑定成功（§3.7.1 B 行 1007）：父级关框 + 刷新列表。 */
  readonly onDone: () => void;
}): ReactNode {
  const { captcha } = props;
  const [started, setStarted] = useState(false);
  const [notice, setNotice] = useState(false);
  const captchaRef = useRef<CaptchaWidgetHandle>(null);

  // 关闭后重置：重开重走 captcha 门控。选关闭沿（非打开沿）——面板体随
  // visible=false 已卸载、controller 已 dispose，重置发生在卸载之后，避免
  // 「打开帧先挂旧面板再重置」的一帧闪挂（旧凭据拉错码）。
  useEffect(() => {
    if (!props.visible) {
      setStarted(false);
      setNotice(false);
    }
  }, [props.visible]);

  /** 门控按钮：凭据就绪才挂面板（挂载即拉码，面板契约）。 */
  const start = () => {
    if (captchaRef.current?.getToken() === undefined) {
      setNotice(true);
      return;
    }
    setStarted(true);
  };

  return (
    <Modal
      title={
        props.displayName === ''
          ? t('account.scanBindTitle')
          : t('account.bindNameTitle', { name: props.displayName })
      }
      visible={props.visible}
      onCancel={props.onCancel}
      footer={null}
    >
      {props.visible && (
        <div className={styles.body}>
          {/* §5 行 489：面板上明示「扫码后将绑定到当前账号」。 */}
          <p className={styles.hint}>{t('account.qrBindHint')}</p>
          {started ? (
            <BindPanelBody
              providerKey={props.providerKey}
              captchaRef={captchaRef}
              onDone={props.onDone}
            />
          ) : (
            <div className={styles.captchaBox}>
              <CaptchaWidget captcha={captcha} ref={captchaRef} />
              <Button theme="solid" onClick={start}>
                {t('account.fetchQrcodeAction')}
              </Button>
              {notice ? (
                <p role="alert" className={styles.notice}>
                  {t('account.qrNeedCaptcha')}
                </p>
              ) : null}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

/**
 * 厂商无感验证码 wrapper 共享基座（docs/前端架构.md §3.5 行 391；接口文档
 * §2.5 行 489-531）：三家 wrapper（Turnstile / Recaptcha /
 * HCaptcha）的公共生命周期——siteKey 校验 → 动态加载厂商脚本
 * （loadVendorScript，运行期注入、不打包不写死标签）→ 挂载挑战 → token
 * 回调缓存 / 过期清空换新 → 失败可见错误态 + 手动重试。子类只封装厂商
 * API 细节（脚本 URL、全局对象、挂载 / 重置），不含业务逻辑（§3.5 行
 * 350-353「每个 wrapper 只做三件事」）。
 *
 * - getToken：厂商 token 未就绪（加载中 / 失败 / 过期 / 用户未完成）→
 *   undefined，调用方不带 captcha 提交（§3.5 行 351，与自绘 adapter 及
 *   §2.8 拉码链路的凭据未就绪语义一致）；就绪 → {providerKey, token}
 *   （§2.5 行 514-522 第三方提交格式，id / answer 留零值、protojson
 *   序列化省略）；
 * - reset：重置挑战（§3.5 行 364），子类按厂商口径覆盖 restart；
 * - 错误态：脚本加载失败 / 超时 / 厂商对象缺失 / siteKey 空串（§2.5 行
 *   501 正常态只应出现在 type=image，第三方出现即配置异常）→ i18n
 *   common.captchaLoadFailed + common.retry 重试按钮，点击重新走加载与
 *   渲染（不自动重试，避免失败死循环）；
 * - 会话序号：每次 recover 递增，旧挑战的迟到回调（token / 过期）作废
 *   （reset 竞态丢弃，与 Image adapter 同构）。
 *
 * 命令式 adapter：容器内 DOM 由本类自管（错误态元素）+ 厂商 SDK 注入
 * （iframe / badge），React 不经手。document 与 loadScript 均可注入，
 * node 测试环境（无 DOM）在纯逻辑层覆盖生命周期（沿既有惯例）。
 */
import { create } from '@bufbuild/protobuf';
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
} from '../../../gen/proto/api/sso/v1/login_pb';
import { t } from '../../i18n';
import { loadVendorScript } from '../loadVendorScript';
import type { CaptchaAdapter } from '../types';
import styles from './Vendor.module.less';

/** 厂商 wrapper 可注入项（缺省生产实现；测试注入替身）。 */
export interface VendorChallengeOptions {
  /** DOM 文档（缺省全局 document；node 测试环境注入桩）。 */
  document?: Document;
  /** 脚本加载入口（缺省 loadVendorScript；测试注入替身）。 */
  loadScript?: (src: string) => Promise<void>;
}

export abstract class VendorChallengeAdapter<
  Vendor extends object,
> implements CaptchaAdapter {
  private providerKey: string;
  protected siteKey: string;
  protected doc: Document;
  private loadScript: (src: string) => Promise<void>;
  private container: HTMLElement | null = null;
  private token = '';
  /** 会话序号：每次 recover 递增，使旧挑战的迟到回调作废（竞态丢弃）。 */
  private session = 0;

  constructor(captcha: CaptchaConfig, options: VendorChallengeOptions) {
    this.providerKey = captcha.providerKey ?? '';
    this.siteKey = captcha.siteKey ?? '';
    this.doc = options.document ?? document;
    this.loadScript = options.loadScript ?? loadVendorScript;
  }

  /** 厂商脚本 URL（含查询参数）。 */
  protected abstract scriptUrl(): string;

  /** 脚本就绪后取厂商全局对象（window.turnstile / grecaptcha / hcaptcha）。 */
  protected abstract getVendor(): Vendor | undefined;

  /** 挂载挑战：调厂商 render / execute，凭据经 acceptToken / onExpired 上报。 */
  protected abstract mountChallenge(
    vendor: Vendor,
    container: HTMLElement,
  ): void;

  /** 重置已挂载的挑战（restart 一环）；未挂载时 no-op。 */
  protected abstract teardownChallenge(): void;

  /** 厂商回调：token 就绪（epoch 过期则丢弃——reset 后旧挑战不作数）。 */
  protected acceptToken(epoch: number, token: string): void {
    if (epoch === this.session && token !== '') {
      this.token = token;
    }
  }

  /** 厂商回调：token 过期 → 清凭据并重启挑战（换新）。 */
  protected onExpired(epoch: number): void {
    if (epoch !== this.session) {
      return;
    }
    this.token = '';
    this.restart();
  }

  /** 挑战失败（如 execute reject）→ 错误态（可见、可重试）。 */
  protected rejectChallenge(epoch: number): void {
    if (epoch !== this.session) {
      return;
    }
    this.token = '';
    const container = this.container;
    if (container !== null) {
      this.paintError(container);
    }
  }

  /** 当前挑战会话序号（子类回调闭包捕获，迟到丢弃判据）。 */
  protected challengeEpoch(): number {
    return this.session;
  }

  render(container: HTMLElement): void {
    this.container = container;
    this.token = '';
    void this.recover();
  }

  reset(): void {
    this.token = '';
    this.restart();
  }

  getToken(): CaptchaPayload | undefined {
    if (this.token === '') {
      return undefined;
    }
    return create(CaptchaPayloadSchema, {
      providerKey: this.providerKey,
      token: this.token,
    });
  }

  /**
   * 重启挑战（reset / 过期换新 / 手动重试共用）：默认清已挂载挑战后从头
   * recover（脚本已加载时幂等直通，仅重新挂载）；hCaptcha 覆盖为原地
   * reset（厂商主流口径，不重复挂载）。
   */
  protected restart(): void {
    this.teardownChallenge();
    void this.recover();
  }

  /** siteKey 校验 → 动态加载脚本 → 挂载挑战；任一步失败 → 错误态（子类 restart 可复入）。 */
  protected async recover(): Promise<void> {
    const container = this.container;
    if (container === null) {
      return;
    }
    const epoch = ++this.session;
    if (this.siteKey === '') {
      this.paintError(container);
      return;
    }
    container.replaceChildren();
    try {
      await this.loadScript(this.scriptUrl());
    } catch {
      if (epoch === this.session && this.container === container) {
        this.paintError(container);
      }
      return;
    }
    if (epoch !== this.session || this.container !== container) {
      return;
    }
    const vendor = this.getVendor();
    if (vendor === undefined) {
      this.paintError(container);
      return;
    }
    this.mountChallenge(vendor, container);
  }

  /** 可见错误态：文案 + 重试按钮（重试 = restart 重新加载与渲染）。 */
  private paintError(container: HTMLElement): void {
    const message = this.doc.createElement('p');
    message.textContent = t('common.captchaLoadFailed');
    message.setAttribute('role', 'alert');
    message.className = styles.errorMessage;
    const button = this.doc.createElement('button');
    button.type = 'button';
    button.textContent = t('common.retry');
    button.className = styles.retryButton;
    button.addEventListener('click', () => {
      this.restart();
    });
    container.replaceChildren(message, button);
  }
}

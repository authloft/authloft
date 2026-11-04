/**
 * 自绘图形码 adapter（docs/前端架构.md §3.5 行 352；接口文档 §2.5 行 489-520）：
 * - 调 SsoService/CreateCaptchaImage（经 shared/api/sso 薄封装，可注入替身）
 *   取 {id, imageBase64, expiresIn}；imageBase64 直接以
 *   `data:image/png;base64,` 前缀渲染（§2.5 行 495-498：不再二次请求图片）；
 * - 用户在 input 作答，getToken() 返回 {providerKey, id, answer}（token 留
 *   零值，标准 protojson 序列化省略零值 → 提交体恰为 §2.5 行 503-506 的自绘
 *   三元组，providerKey 取自当前 captcha 对象——降级时为 builtin_image）；
 * - 取图失败自动换新（重拉，新 id 顶替旧的）；连续失败达上限（不死循环）→
 *   转手动重试态，点击重试重新进入自动换新循环；
 * - reset() 清空作答并重拉新图（§3.5 行 364：校验失败 / 过期 / 场景切换）；
 * - 第三方不可用被服务端降级时同样走本 adapter（§2.5 行 515、§3.5 行 352）。
 *
 * 命令式 adapter：容器内 DOM 由本类自管（与厂商 wrapper 往容器塞 iframe 的
 * 形态同构，§3.5 行 353），React 不经手。取图函数与 DOM 文档均可注入，
 * node 测试环境（无 DOM）在纯逻辑层覆盖生命周期（沿既有组件测试边界
 * 惯例）。零第三方依赖。
 */
import { create } from '@bufbuild/protobuf';
import type { CaptchaConfig } from '../../../gen/proto/api/common/v1/captcha_pb';
import {
  CaptchaPayloadSchema,
  type CaptchaPayload,
  type CreateCaptchaImageResponse,
} from '../../../gen/proto/api/sso/v1/login_pb';
import { createCaptchaImage } from '../../api/sso';
import { t } from '../../i18n';
import type { CaptchaAdapter } from '../types';

/** 连续取图失败上限：达到后停止自动换新、转手动重试态（重拉不死循环）。 */
export const IMAGE_FETCH_MAX_FAILURES = 3;

/** 可注入项（缺省生产实现；测试注入替身）。 */
export interface ImageAdapterOptions {
  /** 取图（缺省 shared/api/sso 的 CreateCaptchaImage 薄封装）。 */
  fetchImage?: () => Promise<CreateCaptchaImageResponse>;
  /** DOM 文档（缺省全局 document；node 无 DOM 测试环境注入桩）。 */
  document?: Document;
}

export class ImageCaptchaAdapter implements CaptchaAdapter {
  private readonly providerKey: string;
  private readonly fetchImage: () => Promise<CreateCaptchaImageResponse>;
  private readonly doc: Document;
  private container: HTMLElement | null = null;
  private input: HTMLInputElement | null = null;
  private currentId = '';
  private failures = 0;
  /** 会话序号：每次 load 递增，使在途取图结果作废（reset 竞态丢弃）。 */
  private session = 0;

  constructor(captcha: CaptchaConfig, options: ImageAdapterOptions = {}) {
    this.providerKey = captcha.providerKey ?? '';
    this.fetchImage = options.fetchImage ?? createCaptchaImage;
    this.doc = options.document ?? document;
  }

  render(container: HTMLElement): void {
    this.container = container;
    this.failures = 0;
    void this.load();
  }

  reset(): void {
    this.input = null;
    this.currentId = '';
    this.failures = 0;
    void this.load();
  }

  getToken(): CaptchaPayload | undefined {
    const answer = this.input?.value ?? '';
    if (this.currentId === '' || answer === '') {
      return undefined;
    }
    return create(CaptchaPayloadSchema, {
      providerKey: this.providerKey,
      id: this.currentId,
      answer,
    });
  }

  /** 取图并渲染；失败自动换新，连续达上限转手动重试态。 */
  private async load(): Promise<void> {
    const container = this.container;
    if (container === null) {
      return;
    }
    const session = ++this.session;
    this.paintLoading(container);
    try {
      const response = await this.fetchImage();
      if (session !== this.session || this.container !== container) {
        return;
      }
      this.currentId = response.id ?? '';
      this.failures = 0;
      this.paintReady(container, response.imageBase64 ?? '');
    } catch {
      if (session !== this.session || this.container !== container) {
        return;
      }
      this.currentId = '';
      this.input = null;
      this.failures += 1;
      if (this.failures < IMAGE_FETCH_MAX_FAILURES) {
        void this.load();
      } else {
        this.paintRetryable(container);
      }
    }
  }

  private paintLoading(container: HTMLElement): void {
    this.input = null;
    container.replaceChildren();
  }

  private paintReady(container: HTMLElement, imageBase64: string): void {
    const img = this.doc.createElement('img');
    img.src = `data:image/png;base64,${imageBase64}`;
    img.alt = 'captcha';
    const input = this.doc.createElement('input');
    input.type = 'text';
    input.autocomplete = 'off';
    container.replaceChildren(img, input);
    this.input = input;
  }

  private paintRetryable(container: HTMLElement): void {
    const message = this.doc.createElement('p');
    message.textContent = t('errors.status.unknown');
    message.setAttribute('role', 'alert');
    const button = this.doc.createElement('button');
    button.type = 'button';
    button.textContent = t('common.retry');
    button.addEventListener('click', () => {
      this.reset();
    });
    container.replaceChildren(message, button);
  }
}

/**
 * 分派器用的工厂（§3.5 行 350：image → 本 adapter）；签名兼容
 * CaptchaAdapterFactory。第二参供测试注入替身，缺省生产实现
 * （shared/api/sso + 全局 document）。
 */
export const createImageAdapter = (
  captcha: CaptchaConfig,
  options?: ImageAdapterOptions,
): CaptchaAdapter => new ImageCaptchaAdapter(captcha, options);

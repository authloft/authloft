/**
 * CaptchaAdapter 接口（docs/前端架构.md §3.5 行 351）：分派器
 * CaptchaWidget 与各 wrapper（自绘 / 厂商）之间的统一生命周期契约；每个
 * wrapper 只做三件事、不含业务逻辑（行 350-353）。
 *
 * 报文类型只从 src/gen/proto 生成物引用（§9 第 15 条，禁止手写 interface
 * 重复描述）：getToken 的返回即提交格式 api.sso.v1.CaptchaPayload（接口文档
 * §2.5）——自绘填 {providerKey, id, answer}（token 留零值，标准
 * protojson 序列化省略零值字段，提交体恰为 §2.5 的自绘三元组）；
 * 第三方 wrapper 填 {providerKey, token}。调用方把凭据挂到**请求顶层
 * `captcha`**（与 `payload` 平级），不再放进 `payload`。
 */
import type { CaptchaConfig } from '../../gen/proto/api/common/v1/captcha_pb';
import type { CaptchaPayload } from '../../gen/proto/api/sso/v1/login_pb';

/**
 * 统一生命周期（§3.5 行 350「统一生命周期」）：
 * - render：渲染进容器（内部可异步取图，fire-and-forget）；
 * - getToken：当前提交凭据；用户未完成（无图 / 未作答 / 厂商 token 未就绪）
 *   → undefined，调用方不带 captcha 提交；
 * - reset：重拉 / 重置——captcha_invalid、过期、场景切换时由调用方触发
 *   （§3.5 行 364）。
 */
export interface CaptchaAdapter {
  /** 渲染进容器；重复调用（reset 触发重拉）幂等重建。 */
  render(container: HTMLElement): void;
  /** 当前提交凭据（api.sso.v1.CaptchaPayload）；未就绪 → undefined。 */
  getToken(): CaptchaPayload | undefined;
  /** 重拉 / 重置（清空用户输入，自绘换新图）。 */
  reset(): void;
}

/** 分派器加载 wrapper 的工厂：入参为当前权威 captcha 对象（接口文档 §2.5）。 */
export type CaptchaAdapterFactory = (captcha: CaptchaConfig) => CaptchaAdapter;

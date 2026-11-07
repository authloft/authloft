/**
 * kind=redirect 步骤实体（docs/前端架构.md §4.2 行 442）：
 * 展示「正在跳转…」+ location.replace(authorize_url)（§2.7.2 行 589：前端
 * 跳转非后端 302；移动端用 replace 避免回退死循环，§4.2 行 442）。
 *
 * 两个消费链路：ProviderButtons 主链路（redirect 渠道点击 → SsoService/
 * Authorize 取 URL 后渲染本组件执行跳转）与 StepDispatcher 防御分派
 * （信封 NextStep 无 authorize_url 字段，§12.9 生成物——空 URL 仅展示文案
 * 不跳转，零值兜底 §9 第 18 条）。
 *
 * 无自有布局样式（单条弱化提示 <p>，reset 兜底）。
 * 文案：经 i18n 字典 login.redirectInProgress 键取用。
 */
import { useEffect } from 'react';

import { Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';

/** 缺省跳转动作（§4.2 行 442 location.replace；非浏览器环境无操作——node 测试）。 */
export function defaultNavigate(url: string): void {
  if (typeof location !== 'undefined') {
    location.replace(url);
  }
}

/**
 * 跳转执行（纯函数，node 可测）：空 URL 不跳（零值兜底，§9 第 18 条）；
 * 非空执行注入的跳转动作。
 */
export function runRedirect(
  authorizeUrl: string,
  navigate: (url: string) => void = defaultNavigate,
): void {
  if (authorizeUrl !== '') {
    navigate(authorizeUrl);
  }
}

export interface RedirectStepProps {
  /** 跳转目标（§2.7.2 authorizeUrl；空串 / 缺省 = 无目标，仅展示文案）。 */
  authorizeUrl?: string;
  /** 跳转动作注入（缺省 location.replace；测试传记录函数）。 */
  navigate?: (url: string) => void;
}

export function RedirectStep({
  authorizeUrl = '',
  navigate = defaultNavigate,
}: RedirectStepProps) {
  useEffect(() => {
    runRedirect(authorizeUrl, navigate);
    // 跳转幂等（location.replace 同 URL 重复执行无感），全依赖不设防重护栏。
  }, [authorizeUrl, navigate]);
  // 跳转中帧接 Spinner（原纯文本无加载视觉）。
  return (
    <p role="status">
      <Spinner /> {t('login.redirectInProgress')}
    </p>
  );
}

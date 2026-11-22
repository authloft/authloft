/**
 * kind=redirect 步骤实体（docs/前端架构.md §4.2 行 442）：
 * 展示「即将前往 {provider} 进行授权，请稍候」+ Spinner + location.replace
 * （§2.7.2 行 589：前端跳转非后端 302；移动端用 replace 避免回退死循环，
 * §4.2 行 442）。
 *
 * 两个消费链路：ProviderButtons 主链路（redirect 渠道点击 → SsoService/
 * Authorize 取 URL 后渲染本组件执行跳转，pending 帧带 provider 展示名）与
 * StepDispatcher 防御分派（信封 NextStep 无 authorize_url 字段，§12.9 生成
 * 物——空 URL 仅展示兜底文案不跳转、无 provider 名，零值兜底 §9 第 18 条）。
 *
 * 文案：主链路经 login.redirectingTo（带 {provider}）；无 provider 名的
 * 防御帧回落 login.redirectInProgress。布局：Spinner 与文案垂直居中、整行
 * 水平居中，字号与失败帧同档（sm）。
 */
import { useEffect } from 'react';

import { Spinner } from '../../shared/components';
import { t } from '../../shared/i18n';
import styles from './RedirectStep.module.less';

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
  /** Provider 展示名（pending 帧文案；缺省 = 防御帧兜底文案）。 */
  providerName?: string;
  /** 跳转动作注入（缺省 location.replace；测试传记录函数）。 */
  navigate?: (url: string) => void;
}

export function RedirectStep({
  authorizeUrl = '',
  providerName,
  navigate = defaultNavigate,
}: RedirectStepProps) {
  useEffect(() => {
    runRedirect(authorizeUrl, navigate);
    // 跳转幂等（location.replace 同 URL 重复执行无感），全依赖不设防重护栏。
  }, [authorizeUrl, navigate]);
  // 跳转中帧：Spinner 与文案垂直居中（字号与失败帧同档），整行水平居中。
  return (
    <div className={styles.wrap} role="status">
      <Spinner />
      <span>
        {providerName
          ? t('login.redirectingTo', { provider: providerName })
          : t('login.redirectInProgress')}
      </span>
    </div>
  );
}

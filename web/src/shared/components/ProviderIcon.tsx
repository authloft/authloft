/**
 * 渠道图标唯一渲染入口（docs/前端架构.md §3.3 行 344）：icon 非空 → <img>
 * （onError 后转占位）；icon 为空 → 内置占位图形。不做按 type 的本地文件
 * 回落（工程内无渠道图标资源）；占位走内联 SVG，不占静态资源。
 *
 * 渲染模式判定（resolveIconMode）为纯函数，node 环境测试覆盖；
 * onError → 占位的翻转在组件壳（icon 变化时重置，给新地址新机会）。
 */
import { useEffect, useState } from 'react';
import styles from './ProviderIcon.module.less';

export type ProviderIconMode = 'image' | 'placeholder';

/**
 * 渲染模式：icon 非空且未加载失败 → image；其余（空串 / undefined /
 * 加载失败）→ placeholder（protojson 零值省略兜底，§9 零值口径）。
 */
export function resolveIconMode(
  icon: string | undefined,
  loadFailed: boolean,
): ProviderIconMode {
  return icon !== undefined && icon !== '' && !loadFailed ? 'image' : 'placeholder';
}

export interface ProviderIconProps {
  /** 后端下发的图标 URL（providers[].icon / bindings[].icon；可省略）。 */
  icon?: string;
  /** 图标说明（无障碍）；缺省用内置文案。 */
  alt?: string;
}

/** 内置占位图形（内联 SVG，不占静态资源，§3.3 行 344）。 */
function PlaceholderGlyph() {
  return (
    <svg className={styles.iconGlyph} viewBox="0 0 24 24" aria-hidden="true">
      <rect
        x="3"
        y="5"
        width="18"
        height="14"
        rx="3"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <circle cx="9" cy="10" r="1.5" fill="currentColor" />
      <path
        d="M6 16.5l4-4 3 3 2.5-2.5L20 15"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function ProviderIcon({ icon, alt }: ProviderIconProps) {
  const [loadFailed, setLoadFailed] = useState(false);
  // icon 变化（渠道切换）重置失败态：新地址重新尝试 <img>。
  useEffect(() => {
    setLoadFailed(false);
  }, [icon]);

  if (resolveIconMode(icon, loadFailed) === 'image') {
    return (
      <span className={styles.icon}>
        <img
          className={styles.iconImage}
          src={icon}
          alt={alt || '渠道图标'}
          onError={() => setLoadFailed(true)}
        />
      </span>
    );
  }
  return (
    <span className={styles.icon} role="img" aria-label={alt || '渠道图标'}>
      <PlaceholderGlyph />
    </span>
  );
}

/**
 * 卡片 footer 语言切换（登录页 / 注册页 / 重置页共用）：小图标触发
 * （当前语言原生名）+ 下拉菜单（列出全部受支持语言，当前项高亮），点击
 * 卡片其他区域收起。
 *
 * 语言切换只做会话内存内切换——locale / onSwitch 由页面受控注入
 *（setLocale 模块级变量 + 页面本地 state 触发整树重渲染，t() 渲染期取
 * 新语言）；不写 localStorage / 不做持久化（持久化口径待定）。
 */
import { useEffect, useRef, useState } from 'react';
import { t, type Locale } from '../../shared/i18n';
import styles from './LocaleSwitcher.module.less';

/** 受支持语言选项（语言名保持原生写法，双语同值）。 */
const LOCALE_OPTIONS: ReadonlyArray<{ value: Locale; labelKey: string }> = [
  { value: 'zh-CN', labelKey: 'login.langZh' },
  { value: 'en-US', labelKey: 'login.langEn' },
];

export function LocaleSwitcher({
  locale,
  onSwitch,
}: {
  locale: Locale;
  onSwitch: (next: Locale) => void;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  // open 时挂 document 监听收起下拉（contains 防触发按钮自身点击误收）。
  useEffect(() => {
    if (!open) {
      return;
    }
    const close = (event: MouseEvent) => {
      if (
        rootRef.current !== null &&
        !rootRef.current.contains(event.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  return (
    <div className={styles.localeSwitch} ref={rootRef}>
      <button
        type="button"
        className={styles.localeTrigger}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t('login.langSwitchLabel')}
        onClick={() => setOpen((v) => !v)}
      >
        {t(locale === 'en-US' ? 'login.langEn' : 'login.langZh')}
      </button>
      {open && (
        <ul className={styles.localeMenu} role="listbox">
          {LOCALE_OPTIONS.map((option) => (
            <li key={option.value}>
              <button
                type="button"
                role="option"
                aria-selected={option.value === locale}
                className={
                  option.value === locale
                    ? styles.localeOptionActive
                    : styles.localeOption
                }
                onClick={() => {
                  onSwitch(option.value);
                  setOpen(false);
                }}
              >
                {t(option.labelKey)}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

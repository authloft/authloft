/**
 * 卡片 footer 语言切换（登录页 / 注册页 / 重置页共用）：小图标触发
 * （当前语言原生名）+ 下拉菜单（列出全部受支持语言，当前项高亮），点击
 * 卡片其他区域收起。
 *
 * 语言切换——locale / onSwitch 由页面受控注入（setLocale 模块级变量 +
 * sessionStorage 会话内持久化 + 页面本地 state 触发整树重渲染，t() 渲染期
 * 取新语言）；登录族页面间是整页跳转，持久化让语言选择跨页存续。
 */
import { useEffect, useRef, useState } from 'react';
import { t, type Locale } from '../../shared/i18n';
import styles from './LocaleSwitcher.module.less';

/** 受支持语言选项（语言名保持原生写法，双语同值）。 */
const LOCALE_OPTIONS: ReadonlyArray<{ value: Locale; labelKey: string }> = [
  { value: 'zh-CN', labelKey: 'login.langZh' },
  { value: 'en-US', labelKey: 'login.langEn' },
];

const LocaleIcon = () => (
  <svg
    className={styles.localeIcon}
    viewBox="0 0 1024 1024"
    version="1.1"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path
      d="M516.864 85.333333l82.261333 19.114667c-10.069333 42.837333 9.984 82.730667 68.053334 124.330667 135.509333 97.024 167.509333 151.722667 128.981333 272.64-22.698667 71.253333 4.821333 97.28 99.84 97.28V682.666667c-145.92 0-223.018667-72.96-180.394667-206.592 24.874667-77.994667 11.434667-100.906667-97.834666-179.2-83.456-59.733333-119.722667-131.84-100.906667-211.541334z"
      fill="currentColor"
      p-id="5200"
    ></path>
    <path
      d="M134.656 440.32a384 384 0 0 0 495.445333 437.162667c-23.594667-54.528-49.322667-66.730667-97.28-65.365334-5.845333 0.128-10.837333 0.426667-21.76 1.066667-82.688 4.992-123.818667-5.333333-162.688-64.426667-43.477333-65.962667-29.866667-113.664 22.613334-174.165333l6.229333-7.168c39.082667-44.8 42.794667-58.794667 14.421333-99.584-31.744-45.653333-49.365333-48.085333-115.669333-29.098667-62.293333 17.792-102.229333 21.717333-141.312 1.578667z m26.368-84.394667c21.418667 16.341333 40.448 15.36 91.477333 0.768 97.408-27.861333 151.637333-20.309333 209.194667 62.421334 55.808 80.213333 41.642667 133.546667-20.181333 204.416l-6.058667 6.954666c-30.293333 34.986667-33.194667 45.013333-15.786667 71.381334 16.981333 25.856 31.317333 29.44 86.229334 26.154666 11.861333-0.725333 17.450667-1.024 24.490666-1.237333 81.664-2.304 137.813333 28.16 177.237334 115.712A384 384 0 1 0 161.066667 355.925333zM512 981.333333C252.8 981.333333 42.666667 771.2 42.666667 512S252.8 42.666667 512 42.666667s469.333333 210.133333 469.333333 469.333333-210.133333 469.333333-469.333333 469.333333z"
      fill="currentColor"
    ></path>
  </svg>
);

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
        <LocaleIcon />
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

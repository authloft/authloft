/**
 * 手机号输入（docs/前端架构.md §3.3）：把 E.164 单字符串拆成「国际区号 +
 * 本地号码」两段展示，对外只收发 E.164 并塞进既有 phone 字段——不加独立
 * 区号字段、不改协议与存储。原生 select + input 实现，零第三方 UI 依赖
 * （login 可安全引用，见 CODE_GUIDE §2.4）；号码格式不在此处校验，交
 * validate.ts 统一口径（体验性预校验，服务端为权威）。
 */
import * as React from 'react';
import { t } from '../i18n';
import styles from './PhoneInput.module.less';

/** 区号条目：dialCode 含前导 +；nameKey 为 shared 字典里的国家 / 地区文案键。 */
export interface DialCodeEntry {
  dialCode: string;
  nameKey: string;
}

/**
 * 常用国家 / 地区码，顺序即下拉顺序。中国大陆为默认项；中国香港 / 中国澳门 /
 * 中国台湾按地区表述，不作为独立国家。
 */
export const DIAL_CODES: readonly DialCodeEntry[] = [
  { dialCode: '+86', nameKey: 'common.regionMainlandChina' },
  { dialCode: '+852', nameKey: 'common.regionHongKongChina' },
  { dialCode: '+853', nameKey: 'common.regionMacaoChina' },
  { dialCode: '+886', nameKey: 'common.regionTaiwanChina' },
  { dialCode: '+1', nameKey: 'common.regionNorthAmerica' },
  { dialCode: '+44', nameKey: 'common.regionUnitedKingdom' },
  { dialCode: '+81', nameKey: 'common.regionJapan' },
  { dialCode: '+82', nameKey: 'common.regionSouthKorea' },
  { dialCode: '+65', nameKey: 'common.regionSingapore' },
  { dialCode: '+61', nameKey: 'common.regionAustralia' },
  { dialCode: '+33', nameKey: 'common.regionFrance' },
  { dialCode: '+49', nameKey: 'common.regionGermany' },
  { dialCode: '+91', nameKey: 'common.regionIndia' },
  { dialCode: '+7', nameKey: 'common.regionRussia' },
];

/** 空值 / 未匹配已知区号时的默认区号。 */
export const DEFAULT_DIAL_CODE = '+86';

/** 本地号输入上限：E.164 最多 15 位数字 + 最长区号 3 位 + 前导 +，留一位余量。 */
export const MAX_NATIONAL_DIGITS = 20;

/**
 * E.164 → 区号 + 本地号：从已知区号中取最长匹配前缀；无匹配（空值、裸号、
 * 未知区号）时回退默认区号并把整串当本地号。未知区号的整串含前导 `+`，
 * 由 onNationalChange 识别并保留原前缀，不叠加默认区号（纯函数，供单测覆盖）。
 */
export function splitE164(value: string): {
  dialCode: string;
  national: string;
} {
  const raw = typeof value === 'string' ? value.trim() : '';
  let matched: string | undefined;
  for (const entry of DIAL_CODES) {
    if (
      raw.startsWith(entry.dialCode) &&
      (matched === undefined || entry.dialCode.length > matched.length)
    ) {
      matched = entry.dialCode;
    }
  }
  if (matched !== undefined) {
    return { dialCode: matched, national: raw.slice(matched.length) };
  }
  return { dialCode: DEFAULT_DIAL_CODE, national: raw };
}

/** 本地号数字归一：剔空白与非数字字符（E.164 数字口径）。 */
export function normalizeNational(input: string): string {
  return input.replace(/\D/g, '');
}

/**
 * E.164 拼装：区号 + 归一后的本地号。本地号为空时不输出裸区号（裸区号不是
 * 合法号码，清空操作须上抛空串，服务端按显式空串 = 清空该字段处理）。
 */
export function joinE164(dialCode: string, national: string): string {
  const digits = normalizeNational(national);
  return digits === '' ? '' : dialCode + digits;
}

/**
 * 本地号编辑上抛。未知区号的存量值（如 +855…）在 splitE164 里整串落入
 * national 且带前导 `+`：此时以原串区号为权威，仅规整数字后原样上抛，
 * 避免误拼默认 +86 形成格式合法却错误的号码（静默数据破坏）。
 */
export function onNationalChange(
  dialCode: string,
  currentNational: string,
  input: string,
): string {
  if (currentNational.startsWith('+')) {
    const digits = normalizeNational(input);
    return digits === '' ? '' : '+' + digits;
  }
  return joinE164(dialCode, input);
}

export interface PhoneInputProps {
  /** E.164 受控值（如 +8613800138000）；空串时区号仍展示默认项。 */
  value: string;
  /** 变更上抛，恒为 E.164 单字符串（区号 + 本地数字）。 */
  onChange: (value: string) => void;
  /** 本地号码输入框 id（label htmlFor 关联用）；区号下拉 id 由其派生。 */
  id?: string;
  disabled?: boolean;
  /** 字段级错误态：透传到两段控件的 aria-invalid。 */
  ariaInvalid?: boolean;
  /** 错误描述元素 id：透传到两段控件的 aria-describedby。 */
  ariaDescribedBy?: string;
  /** 本地号码输入占位文案。 */
  placeholder?: string;
  /** 区号下拉的无障碍名；缺省取字典文案。 */
  ariaLabel?: string;
}

/** 受控手机号输入：区号下拉 + 本地号输入，对外只暴露 E.164。 */
export function PhoneInput({
  value,
  onChange,
  id,
  disabled,
  ariaInvalid,
  ariaDescribedBy,
  placeholder,
  ariaLabel,
}: PhoneInputProps) {
  const { dialCode, national } = splitE164(value);
  const invalidProps = {
    ...(ariaInvalid ? { 'aria-invalid': true as const } : {}),
    ...(ariaDescribedBy !== undefined
      ? { 'aria-describedby': ariaDescribedBy }
      : {}),
  };

  return (
    <div className={styles.group}>
      <select
        className={styles.dialCode}
        id={id === undefined ? undefined : `${id}-dial-code`}
        aria-label={ariaLabel ?? t('common.dialCodeLabel')}
        value={dialCode}
        disabled={disabled}
        onChange={(e) =>
          onChange(joinE164(e.target.value, normalizeNational(national)))
        }
        {...invalidProps}
      >
        {DIAL_CODES.map((entry) => (
          <option key={entry.dialCode} value={entry.dialCode}>
            {t(entry.nameKey)} ({entry.dialCode})
          </option>
        ))}
      </select>
      <input
        className={styles.national}
        id={id}
        type="tel"
        inputMode="tel"
        value={national}
        maxLength={MAX_NATIONAL_DIGITS}
        disabled={disabled}
        placeholder={placeholder}
        aria-invalid={ariaInvalid || undefined}
        aria-describedby={ariaDescribedBy}
        onChange={(e) =>
          onChange(onNationalChange(dialCode, national, e.target.value))
        }
      />
    </div>
  );
}

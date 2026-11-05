/**
 * 分段验证码输入（docs/前端架构.md §3.3 行 323）：与 OTPForm 解耦（TOTP 复用）、
 * 6 位分段（长度可调）、整串粘贴自动拆分、首格 autocomplete="one-time-code"
 * （浏览器自动填充整串时经 onChange 多字符分支同样拆分）、退格跳回上一格。
 *
 * 纯逻辑（pasteValue / applyChar / applyBackspace）与 DOM 壳分离：
 * 本仓 rstest 为 node 环境无 DOM，交互边界在纯函数层覆盖
 * （沿 hooks.test.ts / RestartingPage.test.ts 的模式）。
 */
import { useRef, type ClipboardEvent, type KeyboardEvent } from 'react';
import styles from './CodeInput.module.less';

/** 默认分段数（§2.1 codeLength 6；§1.10 totp 六位动态码）。 */
export const DEFAULT_CODE_LENGTH = 6;

export interface CodeInputProps {
  /** 已输入的数字串（左对齐紧凑形态，长度 ≤ length；受控值）。 */
  value: string;
  /** 输入变化上抛（整串，不含空位；组件不持有业务状态）。 */
  onChange: (value: string) => void;
  /** 分段数（默认 6；FieldRenderer 用 field.length 经 toCount 归一后传入）。 */
  length?: number;
  /** 无障碍组名（视觉标签由调用方自行渲染，组件不重复画）。 */
  ariaLabel?: string;
  disabled?: boolean;
}

export interface CodeEditResult {
  readonly value: string;
  readonly nextIndex: number;
}

/**
 * 整串粘贴拆分：剥离全部非数字（验证码为数字码，§2.1；粘贴常带空白 /
 * 分隔符），截断到 length（超长只取前 length 位）。
 */
export function pasteValue(text: string, length: number): string {
  return text.replace(/\D+/g, '').slice(0, Math.max(0, length));
}

/**
 * 在 index 格键入一个字符：数字 → 已有字符的格原位替换（焦点进一格）、
 * 空尾格追加（焦点落到新末位之后）；非数字忽略（值与焦点都不动）。
 */
export function applyChar(
  value: string,
  index: number,
  char: string,
  length: number,
): CodeEditResult {
  if (!/\d/.test(char)) {
    return { value, nextIndex: index };
  }
  if (index < value.length) {
    return {
      value: value.slice(0, index) + char + value.slice(index + 1),
      nextIndex: Math.min(index + 1, length - 1),
    };
  }
  const appended = (value + char).slice(0, Math.max(0, length));
  return { value: appended, nextIndex: Math.min(appended.length, length - 1) };
}

/**
 * 退格：当前格有字符 → 原位删除（后续左移，焦点停留）；当前格为空 →
 * 删除末位字符并跳回上一格（§3.3「退格跳转」）；第 0 格为空 → 不变。
 */
export function applyBackspace(value: string, index: number): CodeEditResult {
  if (index < value.length) {
    return {
      value: value.slice(0, index) + value.slice(index + 1),
      nextIndex: index,
    };
  }
  if (index > 0) {
    return { value: value.slice(0, -1), nextIndex: index - 1 };
  }
  return { value, nextIndex: 0 };
}

/** 6 位分段输入；受控组件，焦点推进 / 退格跳格由组件内部管理。 */
export function CodeInput({
  value,
  onChange,
  length = DEFAULT_CODE_LENGTH,
  ariaLabel,
  disabled,
}: CodeInputProps) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const boxes = Array.from({ length }, (_, i) => value[i] ?? '');

  const focusBox = (i: number) => {
    const el = refs.current[i];
    if (el) {
      el.focus();
      el.select();
    }
  };

  const handleInput = (i: number, raw: string) => {
    // 多字符 = 整串到达（粘贴未走 paste 事件 / 浏览器自动填充 / 输入法）：
    // 统一按整串拆分回填（autocomplete=one-time-code 的填充路径）。
    if (raw.length > 1) {
      const pasted = pasteValue(raw, length);
      onChange(pasted);
      focusBox(Math.min(pasted.length, length - 1));
      return;
    }
    if (raw === '') {
      // 删除键 / 剪切断尾：清掉当前格字符（无跳格）。
      if (i < value.length) {
        onChange(value.slice(0, i) + value.slice(i + 1));
      }
      return;
    }
    const result = applyChar(value, i, raw, length);
    if (result.value !== value) {
      onChange(result.value);
    }
    focusBox(result.nextIndex);
  };

  const handleKeyDown = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Backspace') {
      return;
    }
    if (boxes[i] !== '') {
      // 有字符的格交给浏览器默认删除，onChange 空串分支收尾。
      return;
    }
    e.preventDefault();
    const result = applyBackspace(value, i);
    if (result.value !== value) {
      onChange(result.value);
    }
    focusBox(result.nextIndex);
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = pasteValue(e.clipboardData.getData('text'), length);
    onChange(pasted);
    focusBox(Math.min(pasted.length, length - 1));
  };

  return (
    <div role="group" aria-label={ariaLabel} className={styles.group}>
      {boxes.map((char, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={1}
          className={styles.box}
          disabled={disabled}
          value={char}
          onChange={(e) => handleInput(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onPaste={handlePaste}
          onFocus={(e) => e.target.select()}
        />
      ))}
    </div>
  );
}

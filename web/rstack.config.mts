// Configuration guide: https://rstack.rs/config
import { define } from 'rstack';

define.lint(({ js, ts }) => [
  js.configs.recommended,
  ts.configs.recommended,
  {
    files: ['**/*.test.{ts,tsx}'],
    rules: {
      // tsconfig moduleResolution=node 解析不了 rstack/test 子路径，
      // 测试文件用 @ts-ignore 放宽该 import；tsconfig 现代化后移除本豁免。
      '@typescript-eslint/ban-ts-comment': 'off',
    },
  },
]);

define.staged({
  '*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}': ['rs lint', 'rs fmt'],
  '*.{md,mdx,json,json5,yml,yaml,css,less,scss,html}': 'rs fmt',
});

define.fmt({
  singleQuote: true,
});

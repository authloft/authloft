// 探针：rstest 下真实加载 @douyinfe/semi-ui-19 并渲染断言。
// 修复前该文件在加载期即崩（Unknown file extension ".css"）；
// 修复后 Semi 经 bundleDependencies 走 rspack 管线，CSS 被测试链吞掉。
// tsconfig moduleResolution=node 解析不了 rstack/test 子路径（已知豁免）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { Button } from '@douyinfe/semi-ui-19';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

describe('Semi 真实加载探针', () => {
  test('Button 渲染出预期文本与 semi 类名', () => {
    const html = renderToStaticMarkup(createElement(Button, null, '探针按钮'));
    expect(html).toContain('探针按钮');
    expect(html).toContain('semi-button');
  });
});

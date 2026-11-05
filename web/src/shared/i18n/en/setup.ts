/**
 * en-US 安装域文案模块（分域底座）：以 zh 侧同名模块为类型约束，
 * 键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块内追加。
 */
import type { setup as zhSetup } from '../zh/setup';

export const setup: typeof zhSetup = {};

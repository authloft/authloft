/**
 * en-US 安全中心域文案模块（分域底座）：以 zh 侧同名模块为类型
 * 约束，键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块
 * 内追加。
 */
import type { account as zhAccount } from '../zh/account';

export const account: typeof zhAccount = {};

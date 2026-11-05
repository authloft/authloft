/**
 * en-US 登录域文案模块（分域底座）：以 zh 侧同名模块为类型约束，
 * 键集编译期对齐（缺译 / 多译都过不了 tsc）；域收口在本模块内追加。
 */
import type { login as zhLogin } from '../zh/login';

export const login: typeof zhLogin = {};

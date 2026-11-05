/**
 * zh-CN 登录域文案模块（分域底座）：login 域的键由后续域收口在
 * 本模块内追加，经 zh-CN.ts 尾部 spread 汇入总字典。
 *
 * 禁止给本对象加 Record<string, string> 等索引类型注解：会被 spread 进
 * 总字典，把 I18nMessages 弱化成索引签名，破坏 en/zh 编译期键对齐。
 */
export const login = {};

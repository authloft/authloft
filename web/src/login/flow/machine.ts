/**
 * login 域状态机定义（docs/前端架构.md §4.1 行 380、行 386-395）。
 *
 * 状态与后端 status 一一对应、不允许前端自造状态：取值即接口文档 §1.6 封闭
 * 全量表（33 词，含扫码轮询三态 pending / scanned / expired），复用
 * shared/api/errors 的 FlowStatusKey 字面量联合（§1.6 行 270「新增取值必须
 * 同步映射」的单一真相）；'idle' 是状态机唯一的本地初始态（§4.1 状态机图
 * 首词：尚未发起任何请求 / 已回到第一步）。
 */
import type { LoginFlowResponse } from '../../gen/proto/api/sso/v1/envelope_pb';
import type { FlowStatusKey } from '../../shared/api/errors';

/** 流程状态 = §1.6 封闭集合（生成物 status 字段为 string 承载，§12.9 行 1754）。 */
export type LoginStatus = FlowStatusKey;

/** 状态机状态：idle 为本地初始态，其余逐字对应后端 status（§4.1 行 386）。 */
export type MachineStatus = 'idle' | LoginStatus;

/**
 * 副作用标记（reducer 产出、容器 LoginContainer 执行；reducer 自身无副作用、
 * 无网络调用，docs/前端架构.md §4.1 行 381）：
 * - complete：status=success → 容器处理终点（跳转链 syncCookieUrl →
 *   redirectTo，§4.1 行 383）；login_token 的清空已在 api.ts 响应后处理完成
 *   （五条之 3，§1.3 行 145），不在此重复；
 * - restart：§1.6「前端动作 = 回到第一步」类（step_invalid / token_invalid /
 *   token_expired / state_mismatch）→ 容器 dispatch reset 并按 status 提示
 *   （token 类提示「登录已超时，请重新开始」，§4.1 行 403）。
 */
export type FlowEffect =
  | { readonly type: 'complete'; readonly envelope: LoginFlowResponse }
  | { readonly type: 'restart'; readonly status: LoginStatus };

/** 状态机状态形状（reducer 的 S）。 */
export interface FlowState {
  /** 当前流程状态；idle = 尚无响应 / 已重置（§4.1 状态机图）。 */
  readonly status: MachineStatus;
  /** 当前认证方式：select_method 设定；status=next 时按 next_step.method 更新（§1.3 行 112）。 */
  readonly method: string;
  /** 当前 step（challenge｜verify｜set_password，§2.2 行 422）：select_method 设首步、advance 推进。 */
  readonly step: string;
  /** 最近一次登录流程信封（§1.3）；idle 时无。 */
  readonly envelope: LoginFlowResponse | undefined;
  /** 请求在途（request_started → response / reset 之间；§3.2 提交按钮按 loading 禁用）。 */
  readonly loading: boolean;
  /** 本次迁移产出的待执行副作用标记；每次事件迁移时重置（容器先处理后继续派发）。 */
  readonly effects: readonly FlowEffect[];
}

/** 初始态（§4.1 状态机图：idle 起点）。 */
export const INITIAL_FLOW_STATE: FlowState = {
  status: 'idle',
  method: '',
  step: '',
  envelope: undefined,
  loading: false,
  effects: [],
};

// tsconfig 的 moduleResolution=node 不识别 rstack 的 exports 子路径
//（tsconfig 现代化后移除）。
// @ts-ignore
import { describe, expect, test } from 'rstack/test';
import { createInflightGuard, runInlineToggle } from './dataTableLogic';

/**
 * dataTableLogic.ts 防重守卫测试（P0-1，定稿 §6.1/§6.4）：行内开关
 * per-row in-flight——「连点两次只发一次请求」由 createInflightGuard 的
 * 同步判定保证；组件壳 DataTable.tsx 含 Semi 不可测（既有 blocker，
 * 落位说明见 dataTableLogic.ts 头注），防重判定全部收口于此。
 * 鉴别力：守卫失效（tryEnter 恒 true）时 persist 计数断言必红。
 */

describe('createInflightGuard（per-row 防重：在途期间重复触发 no-op）', () => {
  test('在途期间同 key 二次进入被拒；leave 后放行（连点两次只发一次请求）', () => {
    const guard = createInflightGuard();
    expect(guard.tryEnter('row-1')).toBe(true);
    expect(guard.has('row-1')).toBe(true);
    // 在途重复触发：同步拒绝（组件据此 no-op，不再发 persist）。
    expect(guard.tryEnter('row-1')).toBe(false);
    expect(guard.tryEnter('row-1')).toBe(false);
    guard.leave('row-1');
    expect(guard.has('row-1')).toBe(false);
    expect(guard.tryEnter('row-1')).toBe(true);
  });

  test('不同 key 互不影响（per-row 粒度，非整表锁）', () => {
    const guard = createInflightGuard();
    expect(guard.tryEnter('row-1')).toBe(true);
    expect(guard.tryEnter('row-2')).toBe(true);
    expect(guard.tryEnter('row-2')).toBe(false);
    expect(guard.tryEnter('row-1')).toBe(false);
  });

  test('与 runInlineToggle 组合：在途内二次编排 persist 计数恒 1（失败离场同样放行）', async () => {
    const guard = createInflightGuard();
    let persistCount = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function toggleOnce(): Promise<boolean> {
      if (!guard.tryEnter('u1')) {
        return false;
      }
      try {
        await runInlineToggle([{ id: 'u1', on: false }], (row) => row.id, 'u1', (row) => ({
          ...row,
          on: true,
        }), async () => {
          persistCount += 1;
          await gate;
        });
        return true;
      } finally {
        guard.leave('u1');
      }
    }
    const first = toggleOnce();
    // 首次仍在途（gate 未放行）：连点第二次 → 守卫拒绝，不进编排。
    await expect(toggleOnce()).resolves.toBe(false);
    release();
    await expect(first).resolves.toBe(true);
    expect(persistCount).toBe(1);
  });
});

# 基于当前能力边界的执行计划（2026-03-10）

## 1. 当前基线

本计划基于两类已完成结果：

1. GT-backed 受控复跑
   - 目录：`/tmp/eval_current_gt_backed_controlled_20260310_034527`
   - 样本：`44`
   - 结果：`positive=386, matched=318, hit_rate=82.38%`

2. no-GT 大规模扫描
   - 参考：`docs/combined_eval_gt_plus_nogt_20260309.json`
   - 样本：`94`
   - 结果：`chains=1937, with_source=655, with_channel=546, dropped=1537`

结论：
- `microbench` 已稳定，不再是主边界。
- `uSBS` 正链召回强，但误链和 reviewer 成本仍高。
- `mesobench` 中的 `Contiki / Zephyr` 是当前真正的主边界。
- 当前主瓶颈不再是 source/sink miner，而是：
  - reviewer 吞吐
  - reviewer 上下文预算
  - semantic trigger validation
  - 少量 `Phase A` 的 family-specific anchoring/binding 缺口

## 2. 指导原则

### 2.1 两阶段职责保持不变

- `Phase A: Deterministic Chain Assembly`
  - 负责 source/sink/object/channel/root/derive/check/chain 的结构恢复
  - 仍然是硬事实 authority
- `Phase B: Semantic Review & Trigger Validation`
  - 负责 triggerability / check effectiveness / taint-preservation 的语义审查

### 2.2 LLM 的定位

LLM 在 `Phase A.5` 和 `Phase B` 都可以“收拾烂摊子”，但必须是受控、可审计、可回放的 bounded layer。

- `Phase A.5`
  - 只监督 deterministic 已经产出的 candidate
  - 不做 unrestricted discovery
- `Phase B`
  - 只审查已成立链的语义可触发性
  - 不推翻 source/object/channel/root 硬事实

### 2.3 优化目标调整

从现在开始，优化目标不是“继续把所有链都挖出来”，而是：

1. 保持 `Phase A` 的召回与结构稳定性
2. 把 reviewer 预算集中在高价值链上
3. 减少 reviewer 成本而不是无上限放大 reviewer
4. 让 `soft` 层保存足够多的高风险材料，供后续 BinAgent/人工继续深挖

## 3. Phase A.5 rollout 顺序

### 3.1 总原则

实施顺序必须保守：

1. `sink supervision`
2. `source supervision`
3. `object/channel supervision`

原因：
- sink supervision 收益最高、方差最低
- source supervision 次之
- object/channel supervision 最昂贵、最不稳定，不应一开始全开

### 3.2 建议 rollout 阶段

#### PR-S0: supervision queue only

目标：
- 不改任何 deterministic 结果
- 只把“适合 supervision 的 candidate”稳定收集出来

输出：
- `supervision_queue.json`
- per-item prompt/session/raw transcript

优先对象：
- low-confidence sinks
- wrapper-like copy sinks
- loop-copy / loop-write sinks
- thunk/indirect callsite sinks

#### PR-S1: internal supervision runner + transcript

目标：
- SourceAgent 内部就能跑 supervision
- 不再依赖外部 BinAgent 才能做第一轮监督

约束：
- 只允许读 supervision queue item 的证据包
- 不能自行扩展成新 discovery

#### PR-S2: sink merge gates

目标：
- 允许 supervision 对 sink label / arg roles 提建议
- 但必须经过 deterministic acceptance gates 才能 merge

优先覆盖：
- `COPY_SINK`
- `LOOP_WRITE_SINK`
- `FORMAT_STRING_SINK`
- `FUNC_PTR_SINK`

#### PR-S3: sink supervision hardening

目标：
- reason codes / transcripts / merge audit 稳定
- 在 `mesobench` 上开始观察 recall/precision 变化

#### PR-S4: source supervision

仅在 sink supervision 稳定后做。

优先覆盖：
- wrapper MMIO
- ISR producer helper
- DMA setup wrapper
- source-proxy / producer helper path

#### PR-S5: object/channel supervision

最后做。

优先覆盖：
- ring buffer
- ISR -> MAIN / TASK
- DMA -> ISR -> TASK
- queue/mailbox/stream buffer

#### PR-S6: evaluation + ablation

对比：
- no supervision
- sink-only supervision
- sink+source supervision
- full supervision

## 4. Phase B reviewer 的 budget / queue 策略

### 4.1 reviewer 不是全量 second pipeline

当前的实测已经证明：
- 大样本上 reviewer 是主耗时
- 如果不控 budget，prompt 会膨胀到 `140k-200k` 级别

因此 reviewer 必须是有层级、有预算的。

### 4.2 默认三级审查策略

#### Tier R0: audit-only

适用：
- 中低风险链
- `SAFE_OR_LOW_RISK + LOW`
- `P2`

动作：
- 只做轻量语义审计
- 不要求 tool-assisted 深挖

#### Tier R1: semantic review

适用：
- `SUSPICIOUS + MEDIUM`
- `P1`
- semantic-only blocked chains

动作：
- 正常 reviewer
- bucketed context + ranking + budget
- 只在需要时 second-pass

#### Tier R2: deep review

适用：
- `P0`
- `SUSPICIOUS + HIGH`
- `CONFIRMED + HIGH`
- 只差一个 blocker 的 semantic-only 链

动作：
- tool-assisted review
- second-pass targeted context
- 必要时人工审查

### 4.3 queue 进入条件

默认 reviewer 队列建议：
- `all_non_exact`
- 加入 `P0/P1` 优先排序
- 同一 binary 上保留 per-sink 限额
- 对同 root family 的重复链做早期 dedup

### 4.4 budget 策略

#### 单链 prompt budget

建议按复杂度动态分配：
- `base_budget`
- `+ uncertain_segment_count`
- `+ hop_count`
- cap 到固定上限

#### per-binary review budget

建议按样本族设置：
- `microbench`: 小预算即可
- `uSBS`: 中预算
- `Contiki / Zephyr`: 高预算但严格排序

### 4.5 二次 review 触发条件

只有出现这些信号时，才进入 second-pass：
- `NEEDS_MORE_CONTEXT`
- `HELPER_SEMANTICS_UNKNOWN`
- `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
- `CHECK_NOT_BINDING_ROOT` 但 guard/context 证据不足

否则不补第二轮。

## 5. 按样本族的优先优化顺序

### 5.1 第一优先级：Contiki

原因：
- 当前命中率最低
- 误链也高
- reviewer 和 Phase A 都暴露问题

重点：
1. `NO_SOURCE_SEGMENT`/source proxy 稳定化
2. helper/parser path 的 formal source anchoring
3. bounded backward 的 path ranking
4. ring-buffer / queue-like object/channel 识别

### 5.2 第二优先级：Zephyr

原因：
- 正链命中已高
- 但 spurious 仍多
- reviewer 成本偏高

重点：
1. 控制/配置 path 过早进入 chain 的问题
2. alloc/array-based capacity evidence
3. helper-returned root 语义
4. reviewer context 裁剪与 second-pass 触发条件

### 5.3 第三优先级：uSBS

原因：
- 正链 recall 已很好
- 更适合做“高召回 + 后续 review”层
- 目前不是 Phase A 的主边界

重点：
1. 控 reviewer 成本
2. 提升风险排序质量
3. 让 `P0/P1` 更稳定地浮现出来

## 6. 对 stripped / raw 的扩展边界

### 6.1 unstripped ELF

- 用作 baseline
- supervision 主要用于 recall/semantic enhancement

### 6.2 stripped ELF

- supervision 的优先扩展对象
- 重点帮助：
  - wrapper/thunk sink
  - loop sink
  - weak source wrappers
  - function-role recovery

### 6.3 raw .bin

- supervision 只能帮助解释 deterministic candidate
- 不能替代：
  - base address selection
  - vector-table parsing
  - code/data separation
  - import/lifting

因此 raw `.bin` 的路线必须是：
- 先 deterministic import/recovery
- 再 supervision/review

## 7. 下一阶段的执行顺序

### 7.1 立即执行

1. 把风险层正式接入 per-binary / suite-level summary
2. 先实现 `PR-S0 / PR-S1`
3. 只对 sink supervision 做 first rollout

### 7.2 然后执行

4. `Contiki` focused supervision
5. `Zephyr` focused supervision
6. 对比 supervision 前后的：
   - hit rate
   - spurious_non_drop
   - reviewer cost
   - top reason codes

### 7.3 暂缓执行

7. 不要立即做 object/channel supervision
8. 不要立即扩大 raw `.bin` 覆盖面
9. 不要再重复扩 source/sink miner 主体，除非 supervision 明确指出 deterministic extractor 有稳定缺口

## 8. 一句话总结

当前的最合理方向不是“继续扩大 deterministic pipeline”，而是：

- 让 `Phase A` 保持高召回、稳结构
- 让 `Phase A.5` 和 `Phase B` 成为两个受控的 LLM cleanup layer
- 先把 `Contiki / Zephyr` 的 supervision 与 reviewer 成本问题做稳
- 再往 stripped binary 推进

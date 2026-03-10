# SourceAgent 联合评测报告（GT + 无 GT，2026-03-09）

## 1. 目的

这份报告回答 4 个问题：

1. 当前 GT-backed 基线是否已经稳定。
2. 在更大的无 GT 固件集合上，SourceAgent 到底产出了多少中间产物，而不只是 source/sink 标签。
3. 为什么无 GT 扫描里 `chains` 数量小于 `sinks`，以及为什么 `DROP` 很多。
4. 当前哪些问题应该继续由 deterministic 阶段解决，哪些问题应该进入 reviewer / BinAgent 风格的语义审查阶段。

## 2. 评测拆分

这轮评测故意拆成两部分。

### 2.1 GT-backed 质量基线

数据集：

- `44` 个带 GT 样本
- `14` 个 `microbench`
- `30` 个 `mesobench`

结果目录：

- `/tmp/eval_gt_backed_suite_v2_p35plus_rerun2_merged`

这部分用于衡量结构正确性，因为它们有 artifact-level / chain-level GT。

### 2.2 无 GT 规模扫描

数据集：

- `94` 个额外 unstripped 固件样本
- `47` 个 `p2im-unit_tests`
- `37` 个 `monolithic-firmware-collection`
- `10` 个 `uSBS`

结果目录：

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

这部分不用于算准确率，而用于看：

- SourceAgent 在大样本上产出多少中间证据
- reviewer 队列压力多大
- 哪些地方还在大量 fail-closed

## 3. GT-backed 基线

来源：

- `/tmp/eval_gt_backed_suite_v2_p35plus_rerun2_merged/summary/artifact_eval_summary.json`

### 3.1 Chain 结果

- GT 样本数：`44`
- 正例 chains：`386`
- matched：`386`
- missed：`0`
- chain hit rate：`100%`
- `must_use_channel = 253 / 253`
- `negative_expectations = 27 / 27`
- `spurious_non_drop = 0`

### 3.2 结论

这个基线说明：

- 结构链恢复已经稳定
- 当前主问题不再是 chain recovery
- 当前主问题是 verdict calibration，也就是语义触发条件和可利用性分级

## 4. 无 GT 规模扫描

来源：

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

### 4.1 总体产物规模

在 `94` 个无 GT 样本上，SourceAgent 产出了：

- verified source labels：`7640`
- verified sink labels：`2135`
- total verified labels：`9775`
- object nodes：`903`
- refined objects：`954`
- channel edges：`369`
- sink roots：`2058`
- chains：`1937`
- with_source：`655`
- with_channel：`546`
- confirmed：`118`
- suspicious：`194`
- safe_or_low_risk：`88`
- dropped：`1537`
- calibration queue：`658`
- soft triage：`752`

### 4.2 按数据集分布

`monolithic-firmware-collection`

- labels：`6058`
- sources：`4979`
- sinks：`1079`
- object nodes：`402`
- refined objects：`437`
- channel edges：`191`
- chains：`945`
- with_source：`326`
- with_channel：`237`
- confirmed：`80`
- suspicious：`105`
- safe_or_low_risk：`72`
- dropped：`688`
- review queue：`259`
- soft triage：`296`

`p2im-unit_tests`

- labels：`3052`
- sources：`2159`
- sinks：`893`
- object nodes：`374`
- refined objects：`383`
- channel edges：`167`
- chains：`830`
- with_source：`278`
- with_channel：`279`
- confirmed：`37`
- suspicious：`40`
- safe_or_low_risk：`15`
- dropped：`738`
- review queue：`329`
- soft triage：`376`

`uSBS`

- labels：`665`
- sources：`502`
- sinks：`163`
- object nodes：`127`
- refined objects：`134`
- channel edges：`11`
- chains：`162`
- with_source：`51`
- with_channel：`30`
- confirmed：`1`
- suspicious：`49`
- safe_or_low_risk：`1`
- dropped：`111`
- review queue：`70`
- soft triage：`80`

## 5. 你刚才问的几个关键问题

### 5.1 为什么之前没有统计 object / channel 等中间产物？

这是旧报告口径不完整。

那轮 no-GT 扫描实际上已经生成了这些中间产物，只是报告里只写了 labels 和 chains，没有把中间层统计汇总出来。

现在补上后，可以看到：

- object nodes：`903`
- refined objects：`954`
- channel edges：`369`
- sink roots：`2058`

所以 SourceAgent 在无 GT 样本上不是只有 source/sink，而是已经有相当大的 pre-flight 证据面。

### 5.2 为什么 `chains < sinks`？不是每个 sink 至少都应该有一条 chain 吗？

不是。

当前 pipeline 是 **root-aware + bounded + fail-closed** 的。

一个 verified sink 想进入 chain 层，至少还要经过两步：

1. 必须先能抽出 usable root
2. root 对应的 chain 必须能在 materialize / prune 阶段保留下来

在这轮 no-GT 扫描里：

- verified sinks：`2135`
- sink roots：`2058`
- chains：`1937`

所以分成两层损失：

1. `2135 -> 2058`
- `77` 个 sink 没有得到 usable root

2. `2058 -> 1937`
- `121` 个 root 在 chain materialization/pruning 阶段被过滤掉

这类过滤来自：

- root parse 失败
- secondary root / pointer companion 去重
- bridge-only copy group 抑制
- store-chain 噪声抑制
- per-sink / per-binary chain 上限

也就是说，当前链层不是“每个 sink 都给一条链”，而是“只保留有根、有意义、没被证明冗余的链”。

### 5.3 为什么 `dropped` 很多？

因为 deterministic 阶段故意是 fail-closed。

在 no-GT 样本里，如果结构链证据不够，就应该被 `DROP`，而不是强行保留成可疑漏洞。

这轮最大的 drop 原因是：

- `OBJECT_HIT_NONE = 646`
- `MAX_DEPTH_REACHED = 211`
- `OBJECT_HIT_NO_EDGE = 192`
- `ROOT_PARSE_FAILED = 97`
- `ROOT_WEAK_FALLBACK = 87`
- `CHECK_UNCERTAIN = 55`

解释：

- 最大瓶颈还是 object anchoring
- 第二类是搜索预算/深度不够
- 还有一类是 object 命中了，但 channel edge 不够强

所以 `DROP = 1537` 并不意味着 pipeline 坏了，而是意味着当前 deterministic 层宁可保守，也不愿意过报。

### 5.4 `confirmed / suspicious` 的 chains 现在有没有原因说明？

对那一轮旧 no-GT 扫描来说：**还不够完整**。

原因是那两个 shard 的扫描发生在 reviewer 强化之前。

也就是说：

- 那时的 `confirmed / suspicious / safe_or_low_risk` 主要还是 deterministic verdict
- 还没有现在这种完整的：
  - review transcript
  - typed semantic reason codes
  - segment assessment
  - rejected rationale preservation

所以那一轮 no-GT 扫描里的这些 verdict 数，主要能说明“工作量和候选分布”，但还不能算“带完整语义解释的最终结论”。

这正是后面 P0-P4 reviewer 工作要解决的问题。

### 5.5 `calibration queue = 658` 和 `soft triage = 752` 分别是什么？

它们不是同一个东西。

`calibration queue`

- 表示被选进 semantic review 候选队列的 chains
- 受 `calibration_mode`、risk、sample suspicious ratio、max queue size 等约束
- 它是 reviewer 的工作清单

`soft triage`

- 表示进入 `soft/dual` verdict 视图的更大集合
- 其中既包括 review queue 里的链，也包括 deterministic soft widen 后保留下来的链
- 所以它可以比 calibration queue 更大

所以：

- `658` = reviewer 候选数
- `752` = 更宽松的 soft 视图规模

## 6. 这轮 no-GT 扫描说明了什么

### 6.1 已经解决的部分

- SourceAgent 现在已经能在大样本上稳定产出大量 pre-flight 证据
- 它不再只是 source/sink miner，而是：
  - object
  - channel
  - root
  - chain
  - review queue
都能产出

### 6.2 仍然没解决的部分

无 GT 扫描本身并不能证明“这些 chain 一定是 vuln”。

它只能证明：

- deterministic pre-flight 已经能把大量结构候选收集出来
- 后续确实需要 reviewer 去做语义触发条件判断

所以 SourceAgent 的职责边界现在已经很清楚：

- SourceAgent：确定性事实和候选链恢复
- reviewer / BinAgent 风格阶段：语义触发条件、check 是否真约束 root、最终 exploitability 校准

## 7. 下一步

1. 增强 reviewer 的 snippet coverage。
2. 引入 tool-assisted review。
3. 重点重跑：
   - `usb_host`
   - `dns`
   - `contiki`
   - `zephyr`
4. 继续保持：
   - deterministic baseline 和 no-GT discovery 口径分开
   - SourceAgent 作为唯一 deterministic authority

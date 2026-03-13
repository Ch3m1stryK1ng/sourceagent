# Canonical CVE Chain 诊断报告（2026-03-12）

## 1. 目的

这份报告聚焦 4 个已补 canonical CVE anchor 的样本，回答两个问题：

1. 官方主链（canonical main chain）有没有被当前 pipeline 命中。
2. 如果命中了，为什么还停在 `SUSPICIOUS + MEDIUM + P1`，而没有升到 `CONFIRMED / HIGH / P0`。

同时，这份报告也给出一个后续诊断方法：

- 将 canonical answer chain 直接送入 Phase B reviewer
- 不改变 runtime 检测结果
- 只用来区分：
  - 是评分 / risk / verdict 利用逻辑偏保守
  - 还是证据层（capacity / check binding / object extent）本身仍不足

## 2. 当前 canonical 样本状态

当前已接入 canonical anchor 的 4 个重点样本：

1. `cve_2018_16525_freertos_dns`
2. `cve_2021_34259_usb_host`
3. `zephyr_cve_2020_10065`
4. `zephyr_cve_2020_10066`

在本轮 GT-backed 全量评测中：

- canonical main chains 总数：`8`
- canonical main chains 命中：`4`
- 命中的 canonical main chains 当前全部为：
  - `final_verdict = SUSPICIOUS`
  - `final_risk_band = MEDIUM`
  - `review_priority = P1`

这意味着：

- 当前系统已经具备“主链有没有命中”的判定能力
- 但还没有把命中的主链稳定提升到 `CONFIRMED / HIGH / P0`

## 3. 样本级诊断

### 3.1 `cve_2018_16525_freertos_dns`

当前状态：

- canonical anchor：`complete`
- canonical main chains：`2`
- 当前命中：`0/2`

但 raw outputs 显示，runtime 中实际上已经存在高度相关的 3 条链：

1. `prvSkipNameField` 对应的 name-walk 链
2. `prvProcessIPPacket` 对应的 downstream copy 链
3. `prvParseDNSReply` 的 supporting precursor 链

关键现象：

- `source_ok / object_ok / channel_ok / root_ok / derive_ok` 基本都为真
- 但 evaluator 仍把 canonical main chain 判为 `missing`

当前最可能的问题不是“链根本没打到”，而是：

- canonical anchor 的 `chain_id` 与 runtime 生成链的对齐规则还不够稳
- evaluator 当前更像做 `chain_id` 级对齐，而不是 `sink/root/function/role` 级对齐

所以，对 `dns`：

- 这更像 `canonical miss due to alignment`
- 不像真正的 `runtime miss`

### 3.2 `cve_2021_34259_usb_host`

当前状态：

- canonical anchor：`complete`
- canonical main chains：`2`
- 当前命中：`0/2`

raw outputs 里，runtime 已经打到了三条非常接近官方主路径的 parser/store 链：

- `USBH_ParseEPDesc(ep_descriptor)`
- `USBH_ParseInterfaceDesc(if_descriptor)`
- `USBH_ParseCfgDesc(cfg_desc)`

而且当前这些链已经具备：

- `source_reached = true`
- `root_bound = true`
- `object_bound = true`
- `channel_satisfied = true`
- `check_strength = weak`

reviewer 也已经能输出：

- `CHECK_NOT_BINDING_ROOT`
- `WEAK_GUARDING`
- `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
- `TAINT_PRESERVED_COPY_FROM_IO`

所以对 `usb_host`：

- 主问题也更像 evaluator / anchor 对齐不稳
- 而不是 runtime 没把主路径打出来

### 3.3 `zephyr_cve_2020_10065`

当前状态：

- canonical anchor：`provisional`
- canonical main chains：`2`
- 当前命中：`2/2`

这说明：

- 主链已经命中
- 当前问题不再是 chain recovery

但这 2 条命中的主链目前都停在：

- `SUSPICIOUS`
- `MEDIUM`
- `P1`

当前最像真的解释是：

1. 结构链已经打到
2. reviewer 也看到了风险因素：
   - `TRIGGERABLE_*`
   - `CHECK_NOT_BINDING_ROOT`
   - `TAINT_PRESERVED_*`
3. 但系统仍然缺少足够硬的 exploitability 证据去升格，例如：
   - destination extent / capacity 不够硬
   - check 虽然弱，但还不能被强证明为无效
   - helper/parser 语义还有保守不确定性

所以对 `zephyr 10065`：

- 这是一个典型的 `canonical hit but under-promoted`

### 3.4 `zephyr_cve_2020_10066`

状态与 `10065` 基本平行：

- canonical anchor：`provisional`
- canonical main chains：`2`
- 当前命中：`2/2`
- 当前最终状态仍为：
  - `SUSPICIOUS`
  - `MEDIUM`
  - `P1`

也就是说：

- 主链命中已经不是问题
- 当前问题同样是 under-promotion，而不是 detection miss

## 4. 当前可以明确区分的三类情况

### A. canonical miss due to alignment

当前最像这一类的：

- `cve_2018_16525_freertos_dns`
- `cve_2021_34259_usb_host`

特点：

- runtime 里存在非常接近官方主路径的链
- 但 evaluator 还没有稳定把它们对齐到 canonical GT

### B. canonical hit but under-promoted

当前最像这一类的：

- `zephyr_cve_2020_10065`
- `zephyr_cve_2020_10066`

特点：

- 主链已经命中
- 但最终只到 `SUSPICIOUS + MEDIUM + P1`

### C. peripheral suspicious

这类链不是官方主链，但仍是高价值相关链：

- 与同一 parser / protocol / helper 相关
- 可能是主链旁路、派生链或风险近邻

这类链不应和 canonical main chain 混在一起解释。

## 5. 一个重要结论：现在的主问题是什么

对于这 4 个 canonical 样本，当前最核心的问题已经可以拆成两种：

1. `dns / usb_host`
   - 更像 canonical 对齐问题
   - 不是 runtime 完全没打到主链

2. `zephyr 10065 / 10066`
   - 更像 verdict / risk / reviewer 利用问题
   - 不是主链没命中，而是升格不够

也就是说：

- 当前不是单纯“链没打到”
- 也不是单纯“reviewer 太保守”
- 而是：
  - 一部分样本卡在 canonical 对齐
  - 一部分样本卡在 canonical 主链升格

## 6. 建议引入的诊断方法：把 answer chain 直接送入 Phase B

### 6.1 为什么值得做

如果一条 canonical 主链已经在 GT 中锚定，但最终仍然只是：

- `SUSPICIOUS + MEDIUM + P1`

我们需要区分两件事：

1. 是 reviewer / risk / verdict 的利用逻辑偏保守
2. 还是这条链的证据层本身还不够硬

### 6.2 做法

增加一个诊断模式：

- 不改变 runtime 检测结果
- 只在 analysis/evaluation 阶段，把 canonical answer chain 直接送给 Phase B reviewer

输入：

- canonical chain 对应的 deterministic feature pack
- 相关 snippets / capacity / guard / object / channel 证据

输出：

- 如果 reviewer 仍然只给 `SUSPICIOUS`
  - 说明当前证据层确实不足
- 如果 reviewer 愿意给 `CONFIRMED / HIGH / P0`
  - 说明当前主要是评分 / risk / verdict 利用逻辑的问题

### 6.3 重要边界

这个模式：

- 只能用于 `evaluation / diagnosis`
- 不能进入 runtime detection
- 不能让系统在运行时“偷看答案”

所以它是：

- 一个诊断工具
- 不是 runtime oracle

## 7. 下一步建议

### 第一优先级

补 canonical 评测对齐：

- 对 `dns / usb_host` 做 canonical 对齐诊断
- 优先看：
  - sink id / root id / function role 映射
  - 而不是只按 `chain_id` 对齐

### 第二优先级

对 `zephyr 10065 / 10066` 做 canonical answer-chain Phase B 诊断：

- 看主链为什么停在 `SUSPICIOUS + MEDIUM + P1`
- 判断是：
  - evidence gap
  - 还是 verdict/risk 利用过于保守

### 第三优先级

把 report 里 canonical 三类显式分开：

- `canonical main`
- `related risky`
- `peripheral suspicious`

## 8. 最终一句话结论

当前系统已经能够在一部分真实 CVE 样本上回答“官方主链有没有命中”。

但我们现在看到的主要问题不是“链没打到”，而是：

- 一类样本（如 `dns / usb_host`）卡在 canonical 对齐
- 另一类样本（如 `zephyr 10065 / 10066`）主链已命中，但还没有被提升成 `CONFIRMED / HIGH / P0`

所以下一步最值的不是继续泛泛加预算，而是：

1. 修 canonical 对齐
2. 用 canonical answer-chain 直接诊断 reviewer / risk / verdict 的保守性

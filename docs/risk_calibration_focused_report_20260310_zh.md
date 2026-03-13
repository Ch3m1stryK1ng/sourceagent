# Focused 风险分层校准报告（2026-03-10）

## 1. 目的

本轮测试的目标不是继续提升 chain recovery，而是验证新加入的风险分层字段是否能更合理地表达：

- `final_verdict`：最终证据状态
- `final_risk_band`：风险强度
- `review_priority`：后续审查优先级

本轮重点检查四个样本：

- `cve_2021_34259_usb_host`
- `cve_2018_16525_freertos_dns`
- `contiki hello-world`
- `zephyr-CVE-2020-10065`

本轮 reviewer 使用 `.env` 中的 `gpt-5.4`。

## 2. 输出目录

- `usb_host`：`/tmp/eval_riskcal_usb_host_v2`
- `dns`：`/tmp/eval_riskcal_dns_v2`
- `contiki`：`/tmp/eval_riskcal_contiki_v2`
- `zephyr`：`/tmp/eval_riskcal_zephyr10065_v2`

## 3. 核心结果

### 3.1 usb_host

- 最终 verdict：`CONFIRMED 1 / SUSPICIOUS 2`
- 风险分层：`MEDIUM 3`
- 审查优先级：`P0 1 / P1 2`

解读：

- 这说明 parser 型链路里，至少有 1 条在 reviewer 看来已经具备较强触发逻辑。
- 其余 2 条仍保留为 `SUSPICIOUS`，说明 reviewer 认为仍有风险，但还差最后一层确认条件。
- 风险带没有再全部挤到 `HIGH`，说明校准后没有过饱和。

### 3.2 dns

- 最终 verdict：`CONFIRMED 1 / SAFE_OR_LOW_RISK 2`
- 风险分层：`MEDIUM 2 / LOW 1`
- 审查优先级：`P0 1 / P2 2`

解读：

- 这组结果比较符合预期：真正高价值链被保留为 `CONFIRMED + P0`。
- 其余链虽然仍可能有结构风险，但在当前证据下更接近低到中风险，不应全部堆到高风险队列。

### 3.3 contiki hello-world

- 最终 verdict：`SUSPICIOUS 25 / SAFE_OR_LOW_RISK 39 / DROP 1`
- 风险分层：`MEDIUM 25 / LOW 40`
- 审查优先级：`P1 25 / P2 40`

解读：

- 这是大样本的典型分布：大量链条在结构上成立，但 reviewer 认为更适合保留为 `SUSPICIOUS + MEDIUM + P1`。
- 这说明这批链是“值得继续审查”的，而不是“已经确认”。
- 同时，`SAFE_OR_LOW_RISK` 现在基本落在 `LOW/P2`，没有再出现大面积 `HIGH/P0` 误堆积。

### 3.4 zephyr-CVE-2020-10065

- 最终 verdict：`SUSPICIOUS 16 / SAFE_OR_LOW_RISK 26 / DROP 8`
- 风险分层：`MEDIUM 16 / LOW 34`
- 审查优先级：`P1 16 / P2 34`

解读：

- 这说明 reviewer 对该样本整体仍偏保守。
- 但新的风险层至少把真正需要继续看的链压到了 `SUSPICIOUS + MEDIUM + P1`，而不是和低风险链混在一起。
- `SAFE_OR_LOW_RISK` 现在主要落在 `LOW/P2`，这比之前“很多链几乎都被打成高风险”更合理。

## 4. 结论

本轮风险层校准后，输出已经从“只有 verdict”提升为“三层表达”：

- 证据状态：`final_verdict`
- 风险强度：`final_risk_band`
- 处理优先级：`review_priority`

从 focused 样本结果看：

1. `HIGH/P0` 过饱和问题已经明显缓解。
2. `usb_host` 这类 parser 样本开始出现更合理的分层：不是全部保守，也不是全部拉满。
3. `contiki/zephyr` 这类大样本现在能把“值得继续挖”的链集中到 `SUSPICIOUS + MEDIUM + P1`。
4. 当前风险层已经可以用于：
   - 后续 reviewer/BinAgent 排序
   - 人工审查优先级安排
   - 报告中区分“证据状态”和“风险强度”

## 5. 当前边界

需要强调：

- `final_verdict = CONFIRMED` 仍然不等于“已经证明是真实 CVE”。
- 它表示的是：在当前 deterministic facts + reviewer 语义审查下，这条链已经达到最高内部确认等级。
- 对 no-GT 样本，后续仍应结合更多人工审查或更强的语义/上下文证据来判断是否真是漏洞。

## 6. 下一步建议

下一步最自然的工作是：

1. 把这套风险层接入 summary/report 输出。
2. 对 `P0/P1` 样本做进一步 reviewer 深挖或人工审查。
3. 如果继续优化 deterministic 层，优先围绕：
   - parser destination capacity 证据
   - family-specific object extent
   - reviewer 的上下文排序

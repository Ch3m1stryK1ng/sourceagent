# 当前能力边界报告（2026-03-10）

## 1. 测试范围
- 运行目录：`/tmp/eval_gt_backed_supervision_all_20260310`
- 样本：`44` 个 GT-backed 样本（microbench + monolithic/mesobench + uSBS）。
- 配置：`Stage 10 + review(default on) + supervision(all) + gpt-5.4 + tool-assisted review`。

## 2. 顶层结果
- strict label：TP=41.0, FP=8.0, FN=5.0, P=0.837, R=0.891, F1=0.863
- weighted label：TP=43.5, FP=5.5, FN=2.5, P=0.888, R=0.946, F1=0.916
- GT positive chains：318/386，命中率 `82.38%`
- must-use-channel：185/253
- negative expectations：27/27
- spurious non-drop：680

## 3. Artifact 层能力边界
- `sources`：GT=105, matched=97, recall=0.9238, pred=1761, fp=1664
- `objects`：GT=58, matched=51, recall=0.8793, pred=842, fp=791
- `channels`：GT=48, matched=42, recall=0.8750, pred=116, fp=74
- `sinks`：GT=376, matched=374, recall=0.9947, pred=1270, fp=896
- `sink_roots`：GT=721, matched=718, recall=0.9958, pred=2697, fp=1979
- `derive_checks`：GT=390, matched=310, recall=0.7949, pred=1275, fp=965

当前最弱的一层不是 `sink/root`，而是 `derive_checks` 与大样本上的 chain 选择/语义校准。

## 4. Phase A.5 supervision 概况
- supervision queue：148
- supervision reviewed：122
- supervision accepted：70
- supervision audit-only：30
- supervision rejected：22
- objects_enriched：12
- channels_enriched：2
- accepted_by_kind：`{'sink': 13, 'source': 43, 'channel': 2, 'object': 12}`
- accepted_by_label top：`[('MMIO_READ', 40), ('COPY_SINK', 9), ('SRAM_CLUSTER', 9), ('STORE_SINK', 4), ('DMA_BUFFER', 2), ('DMA_CHANNEL', 2), ('ISR_MMIO_READ', 2), ('DMA_BACKED_BUFFER', 1), ('RING_BUFFER', 1)]`

解释：source/sink supervision 已经明显工作，object/channel supervision 已接线但当前接受量仍低，说明后两者的 merge gate 仍偏保守。

## 5. Phase B review / 风险层
- review queue：556
- llm reviewed：238
- final verdict 分布：`{'SAFE_OR_LOW_RISK': 483, 'CONFIRMED': 9, 'SUSPICIOUS': 525, 'DROP': 258}`
- risk band 分布：`{'LOW': 742, 'MEDIUM': 533}`
- review priority 分布：`{'P2': 741, 'P0': 9, 'P1': 525}`
- top reason codes：`[('CHECK_NOT_BINDING_ROOT', 105), ('ROOT_NOT_CAPACITY_RELEVANT', 54), ('ROOT_FROM_MMIO_OR_DMA', 38), ('CHECK_ONLY_STATE_GATE', 29), ('LIKELY_SAFE_BOUND_PRESENT', 26), ('TRIGGER_UNCERTAIN_MISSING_CAPACITY', 17), ('WEAK_GUARDING', 13), ('TRIGGERABLE_LEN_GT_CAPACITY', 13), ('ROOT_SECONDARY_ONLY', 13), ('NO_SOURCE_SEGMENT', 12), ('TRIGGERABLE_WITH_SIMPLE_CONSTRAINTS', 10), ('ROOT_DERIVED_ARITHMETIC', 10), ('TAINT_CLEANSED_CONST_ASSIGN', 5), ('TAINT_PRESERVED_COPY_FROM_IO', 3), ('TRIGGERABLE_FORMAT_CONTROLLED', 3)]`
- top blockers：`[('review_required', 80), ('object_bound', 1)]`

解释：当前风险层已接入，但 `HIGH/P0` 仍被有意压得很低；`MEDIUM/P1` 是现在的主要高价值审查池。

## 6. 按数据集汇总
### microbench
- supervision_queue: 32
- supervision_reviewed: 32
- supervision_accepted: 22
- objects_enriched: 3
- channels_enriched: 2
- review_queue: 5
- llm_reviewed: 10
- final_CONFIRMED: 8
- final_SUSPICIOUS: 1
- final_SAFE_OR_LOW_RISK: 8
- risk_LOW: 7
- risk_MEDIUM: 10
- prio_P0: 8
- prio_P1: 1
- prio_P2: 8

### monolithic-firmware-collection
- supervision_queue: 76
- supervision_reviewed: 58
- supervision_accepted: 32
- objects_enriched: 9
- channels_enriched: 0
- review_queue: 407
- llm_reviewed: 149
- final_SUSPICIOUS: 390
- final_SAFE_OR_LOW_RISK: 430
- final_DROP: 182
- risk_LOW: 612
- risk_MEDIUM: 390
- prio_P1: 390
- prio_P2: 612

### uSBS
- supervision_queue: 40
- supervision_reviewed: 32
- supervision_accepted: 16
- objects_enriched: 0
- channels_enriched: 0
- review_queue: 144
- llm_reviewed: 79
- final_CONFIRMED: 1
- final_SUSPICIOUS: 134
- final_SAFE_OR_LOW_RISK: 45
- final_DROP: 76
- risk_LOW: 123
- risk_MEDIUM: 133
- prio_P0: 1
- prio_P1: 134
- prio_P2: 121

## 7. 最难样本（按命中率与误链）
- `contiki_cve_2020_12141_snmp_server` (monolithic-firmware-collection): matched 21/46 (45.6%), spurious_non_drop=30, must_use_channel=14/39
- `contiki_cve_2020_12140_hello_world` (monolithic-firmware-collection): matched 30/64 (46.9%), spurious_non_drop=36, must_use_channel=22/56
- `contiki_halucinator_cve_2019_9183_hello_world` (monolithic-firmware-collection): matched 47/54 (87.0%), spurious_non_drop=19, must_use_channel=43/50
- `zephyr_cve_2020_10066` (monolithic-firmware-collection): matched 20/21 (95.2%), spurious_non_drop=38, must_use_channel=20/21
- `zephyr_cve_2020_10065` (monolithic-firmware-collection): matched 21/22 (95.5%), spurious_non_drop=38, must_use_channel=21/22
- `zephyr_cve_2021_3330` (monolithic-firmware-collection): matched 1/1 (100.0%), spurious_non_drop=41, must_use_channel=1/1
- `zephyr_cve_2021_3320` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2
- `zephyr_cve_2021_3321` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2
- `zephyr_cve_2021_3322` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2
- `zephyr_cve_2021_3323` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2
- `zephyr_false_positive_rf_size_check` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2
- `zephyr_false_positive_watchdog_callback` (monolithic-firmware-collection): matched 2/2 (100.0%), spurious_non_drop=39, must_use_channel=2/2

## 8. 当前能力边界结论
- `microbench` 已稳定，可继续作为回归集。
- `uSBS` 维持高召回，但误链和 reviewer 成本仍高。
- `mesobench/monolithic` 是当前主边界，尤其是 `Contiki / Zephyr`。
- 当前主瓶颈不是 source/sink miner，而是：大样本上的 chain 选择、derive/check 解释、review 吞吐，以及 supervision 在 object/channel 层的保守 merge gate。
- 这支持当前路线：Phase A 继续做 deterministic authority；Phase A.5 与 Phase B 都允许 LLM bounded 地“收拾烂摊子”，但不能让它变成第二套无约束发现器。

## 9. 下一步建议
1. 继续做 `PR-S3/4/5` 之后的 hardening，但优先放在 object/channel supervision merge gate。
2. 对 `Contiki / Zephyr` 的 `P1` 链做更强 second-pass review，而不是一味扩大 reviewer 覆盖。
3. 把风险层接进 suite-level summary/report，显式输出 `High-Risk Suspicious Chains` 和 `P0/P1 review targets`。

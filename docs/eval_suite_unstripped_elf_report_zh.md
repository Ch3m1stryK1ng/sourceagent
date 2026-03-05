# Unstripped ELF 评测套件实验报告（中文，增强版）

## 1. 实验目标
- 评估 SourceAgent 在 **unstripped ELF** 条件下的 source/sink 检测能力。
- 覆盖 4 类数据集：`microbench`、`p2im-unit_tests`、`uSBS`、`monolithic-firmware-collection`。
- 对有 GT 样本做严格 TP/FP/FN 统计；对无 GT 样本给出检测分布与平台画像。

## 2. 实验配置
- Suite 目录: `/tmp/eval_suite_unstripped_elf_20260305_131606`
- 输入格式: `unstripped .elf`（`--only-unstripped-elf`）
- 运行模式: `--online --stage 7`
- Proposer: heuristic（`model=null`）
- 验收 verdict: `VERIFIED, PARTIAL`
- GT: `firmware/ground_truth_bundle/normalized_gt_sinks.json`（**本轮是 sink-oriented GT**）
- 重要处理: uSBS 同名 ELF 采用唯一样本副本（`usbs_XX_*.elf`）避免 stem 冲突。

## 3. 输出产物
- 总汇总 JSON: `/tmp/eval_suite_unstripped_elf_20260305_131606/summary/eval_summary.json`
- 分文件: `/tmp/eval_suite_unstripped_elf_20260305_131606/tables/by_file.csv`
- 平台画像: `/tmp/eval_suite_unstripped_elf_20260305_131606/tables/sample_platform_profile.csv`

## 4. 实验结果统计
### 4.1 总体统计
- 样本总数: **48**
- 状态分布: {'ok': 10, 'ok_no_ground_truth': 37, 'eval_timeout': 1}
- 检测总量: **3588**（source=2529, sink=1059）
- Sink GT 严格指标: TP=17, FP=0, FN=0, P=1.000, R=1.000, F1=1.000

### 4.2 Source 标签统计（分母=source 总数）
Source 总数 = 2529

| Source 标签 | 检测数量 | Source内部占比 | GT样本内检测 | 无GT样本内检测 |
|---|---|---|---|---|
| MMIO_READ | 2398 | 94.82% | 22 | 2376 |
| DMA_BACKED_BUFFER | 114 | 4.51% | 1 | 113 |
| ISR_MMIO_READ | 16 | 0.63% | 0 | 16 |
| ISR_FILLED_BUFFER | 1 | 0.04% | 0 | 1 |

### 4.3 Sink 标签统计（分母=sink 总数）
Sink 总数 = 1059

| Sink 标签 | 检测数量 | Sink内部占比 | GT样本内检测 | 无GT样本内检测 | GT覆盖(匹配/总数) |
|---|---|---|---|---|---|
| COPY_SINK | 370 | 34.94% | 7 | 363 | 7/8 |
| STORE_SINK | 335 | 31.63% | 8 | 327 | 1/1 |
| LOOP_WRITE_SINK | 160 | 15.11% | 2 | 158 | 1/1 |
| FUNC_PTR_SINK | 111 | 10.48% | 1 | 110 | 1/1 |
| FORMAT_STRING_SINK | 46 | 4.34% | 1 | 45 | 1/1 |
| MEMSET_SINK | 37 | 3.49% | 1 | 36 | 1/1 |

### 4.4 microbench（有 GT）按样本结果：Source 与 Sink分开
- 说明：当前 GT 为 sink-oriented，所以 **TP/FP/FN 仅对 sink 有定义**。

#### 4.4.1 Sink 严格评估（TP/FP/FN）
| 样本 | TP | FP | FN | Precision | Recall | F1 | sink检测总量 |
|---|---|---|---|---|---|---|---|
| cve_2018_16525_freertos_dns | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 3 |
| cve_2020_10065_hci_spi | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| cve_2021_34259_usb_host | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 6 |
| t0_copy_sink | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| t0_dma_length_overflow | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_format_string | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_func_ptr_dispatch | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_indirect_memcpy | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_store_loop_sink | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 3 |
| t0_uart_rx_overflow | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |

#### 4.4.2 Source 检测分布（无 source-TP/FP/FN）
| 样本 | source检测总量 | MMIO_READ | ISR_MMIO_READ | ISR_FILLED_BUFFER | DMA_BACKED_BUFFER |
|---|---|---|---|---|---|
| cve_2018_16525_freertos_dns | 2 | 2 | 0 | 0 | 0 |
| cve_2020_10065_hci_spi | 3 | 3 | 0 | 0 | 0 |
| cve_2021_34259_usb_host | 1 | 1 | 0 | 0 | 0 |
| t0_copy_sink | 2 | 2 | 0 | 0 | 0 |
| t0_dma_length_overflow | 5 | 4 | 0 | 0 | 1 |
| t0_format_string | 2 | 2 | 0 | 0 | 0 |
| t0_func_ptr_dispatch | 2 | 2 | 0 | 0 | 0 |
| t0_indirect_memcpy | 2 | 2 | 0 | 0 | 0 |
| t0_store_loop_sink | 2 | 2 | 0 | 0 | 0 |
| t0_uart_rx_overflow | 2 | 2 | 0 | 0 | 0 |

### 4.5 按数据集统计
| 数据集 | 样本数 | GT样本 | 成功(ok*) | 异常 | 检测总量 | Source | Sink | GT-TP | GT-FP | GT-FN | GT-F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| microbench | 14 | 10 | 14 | 0 | 55 | 32 | 23 | 17 | 0 | 0 | 1.000 |
| monolithic-firmware-collection | 12 | 0 | 12 | 0 | 1716 | 1159 | 557 | 0 | 0 | 0 | 0.000 |
| p2im-unit_tests | 12 | 0 | 12 | 0 | 960 | 695 | 265 | 0 | 0 | 0 | 0.000 |
| uSBS | 10 | 0 | 9 | 1 | 857 | 643 | 214 | 0 | 0 | 0 | 0.000 |

## 5. 为什么定位这些标签？是否覆盖全部 source/sink 类型？
### 5.1 Source 标签选择动机
- 我们优先覆盖固件里最常见、最稳定的输入路径：轮询寄存器读取、中断上下文读取、ISR 生产/主流程消费缓冲区、DMA 写入 RAM 后被业务逻辑读取。
- 这四类路径在 bare-metal 和 RTOS 固件里都很常见，且容易映射成可验证的静态特征，因此适合作为第一阶段的 source 基线。

### 5.2 Sink 标签选择动机
- 我们优先覆盖最直接的内存破坏风险：复制写入、清零写入、指针写入、循环写入，以及格式串和函数指针这两类高风险控制路径。
- 这些标签能覆盖多数“外部输入进入后触发危险写/控制流”的主干模式，适合先建立可评估、可迭代的检测闭环。

### 5.3 覆盖性结论
- 当前标签集是 Type II/III 场景下的“核心覆盖集”，不是全部漏洞类型全集。
- 尚未完整覆盖的方向包括：更细粒度语义 sink、内存管理型问题（如 UAF/double-free 专项）、非内存破坏型漏洞、以及信息泄漏/OOB-read 类读风险。
- 因此结论应理解为：在当前标签空间内性能稳定，而不是“对所有漏洞类型都完备”。

## 6. Method：Source/Sink 如何被检测（实现级说明）
### 6.1 Source 标签（代码实际做法）
- `MMIO_READ`
  - 输入：`MemoryAccessIndex.mmio_accesses`。
  - 过滤条件：`kind=="load"`，`base_provenance in {CONST, FLASH_CONST_PTR, INTERPROCEDURAL, STRUCT_RESOLVED, INTRA_RESOLVED}`，`in_isr==False`，`target_addr!=None`。
  - 去重键：`(function_name, target_addr)`。
  - 产物：记录 `addr_expr/provenance/cluster/rmw/multi_function` 等 facts，并计算置信度后输出候选。
- `ISR_MMIO_READ`
  - 逻辑与 `MMIO_READ` 类似，但强制 `in_isr==True`。
  - 去重同样使用 `(function_name, target_addr)`，并在 facts 中写入 ISR 证据。
- `ISR_FILLED_BUFFER`
  - 扫描 `mai.accesses`，找 `ISR store` 与 `non-ISR load` 在同一 SRAM cluster（256B 粒度）的交集。
  - 当“同簇同时出现 ISR 写 + 非 ISR 读”时生成候选，附带写者/读者函数集合与访问计数。
- `DMA_BACKED_BUFFER`
  - 先找 DMA 配置点：同一函数对同一 MMIO cluster 的 `store` 次数 `>=3`。
  - 再检查是否存在 pointer-like 配置写（如 `GLOBAL_PTR/CONST`），并结合后续 SRAM 消费证据提升分值。

### 6.2 Sink 标签（代码实际做法）
- `COPY_SINK`
  - 先按函数名检索 `memcpy/memmove/strcpy/sprintf...`（含 intrinsic）；对 stripped 场景有 heuristic fallback。
  - 通过 xref 找 caller；若 xref 为空，回退到 decompile cache 扫描调用模式。
  - 在 caller 反编译结果中抽取参数、长度是否常量、目标指针来源、是否有 bounds guard，再生成候选。
- `MEMSET_SINK`
  - 与 `COPY_SINK` 同框架（symbol/xref/decompile）。
  - 额外过滤初始化噪声：例如常量长度、典型栈清零等低风险模式会被跳过。
- `STORE_SINK`
  - MAI 路径：选择 `kind=="store"` 且 `provenance in {ARG, GLOBAL_PTR, UNKNOWN}`，并排除 MMIO/Flash 写。
  - 参数写回退路径：在反编译代码中匹配 `*param_N=...`、`param_N[idx]=...`、`ptr->field=...`。
  - 去噪：库函数过滤 + 高扇出函数过滤 + 每函数 top-k + 全局上限。
- `LOOP_WRITE_SINK`
  - 在反编译代码中找 `for/while/do` 循环，再找循环体写入模式（索引写、指针写）。
  - 若识别到 `dst[i]=src[i]` 类拷贝惯用法，会从 `LOOP_WRITE_SINK` 提升为 `COPY_SINK`。
- `FORMAT_STRING_SINK`
  - 识别 printf 家族调用，提取 format 参数。
  - 规则是：format 为字面量则跳过；format 为变量/参数则保留为 sink。
- `FUNC_PTR_SINK`
  - 在反编译代码中匹配间接调用模式：`(*param_N)()`, table-dispatch, casted indirect call 等。
  - 再判断调用目标/索引是否有输入相关特征（如 `param_` 参与）。

### 6.3 证据校验与判定（Verifier）
- 每个候选会带上结构化 facts（调用点、参数、来源、边界条件、上下文）。
- Verifier 对每个标签应用 obligation 集：
  - required obligation 全满足 => `VERIFIED`
  - required 出现违反 => `REJECTED`
  - required 无违反但存在未知 => `PARTIAL`
- 因此最终输出由“模式命中 + obligation 一致性”共同决定，而不是仅凭单条规则命中。

## 7. 样本平台画像（Architecture / RTOS 或运行环境）
> 说明：画像基于 `readelf` + strings + 路径特征，为工程推断。

| 架构推断 | 数量 |
|---|---|
| ARM Cortex-M4/M7 (v7E-M) | 32 |
| ARM Cortex-M3 (STM32F103) | 7 |
| ARM (Cortex-M likely) | 4 |
| ARM Cortex-M3 (Atmel SAM3) | 4 |
| ARM Cortex-M4 (NXP K64F) | 1 |

| 运行环境推断 | 数量 |
|---|---|
| Microbench synthetic bare-metal | 14 |
| STM32 HAL + LwIP (bare-metal style) | 10 |
| Arduino framework (bare-metal style) | 7 |
| Zephyr RTOS | 6 |
| RIOT OS | 4 |
| NuttX | 3 |
| Contiki-NG | 2 |
| Mixed real firmware (framework varies) | 1 |
| FreeRTOS-based | 1 |

完整 48 样本画像见：`/tmp/eval_suite_unstripped_elf_20260305_131606/tables/sample_platform_profile.csv`。

## 8. 局限与下一步
1. 补 source GT（当前严格评分仅 sink）。
2. 增加 sample_id 级落盘命名，永久解决同名 ELF 冲突。
3. 增强大固件稳健性（decompile 缓存/分片/重试）以降低 timeout。
4. 在无 GT 数据集引入小规模人工标注，补 precision 闭环。

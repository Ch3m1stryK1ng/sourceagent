# 详细规划备忘录（PATCH v1.1）
## 异步上下文通信、ChannelGraph 恢复与 Sink-to-Source 隧道检测（代码级实现）

## 执行摘要
当前 SourceAgent 的 RQ1 层已经可用：source/sink 标签体系基本落地。下一阶段的重点不再是继续叠加孤立标签，而是把这些标签**连接成可验证、可解释、可复现的 source-to-sink 链路**，并支持**跨上下文传播**（ISR/task/main/DMA）。

本次 PATCH v1.1 修复了会导致实现歧义的规范不一致（尤其是 DMA、对象身份、链路示例相关），并强化了 stripped binary 场景下的可复现性。

### 补丁变更日志（v1.1）
1. **显式并统一 DMA 上下文定义：** 将 DMA 视为*合成生产者上下文*（不是 CPU 函数上下文），补充规则与 schema 字段。
2. **修复不一致链路示例：** 移除误导性的 `DMA->TASK + MMIO_READ` 混合示例，改为两个示例：
   - (a) 单上下文 MMIO 链路
   - (b) 真正的跨上下文 ISR->MAIN 隧道链路
3. **为 stripped binary 强化对象 schema：** 新增 `writer_sites` / `reader_sites`（地址级证据）与可选 `binary_sha256`。
4. **不丢弃对象节点：** 保留全部 object node（便于 app anchor 与可解释性）；仅过滤**边**为跨上下文（以及 DMA->CPU）。
5. **收紧约束 schema：** 在 constraints 中加入 `vars` 与 `strength`，区分“通道使能条件”与“sink 边界检查”。
6. **明确 sink root 提取优先级：** 优先 miner facts / p-code 调用参数，反编译正则仅作为兜底。
7. **隧道 linker 改为 best-first + caching + state 去重**，避免指数爆炸。
8. **将 `endpoint_in_app` 替换为可实现的 `has_app_anchor`**（MMIO/DMA/object 证据锚点）。
9. 新增**目标 / 非目标 / 假设**章节，并增加**最小链路级 GT 格式**用于评测。
10. 清理 Related Work：补充明确引用，无法确认项标记 TODO。

---

## 1. 目标、非目标、假设（新增）

### 1.1 目标（v1）
- **G1. 面向 Type II/III 固件产出可行动、可审计的 source-to-sink 链路：**
  - 每条链路都有证据支撑（`evidence_refs`、地址、site）。
  - 每条链路明确解释：**source**、**承载对象**、**derive**、**check**、**sink**。
- **G2. 通过异步通信对象处理跨上下文传播：**
  - ISR <-> task/main
  - DMA -> CPU 上下文
- **G3. 避免 source x sink 穷举配对。** 使用 sink-first 有界搜索 + tunnel jump。

### 1.2 非目标（v1）
- **NG1. 不做完整交错/并发证明。** 对异步行为采用 producer-consumer 边近似建模。
- **NG2. 不做全程序精确 points-to。** 接受别名不确定性并保留 top-K 候选。
- **NG3. v1 不要求在 stripped binary 中完整恢复 RTOS 队列。**
  - 先覆盖共享内存通道 + DMA 通道（收益高、稳定性好）。
- **NG4. 不深入未知库内部做深度追踪。**
  - 使用 summary/barrier 模式。

### 1.3 假设
- **A1. MAI（MemoryAccessIndex）质量“足够可用”：** 能提供 load/store、目标地址、`in_isr` 标记。
- **A2. 已有 memory map 假设：** ELF 最佳；raw bin 可接受。
- **A3. 必须使用预算控制（slice budget、K、d）：** stripped/优化二进制无法保证完全恢复。

---

## 2. 输入、威胁模型、输出（新增）

### 2.1 输入
- 固件二进制（优先 ELF；raw bin 在有 memory map 假设时支持）
- SourceAgent 的已验证标签（RQ1 层）：sources + sinks
- MAI 产物（访问轨迹、反编译缓存）

### 2.2 威胁模型（“攻击者可控”定义）
- Type II/III 输入来自硬件侧：
  - **MMIO 读取**（UART/SPI/I2C/USB FIFO 寄存器）
  - **DMA 传输**写入 RAM
  - 通过共享对象在 ISR/task/main 之间传播
- “可控”判定基于：值到达 source（MMIO/DMA），并证明其导出值进入 sink 参数且缺失有效边界检查。

### 2.3 输出
- `channel_graph.json`：异步 producer-consumer 对象图
- `refined_objects.json`：细化后的对象边界（payload vs flag vs index）
- `sink_roots.json`：每个 sink 需要回溯的根参数
- `chains.json`：带 verdict 的证据化链路
- `triage_queue.json`：高可疑项队列（供 BinAgent / 人工 / 可选 LLM 深挖）

---

## 3. 架构总览（Pipeline + Artifacts）

### 3.1 逻辑模块视图
```text
+---------------------------------------------------------------+
| Stage 1/2/2.5: Loader + MAI + Interprocedural                |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| Stage 3/4: Source/Sink Miners                                 |
| - Sources: MMIO_READ / ISR_* / DMA_BACKED_BUFFER             |
| - Sinks: COPY / MEMSET / STORE / LOOP_WRITE / FUNC_PTR / FMT |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| Stage 5/6/7: Evidence Pack -> Proposal -> Verifier           |
| Output: verified labels                                      |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M8.5/M8.6: ChannelGraph + Object Boundary Refinement         |
| Output: channel_graph.json / refined_objects.json            |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M9/M9.1/M9.2: Sink Roots -> Tunnel Linker -> Derive/Check    |
| Output: sink_roots.json / chains.json / chain_eval.json      |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M9.3: Suspicious Queue Export                                |
| Output: low_conf_sinks.json / triage_queue.json              |
+---------------------------------------------------------------+
```

### 3.2 产物流转
```text
MAI
 |- source_candidates.json
 |- sink_candidates.json
 `- verified_labels.json
      |- channel_graph.json       (M8.5)
      |- refined_objects.json     (M8.6)
      |- sink_roots.json          (M9)
      |- chains.json              (M9.1, primary output)
      |- chain_eval.json          (M9.2 summary)
      |- low_conf_sinks.json      (M9.3 input-side snapshot)
      `- triage_queue.json        (M9.3 top-K queue)
```

---

## 4. 异步上下文通信与 ChannelGraph（定义与规范）

### 4.1 术语与边界

#### 4.1.1 MAI
`MAI = MemoryAccessIndex`，来自 Stage 2：
- 单条访问字段：`address/kind(load|store)/target_addr/base_provenance/function/in_isr`。
- 子集：`mmio_accesses`。
- 缓存：`decompiled_cache`（函数级反编译文本）。

#### 4.1.2 `src_context` / `dst_context`（PATCHED）
这两个字段表示**执行上下文边界**，不是 caller/callee。

区分如下：
- **CPU 上下文**（函数在 CPU 上执行）：
  - `ISR`：中断处理上下文
  - `TASK`：RTOS 任务/线程入口上下文
  - `MAIN`：reset/main/super-loop 上下文
  - `UNKNOWN`：无法确定的 CPU 上下文
- **合成生产者上下文**（不是 CPU 函数）：
  - `DMA`：对象由 DMA 引擎写入，依据 DMA 控制器配置 + buffer 绑定识别。

示例：
- ISR 写 `g_rx_buf`，MAIN 读 `g_rx_buf` -> `ISR -> MAIN`。
- DMA 写 `dma_rx_buf`，TASK 读该对象 -> `DMA -> TASK`。

重要：`DMA` 不能由函数名启发式硬判，必须来自**DMA 配置证据**与 buffer 绑定。

#### 4.1.3 约束应该放在哪里（PATCHED）
约束分两类：
- **通道使能约束**：放在 `ChannelEdge.constraints`。
  - 示例：ring non-empty（`tail!=head`）、ready flag（`rx_ready==1`）、DMA done flag。
- **sink 安全约束**：放在链路 `check_facts`。
  - 示例：`len<=MAX` 是否支配 sink；是否存在 clamp。

两类都必须建模，但层级不同。

#### 4.1.4 Producer / Consumer
- Producer：写入/赋值某对象的上下文。
- Consumer：读取该对象并用于数据流/控制流的上下文。

即使没有直接 callgraph 链接，也可定义边。

#### 4.1.5 Sink root
sink root 是需要追踪的风险承载表达式。
- COPY_SINK 常见 root：`len`（以及 `dst` / index）。
- FUNC_PTR_SINK 常见 root：dispatch index 或计算得到的函数指针。

root 是“值中心”，object 是“内存中心”；当 root 回溯映射到对象地址范围时，两者连通。

#### 4.1.6 `derive_facts` / `check_facts`
- `derive_facts`：危险参数如何由输入/共享对象导出。
- `check_facts`：sink 前 guard 是 `effective/weak/absent/unknown`。

#### 4.1.7 Chain verdict
- `CONFIRMED`：source 已到达 + root 可控 + 关键检查缺失/薄弱。
- `SUSPICIOUS`：sink 信号强，但链路不完整或存在不确定性。
- `SAFE_OR_LOW_RISK`：存在有效上界检查。
- `DROP`：证据矛盾或证据不足。

---

### 4.2 统一 ChannelGraph 契约

#### 4.2.1 ObjectNode schema（PATCHED：地址级证据）
所有对象类型使用同一主 schema，通过可选 `type_facts` 做类型差异化。

```json
{
  "object_id": "obj_rx_buf_20000000_2000007f",
  "region_kind": "SRAM_CLUSTER",
  "addr_range": ["0x20000000", "0x2000007f"],

  "producer_contexts": ["ISR"],
  "consumer_contexts": ["MAIN"],

  "writer_sites": [
    {
      "context": "ISR",
      "fn": "USART1_IRQHandler",
      "fn_addr": "0x08001234",
      "site_addr": "0x08001288",
      "access_kind": "store",
      "target_addr": "0x20000010"
    }
  ],
  "reader_sites": [
    {
      "context": "MAIN",
      "fn": "process_packet",
      "fn_addr": "0x08002000",
      "site_addr": "0x08002044",
      "access_kind": "load",
      "target_addr": "0x20000010"
    },
    {
      "context": "MAIN",
      "fn": "process_packet",
      "fn_addr": "0x08002000",
      "site_addr": "0x08002010",
      "access_kind": "guard",
      "expr": "g_rx_tail != g_rx_head"
    }
  ],

  "writers": ["USART1_IRQHandler"],
  "readers": ["process_packet"],

  "evidence_refs": ["E_ISR_STORE_1", "E_MAIN_LOAD_3"],
  "confidence": 0.82,

  "type_facts": {
    "kind_hint": "payload",
    "index_vars": ["g_rx_head", "g_rx_tail"],
    "is_ring_like": true
  },

  "notes": "ring payload"
}
```

说明：
- `writer_sites/reader_sites` 让产物在 stripped/symbol 丢失情况下仍稳定。
- `writers/readers` 为可选便捷字段。

#### 4.2.2 ChannelEdge schema（PATCHED：constraints）
```json
{
  "src_context": "ISR",
  "object_id": "obj_rx_buf_20000000_2000007f",
  "dst_context": "MAIN",

  "edge_kind": "DATA",

  "constraints": [
    {
      "kind": "ring_guard",
      "vars": ["g_rx_tail", "g_rx_head"],
      "expr": "g_rx_tail != g_rx_head",
      "site": {"fn": "process_packet", "site_addr": "0x08002010"},
      "strength": "likely"
    }
  ],

  "evidence_refs": ["E_ISR_STORE_1", "E_LOOP_COND_2"],
  "score": 0.79
}
```

---

### 4.3 M8.5 ChannelGraph Builder（PATCHED）
- 目标文件：`sourceagent/pipeline/channel_graph.py`
- 输入：`MAI + verified labels + MemoryMap`
- 输出：`channel_graph.json`

接口：
```python
def build_channel_graph(mai, verified_labels, memory_map, *, top_k=3) -> dict:
    ...
```

核心逻辑（PATCHED）：
1. 从 MAI 提取候选对象：
   - SRAM 聚类对象（payload/flag/index 候选）
   - DMA-backed 对象（来自已验证 `DMA_BACKED_BUFFER` 绑定）
2. 构建 writer/reader/context 集合及 `writer_sites/reader_sites`。
3. **保留全部 object node**（保证召回与 app anchor），但：
   - 只输出**跨上下文边**（ISR<->MAIN/TASK）和 **DMA->CPU 边**。
4. 收集边的 constraints 与 evidence refs。
5. producer 冲突时保留 top-K，而不是强制单解释。

失败模式：
- 没有跨上下文边 -> 只输出 `object_nodes`（合法）。
- 上下文不确定 -> 标为 `UNKNOWN` 并降分。

---

### 4.4 M8.6 Object Boundary Refiner（澄清为特征驱动 MVP）
- 目标文件：`sourceagent/pipeline/object_refine.py`
- 输入：`raw_objects + access_traces`
- 输出：`refined_objects.json`

接口：
```python
def refine_object_boundaries(raw_objects, access_traces) -> list[dict]:
    ...
```

拆分规则（特征驱动 MVP）：
1. **Payload-like**：
   - 访问偏移种类多（>= 16），或循环中存在 indexed store/load
2. **Flag-like**：
   - 标量（1/2/4 字节），频繁用于 `if/while` guard
3. **Index-like**：
   - 存在单调更新（`++/--/+=`）、取模、与另一索引比较（`head!=tail`）

---

### 4.5 已有对象时为何还需要 M8.6
- M8.5 输出的是粗粒度对象（召回优先）。
- M8.6 负责细化/拆分/合并（精度与可解释性优先）。

细化前（粗粒度）：
```json
{
  "object_id": "obj_cluster_20000000_200000ff",
  "members": ["g_rx_buf", "g_rx_head", "g_rx_tail", "g_mode_flag"],
  "region_kind": "SRAM_CLUSTER"
}
```

细化后：
```json
[
  {"object_id":"obj_rx_payload","members":["g_rx_buf"],"region_kind":"SRAM_CLUSTER"},
  {"object_id":"obj_rx_ctrl","members":["g_rx_head","g_rx_tail"],"region_kind":"FLAG"},
  {"object_id":"obj_mode_flag","members":["g_mode_flag"],"region_kind":"FLAG"}
]
```

没有 M8.6 时，DATA/CONTROL 边会混杂，root-to-object 映射噪声大，tunnel jump 容易误跳。

---

## 5. Sink Roots、Linker 与链路产物

### 5.0 模块 DAG
```text
M8.5 ChannelGraph Builder
  -> M8.6 Object Boundary Refiner
  -> M9 Sink Root Extractor
  -> M9.1 Tunnel-Aware Backward Linker
  -> M9.2 Derive+Check Summarizer
  -> M9.3 Suspicious Queue + Chain Verdict Export
```

### 5.1 M9 Sink Root Extractor（PATCHED 优先级）
- 目标文件：`sourceagent/pipeline/linker/sink_roots.py`
- 输入：`verified sinks + sink miner facts + MAI (p-code call arguments) + decompiled cache (fallback)`
- 输出：`sink_roots.json`

接口：
```python
def extract_sink_roots(verified_sinks, *, sink_facts, mai, decompiled_cache) -> list[dict]:
    ...
```

优先级（PATCHED）：
1. **优先使用 sink miner facts**（已提取参数、callsite、角色）。
2. **其次用 p-code 调用参数恢复**（适配 wrapper/thunk）。
3. **反编译正则仅兜底**，歧义时标记 `status=partial`。

root 映射：
- COPY_SINK：主 root 为 `len`，次 root 为 `dst`。
- LOOP_WRITE_SINK：循环边界/index。
- MEMSET_SINK：length。
- FUNC_PTR_SINK：dispatch index / target pointer。
- FORMAT_STRING_SINK：format 参数。

示例输出：
```json
[
  {
    "sink_id": "SINK_t0_copy_1",
    "sink_label": "COPY_SINK",
    "sink_function": "process_packet",
    "sink_site": "0x08000120",
    "roots": [
      {"role": "primary", "expr": "count", "kind": "length"},
      {"role": "secondary", "expr": "out", "kind": "dst_ptr"}
    ],
    "evidence_refs": ["E_COPY_CALL", "E_ARG_PARSE"],
    "confidence": 0.78,
    "status": "ok"
  }
]
```

---

### 5.2 M9.1 Tunnel-Aware Backward Linker（PATCHED best-first + caching）
- 目标文件：`sourceagent/pipeline/linker/tunnel_linker.py`
- 输入：`sink_roots.json + channel_graph.json + MAI + sources`
- 输出：`chains.json`

接口：
```python
def link_chains(
    sink_roots, channel_graph, mai, sources,
    *, budget=200, K=2, max_depth=2, max_chains_per_sink=4
) -> list[dict]:
    ...
```

定义：tunnel jump 不是函数调用跳转，而是 root 回溯命中 object node 后，沿对象边做上下文切换。

实现策略（PATCHED）：
- **Best-first 搜索**：按部分评分优先扩展。
- **状态去重**：键为 `(ctx, normalized_expr, object_id, depth)`。
- **切片缓存**：键为 `(fn_addr, normalized_expr)`。

伪代码：
```python
pq = PriorityQueue()
pq.push(initial_state_from(sink_root))
seen = set()

while pq and emitted < max_chains_per_sink:
    st = pq.pop_best()
    if st.key in seen:
        continue
    seen.add(st.key)

    slice_res = cached_backward_slice(st.ctx, st.expr, budget=budget)

    if slice_res.hit_source():
        emit_chain(st, slice_res, status="ok")
        continue

    obj_hits = slice_res.hit_objects()
    if not obj_hits:
        emit_partial_chain(st, slice_res, failure_code="NO_SOURCE_REACH")
        continue

    for obj in obj_hits:
        producers = topK_producers(channel_graph, obj.object_id, K=K)
        for prod in producers:
            st2 = tunnel_jump(st, obj, prod)
            if st2.depth <= max_depth:
                pq.push(st2)
```

---

### 5.3 M9.2 Derive + Check Summarizer（PATCHED 检查分类）
- 目标文件：`sourceagent/pipeline/linker/derive_check.py`
- 输入：切片路径（SSA 节点 / p-code / 反编译行）
- 输出：`derive_facts` 与 `check_facts`

derive 示例：
- `len = buf[k]`
- `len = (buf[k]<<8)|buf[k+1]`
- `len = *(uint16_t*)(buf+off)`
- `idx = cmd_byte`（dispatch index）

check 强度分类（PATCHED）：
- `effective`：
  - 存在支配 sink 的明确上界，如 `if (len > C) return;`
  - 存在 clamp，如 `len = MIN(len, C)`
- `weak`：
  - 不是上界（如 `len > 0`）
  - 检查字段与 sink 使用字段不一致
  - 检查不支配 sink
- `absent`：
  - 未发现上界/clamp
- `unknown`：
  - 支配关系不清晰；反编译信息不足

---

### 5.4 M9.3 Suspicious Triage Queue
- 目标文件：`sourceagent/pipeline/triage_queue.py`
- 输入：低置信 sink、未闭环链、矛盾 check
- 输出：`triage_queue.json`（top-K）

低置信来源：
1. Miner 置信度 `< T_low`。
2. Verifier 状态为 `PARTIAL/UNKNOWN`。
3. Root 提取失败或 root-object 映射失败。
4. 命中 sink 但未到达 source。

两类文件都持久化：
- `low_conf_sinks.json`（完整快照）
- `triage_queue.json`（排序后的 top-K）

---

## 6. Sink-First 隧道检测（算法、复杂度、启发式）

### 6.1 组成
- `sink_roots.json` -> root 选择
- `channel_graph.json` -> tunnel jump
- `derive/check` -> 语义判定输入
- `chains.json` -> linker 最终输出

### 6.2 为什么 sink-first、为什么启发式
- `source x sink` 穷举在规模上不可行。
- stripped/优化会导致精确静态恢复不完备。
- sink-first 有界搜索能在可控耗时下最大化漏洞产出。

### 6.3 复杂度回顾
- 无 sink-first（`source x sink`）：`O(|Src| * |Sink| * C_slice)`
- sink-first + 有界搜索：`O(|Sink| * R * B * K^d)`
  - `R`：每个 sink 的 roots 数（通常 1-2）
  - `B`：切片预算
  - `K`：top-K producer
  - `d`：tunnel 深度

### 6.4 `chains.json` 输出示例（PATCHED）

#### 示例 1：单上下文 MMIO 链路（CVE 风格，不需要 tunnel）
```json
{
  "chain_id": "chain_cve2020_10065_evt_like_1",
  "sink": {
    "sink_id": "SINK_evt_add_mem",
    "label": "COPY_SINK",
    "function": "bt_spi_rx_thread",
    "root_expr": "payload_len"
  },
  "steps": [
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"SPI1_DR", "evidence_refs":["E_SRC_SPI_DR"]},
    {"kind":"DERIVE", "expr":"payload_len = rxmsg[2] + 2", "site":"bt_spi_rx_thread", "evidence_refs":["E_DERIVE_LEN"]},
    {"kind":"SINK", "label":"COPY_SINK", "callee":"net_buf_add_mem", "arg_role":"len", "site":"0x0800abcd", "evidence_refs":["E_SINK_CALL"]}
  ],
  "derive_facts": [
    {"expr":"payload_len = rxmsg[2] + 2", "kind":"len_from_header", "site":"bt_spi_rx_thread"}
  ],
  "checks": [
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ],
  "has_app_anchor": true,
  "verdict": "CONFIRMED",
  "score": 0.91,
  "status": "ok",
  "evidence_refs": ["E_SRC_SPI_DR","E_DERIVE_LEN","E_SINK_CALL"]
}
```

#### 示例 2：真实跨上下文隧道链（ISR -> MAIN）
```json
{
  "chain_id": "chain_t0_isr_buf_copy_1",
  "sink": {
    "sink_id": "SINK_memcpy_1",
    "label": "COPY_SINK",
    "function": "process_packet",
    "root_expr": "count"
  },
  "steps": [
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"USART1_DR", "evidence_refs":["E_SRC_UART_DR"]},
    {"kind":"CHANNEL", "edge":"ISR->MAIN", "object_id":"obj_rx_buf_20000000_2000007f", "evidence_refs":["E_ISR_STORE_1","E_MAIN_LOAD_3"]},
    {"kind":"DERIVE", "expr":"count++ while (tail!=head)", "site":"process_packet", "evidence_refs":["E_DERIVE_COUNT"]},
    {"kind":"SINK", "label":"COPY_SINK", "callee":"memcpy", "arg_role":"len", "site":"0x08001200", "evidence_refs":["E_SINK_MEMCPY"]}
  ],
  "checks": [
    {"expr":"count < max_len", "strength":"unknown", "site":"process_packet"}
  ],
  "has_app_anchor": true,
  "verdict": "SUSPICIOUS",
  "score": 0.63,
  "status": "partial",
  "failure_code": "CHECK_UNCERTAIN",
  "evidence_refs": ["E_SRC_UART_DR","E_ISR_STORE_1","E_MAIN_LOAD_3","E_SINK_MEMCPY"]
}
```

---

## 7. SourceAgent 与 BinAgent 分工
- SourceAgent：确定性规则实现、结构化事实、graph/chain preflight。
- BinAgent：更深层验证（动态/混合）、执行侧优先级排序。

计划：
1. 近期：SourceAgent 先交付 `channel_graph + chains` 基线。
2. 中期：两仓库共享 schema 与评测脚本。
3. 远期：BinAgent 直接消费 SourceAgent chain artifacts 做深度确认。

---

## 8. 路线图与评测

### 8.1 路线图（P0-P3）
- P0：ChannelGraph（SRAM + DMA）+ best-first linker 基线 + 两条示例链。
- P1：对象边界细化 + producer 排序 + 稳定证据字段。
- P2：增强 derive/check + 链路级 GT 评测 + verdict 校准。
- P3：RTOS 队列恢复（先符号化）+ 与 BinAgent 的 schema 收敛。

### 8.2 评测指标（从 label 到 chain）
1. 标签级：TP/FP/FN。
2. 链路级：
   - 是否到达 source？
   - 隧道是否正确（object + producer site 匹配）
   - derive 是否正确（len/index 提取是否正确）
   - check 强度是否一致
   - verdict 是否稳定（同一固件构建下）

### 8.3 最小链路级 GT 格式（新增）
```json
{
  "binary": "cve_2020_10065_hci_spi.elf",
  "gt_chains": [
    {
      "sink_site": "0x0800abcd",
      "sink_label": "COPY_SINK",
      "root_role": "len",
      "expected_source": {"label":"MMIO_READ", "site":"SPI1_DR"},
      "expected_object_hint": {"addr_range":["0x20001f00","0x20001fff"]},
      "expected_check_strength": "absent"
    }
  ]
}
```

---

## 9. 带目标链路的案例

### 9.1 Case A：`t0_isr_filled_buffer.c`
```c
void USART1_IRQHandler(void) {
    uint8_t b = (uint8_t)(USART1_DR & 0xFFu);
    g_rx_buf[g_rx_head] = b;
}

void process_packet(char *out, unsigned int max_len) {
    while (g_rx_tail != g_rx_head) {
        tmp[count++] = g_rx_buf[g_rx_tail];
    }
    memcpy(out, tmp, count);
}
```
目标链路：
`MMIO_READ(USART1_DR) -> object(g_rx_buf) -> derive(count) -> check(count<max_len?) -> COPY_SINK(memcpy)`

### 9.2 Case B：`t0_dma_backed_buffer.c`
```c
DMA1_CH5_CPAR  = USART1_DR_ADDR;
DMA1_CH5_CMAR  = (uint32_t)g_dma_rx_buf;
DMA1_CH5_CNDTR = sizeof(g_dma_rx_buf);

if (g_dma_rx_buf[0] != 0) {
    parse_frame(g_dma_rx_buf, 256);
}
```
关键要求：
- 将 `CMAR` 绑定到 `g_dma_rx_buf`。
- consumer 必须读取同一对象/地址范围。

### 9.3 Case C：`cve_2020_10065_hci_spi.c`（完整标注）
source 点：
```c
while (!(SPI1_SR & 0x01u)) {}
dst[i] = (uint8_t)(SPI1_DR & 0xFFu);   // MMIO_READ(SPI1_DR)
```

sink 触发点：
```c
net_buf_add_mem(buf, &rxmsg[1], rxmsg[EVT_HEADER_SIZE] + 2);   // EVT
net_buf_add_mem(buf, &rxmsg[5], sys_le16_to_cpu(acl_hdr.len)); // ACL
```

helper 内部语义 sink：
```c
memcpy(dst, mem, len); // inside net_buf_add_mem
```

要求输出的链路：
- Chain-1 EVT root：`rxmsg[2]+2`，缺少有效上界。
- Chain-2 ACL root：`acl_hdr.len`，缺少 tailroom 上界。

为什么这是 CVE-2020-10065：
1. 长度字段来自 MMIO 输入流，可被输入驱动。
2. 长度值流入 copy size。
3. copy 前缺失有效上界检查。

---

## 10. 冻结实现规范（编码前）(PATCHED)

### 10.1 JSON 产物最终字段契约

#### 10.1.1 `channel_graph.json`（PATCHED）
顶层必填：`schema_version`, `binary`, `object_nodes`, `channel_edges`。
顶层建议：`binary_sha256`, `build_meta`。

`object_nodes[]` 必填字段：
- `object_id`（string）, `region_kind`（enum）, `addr_range`（[hex,hex]）
- `producer_contexts`（enum[]）, `consumer_contexts`（enum[]）
- `writer_sites`（object[]）, `reader_sites`（object[]）
- `evidence_refs`（string[]）, `confidence`（float）
可选：`writers/readers`（名称）, `type_facts`, `notes`

`channel_edges[]` 必填字段：
- `src_context`, `object_id`, `dst_context`, `edge_kind`
- `constraints`（object[]）, `evidence_refs`（string[]）, `score`（float）

#### 10.1.2 `refined_objects.json`
与 ObjectNode schema 保持一致，保留 `writer_sites/reader_sites`。

#### 10.1.3 `sink_roots.json`
必填：`schema_version`, `binary`, `sink_roots`。
每个 root 条目必填：`sink_id`, `sink_label`, `sink_function`, `sink_site`, `roots`, `evidence_refs`, `confidence`, `status`。

#### 10.1.4 `chains.json`（PATCHED）
每条链路必填：
- `chain_id`, `sink`, `steps`, `checks`, `derive_facts`
- `verdict`, `score`, `status`, `evidence_refs`
- `has_app_anchor`（bool）
可选：`failure_code`, `failure_detail`, `fallback_action`

#### 10.1.5 `chain_eval.json`
必填：`schema_version`, `binary`, `stats`, `by_verdict`。

#### 10.1.6 `low_conf_sinks.json`
必填：`schema_version`, `binary`, `items`。

---

### 10.2 Verdict 判定表（PATCHED：`has_app_anchor`）
输入字段：
- `source_reached`（bool）
- `root_controllable`（bool）
- `check_strength`（`effective/weak/absent/unknown`）
- `chain_complete`（bool）
- `has_contradiction`（bool）
- `has_app_anchor`（bool）
- `chain_score`（0..1）

`has_app_anchor=true` 定义（满足任一）：
- MMIO 寄存器证据（地址落在外设区间）
- DMA 配置证据 + 目标对象绑定
- SRAM 对象证据（含 writer/reader site）
- 与链路绑定的 verified source label

规则：
- `CONFIRMED`：
  - `source_reached=true`
  - `root_controllable=true`
  - `check_strength in {weak, absent}`
  - `chain_complete=true`
  - `has_contradiction=false`
  - `has_app_anchor=true`
  - `chain_score >= 0.80`
- `SUSPICIOUS`：
  - 已有 sink/root 证据，但未满足 CONFIRMED 全条件
  - 建议 `chain_score >= 0.35`
- `SAFE_OR_LOW_RISK`：
  - `check_strength=effective` 且链路可解释
- `DROP`：
  - 存在矛盾，或证据很弱（`chain_score < 0.35`），或
  - 两端都在库内部且 `has_app_anchor=false`

策略：
- 对 `CONFIRMED` 从严。
- 对 `SUSPICIOUS` 适当放宽。

---

### 10.3 全局默认参数（速度优先）
- `T_low = 0.45`
- `top_k = 3`
- `B = 160`（slice budget）
- `K = 2`（tunnel producer top-K）
- `max_depth d = 2`
- `max_chains_per_sink = 4`
- `max_chains_per_binary = 200`

### 10.4 Context 分类规则（PATCHED）
CPU 函数上下文（函数级）：
1. `ISR`：来自 MAI 的 `in_isr=true`。
2. `TASK`：存在 RTOS task-entry 证据（create callsites）或名称启发式（尽力而为）。
3. `MAIN`：reset/main/super-loop。
4. `UNKNOWN`：无法确定。

DMA 上下文（合成生产者，非函数）：
- 仅在满足以下条件时设置 `src_context="DMA"`：
  - 存在已验证 `DMA_BACKED_BUFFER`，且
  - DMA 配置 site 可绑定 `dst_object`，且
  - consumer site 从该对象范围读取。

不确定时不得强行分类。

### 10.5 统一失败回退格式（PATCHED）
`sink_roots/chains` 通用字段：
- `status`（`ok/partial/failed`）
- `failure_code`

建议 failure code：
- `ROOT_UNRESOLVED`
- `OBJECT_MAP_MISS`
- `BUDGET_EXCEEDED`
- `NO_SOURCE_REACH`
- `CONTRADICTION`
- `LIB_BARRIER`
- `CHECK_UNCERTAIN`

### 10.6 当 backward tracing 进入库内部时如何处理（PATCHED）
策略：
1. `summary mode`：对已知 API（`memcpy/memset/strcpy/...`）用语义摘要。
2. `barrier mode`：未知库内部设置严格步数上限；超限则 `LIB_BARRIER`。
3. `anchor policy`：
   - sink 在库内但 `has_app_anchor=true`，保留为 `SUSPICIOUS`。
   - 两端都在库内且无 anchor，则 `DROP`。

原因：
- 深追库内部会显著增加耗时与噪声。
- anchor 可以保留与应用逻辑相关性。

---

## 参考与来源文档
内部文档：
- [I1] RQ1 Detailed Planning: Semantic Recovery v1.3
- [I2] SourceAgent `update_0305.md`
- [I3] `eval_suite_unstripped_elf_report_en.md`

外部文献（非穷举）：
- [R1] Operation Mango, USENIX Security 2024
- [R2] KARONTE, IEEE S&P 2020
- [R3] Sharing More and Checking Less (SaTC), USENIX Security 2021
- [R4] P2IM, USENIX Security 2020
- [R5] Fuzzware, USENIX Security 2022
- [R6] HALucinator, USENIX Security 2020
- [R7] FirmXRay, CCS 2020
- [R8] Heapster, IEEE S&P 2022

占位 / TODO（论文定稿前需核验）：
- LATTE (TODO)
- IRIS (TODO)
- AdaTaint (TODO)

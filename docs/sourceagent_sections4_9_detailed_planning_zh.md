# 详细规划备忘录
## 异步上下文通信、ChannelGraph 恢复与 Sink→Source 隧道检测（代码级实施版）

## 执行摘要
当前 SourceAgent 在 RQ1 标签层已经可用：source/sink 标签识别能力基本建立。下一阶段的核心不是再加标签，而是把标签连接成链（chain），并能解释“为什么这个 sink 真的由外部输入驱动”。

本版文档聚焦以下工程目标：
- 定义统一的 `ChannelGraph` 与 `Chain` JSON 契约。
- 给出模块级输入/输出、前后依赖、失败模式。
- 用 microbench 与 CVE-2020-10065 说明真实链路恢复过程。

---

## 3. 总览结构图（Pipeline + Artifact）

### 3.1 模块总览（逻辑层）
```text
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 1/2/2.5: Loader + MAI + Interprocedural                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 3/4: Source/Sink Miners                                      │
│  - Sources: MMIO_READ / ISR_* / DMA_BACKED_BUFFER                  │
│  - Sinks: COPY / MEMSET / STORE / LOOP_WRITE / FUNC_PTR / FORMAT   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 5/6/7: Evidence Pack -> Proposal -> Verifier                 │
│  输出: verified labels                                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ M8.5/M8.6: ChannelGraph + Object Boundary Refine                   │
│  输出: channel_graph.json / refined_objects.json                    │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ M9/M9.1/M9.2: Sink Root -> Tunnel Linker -> Derive/Check           │
│  输出: sink_roots.json / chains.json / chain_eval.json              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ M9.3: Suspicious Queue Export                                      │
│  输出: low_conf_sinks.json / triage_queue.json                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 产物流（文件层）
```text
MAI
 ├─> source_candidates.json
 ├─> sink_candidates.json
 └─> verified_labels.json
         │
         ├─> channel_graph.json          (M8.5)
         ├─> refined_objects.json        (M8.6)
         ├─> sink_roots.json             (M9)
         ├─> chains.json                 (M9.1, 主输出)
         ├─> chain_eval.json             (M9.2 汇总)
         ├─> low_conf_sinks.json         (M9.3 输入侧保存)
         └─> triage_queue.json           (M9.3 top-K 队列)
```

---

## 4. 异步上下文通信与 ChannelGraph 恢复（定义与规格）

### 4.1 术语与边界

#### 4.1.1 MAI 是什么
`MAI = MemoryAccessIndex`，是 Stage 2 的结构化访问索引：
- 每条访问：`address/kind(load|store)/target_addr/base_provenance/function/in_isr`。
- 子集：`mmio_accesses`。
- 缓存：`decompiled_cache`（函数级反编译文本）。

#### 4.1.2 src_context / dst_context 是什么
是“上下文边界”两端，不是 callgraph 的 caller/callee：
- `src_context`: 生产者上下文（`ISR/TASK/MAIN/DMA/UNKNOWN`）。
- `dst_context`: 消费者上下文。

示例：
- ISR 写 `g_rx_buf`，MAIN 读 `g_rx_buf` => `ISR -> MAIN`。
- DMA 写 `dma_rx_buf`，TASK 读 `dma_rx_buf` => `DMA -> TASK`。

#### 4.1.3 constraint 放在哪里
约束分两类：
- 通道使能约束：放 `ChannelEdge.constraints`（如 `tail!=head`、`dma_done!=0`）。
- sink 安全约束：放 chain 的 `check_facts`（如 `len<=MAX` 是否支配 sink）。

结论：都要建模，但不放在同一层。

#### 4.1.4 producer / consumer
- `producer`: 对对象执行“写入或赋值”的上下文（ISR、DMA、TASK、MAIN）。
- `consumer`: 对对象执行“读取并参与后续计算/控制”的上下文。

这两个概念是构造 edge 的核心，不依赖函数调用关系。

#### 4.1.5 sink root
`sink root` 是要追踪的危险参数表达式，不等于 sink 本身。
- COPY_SINK 常见 root: `len`。
- FUNC_PTR_SINK 常见 root: `dispatch index`。

root 是 value-centric，object 是 memory-centric，两者通过“root 回溯到内存对象”建立连接。

#### 4.1.6 derive_facts / check_facts
- `derive_facts`: 参数如何从输入字节或共享对象派生（例如位拼接、长度字段提取）。
- `check_facts`: sink 前的约束强弱（`effective/weak/absent`）。

它们是 chain verdict 的证据层，不是 miner 的初始标签层。

#### 4.1.7 chain verdict
- `CONFIRMED`: source 可达 + root 可控 + 关键检查缺失/弱。
- `SUSPICIOUS`: sink 强但链未闭环或证据不足。
- `SAFE_OR_LOW_RISK`: 存在有效上界或关键约束可证明。
- `DROP`: 证据冲突或路径不可成立。

### 4.2 ChannelGraph 统一数据契约

#### 4.2.1 ObjectNode：是否同一 JSON 规格
是。建议**所有对象使用同一主 schema**，按类型添加可选 `type_facts`。

统一 schema（推荐）：
```json
{
  "object_id": "obj_rx_buf_20000000_2000007f",
  "region_kind": "SRAM_CLUSTER",
  "addr_range": ["0x20000000", "0x2000007f"],
  "writers": ["USART1_IRQHandler"],
  "readers": ["process_packet"],
  "producer_contexts": ["ISR"],
  "consumer_contexts": ["MAIN"],
  "evidence_refs": ["E_ISR_STORE_1", "E_MAIN_LOAD_3"],
  "confidence": 0.82,
  "type_facts": {
    "index_vars": ["g_rx_head", "g_rx_tail"],
    "is_ring_like": true
  },
  "notes": "ring payload"
}
```

`region_kind` 决定 `type_facts` 的内容：
- `SRAM_CLUSTER`: `index_vars`, `stride`, `array_like`。
- `DMA_BUFFER`: `cmar_site`, `cndtr_expr`, `dma_channel`。
- `FLAG`: `const_writes`, `condition_sites`。
- `QUEUE_HANDLE`: `enqueue_sites`, `dequeue_sites`。

#### 4.2.2 ChannelEdge 统一 schema
```json
{
  "src_context": "ISR",
  "object_id": "obj_rx_buf_20000000_2000007f",
  "dst_context": "MAIN",
  "edge_kind": "DATA",
  "constraints": [
    {"kind": "ring_guard", "expr": "g_rx_tail != g_rx_head", "site": "process_packet"}
  ],
  "evidence_refs": ["E_ISR_STORE_1", "E_LOOP_COND_2"],
  "score": 0.79
}
```

### 4.3 M8.5 ChannelGraph Builder（新）
- 目标文件：`sourceagent/pipeline/channel_graph.py`
- 输入：`MAI + verified source labels + MemoryMap`
- 输出：`channel_graph.json`

建议接口：
```python
def build_channel_graph(mai, verified_labels, memory_map, *, top_k=3) -> dict:
    ...
```

核心逻辑：
1. 从 MAI 提取对象候选（SRAM/DMA/flag）。
2. 组装 `writers/readers` 与上下文集合。
3. 仅保留跨上下文对象。
4. 提取 edge constraints 与 evidence。
5. 冲突对象保留 top-K，防止过拟合到单一解释。

失败模式：
- 无跨上下文对象 => 输出空图（合法）。
- 上下文不确定 => 标为 `UNKNOWN` 并降低 score。

#### 4.3.1 示例输出（完整）
```json
{
  "binary": "t0_isr_filled_buffer.elf",
  "object_nodes": [
    {
      "object_id": "obj_rx_payload",
      "region_kind": "SRAM_CLUSTER",
      "addr_range": ["0x20000000", "0x2000007f"],
      "writers": ["USART1_IRQHandler"],
      "readers": ["process_packet"],
      "producer_contexts": ["ISR"],
      "consumer_contexts": ["MAIN"],
      "confidence": 0.86,
      "evidence_refs": ["E_ISR_BUF_WRITE", "E_MAIN_BUF_READ"],
      "type_facts": {"array_like": true, "index_vars": ["g_rx_head", "g_rx_tail"]}
    },
    {
      "object_id": "obj_rx_gate",
      "region_kind": "FLAG",
      "addr_range": ["0x20000080", "0x20000087"],
      "writers": ["USART1_IRQHandler"],
      "readers": ["process_packet"],
      "producer_contexts": ["ISR"],
      "consumer_contexts": ["MAIN"],
      "confidence": 0.71,
      "evidence_refs": ["E_ISR_HEAD_WRITE", "E_MAIN_LOOP_COND"],
      "type_facts": {"condition_sites": ["while(g_rx_tail != g_rx_head)"]}
    }
  ],
  "channel_edges": [
    {
      "src_context": "ISR",
      "object_id": "obj_rx_payload",
      "dst_context": "MAIN",
      "edge_kind": "DATA",
      "constraints": [],
      "score": 0.84,
      "evidence_refs": ["E_ISR_BUF_WRITE", "E_MAIN_BUF_READ"]
    },
    {
      "src_context": "ISR",
      "object_id": "obj_rx_gate",
      "dst_context": "MAIN",
      "edge_kind": "CONTROL",
      "constraints": [{"kind": "loop_gate", "expr": "g_rx_tail != g_rx_head", "site": "process_packet"}],
      "score": 0.73,
      "evidence_refs": ["E_ISR_HEAD_WRITE", "E_MAIN_LOOP_COND"]
    }
  ]
}
```

### 4.4 M8.6 Object Boundary Refiner（新）
- 目标文件：`sourceagent/pipeline/object_refine.py`
- 输入：`raw_objects + access_traces`
- 输出：`refined_objects.json`

建议接口：
```python
def refine_object_boundaries(raw_objects, access_traces) -> list[dict]:
    ...
```

拆分规则：
1. 数组索引密集读写优先作为 payload 对象。
2. 标量且频繁参与 `if/while` 条件的对象标记为 flag/control。
3. head/tail/index 更新变量与 payload 分离。

示例输出：
```json
[
  {
    "object_id":"obj_rx_payload",
    "region_kind":"SRAM_CLUSTER",
    "addr_range":["0x20000000","0x2000007f"],
    "members":["g_rx_buf"],
    "type_facts":{"array_like":true}
  },
  {
    "object_id":"obj_rx_ctrl",
    "region_kind":"FLAG",
    "addr_range":["0x20000080","0x20000087"],
    "members":["g_rx_head","g_rx_tail"],
    "type_facts":{"condition_sites":["tail!=head"]}
  }
]
```

### 4.5 为什么已经有 object 还要单独做 M8.6
你问到“和前文 object 的关系是什么”，这里明确：

- `M8.5` 产出的 object 是**初始粗对象（raw_objects）**，主要靠地址聚类与基础读写统计，追求召回。
- `M8.6` 是**后处理细化**，对 raw_objects 做拆分/重命名/重打分，追求精度和可解释性。

它们不是两套模型，而是同一模型的两个阶段。

流程上：
```text
M8.5: raw object candidates
  -> M8.6: split/merge/refine object boundaries
  -> rebuild channel edges with refined object_id
```

before（M8.5 粗对象）：
```json
{
  "object_id": "obj_cluster_20000000_200000ff",
  "members": ["g_rx_buf", "g_rx_head", "g_rx_tail", "g_mode_flag"],
  "region_kind": "SRAM_CLUSTER"
}
```

after（M8.6 细化）：
```json
[
  {"object_id":"obj_rx_payload","members":["g_rx_buf"],"region_kind":"SRAM_CLUSTER"},
  {"object_id":"obj_rx_ctrl","members":["g_rx_head","g_rx_tail"],"region_kind":"FLAG"},
  {"object_id":"obj_mode_flag","members":["g_mode_flag"],"region_kind":"FLAG"}
]
```

如果没有 M8.6，常见问题是：
- DATA edge 与 CONTROL edge 混在一个对象上。
- root 到 object 的映射变脏，tunnel jump 容易跳错 producer。
- chain 可解释性明显下降。

---

## 5. Sink-root、Linker 与 chain 产物（模块契约与关系）

### 5.0 模块前后关系（DAG）
```text
M8.5 ChannelGraph Builder
          |
M8.6 Object Boundary Refiner
          |
M9 Sink Root Extractor
          |
M9.1 Tunnel-Aware Backward Linker
          |
M9.2 Derive+Check Summarizer
          |
M9.3 Suspicious Queue + Chain Verdict Export
```

### 5.1 M9 Sink Root Extractor（新）
- 目标文件：`sourceagent/pipeline/linker/sink_roots.py`
- 输入：`verified sink labels + decompiled code + sink facts`
- 输出：`sink_roots.json`

建议接口：
```python
def extract_sink_roots(verified_sinks, decompiled_cache) -> list[dict]:
    ...
```

root 定义：
- `COPY_SINK`: `len` 主根，`dst` 次根。
- `LOOP_WRITE_SINK`: loop bound / index。
- `MEMSET_SINK`: `len`。
- `FUNC_PTR_SINK`: dispatch index / target ptr。
- `FORMAT_STRING_SINK`: format arg。

#### 5.1.1 示例输出
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
    "confidence": 0.78
  },
  {
    "sink_id": "SINK_funcptr_1",
    "sink_label": "FUNC_PTR_SINK",
    "sink_function": "dispatch_command",
    "sink_site": "0x0800009a",
    "roots": [
      {"role": "primary", "expr": "cmd_id", "kind": "dispatch_index"}
    ],
    "evidence_refs": ["E_INDIRECT_CALL"],
    "confidence": 0.72
  }
]
```

#### 5.1.2 root 与 object 的关系
不是一对一、也不是同层实体：
- root 是“要追踪的值表达式”（value-centric）。
- object 是“跨上下文共享载体”（memory-centric）。

连接条件：当 root 回溯到内存读写表达式并能映射到某个 object addr_range 时，linker 才能 tunnel jump。

### 5.2 M9.1 Tunnel-Aware Backward Linker（新）
- 目标文件：`sourceagent/pipeline/linker/tunnel_linker.py`
- 输入：`sink_roots.json + channel_graph.json + MAI/decompiled_cache + source labels`
- 输出：`chains.json`

建议接口：
```python
def link_chains(sink_roots, channel_graph, mai, sources, *, budget=200) -> list[dict]:
    ...
```

要点：
- tunnel jump 不是 caller->callee 跳转。
- 是 root 追踪触达 object 后，从 `dst_context` 切换到 `src_context` 的 producer 继续追踪。

### 5.3 M9.2 Derive + Check Summarizer（新）
- 目标文件：`sourceagent/pipeline/linker/derive_check.py`
- 输入：切片路径（SSA 节点序列/表达式边）
- 输出：`derive_facts` 与 `check_facts`

你提到“这块太简单，不清楚做什么”，这里补充：

#### 5.3.1 它解决的问题
Linker 找到的是“路径”，但研究与评测需要的是“语义解释”：
- `derive_facts`: 危险参数如何从输入字节派生。
- `check_facts`: 在 sink 前是否有有效边界检查。

没有这一步，chain 只有图结构，没有可判断安全性的证据。

#### 5.3.2 输入输出更具体
输入（简化）：
```json
{
  "slice_nodes": [
    "payload_len = (rxmsg[2] | rxmsg[3]<<8)",
    "if (payload_len > 0)",
    "net_buf_add_mem(buf, rxmsg+5, payload_len)"
  ]
}
```

输出（简化）：
```json
{
  "derive_facts": [
    {"expr":"payload_len = rxmsg[2] | (rxmsg[3] << 8)", "kind":"len_from_header", "site":"bt_spi_rx_thread"}
  ],
  "check_facts": [
    {"expr":"payload_len > 0", "strength":"weak", "reason":"non-upper-bound", "site":"bt_spi_rx_thread"},
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ]
}
```

### 5.4 M9.3 Suspicious Triage Queue（新）
- 目标文件：`sourceagent/pipeline/triage_queue.py`
- 输入：低置信 sink、未闭环链、检查矛盾
- 输出：`triage_queue.json`（top-K）

你问到“低置信 sink 如何生成/保存”，这里明确：

#### 5.4.1 低置信来源（可直接从现有字段得到）
1. miner 候选低分：`SinkCandidate.confidence_score < T_low`。  
2. verifier 结果弱：`PARTIAL/UNKNOWN`。  
3. root 提取失败或 root->object 映射失败。  
4. chain 到 sink 但 source 不可达（开链未闭环）。

#### 5.4.2 建议保存文件
- `low_conf_sinks.json`：所有低置信 sink 候选（可回溯）。
- `triage_queue.json`：排序后的 top-K（供人工复核）。

示例：
```json
{
  "queue": [
    {
      "candidate_id": "SINK_uart_receive_1",
      "sink_label": "COPY_SINK",
      "reason_codes": ["LOW_CONFIDENCE", "NO_SOURCE_REACH"],
      "score": 0.81,
      "evidence_refs": ["E1", "E3"]
    }
  ]
}
```

---

## 6. Sink-first 隧道检测（算法、复杂度、启发式必要性）

### 6.1 与第 5 节模块如何配合
- 第 5 节产物是“中间结果层”。
- 第 6 节算法是“消费这些中间结果，生成最终 chain verdict 的执行层”。

对应关系：
- `M9 sink_roots.json` -> 算法 Step-1 根选择。
- `M8 channel_graph.json` -> 算法 Step-3 tunnel jump。
- `M9.2 derive/check` -> 算法 Step-5 语义判断。
- `M9.1 chains.json` -> 算法最终输出（第 6.4 示例就是 M9.1 产物格式）。

### 6.2 伪代码（工程实现视角）
```python
for sink in sink_roots:
    for root in sink.roots:
        path = backward_slice(root, budget=B)
        while path.hit_object_node():
            producers = topk_producers(path.object_id, K)
            path = tunnel_jump_and_continue(path, producers, budget=B)
        derive = summarize_derive(path)
        checks = summarize_checks(path, sink.site)
        verdict = score_and_decide(path, derive, checks)
        emit_chain(sink, root, path, derive, checks, verdict)
```

### 6.3 数学复杂度与为何要启发式

#### 6.3.1 不做 sink-first 的代价
若穷举 source×sink：
- 复杂度近似 `O(|Src| * |Sink| * C_slice)`。
- 当 `|Src|, |Sink|` 都是千级时不可接受。

#### 6.3.2 sink-first + budget 的复杂度
- 每个 sink 只追踪有限 root，复杂度约：
  `O(|Sink| * R * B * K^d)`
  - `R`: 每个 sink 的 root 数（通常 1~2）
  - `B`: 每次切片预算
  - `K`: tunnel jump 保留 producer top-K
  - `d`: tunnel 深度（通常很小）

通过 `R/B/K/d` 限制，可把问题从全笛卡尔积降为可控搜索。

#### 6.3.3 为什么仍需启发式
静态恢复在 stripped/优化后二进制里不完备：
- 指针别名不完备。
- 对象边界不精确。
- 调用点恢复不总稳定。

启发式的作用不是替代事实，而是**在事实不完备时做可控剪枝**：
- top-K producers
- budget 限制
- guard 强弱规则

### 6.4 M9.1 `chains.json` 典型输出（与第 5.2 对应）
下面示例即 M9.1 直接产物，不是额外附录：
```json
{
  "chain_id": "chain_cve2020_10065_evt_1",
  "sink": {
    "sink_id": "SINK_evt_add_mem",
    "label": "COPY_SINK",
    "function": "bt_spi_rx_thread",
    "root_expr": "rxmsg[2] + 2"
  },
  "steps": [
    {"kind":"DERIVE", "expr":"payload_len = rxmsg[2] + 2", "site":"bt_spi_rx_thread"},
    {"kind":"CHANNEL", "object_id":"obj_rxmsg", "edge":"DMA->TASK", "evidence_refs":["E_CH_1"]},
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"SPI1_DR", "evidence_refs":["E_SRC_2"]}
  ],
  "checks": [
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ],
  "verdict": "CONFIRMED",
  "score": 0.93,
  "evidence_refs": ["E1","E2","E7"]
}
```

---

## 7. SourceAgent 与 BinAgent 分工

当前实践可行分工：
- SourceAgent：规则实现、结构化事实、graph/chain preflight。
- BinAgent：运行态验证、深检、执行端优先级调度。

阶段化策略：
1. 近期：SourceAgent 先打通 `channel_graph + chains` 基线。  
2. 中期：将稳定 linker 子集回迁 SourceAgent，保证单仓库可复现实验。  
3. 远期：共享统一 `schema` 与评测脚本。

---

## 8. 路线图与评测（不含 LLM）

> 按你的要求，LLM 相关章节已移除。当前版本仅保留确定性静态链路方案。

### 8.1 路线图（P0–P3）
- **P0**：ContextIndex MVP + ChannelGraph(SRAM/DMA) + 基础 linker。
- **P1**：对象边界细化 + DMA consumer 绑定 + 多 callsite 完整建模。
- **P2**：derive/check 强化 + chain_eval 指标。
- **P3**：RTOS queue 强证据识别 + SourceAgent/BinAgent schema 融合。

### 8.2 评测指标（label -> chain）
1. label 级：TP/FP/FN。  
2. chain 级：
   - Reachability（sink 是否可达 source）
   - Derive correctness（派生事实正确率）
   - Check consistency（检查强弱判定一致性）
   - Verdict stability（重复运行稳定性）

### 8.3 成功标准
1. 至少 1 条真实 CVE + 2 条 microbench 的完整链。  
2. 不做 source×sink 穷举。  
3. 每一步可回溯 evidence refs。  
4. 输出可解释且可复核。

---

## 9. Case Study（带目标链输出）

### 9.1 Case A: `t0_isr_filled_buffer.c`
代码片段：
```c
void USART1_IRQHandler(void) {
    uint8_t b = (uint8_t)(USART1_DR & 0xFFu);  // source
    g_rx_buf[g_rx_head] = b;                   // producer write
}

void process_packet(char *out, unsigned int max_len) {
    while (g_rx_tail != g_rx_head) {
        tmp[count++] = g_rx_buf[g_rx_tail];    // consumer read
    }
    memcpy(out, tmp, count);                   // sink
}
```
目标链：
`MMIO_READ(USART1_DR) -> obj(g_rx_buf) -> derive(count) -> check(count<max_len?) -> COPY_SINK(memcpy)`

### 9.2 Case B: `t0_dma_backed_buffer.c`（补充目标链输出）
代码片段：
```c
DMA1_CH5_CPAR  = USART1_DR_ADDR;
DMA1_CH5_CMAR  = (uint32_t)g_dma_rx_buf;
DMA1_CH5_CNDTR = sizeof(g_dma_rx_buf);

if (g_dma_rx_buf[0] != 0) {
    parse_frame(g_dma_rx_buf, 256);
}
```

关键要求：
- `CMAR` 绑定 `g_dma_rx_buf`。
- consumer 必须读取同 object 或同 addr_range。

正例：`parse_frame(g_dma_rx_buf, ...)`。  
反例：`handle_cfg(g_cfg_buf)` 不应视作该 DMA 对象消费。

目标链输出（DMA 类型）：
```json
{
  "chain_id": "chain_dma_rxbuf_parse_1",
  "source": {"label":"DMA_BACKED_BUFFER", "site":"dma_uart_rx_init", "object_id":"obj_dma_rx_buf"},
  "steps": [
    {"kind":"CHANNEL", "edge":"DMA->MAIN", "object_id":"obj_dma_rx_buf"},
    {"kind":"DERIVE", "expr":"frame_tag = g_dma_rx_buf[0]", "site":"main"}
  ],
  "sink": {"label":"STORE_SINK", "function":"parse_frame", "root_expr":"buf[idx]"},
  "checks": [
    {"expr":"idx < len", "strength":"effective", "site":"parse_frame"}
  ],
  "verdict": "SAFE_OR_LOW_RISK"
}
```

### 9.3 Case C: `cve_2020_10065_hci_spi.c`（完整标注）

#### 9.3.1 需要关注的 source / sink 位点

**Source 位点（输入进入内存）：**
```c
// bt_spi_transceive()
while (!(SPI1_SR & 0x01u)) {}
dst[i] = (uint8_t)(SPI1_DR & 0xFFu);   // SOURCE: MMIO_READ(SPI1_DR)
```

**Sink 位点（真实触发点）：**
```c
// bt_spi_rx_thread(), EVT path
net_buf_add_mem(buf, &rxmsg[1], rxmsg[EVT_HEADER_SIZE] + 2);  // SINK_EVT

// bt_spi_rx_thread(), ACL path
net_buf_add_mem(buf, &rxmsg[5], sys_le16_to_cpu(acl_hdr.len)); // SINK_ACL
```

**底层拷贝语义点（helper 内部）：**
```c
// net_buf_add_mem()
memcpy(dst, mem, len);   // 语义 copy sink，在 helper 内
```

说明：
- 漏洞语义应锚定在 `bt_spi_rx_thread` 两个调用点（参数可控且无上界）。
- `memcpy` 在 helper 内是执行语义，最终链路应回到外层两个 root。

#### 9.3.2 我们需要看的两条关键 chain

**Chain-1 (EVT):**
- Root: `rxmsg[EVT_HEADER_SIZE] + 2`（即 `rxmsg[2]+2`）
- 路径：`SPI1_DR -> rxmsg[] -> derive(len_evt) -> net_buf_add_mem(..., len_evt)`
- 问题：缺失 `len_evt <= NET_BUF_DATA_SIZE` 上界检查。
- 风险：最大约 257 字节写入 76 字节缓冲，OOB 写。

**Chain-2 (ACL):**
- Root: `sys_le16_to_cpu(acl_hdr.len)`（来自输入头）
- 路径：`SPI1_DR -> rxmsg[] -> acl_hdr.len -> net_buf_add_mem(..., len_acl)`
- 问题：缺失 `len_acl <= tailroom` 上界检查。
- 风险：理论上可达 65535，远超缓冲。

#### 9.3.3 为什么这些 chain 导致 CVE-2020-10065
满足漏洞链三条件：
1. 输入可控：长度字段来自外设 MMIO 输入流。  
2. 风险参数直达 sink：长度字段直接作为 copy length。  
3. 缺失有效上界：仅有存在性或流程检查（如 `size!=0`），没有缓冲容量约束。

因此两条链都应输出 `CONFIRMED`（在静态证据充分条件下）。

---

## 10. 实现冻结规范（开工前硬规格）

本节用于“直接指导编码”，默认视为 `v1` 规范。后续改动需同步更新该节。

### 10.1 六个 JSON 字段契约（v1）

#### 10.1.1 `channel_graph.json`

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` | 契约版本 |
| `binary` | string | 是 | `""` | 二进制名称/路径 |
| `object_nodes` | array | 是 | `[]` | 对象节点列表 |
| `channel_edges` | array | 是 | `[]` | 上下文边列表 |
| `build_meta` | object | 否 | `{}` | 构建参数与统计 |

`object_nodes[i]` 子字段：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `object_id` | string | 是 | `""` |
| `region_kind` | enum | 是 | `"UNKNOWN"` |
| `addr_range` | [string, string] | 是 | `["0x0","0x0"]` |
| `writers` | array[string] | 是 | `[]` |
| `readers` | array[string] | 是 | `[]` |
| `producer_contexts` | array[enum] | 是 | `["UNKNOWN"]` |
| `consumer_contexts` | array[enum] | 是 | `["UNKNOWN"]` |
| `evidence_refs` | array[string] | 是 | `[]` |
| `confidence` | number | 是 | `0.0` |
| `type_facts` | object | 否 | `{}` |
| `notes` | string | 否 | `""` |

`channel_edges[i]` 子字段：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `src_context` | enum | 是 | `"UNKNOWN"` |
| `object_id` | string | 是 | `""` |
| `dst_context` | enum | 是 | `"UNKNOWN"` |
| `edge_kind` | enum(DATA/CONTROL/MIXED) | 是 | `"DATA"` |
| `constraints` | array[object] | 是 | `[]` |
| `evidence_refs` | array[string] | 是 | `[]` |
| `score` | number | 是 | `0.0` |

#### 10.1.2 `refined_objects.json`

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` | 契约版本 |
| `binary` | string | 是 | `""` | 二进制名称/路径 |
| `objects` | array | 是 | `[]` | 细化后对象列表 |
| `refine_meta` | object | 否 | `{}` | split/merge 统计 |

`objects[i]` 与 `ObjectNode` 结构保持一致，可额外包含：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `members` | array[string] | 否 | `[]` |
| `source_raw_object_ids` | array[string] | 否 | `[]` |

#### 10.1.3 `sink_roots.json`

| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` |
| `binary` | string | 是 | `""` |
| `sink_roots` | array | 是 | `[]` |

`sink_roots[i]`：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `sink_id` | string | 是 | `""` |
| `sink_label` | string | 是 | `""` |
| `sink_function` | string | 是 | `""` |
| `sink_site` | string(hex) | 是 | `"0x0"` |
| `roots` | array | 是 | `[]` |
| `evidence_refs` | array[string] | 是 | `[]` |
| `confidence` | number | 是 | `0.0` |
| `status` | enum(ok/partial/failed) | 是 | `"ok"` |
| `failure_code` | string | 否 | `""` |

`roots[j]`：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `role` | enum(primary/secondary) | 是 | `"primary"` |
| `expr` | string | 是 | `""` |
| `kind` | string | 是 | `"unknown"` |
| `resolvable` | bool | 是 | `false` |

#### 10.1.4 `chains.json`

| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` |
| `binary` | string | 是 | `""` |
| `chains` | array | 是 | `[]` |

`chains[i]`：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `chain_id` | string | 是 | `""` |
| `sink` | object | 是 | `{}` |
| `source` | object | 否 | `{}` |
| `steps` | array | 是 | `[]` |
| `checks` | array | 是 | `[]` |
| `derive_facts` | array | 是 | `[]` |
| `verdict` | enum | 是 | `"SUSPICIOUS"` |
| `score` | number | 是 | `0.0` |
| `status` | enum(ok/partial/failed) | 是 | `"ok"` |
| `failure_code` | string | 否 | `""` |
| `evidence_refs` | array[string] | 是 | `[]` |

#### 10.1.5 `chain_eval.json`

| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` |
| `binary` | string | 是 | `""` |
| `stats` | object | 是 | `{}` |
| `by_verdict` | object | 是 | `{}` |
| `timing_ms` | object | 否 | `{}` |

`stats` 建议字段：
- `chain_count`, `confirmed_count`, `suspicious_count`, `safe_count`, `drop_count`。
- `avg_chain_score`, `avg_steps`, `source_reach_rate`。

#### 10.1.6 `low_conf_sinks.json`

| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `schema_version` | string | 是 | `"1.0"` |
| `binary` | string | 是 | `""` |
| `items` | array | 是 | `[]` |

`items[i]`：
| 字段 | 类型 | 必填 | 默认值 |
|---|---|---|---|
| `sink_id` | string | 是 | `""` |
| `sink_label` | string | 是 | `""` |
| `function` | string | 是 | `""` |
| `site` | string(hex) | 是 | `"0x0"` |
| `confidence` | number | 是 | `0.0` |
| `reason_codes` | array[string] | 是 | `[]` |
| `evidence_refs` | array[string] | 是 | `[]` |

---

### 10.2 Verdict 决策表（`SUSPICIOUS` 宽松，`CONFIRMED` 收紧）

判定输入（建议统一）：
- `source_reached`（bool）
- `root_controllable`（bool）
- `check_strength`（`effective/weak/absent/unknown`）
- `chain_complete`（bool）
- `has_contradiction`（bool）
- `endpoint_in_app`（bool，至少一个端点在非库函数）
- `chain_score`（0~1）

| Verdict | 条件（全部满足） |
|---|---|
| `CONFIRMED` | `source_reached=true` 且 `root_controllable=true` 且 `check_strength in {weak, absent}` 且 `chain_complete=true` 且 `has_contradiction=false` 且 `endpoint_in_app=true` 且 `chain_score>=0.80` |
| `SUSPICIOUS` | sink/root 证据存在，但未达到 `CONFIRMED`；典型为 `source_reached=false` 或 `check_strength=unknown` 或 `chain_complete=false`；建议 `chain_score>=0.35` |
| `SAFE_OR_LOW_RISK` | `check_strength=effective` 且链条可解释（通常 `source_reached=true`）且无矛盾 |
| `DROP` | `has_contradiction=true`，或证据严重不足（`chain_score<0.35`），或端点均在库函数且无应用对象锚点 |

补充策略：
- 低分不直接删，先进入 `SUSPICIOUS`（宽松）。
- `CONFIRMED` 严格收敛，避免误报污染高优先级结果。

---

### 10.3 全局默认参数（速度优先）

| 参数 | 默认值 | 说明 |
|---|---|---|
| `T_low` | `0.45` | 低置信 sink 阈值（`<T_low` 进入 low_conf） |
| `top_k` | `3` | object 冲突保留数（M8.5） |
| `B` | `160` | 单 root 回溯预算（节点/步数上限） |
| `K` | `2` | tunnel jump producer top-K |
| `max_depth d` | `2` | 最大 tunnel 深度 |
| `max_chains_per_sink` | `4` | 每 sink 最多输出链数 |
| `max_chains_per_binary` | `200` | 每 binary 链数上限（防慢） |

---

### 10.4 Context 判定规则（MAIN vs TASK vs UNKNOWN）

判定顺序（先命中先返回）：
1. `ISR`: 已在 MAI 标记 `in_isr=true`。  
2. `TASK`: 函数名/符号匹配 `*task*/*thread*`，或由 RTOS 创建 API（如 `xTaskCreate`）可追到入口。  
3. `MAIN`: `main` 本体，或从 `Reset_Handler` 主路径可达、且非 ISR/TASK。  
4. `UNKNOWN`: 无法可靠归类时使用。

注意：
- 不强行分类，`UNKNOWN` 是合法输出。
- `UNKNOWN` context 的 edge/chain 可以保留，但分数下调。

---

### 10.5 多 callsite 策略（同函数多 sink）

目标：尽量多收集，不做激进裁剪。

`sink_id` 生成规则（推荐）：
```text
{label}@{function}@{callsite_hex}@{root_kind}:{hash8}
```

去重键：
```text
(label, function, callsite_hex, normalized_root_expr)
```

策略：
- 同函数不同 callsite 全保留。
- 同 callsite 多 root（primary/secondary）全保留。
- 仅受 `max_chains_per_sink` 与 `max_chains_per_binary` 保护。

---

### 10.6 失败回退策略（统一输出格式）

统一字段（出现在 `sink_roots.json` 与 `chains.json`）：
- `status`: `ok/partial/failed`
- `failure_code`
- `failure_detail`（可选）
- `fallback_action`（可选）

建议失败码：
- `ROOT_UNRESOLVED`
- `OBJECT_MAP_MISS`
- `BUDGET_EXCEEDED`
- `NO_SOURCE_REACH`
- `CONTRADICTION`
- `LIB_BARRIER`

回退规则：
1. root 提取失败：保留记录，`status=partial`，`verdict=SUSPICIOUS`。  
2. object 映射失败：`status=partial`，`verdict=SUSPICIOUS`，并保留局部路径。  
3. 切片超预算：  
  `sink/root` 强证据存在 -> `SUSPICIOUS`；  
  否则 -> `DROP`。  
4. 证据矛盾（同一变量既被证明可控又被证明常量）：`DROP`。

---

### 10.7 回溯进入库函数时如何处理（必须策略）

你的问题很关键：不会“自动取消”，需要显式策略。

处理原则：
1. **summary mode**：对已知库 API（`memcpy/memset/strcpy/...`）不深入内部，使用语义摘要边。  
2. **barrier mode**：进入未知库内部时设置步数上限，超过后打 `LIB_BARRIER` 并停止下钻。  
3. **endpoint policy**：若 source/sink 两端都落在库函数，且无应用对象锚点，则 `DROP`。  
4. **app-anchor exception**：若 sink 在库函数但 root 来自应用对象（可证据化），可保留为 `SUSPICIOUS`。  

为什么必须这样做：
- 库内部路径会显著放大搜索空间，影响速度。
- 库代码常产生“语义上像 sink”的噪声，需要以应用锚点收敛。

---

### 10.8 编码前最小补充清单

若按本节执行，可直接开工。开工前只需再确认两件事：
1. `SAFE_OR_LOW_RISK` 是否保留该命名（或统一改为 `SAFE`）。  
2. `chain_score` 具体公式（线性加权即可，先实现后校准）。

---

## 参考文献与来源文档
- [I1] RQ1 Detailed Planning: Semantic Recovery v1.3（内部提案）  
- [I2] SourceAgent `update_0305.md`（内部周报）  
- [I3] `eval_suite_unstripped_elf_report_en.md`（内部评测报告）  
- [R1] Operation Mango, USENIX Security 2024  
- [R2] KARONTE, IEEE S&P 2020  
- [R3] Sharing More and Checking Less, USENIX Security 2021  
- [R4] P2IM, USENIX Security 2020  
- [R5] DICE, IEEE S&P 2021  
- [R6] Fuzzware, USENIX Security 2022  
- [R7] RTCON, NDSS 2026  
- [R8] HEAPSTER, IEEE S&P 2022  
- [R9] FirmXRay, CCS 2020  
- [R10] LATTE, ACM TOSEM 2025  
- [R11] IRIS, ICLR 2025  
- [R12] AdaTaint, 2025 preprint

# Weekly Update
## Context boundaries + Source/Sink identification in Type II/III monolithic firmware
### Worked example (code-style): CVE-2020-10065 (Zephyr HCI over SPI)

## 1) Three points I will emphasize

### (A) Context boundaries are the “IPC” of Type II/III
Type II/III firmware is often a **single monolithic binary**, but it executes in multiple contexts:
- **ISR context** (interrupt handlers)
- **Task/thread context** (RTOS)
- **Main-loop context** (bare-metal super-loop)
- optional **workqueue/deferred handler** context
- **DMA** as a “hardware producer” (data written to RAM without CPU loads)

The key Type-II/III obstacle is that important data flows cross these contexts via **global buffers, ring buffers, queues, and state flags**, not via a normal call chain.

### (B) Why we look for **sources**, and how we find them
In Type II/III, **source = external / attacker-influenced input**. Instead of syscalls (Type-I), the dominant sources are:
- **MMIO reads** from FIFO/data registers (UART/SPI/I2C/USB/ETH)
- **DMA-backed buffers** (peripheral/DMA writes RAM directly)
- **ISR-filled buffers** (ISR writes a global/static buffer that later gets parsed in task/main)

**Current SourceAgent approach (evidence-grounded labeling):**
1) Lift the program to Ghidra p-code.
2) Build a **MemoryAccessIndex (MAI)** of LOAD/STORE operations.
3) Mine source candidates using bounded slicing over p-code:
   - For **MMIO_READ**: a LOAD where the address expression traces back to a **constant base** in the peripheral/MMIO range.
   - Strengthen with context: if the site is in ISR context, mark **ISR_MMIO_READ**.
   - For **ISR_FILLED_BUFFER**: find an object written in ISR context and read/parsed outside ISR.
   - For **DMA_BACKED_BUFFER**: detect DMA configuration clusters and slice the destination pointer to a stable RAM object.

**Output:** structured source labels with evidence (site, addr expr, slice roots) and a verifier verdict (fail-closed).

### (C) Why we look for **sinks**, and how we find them
A **sink** is a program point that can cause memory corruption or dangerous control transfers when fed unsafe data. In our staged taxonomy:
- **COPY_SINK**: memcpy/strcpy/memmove and copy-like wrappers (e.g., net_buf_add_mem)
- **MEMSET_SINK**: memset/memclr with variable length/target
- **STORE_SINK**: indirect stores through pointers or base+offset
- **LOOP_WRITE_SINK**: loop-based writes (often inlined copy/write)
- **FUNC_PTR_SINK**: indirect calls (CALLIND), handler tables
- **FORMAT_STRING_SINK**: sprintf/vsnprintf with non-literal format

**Current sink mining strategy (staged):**
1) **API/signature-based sinks first** (stable): find callsites to known routines; extract key args (dst/src/len/format) using p-code slices.
2) **Hard-mode sinks later** (loop/callind): detect STORE-in-loop or CALLIND patterns and emit candidates with conservative confidence until verified.

**Important:** source labels + sink labels are *building blocks*. To claim a vulnerability, we still need to connect them via cross-context channels and show missing/weak checks.

## 2) Worked example: CVE-2020-10065 (Zephyr HCI over SPI)

### 2.1 What we want to recover (chain view)
The vulnerability fits a common Type II/III pattern:

**SPI FIFO (MMIO) -> RX buffer -> parse length -> copy into fixed destination (COPY sink) -> missing/weak bounds check**

The important twist (vs Type-I) is that different parts of the chain can sit in different contexts (ISR vs task/worker), and communication happens through shared objects (flags, buffers, queues).

### 2.2 Representative pseudocode (decompiler-style)
This is a representative shape of the flow (names simplified to highlight the semantics):

```c
// Producer side: short ISR/callback that wakes a consumer
void spi_ready_isr(void) {
  rx_ready = 1;             // flag or event
  give(rx_sem);             // optional RTOS signal
}

// Consumer side: thread/task that reads SPI FIFO and parses a packet
void hci_spi_rx_thread(void) {
  take(rx_sem);
  if (!rx_ready) return;
  rx_ready = 0;

  // SOURCE: reads from SPI FIFO / data register (MMIO)
  for (i = 0; i < HDR_LEN; i++) {
    hdr[i] = *(volatile uint8_t*)SPI1_DR;    // MMIO_READ
  }

  // PARSE: length derived from attacker-controlled header bytes
  payload_len = (hdr[2] << 8) | hdr[3];      // example: 16-bit length

  for (i = 0; i < payload_len; i++) {
    payload[i] = *(volatile uint8_t*)SPI1_DR; // MMIO_READ
  }

  // SINK: copy into a destination buffer (direct or wrapper)
  net_buf_add_mem(dst, payload, payload_len); // copy-like wrapper
  // internally: memcpy(dst_ptr, payload, payload_len);
}
```

### 2.3 How the pipeline identifies each part

#### Step 1: Context boundary recovery (why + how)
Goal: distinguish ISR-context from task/main-context so we can talk about cross-context edges.
- **ISR entrypoints**: parsed from Cortex-M vector table; functions reachable from these are tagged `ISR`.
- **Task/worker entrypoints**: if symbols exist, locate RTOS creation calls; if stripped, fall back to wait/signal patterns (sem take/queue receive loops) to mark likely consumer threads.

Output: a **ContextIndex** tagging functions as ISR/task/main/unknown.

#### Step 2: Source detection on this CVE
Goal: locate hardware-driven inputs.
- The FIFO read `*(volatile uint8_t*)SPI1_DR` is detected as **MMIO_READ** because the address expression slices to a constant peripheral-range base.
- If it happens in an ISR-tagged function, it becomes **ISR_MMIO_READ**.

Output: evidence-grounded label like:
- `MMIO_READ @ SPI1_DR` (with p-code slice showing `addr := CONST(0x40013000) + 0x0c` style pattern)

#### Step 3: Sink detection on this CVE
Goal: locate the dangerous copy/write operation.
- If the copy is via a recognized API (`memcpy`) or a known wrapper (`net_buf_add_mem`), we emit **COPY_SINK** at the callsite.
- If the copy is inlined, we try to emit **LOOP_WRITE_SINK** / `COPY_SINK (idiom)` based on store-in-loop patterns.

Output: evidence-grounded sink label like:
- `COPY_SINK @ net_buf_add_mem(...)` or `COPY_SINK @ memcpy(...)`

#### Step 4: What is still missing to make this a *vulnerability* finding
Source and sink are necessary but not sufficient. We still need these modules:

1) **ChannelGraph (IPC-equivalent object recovery)**
   - Identify the objects that carry data across contexts:
     - `rx_ready` flag, `rx_sem` semaphore/queue handle
     - shared buffers (`hdr`, `payload`, ring buffers)
   - Build edges: `producer_context -> object -> consumer_context`.

2) **Parse/Derive miner (taint -> semantic variable transition)**
   - Recognize that `payload_len` is derived from attacker-controlled bytes:
     - `payload_len <- hdr[k..k+1]` or `payload_len <- buf[offset]`.
   - This is what links raw input bytes to the sink’s dangerous argument.

3) **Check summarizer (is there a real bound?)**
   - Detect clamps/guards that dominate the sink:
     - `if (payload_len <= MAX)` or `payload_len = MIN(payload_len, MAX)`.
   - Decide: CHECK present/weak/absent.

4) **Evidence-chain linker (sink-first linking)**
   - Starting from the sink, backward-slice `payload_len`.
   - If the slice reaches a shared object, jump across ChannelGraph to the producer side.
   - Stop when reaching a source (MMIO/DMA) or budget limit.

The final output becomes a chain like:
- `MMIO_READ(SPI1_DR) -> fills hdr[] -> payload_len derived -> COPY_SINK(len=payload_len) -> missing/weak check`

### 2.4 Where LLM helps (optional, but useful for advisor narrative)
LLM is not used to invent facts. It is used to reduce manual effort in the hardest-to-generalize semantic steps:
- Summarize parse logic (which header bytes form length/type?)
- Judge check adequacy (is the guard actually bounding the copy?)
- Classify ambiguous loops (copy loop vs benign loop)

All LLM claims must be backed by evidence items and pass verifier obligations.

## 3) Why Type-I work starts from syscalls/IPC, but we start from context boundaries
In Type-I (embedded Linux/service firmware), the OS provides stable, explicit input endpoints (e.g., file/socket reads, ioctl) and explicit IPC edges (socket/pipe/RPC). This means “source modeling” can start with syscalls and IPC semantics.

In Type II/III, those abstractions are absent or blurred:
- hardware-driven inputs replace syscalls (MMIO, interrupts, DMA)
- propagation often crosses ISR/task/main via shared objects (flags, ring buffers, queues)

So in Type II/III, **context boundaries + async communication objects** are necessary to connect a source label to a sink label.

## 4) What remains to build after source+sink identification (short list)
If the goal is “find more real vulnerabilities” (not just label sites), we need:

1) **ContextIndex** (done / baseline): ISR vs non-ISR tagging.
2) **ChannelGraph MVP** (next): recover cross-context producer-consumer objects.
3) **Parse/Derive miner** (next): recognize len/index/type derived from input buffers.
4) **Check summarizer** (next): identify effective bounds checks (or lack thereof).
5) **Evidence-chain linker** (next): sink-first linking from sink args back to sources (jump across channels).
6) Optional: **LLM triage on suspicious** to summarize complex parsing and check adequacy, then verify with obligations.

## 5) Minimal “tomorrow-ready” framing
- Today: we have a trustworthy, evidence-grounded layer that can label **where input enters** (sources) and **where dangerous operations happen** (sinks).
- Next: we connect them with a recovered async graph + short slicing to produce **actionable source-to-sink chains** (and reduce FP).

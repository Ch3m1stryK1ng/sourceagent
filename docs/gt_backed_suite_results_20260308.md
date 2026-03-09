# GT-Backed Suite v2 Results and Progress Check

Date: 2026-03-08

## 1. Scope

This report summarizes the current state of the `SourceAgent` pipeline after the recent chain-linking and GT expansion work.

The evaluated suite is the current **GT-backed baseline**:
- `44` samples total
- `14` `microbench` samples
- `30` `mesobench` full-GT samples

The suite definition lives in:
- `firmware/ground_truth_bundle/gt_backed_suite/index.json`
- `firmware/ground_truth_bundle/gt_backed_suite/README.md`

The latest evaluated output directory is local-only and was not committed:
- `/tmp/eval_gt_backed_suite_p35plus_rerun2_merged`

## 2. Latest Headline Result

From `/tmp/eval_gt_backed_suite_p35plus_rerun2_merged/summary/artifact_eval_summary.json`:

| Metric | Value |
|---|---:|
| sample_count | 44 |
| positive_total | 386 |
| matched | 386 |
| missed | 0 |
| chain hit rate | 100.0% |
| verdict_exact | 276 |
| verdict_under | 109 |
| verdict_over | 1 |
| pred_non_drop | 279 |
| spurious_non_drop | 0 |
| must_use_channel_total | 253 |
| must_use_channel_ok | 253 |
| negative_expectations | 27 / 27 |

This means the current chain layer satisfies the structural goal:
- all GT positive chains are recovered
- no spurious non-drop chains remain
- all channel-required chains are recovered through channel paths
- all explicit negative expectations are satisfied

## 3. Artifact-Level Metrics

The artifact-level evaluator is intentionally strict and counts all predicted objects/roots/channels, so precision is low by design on large binaries. The more important signal is recall and chain correctness.

| Artifact | GT Total | Pred Total | Matched GT | Recall |
|---|---:|---:|---:|---:|
| sources | 105 | 1761 | 97 | 92.38% |
| objects | 58 | 842 | 51 | 87.93% |
| channels | 48 | 116 | 42 | 87.50% |
| sinks | 376 | 1270 | 374 | 99.47% |
| sink_roots | 721 | 2697 | 718 | 99.58% |
| derive_checks | 390 | 1275 | 361 | 92.56% |

Interpretation:
- source/sink/root extraction is already strong enough for chain construction
- the hard part was root-aware matching, channel enforcement, and spurious chain suppression
- verdict calibration is still the main remaining open problem

## 4. Representative Samples

Top chain-heavy samples from `artifact_eval_by_sample.json`:

| Sample | Positives | Matched | Exact | Under | Over | Spurious | Channel OK |
|---|---:|---:|---:|---:|---:|---:|---:|
| contiki_cve_2020_12140_hello_world | 64 | 64 | 50 | 14 | 0 | 0 | 56/56 |
| contiki_halucinator_cve_2019_9183_hello_world | 54 | 54 | 35 | 19 | 0 | 0 | 50/50 |
| contiki_cve_2020_12141_snmp_server | 46 | 46 | 30 | 16 | 0 | 0 | 39/39 |
| zephyr_cve_2020_10065 | 22 | 22 | 18 | 4 | 0 | 0 | 22/22 |
| zephyr_cve_2020_10066 | 21 | 21 | 18 | 3 | 0 | 0 | 21/21 |
| usbs_tcp_echo_client_vuln_bof_dhcp | 14 | 14 | 8 | 6 | 0 | 0 | 7/7 |
| usbs_tcp_echo_client_vuln_off_by_one_dhcp | 14 | 14 | 8 | 6 | 0 | 0 | 7/7 |
| usbs_udp_echo_server_bof_expl | 13 | 13 | 7 | 6 | 0 | 0 | 7/7 |
| usbs_tcp_echo_client_vuln_bof | 12 | 12 | 8 | 4 | 0 | 0 | 4/4 |
| usbs_udp_echo_server_bof_instrumented_patched | 11 | 11 | 7 | 4 | 0 | 0 | 4/4 |

The only remaining over-calibrated chain is in:
- `stm32cube_lwip_udp_echo_client`

That is a verdict-calibration issue, not a chain-recovery issue.

## 5. What Changed in Code

### 5.1 Root fan-out and canonicalization
Implemented across:
- `sourceagent/pipeline/linker/sink_roots.py`
- `sourceagent/pipeline/linker/tunnel_linker.py`
- `sourceagent/pipeline/microbench_gt_v2_eval.py`

Representative logic now carried in each root bundle:

```python
{
    "expr": "rxmsg[2] + 2",
    "canonical_expr": "rxmsg[2]+2",
    "aliases": ["rxmsg[2]+2", "payload_len"],
    "kind": "length",
    "role": "primary",
    "family": "length",
    "source": "call_args",
}
```

This was the key fix for the original `root_ok=false` failure bucket.

### 5.2 Channel-required enforcement
Implemented mainly in:
- `sourceagent/pipeline/linker/tunnel_linker.py`
- `sourceagent/pipeline/channel_graph.py`

Representative rule:

```python
if channel_required_hint and not has_channel_step:
    return "DROP"
```

This is what moved the suite from partial same-context shortcuts to `253/253` channel-required satisfaction.

### 5.3 Secondary-root suppression
Implemented in:
- `sourceagent/pipeline/linker/tunnel_linker.py`

Representative behavior:
- keep the true risk-root family (`length`, `dispatch`, `format_arg`)
- aggressively suppress redundant pointer-only siblings when a stronger root exists

This is what drove `spurious_non_drop` down to `0`.

### 5.4 Family-specific root aliases
Implemented in:
- `sourceagent/pipeline/linker/sink_roots.py`

Added support for common length families in larger firmware:
- `len`
- `tot_len`
- `payload_len`
- `data_len`
- `uip_len`
- helper-returned packet length aliases in `Contiki`, `Zephyr`, and `uSBS/lwIP`

### 5.5 GT-backed evaluators
Implemented in:
- `sourceagent/pipeline/microbench_gt_v2.py`
- `sourceagent/pipeline/microbench_gt_v2_eval.py`
- `sourceagent/pipeline/mesobench.py`

This added:
- `microbench` artifact GT
- `mesobench` full GT inventory
- `gt_backed_suite` combined evaluator baseline

## 6. Progress Against `planning_patch_v1_1_en.md`

### 6.1 Implemented
The following planned modules are now present and working:

| Planning item | Status | Main files |
|---|---|---|
| Stage 1/2/2.5 Loader + MAI + interprocedural | Implemented | `loader.py`, `memory_access_index.py`, `interprocedural.py` |
| Stage 3/4 source/sink miners | Implemented | `miners/mmio_read.py`, `miners/isr_context.py`, `miners/dma_buffer.py`, `miners/copy_sink.py`, `miners/additional_sinks.py`, `miners/format_string_sink.py`, `miners/func_ptr_sink.py` |
| Stage 5/6/7 evidence -> proposal -> verifier | Implemented | `evidence_packer.py`, `proposer.py`, `verifier.py` |
| M8.5 ChannelGraph Builder | Implemented | `pipeline/channel_graph.py` |
| M8.6 Object Boundary Refiner | Implemented (heuristic v1) | `pipeline/object_refine.py` |
| M9 Sink Root Extractor | Implemented | `pipeline/linker/sink_roots.py` |
| M9.1 Tunnel-Aware Backward Linker | Implemented | `pipeline/linker/tunnel_linker.py` |
| M9.2 Derive + Check summarization | Implemented | `pipeline/linker/derive_check.py` |
| M9.3 Suspicious queue | Implemented | `pipeline/linker/triage_queue.py` |
| GT-backed evaluator | Implemented | `pipeline/microbench_gt_v2_eval.py` |
| Mesobench inventory / GT generator | Implemented | `pipeline/mesobench.py` |

### 6.2 Implemented but still calibrating
| Topic | Current state |
|---|---|
| verdict calibration | structural chain recovery is complete; exact verdict still conservative/occasionally over by 1 case |
| object/channel artifact precision | low precision because large binaries produce many extra candidates; recall is acceptable for chain construction |
| library/internal noise | mostly contained at chain level; still visible in raw artifact precision |

### 6.3 Not the current bottleneck
These are no longer blocking chain closure:
- source labeling
- sink labeling
- root extraction presence
- channel graph construction presence

## 7. What “add more mesobench into the 44-sample baseline” means

Concretely, it means:
1. take more `mesobench` samples that are currently `seed` or only locally analyzed
2. promote them to **pipeline-scope full GT**
3. add them into `firmware/ground_truth_bundle/gt_backed_suite/index.json`
4. include them in the same evaluator baseline and reproduction manifest

So the baseline would grow from:
- `14 microbench + 30 mesobench = 44`

to something like:
- `14 microbench + 40/50 mesobench = 54/64`

This is not just “collect more binaries”. It means those binaries must have:
- source-code anchors
- object/channel/root/derive/check annotations
- positive and negative chain expectations

## 8. Verdict Calibration and BinAgent/LLM

### 8.1 Does BinAgent-style LLM validation make sense here?
Yes, but only as a **semantic triage layer**, not as the final oracle.

Recommended split:
- `SourceAgent`: deterministic facts
  - source/sink labels
  - channel graph
  - root bundles
  - derive/check facts
  - structural chain generation
- `BinAgent` / LLM: semantic calibration
  - whether a chain that is already structurally valid should be `SAFE_OR_LOW_RISK`, `SUSPICIOUS`, or `CONFIRMED`
  - whether parser-specific checks are actually effective
  - whether a weak bound or state predicate really blocks exploitability

### 8.2 Why not let LLM decide the whole chain?
Because the parts that must remain deterministic are exactly the parts we just made reproducible:
- source reachability
- object binding
- channel traversal
- root matching
- derive/check extraction

If the LLM is allowed to replace those, reproducibility collapses.

### 8.3 Best next use of LLM
Use it only on the residual verdict bucket:
- the `109` `verdict_under` cases
- the `1` `verdict_over` case

That gives a bounded, auditable workload.

## 9. Reproduction Commands

### 9.1 Full evaluator rerun on the current merged output
```bash
cd /home/a347908610/sourceagent
python3 -m sourceagent.pipeline.microbench_gt_v2_eval \
  /tmp/eval_gt_backed_suite_p35plus_rerun2_merged \
  --gt-root /home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite
```

### 9.2 Main online eval pattern
```bash
cd /home/a347908610/sourceagent
python3 -m sourceagent.interface.main eval \
  --manifest-json <manifest.json> \
  --gt-json firmware/ground_truth_bundle/normalized_gt_bundle.json \
  --online --stage 10 \
  --mcp-connect-timeout-sec 40 \
  --sample-timeout 300 \
  --analysis-wait-sec 90 \
  --output-dir <out_dir>
```

## 10. Recommended Next Steps

1. Keep the current `44`-sample suite as the frozen structural baseline.
2. Start a separate `verdict calibration` track, ideally with BinAgent/LLM as triage-only semantic review.
3. Expand `gt_backed_suite` by promoting more `mesobench` samples into full GT, not by adding binary-only samples.
4. Do not spend more time on chain recall unless the baseline grows again; structural chain recovery is already complete on the current suite.

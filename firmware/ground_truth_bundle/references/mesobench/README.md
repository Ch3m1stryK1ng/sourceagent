# Mesobench Source Anchors

This directory documents the source-code anchors used by `mesobench_v1`.

Primary anchors:
- `firmware/source_repos/contiki-ng`
  - official repo: `https://github.com/contiki-ng/contiki-ng`
  - used for Contiki-NG prebuilt CVE samples from
    `monolithic-firmware-collection/.../contiki-ng/prebuilt_samples`
- `firmware/source_repos/zephyr`
  - official repo: `https://github.com/zephyrproject-rtos/zephyr`
  - used for Zephyr prebuilt CVE and false-positive samples from
    `monolithic-firmware-collection/.../zephyr-os/prebuilt_samples`
- `firmware/source_repos/STM32CubeF4`
  - official repo: `https://github.com/STMicroelectronics/STM32CubeF4`
  - used as the base source tree for uSBS STM32469I_EVAL networking samples
- `firmware/uSBS`
  - benchmark overlay, trigger inputs, and injected snippets
  - especially:
    - `firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c`
    - `firmware/ground_truth_bundle/uSBS_trigger_inputs/...`

Second-priority source targets already anchored locally:
- `firmware/source_repos/FreeRTOS-Plus-TCP`
  - official repo: `https://github.com/FreeRTOS/FreeRTOS-Plus-TCP`
  - intended for future real DNS / LLMNR parser builds
- `firmware/source_repos/stm32-mw-usb-host`
  - official repo: `https://github.com/STMicroelectronics/stm32-mw-usb-host`
  - intended for future real USB descriptor parser builds

Interpretation:
- `full_upstream_repo`: the official codebase is present locally and can be used
  to resolve functions, structs, parser state, and checks
- `upstream_base_plus_overlay`: the base firmware source lives in the official
  repo, while benchmark-specific behavior or vulnerability injection comes from
  local overlay files (for example uSBS snippets and triggers)

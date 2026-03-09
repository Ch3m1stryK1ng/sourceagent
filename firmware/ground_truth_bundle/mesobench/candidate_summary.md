# Mesobench v1 Candidate Summary

- sample_count: 30
- primary_chain_driver: 26
- hard_mode_chain_driver: 2
- negative_control: 2
- future_sink_expansion: 0

| sample_id | dataset | priority | role | source_repo | channel | sink families |
|---|---|---|---|---|---|---|
| contiki_cve_2020_12140_hello_world | monolithic-firmware-collection | high | primary_chain_driver | contiki-ng | optional | COPY_SINK, LOOP_WRITE_SINK |
| contiki_cve_2020_12141_snmp_server | monolithic-firmware-collection | high | primary_chain_driver | contiki-ng | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| contiki_halucinator_cve_2019_9183_hello_world | monolithic-firmware-collection | high | primary_chain_driver | contiki-ng | optional | COPY_SINK, STORE_SINK |
| zephyr_cve_2020_10064 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK |
| zephyr_cve_2020_10065 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK |
| zephyr_cve_2020_10066 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, LOOP_WRITE_SINK, STORE_SINK |
| zephyr_cve_2021_3319 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, FORMAT_STRING_SINK, FUNC_PTR_SINK |
| zephyr_cve_2021_3320 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| zephyr_cve_2021_3321 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| zephyr_cve_2021_3322 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| zephyr_cve_2021_3323 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| zephyr_cve_2021_3329 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, FUNC_PTR_SINK |
| zephyr_cve_2021_3330 | monolithic-firmware-collection | high | primary_chain_driver | zephyr | optional | COPY_SINK, STORE_SINK, FORMAT_STRING_SINK |
| zephyr_false_positive_rf_size_check | monolithic-firmware-collection | high | negative_control | zephyr | optional | COPY_SINK, STORE_SINK |
| zephyr_false_positive_watchdog_callback | monolithic-firmware-collection | high | negative_control | zephyr | optional | FUNC_PTR_SINK, STORE_SINK |
| stm32cube_lwip_tcp_echo_client | monolithic-firmware-collection | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| stm32cube_lwip_tcp_echo_server | monolithic-firmware-collection | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| stm32cube_lwip_udp_echo_client | monolithic-firmware-collection | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK |
| stm32cube_lwip_udp_echo_server | monolithic-firmware-collection | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| usbs_tcp_echo_client_vuln_bof | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, LOOP_WRITE_SINK |
| usbs_tcp_echo_client_vuln_bof_dhcp | uSBS | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, LOOP_WRITE_SINK |
| usbs_tcp_echo_client_vuln_off_by_one | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, LOOP_WRITE_SINK |
| usbs_tcp_echo_client_payload_len_variant | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, LOOP_WRITE_SINK |
| usbs_test_printf_fw | uSBS | high | primary_chain_driver | stm32cubef4 | optional | FORMAT_STRING_SINK, COPY_SINK |
| usbs_udp_echo_server_bof | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, LOOP_WRITE_SINK, STORE_SINK |
| usbs_udp_echo_server_bof_expl | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| usbs_tcp_echo_client_vuln_off_by_one_dhcp | uSBS | high | primary_chain_driver | stm32cubef4 | likely | COPY_SINK, LOOP_WRITE_SINK |
| usbs_udp_echo_server_off_by_one | uSBS | high | primary_chain_driver | stm32cubef4 | optional | COPY_SINK, LOOP_WRITE_SINK |
| usbs_udp_echo_server_bof_instrumented_patched | uSBS | high | hard_mode_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |
| usbs_udp_echo_server_bof_instrumented | uSBS | high | hard_mode_chain_driver | stm32cubef4 | likely | COPY_SINK, STORE_SINK, LOOP_WRITE_SINK |

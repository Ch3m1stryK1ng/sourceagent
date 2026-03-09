# Mesobench Large-Binary Ranking

- sample_count: 30

| rank | sample_id | size_mb | dataset | role | depth | breadth | source_repo |
|---|---|---:|---|---|---|---|---|
| 1 | usbs_udp_echo_server_bof_instrumented | 4.51 | uSBS | hard_mode_chain_driver | deep | wide | stm32cubef4 |
| 2 | usbs_udp_echo_server_bof_instrumented_patched | 4.51 | uSBS | hard_mode_chain_driver | deep | wide | stm32cubef4 |
| 3 | usbs_test_printf_fw | 4.27 | uSBS | primary_chain_driver | deep | medium | stm32cubef4 |
| 4 | usbs_tcp_echo_client_vuln_bof_dhcp | 2.21 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 5 | usbs_tcp_echo_client_vuln_off_by_one_dhcp | 2.21 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 6 | usbs_tcp_echo_client_vuln_bof | 2.09 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 7 | usbs_tcp_echo_client_vuln_off_by_one | 2.09 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 8 | usbs_tcp_echo_client_payload_len_variant | 2.09 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 9 | usbs_udp_echo_server_bof | 2.08 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 10 | stm32cube_lwip_tcp_echo_client | 2.08 | monolithic-firmware-collection | primary_chain_driver | deep | wide | stm32cubef4 |
| 11 | usbs_udp_echo_server_off_by_one | 2.08 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 12 | stm32cube_lwip_udp_echo_client | 2.08 | monolithic-firmware-collection | primary_chain_driver | deep | medium | stm32cubef4 |
| 13 | stm32cube_lwip_tcp_echo_server | 2.05 | monolithic-firmware-collection | primary_chain_driver | deep | wide | stm32cubef4 |
| 14 | stm32cube_lwip_udp_echo_server | 2.04 | monolithic-firmware-collection | primary_chain_driver | deep | wide | stm32cubef4 |
| 15 | usbs_udp_echo_server_bof_expl | 1.94 | uSBS | primary_chain_driver | deep | wide | stm32cubef4 |
| 16 | zephyr_cve_2020_10064 | 1.80 | monolithic-firmware-collection | primary_chain_driver | medium | medium | zephyr |
| 17 | zephyr_false_positive_rf_size_check | 1.78 | monolithic-firmware-collection | negative_control | medium | medium | zephyr |
| 18 | zephyr_cve_2021_3320 | 1.78 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 19 | zephyr_false_positive_watchdog_callback | 1.78 | monolithic-firmware-collection | negative_control | medium | medium | zephyr |
| 20 | zephyr_cve_2021_3321 | 1.78 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 21 | zephyr_cve_2021_3323 | 1.78 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 22 | zephyr_cve_2021_3319 | 1.78 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 23 | zephyr_cve_2021_3322 | 1.78 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 24 | zephyr_cve_2021_3330 | 1.77 | monolithic-firmware-collection | primary_chain_driver | deep | medium | zephyr |
| 25 | zephyr_cve_2020_10066 | 1.20 | monolithic-firmware-collection | primary_chain_driver | deep | medium | zephyr |
| 26 | zephyr_cve_2020_10065 | 1.20 | monolithic-firmware-collection | primary_chain_driver | deep | wide | zephyr |
| 27 | zephyr_cve_2021_3329 | 1.17 | monolithic-firmware-collection | primary_chain_driver | deep | medium | zephyr |
| 28 | contiki_cve_2020_12140_hello_world | 0.52 | monolithic-firmware-collection | primary_chain_driver | medium | medium | contiki-ng |
| 29 | contiki_cve_2020_12141_snmp_server | 0.45 | monolithic-firmware-collection | primary_chain_driver | deep | wide | contiki-ng |
| 30 | contiki_halucinator_cve_2019_9183_hello_world | 0.43 | monolithic-firmware-collection | primary_chain_driver | medium | medium | contiki-ng |

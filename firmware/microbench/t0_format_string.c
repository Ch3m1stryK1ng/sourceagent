/*
 * T0 Microbench: Format string via peripheral data (CWE-134)
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 (USART1_DR) in uart_read_byte()
 *   - Sink:   FORMAT_STRING_SINK @ log_message() — sprintf uses
 *             attacker-controlled buffer as format string argument
 *
 * Pattern: UART DR fills a buffer byte-by-byte. That buffer is then
 *          passed as the format string to sprintf. Attacker-controlled
 *          format specifiers (%x, %n, etc.) lead to info leak or write.
 *
 * CWE-134: Use of Externally-Controlled Format String
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint32_t __stack_top__;

void Reset_Handler(void);
void Default_Handler(void);
int main(void);

/* --- Vector table --- */
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[16] = {
    (uint32_t)&__stack_top__,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0, 0, 0, 0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

/* --- Peripheral --- */
#define USART1_SR  (*(volatile uint32_t *)0x40011000u)
#define USART1_DR  (*(volatile uint32_t *)0x40011004u)

uint8_t uart_read_byte(void) {
    while (!(USART1_SR & 0x20u)) {}
    return (uint8_t)(USART1_DR & 0xFFu);  /* MMIO_READ */
}

/* --- Read a string from UART into buffer --- */
void uart_read_string(char *buf, unsigned int max_len) {
    for (unsigned int i = 0; i < max_len - 1; i++) {
        uint8_t c = uart_read_byte();
        if (c == '\0' || c == '\n') {
            buf[i] = '\0';
            return;
        }
        buf[i] = (char)c;
    }
    buf[max_len - 1] = '\0';
}

/* --- Sink: sprintf with attacker-controlled format string --- */
char g_log_buf[128];

void log_message(const char *fmt) {
    /* BUG: fmt comes from UART, attacker controls format specifiers */
    sprintf(g_log_buf, fmt);  /* FORMAT_STRING_SINK */
}

/* --- Higher-level handler that receives and logs --- */
void handle_command(void) {
    char cmd_buf[64];
    uart_read_string(cmd_buf, sizeof(cmd_buf));  /* read from UART */
    log_message(cmd_buf);                        /* use as format string */
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    handle_command();
    return 0;
}

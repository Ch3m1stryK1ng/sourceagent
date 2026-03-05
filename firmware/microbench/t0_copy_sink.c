/*
 * T0 Microbench: COPY_SINK + MMIO_READ combined
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 in uart_read_byte()
 *   - Sink:   COPY_SINK @ memcpy in handler() — variable length, small dst
 *   - Sink:   COPY_SINK @ strcpy in handle_name() — unbounded
 *
 * Pattern: UART data → memcpy into stack buffer with attacker-controlled length.
 *          Also: strcpy from global into local (classic overflow).
 */
#include <stdint.h>
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

/* Global name buffer (simulating received data) */
char g_name[256];

/* --- Sink: memcpy with variable length --- */
void handler(char *dst, unsigned int n) {
    uint8_t src[64];
    for (unsigned int i = 0; i < n && i < 64; i++) {
        src[i] = uart_read_byte();
    }
    if (n < 16) n = 16;
    memcpy(dst, src, n);  /* COPY_SINK: n can be up to 64, dst may be small */
}

/* --- Sink: strcpy (unbounded) --- */
void handle_name(void) {
    char local_name[32];
    strcpy(local_name, g_name);  /* COPY_SINK: unbounded, g_name can be 256 */
    (void)local_name;
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    char buf[16];
    handler(buf, 32);
    handle_name();
    return 0;
}

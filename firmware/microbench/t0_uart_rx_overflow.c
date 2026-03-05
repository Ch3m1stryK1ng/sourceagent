/*
 * T0 Microbench: UART RX buffer overflow (CWE-120)
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 (USART1_DR) in uart_read_byte()
 *   - Sink:   COPY_SINK @ uart_receive() — reads DR-controlled length into
 *             fixed 32-byte buffer with no bounds check
 *
 * Pattern: UART DR provides both a length byte and payload data.
 *          Length is used unchecked to control a receive loop writing
 *          into a fixed-size stack buffer → classic stack overflow.
 *
 * CWE-120: Buffer Copy without Checking Size of Input
 */
#include <stdint.h>

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
    while (!(USART1_SR & 0x20u)) {}       /* poll RXNE */
    return (uint8_t)(USART1_DR & 0xFFu);  /* MMIO_READ */
}

/* --- Sink: receive into fixed buffer with attacker-controlled length --- */
void uart_receive(uint8_t *buf, uint8_t len) {
    /* BUG: len comes from DR, buf is only 32 bytes, no check */
    for (uint8_t i = 0; i < len; i++) {
        buf[i] = uart_read_byte();  /* overflow when len > 32 */
    }
}

/* --- Protocol handler: reads length from UART, then payload --- */
void protocol_handler(void) {
    uint8_t frame[32];
    uint8_t length = uart_read_byte();  /* attacker controls length */
    uart_receive(frame, length);        /* SINK: no bounds check */
    (void)frame;
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    protocol_handler();
    return 0;
}

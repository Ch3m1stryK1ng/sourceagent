/*
 * T0 Microbench: MMIO_READ source
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 (UART_DR) in uart_read_byte()
 *   - Source: MMIO_READ @ 0x40011000 (UART_SR) in uart_status() [status register poll]
 *   - Sink:   COPY_SINK @ memcpy callsite in process_data()
 *
 * Pattern: Direct volatile MMIO register read via constant address.
 *          Read-modify-write on control register.
 */
#include <stdint.h>
#include <string.h>

extern uint32_t __stack_top__;

/* Forward declarations */
void Reset_Handler(void);
void Default_Handler(void);
int main(void);

/* --- Vector table --- */
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[] = {
    (uint32_t)&__stack_top__,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler, /* NMI */
    (uint32_t)Default_Handler, /* HardFault */
    0, 0, 0, 0, 0, 0, 0,
    (uint32_t)Default_Handler, /* SVCall */
    0, 0,
    (uint32_t)Default_Handler, /* PendSV */
    (uint32_t)Default_Handler, /* SysTick */
};

/* --- Peripheral definitions (STM32-like USART1) --- */
#define USART1_SR   (*(volatile uint32_t *)0x40011000u)
#define USART1_DR   (*(volatile uint32_t *)0x40011004u)
#define USART1_CR1  (*(volatile uint32_t *)0x4001100Cu)

/* --- Source: MMIO_READ (status register) --- */
uint32_t uart_status(void) {
    return USART1_SR;  /* MMIO_READ @ 0x40011000 */
}

/* --- Source: MMIO_READ (data register) --- */
uint8_t uart_read_byte(void) {
    while (!(uart_status() & 0x20u)) { /* RXNE bit poll */ }
    return (uint8_t)(USART1_DR & 0xFFu);  /* MMIO_READ @ 0x40011004 */
}

/* --- Read-modify-write pattern on MMIO --- */
void uart_enable_rx(void) {
    USART1_CR1 |= (1u << 2);  /* read-modify-write @ 0x4001100C */
}

/* --- Sink: COPY_SINK (memcpy with variable length) --- */
static uint8_t rx_buf[64];

void process_data(char *dst, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        rx_buf[i] = uart_read_byte();
    }
    memcpy(dst, rx_buf, n);  /* COPY_SINK: variable length, dst from caller */
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    char buf[32];
    uart_enable_rx();
    process_data(buf, 16);
    return 0;
}

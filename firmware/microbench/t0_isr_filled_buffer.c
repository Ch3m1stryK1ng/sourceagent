/*
 * T0 Microbench: ISR_FILLED_BUFFER source
 *
 * Ground truth:
 *   - Source: ISR_MMIO_READ @ 0x40011004 in USART1_IRQHandler()
 *   - Source: ISR_FILLED_BUFFER for g_rx_buf (written in ISR, read in main)
 *   - Sink:   COPY_SINK @ memcpy in process_packet()
 *
 * Pattern: Classic interrupt-driven ring buffer.
 *   ISR reads MMIO, stores into global buffer.
 *   Main loop reads from global buffer → memcpy into local buffer.
 */
#include <stdint.h>
#include <string.h>

extern uint32_t __stack_top__;

void Reset_Handler(void);
void Default_Handler(void);
void USART1_IRQHandler(void);
int main(void);

/* --- Vector table --- */
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[48] = {
    (uint32_t)&__stack_top__,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,      /* NMI */
    (uint32_t)Default_Handler,      /* HardFault */
    (uint32_t)Default_Handler,      /* MemManage */
    (uint32_t)Default_Handler,      /* BusFault */
    (uint32_t)Default_Handler,      /* UsageFault */
    0, 0, 0, 0,
    (uint32_t)Default_Handler,      /* SVCall */
    (uint32_t)Default_Handler,      /* DebugMon */
    0,
    (uint32_t)Default_Handler,      /* PendSV */
    (uint32_t)Default_Handler,      /* SysTick */
    /* External IRQs */
    (uint32_t)Default_Handler,      /* 16: IRQ0 */
    (uint32_t)Default_Handler,      /* 17 */
    (uint32_t)Default_Handler,      /* 18 */
    (uint32_t)Default_Handler,      /* 19 */
    (uint32_t)Default_Handler,      /* 20 */
    (uint32_t)Default_Handler,      /* 21 */
    (uint32_t)Default_Handler,      /* 22 */
    (uint32_t)Default_Handler,      /* 23 */
    (uint32_t)Default_Handler,      /* 24 */
    (uint32_t)Default_Handler,      /* 25 */
    (uint32_t)Default_Handler,      /* 26 */
    (uint32_t)Default_Handler,      /* 27 */
    (uint32_t)Default_Handler,      /* 28 */
    (uint32_t)Default_Handler,      /* 29 */
    (uint32_t)Default_Handler,      /* 30 */
    (uint32_t)Default_Handler,      /* 31 */
    (uint32_t)Default_Handler,      /* 32 */
    (uint32_t)Default_Handler,      /* 33 */
    (uint32_t)Default_Handler,      /* 34 */
    (uint32_t)Default_Handler,      /* 35 */
    (uint32_t)Default_Handler,      /* 36 */
    (uint32_t)USART1_IRQHandler,    /* 37: USART1 IRQ */
    (uint32_t)Default_Handler,      /* 38 */
    (uint32_t)Default_Handler,      /* 39 */
    (uint32_t)Default_Handler,      /* 40 */
    (uint32_t)Default_Handler,      /* 41 */
    (uint32_t)Default_Handler,      /* 42 */
    (uint32_t)Default_Handler,      /* 43 */
    (uint32_t)Default_Handler,      /* 44 */
    (uint32_t)Default_Handler,      /* 45 */
    (uint32_t)Default_Handler,      /* 46 */
    (uint32_t)Default_Handler,      /* 47 */
};

/* --- Peripheral registers --- */
#define USART1_SR   (*(volatile uint32_t *)0x40011000u)
#define USART1_DR   (*(volatile uint32_t *)0x40011004u)

/* --- ISR-filled ring buffer (ground truth: ISR_FILLED_BUFFER) --- */
volatile uint8_t  g_rx_buf[128];
volatile uint32_t g_rx_head = 0;
volatile uint32_t g_rx_tail = 0;

/* --- ISR: fills the ring buffer from UART MMIO --- */
void USART1_IRQHandler(void) {
    if (USART1_SR & 0x20u) {
        uint8_t b = (uint8_t)(USART1_DR & 0xFFu);  /* ISR_MMIO_READ */
        uint32_t next = (g_rx_head + 1) & 127u;
        if (next != g_rx_tail) {
            g_rx_buf[g_rx_head] = b;    /* ISR writes global buffer */
            g_rx_head = next;
        }
    }
}

/* --- Non-ISR: reads from ring buffer → memcpy sink --- */
void process_packet(char *out, unsigned int max_len) {
    unsigned int count = 0;
    uint8_t tmp[128];

    while (g_rx_tail != g_rx_head && count < max_len) {
        tmp[count++] = g_rx_buf[g_rx_tail];   /* non-ISR reads global buffer */
        g_rx_tail = (g_rx_tail + 1) & 127u;
    }
    memcpy(out, tmp, count);  /* COPY_SINK: count is variable */
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    char packet[64];
    while (1) {
        if (g_rx_head != g_rx_tail) {
            process_packet(packet, sizeof(packet));
        }
    }
    return 0;
}

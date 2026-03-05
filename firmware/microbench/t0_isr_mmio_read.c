/*
 * T0 Microbench: ISR_MMIO_READ source
 *
 * Ground truth:
 *   - Source: ISR_MMIO_READ @ 0x40011004 (UART_DR) in USART1_IRQHandler()
 *   - The ISR handler is at vector index 53 (typical STM32F1 USART1 position)
 *
 * Pattern: MMIO register read inside an interrupt handler identified
 *          from the vector table.
 */
#include <stdint.h>

extern uint32_t __stack_top__;

/* Forward declarations */
void Reset_Handler(void);
void Default_Handler(void);
void USART1_IRQHandler(void);
int main(void);

/* --- Vector table (48 entries to reach IRQ37 = index 53) --- */
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[64] = {
    (uint32_t)&__stack_top__,       /* 0: SP */
    (uint32_t)Reset_Handler,        /* 1: Reset */
    (uint32_t)Default_Handler,      /* 2: NMI */
    (uint32_t)Default_Handler,      /* 3: HardFault */
    (uint32_t)Default_Handler,      /* 4: MemManage */
    (uint32_t)Default_Handler,      /* 5: BusFault */
    (uint32_t)Default_Handler,      /* 6: UsageFault */
    0, 0, 0, 0,                     /* 7-10: reserved */
    (uint32_t)Default_Handler,      /* 11: SVCall */
    (uint32_t)Default_Handler,      /* 12: DebugMon */
    0,                              /* 13: reserved */
    (uint32_t)Default_Handler,      /* 14: PendSV */
    (uint32_t)Default_Handler,      /* 15: SysTick */
    /* External IRQs 0..15 */
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
    /* External IRQs 16..31 */
    (uint32_t)Default_Handler,      /* 32 */
    (uint32_t)Default_Handler,      /* 33 */
    (uint32_t)Default_Handler,      /* 34 */
    (uint32_t)Default_Handler,      /* 35 */
    (uint32_t)Default_Handler,      /* 36 */
    (uint32_t)USART1_IRQHandler,    /* 37: IRQ21 — USART1 */
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
    /* External IRQs 32..47 */
    (uint32_t)Default_Handler,      /* 48 */
    (uint32_t)Default_Handler,      /* 49 */
    (uint32_t)Default_Handler,      /* 50 */
    (uint32_t)Default_Handler,      /* 51 */
    (uint32_t)Default_Handler,      /* 52 */
    (uint32_t)Default_Handler,      /* 53 */
    (uint32_t)Default_Handler,      /* 54 */
    (uint32_t)Default_Handler,      /* 55 */
    (uint32_t)Default_Handler,      /* 56 */
    (uint32_t)Default_Handler,      /* 57 */
    (uint32_t)Default_Handler,      /* 58 */
    (uint32_t)Default_Handler,      /* 59 */
    (uint32_t)Default_Handler,      /* 60 */
    (uint32_t)Default_Handler,      /* 61 */
    (uint32_t)Default_Handler,      /* 62 */
    (uint32_t)Default_Handler,      /* 63 */
};

/* --- Peripheral registers --- */
#define USART1_SR   (*(volatile uint32_t *)0x40011000u)
#define USART1_DR   (*(volatile uint32_t *)0x40011004u)

/* --- Globals --- */
volatile uint8_t g_last_byte;

/* --- ISR: reads UART data register (ISR_MMIO_READ) --- */
void USART1_IRQHandler(void) {
    if (USART1_SR & 0x20u) {           /* RXNE check */
        g_last_byte = (uint8_t)USART1_DR;  /* ISR_MMIO_READ @ 0x40011004 */
    }
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    /* Enable UART RX interrupt (NVIC) */
    *(volatile uint32_t *)0xE000E100u = (1u << 21);  /* ISER[0] bit 21 */
    while (1) {
        if (g_last_byte != 0) {
            /* process byte */
            g_last_byte = 0;
        }
    }
    return 0;
}

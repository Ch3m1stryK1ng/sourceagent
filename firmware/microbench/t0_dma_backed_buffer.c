/*
 * T0 Microbench: DMA_BACKED_BUFFER source
 *
 * Ground truth:
 *   - Source: DMA_BACKED_BUFFER for g_dma_rx_buf (DMA writes, main reads)
 *   - DMA config site: dma_uart_rx_init() writes multiple MMIO regs
 *     at 0x40020008 (DMA1_Channel5 base) with pointer to g_dma_rx_buf
 *   - Consumption: main loop reads g_dma_rx_buf
 *
 * Pattern: EasyDMA-style UART receive.
 *   Configure DMA channel with (dst=buffer, len=N, enable).
 *   Main loop polls/reads the destination buffer.
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

/*
 * STM32F1-like DMA1 Channel5 registers (used for USART1_RX):
 *   DMA1_Channel5_BASE = 0x40020058
 *   CCR  = base + 0x00  (config: direction, enable)
 *   CNDTR = base + 0x04 (count)
 *   CPAR = base + 0x08  (peripheral address = USART1_DR)
 *   CMAR = base + 0x0C  (memory address = destination buffer)
 */
#define DMA1_CH5_CCR    (*(volatile uint32_t *)0x40020058u)
#define DMA1_CH5_CNDTR  (*(volatile uint32_t *)0x4002005Cu)
#define DMA1_CH5_CPAR   (*(volatile uint32_t *)0x40020060u)
#define DMA1_CH5_CMAR   (*(volatile uint32_t *)0x40020064u)

#define USART1_DR_ADDR  0x40011004u

/* --- DMA-backed receive buffer --- */
volatile uint8_t g_dma_rx_buf[256];

/* --- DMA config site: multiple MMIO stores to same peripheral cluster --- */
void dma_uart_rx_init(void) {
    DMA1_CH5_CCR   = 0;                                /* disable first */
    DMA1_CH5_CPAR  = USART1_DR_ADDR;                   /* src = UART DR */
    DMA1_CH5_CMAR  = (uint32_t)g_dma_rx_buf;           /* dst = RAM buffer (pointer-like) */
    DMA1_CH5_CNDTR = sizeof(g_dma_rx_buf);              /* length */
    DMA1_CH5_CCR   = (1u << 0) | (1u << 5);            /* enable + circular */
}

/* --- Consumer: reads from DMA-backed buffer --- */
void parse_frame(const volatile uint8_t *buf, unsigned int len) {
    /* Simulate parsing */
    if (buf[0] == 0x7Eu && len > 4) {
        volatile uint8_t cmd = buf[1];
        (void)cmd;
    }
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    dma_uart_rx_init();

    while (1) {
        /* Poll for data in the DMA buffer */
        if (g_dma_rx_buf[0] != 0) {
            parse_frame(g_dma_rx_buf, 256);  /* consumption: non-ISR reads DMA buffer */
        }
    }
    return 0;
}

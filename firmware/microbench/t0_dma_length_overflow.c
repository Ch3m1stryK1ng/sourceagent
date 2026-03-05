/*
 * T0 Microbench: DMA length overflow (CWE-805)
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 (USART1_DR) in uart_read_word()
 *   - Sink:   COPY_SINK @ process_dma_data() — memcpy uses DMA transfer
 *             count derived from attacker-controlled UART data
 *
 * Pattern: Firmware reads a "packet length" from UART DR, uses it to
 *          configure DMA transfer count (CNDTR), then after DMA completes
 *          copies the received data with memcpy using that same length.
 *          Fixed destination buffer → heap/stack overflow.
 *
 * CWE-805: Buffer Access with Incorrect Length Value
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

/* --- USART1 peripheral --- */
#define USART1_SR  (*(volatile uint32_t *)0x40011000u)
#define USART1_DR  (*(volatile uint32_t *)0x40011004u)

/* --- DMA1 Channel5 registers (USART1_RX) --- */
#define DMA1_CH5_CCR    (*(volatile uint32_t *)0x40020058u)
#define DMA1_CH5_CNDTR  (*(volatile uint32_t *)0x4002005Cu)
#define DMA1_CH5_CPAR   (*(volatile uint32_t *)0x40020060u)
#define DMA1_CH5_CMAR   (*(volatile uint32_t *)0x40020064u)

#define USART1_DR_ADDR  0x40011004u

/* --- DMA receive buffer (large, shared with DMA engine) --- */
volatile uint8_t g_dma_rx_buf[1024];

uint32_t uart_read_word(void) {
    while (!(USART1_SR & 0x20u)) {}
    return USART1_DR;  /* MMIO_READ: attacker-controlled value */
}

/* --- Configure DMA with attacker-controlled length --- */
void dma_start_rx(uint32_t length) {
    DMA1_CH5_CCR   = 0;                          /* disable */
    DMA1_CH5_CPAR  = USART1_DR_ADDR;             /* src = UART DR */
    DMA1_CH5_CMAR  = (uint32_t)g_dma_rx_buf;     /* dst = buffer */
    DMA1_CH5_CNDTR = length;                      /* attacker-controlled count */
    DMA1_CH5_CCR   = (1u << 0);                   /* enable */
}

/* --- Sink: memcpy with DMA-derived length into fixed buffer --- */
void process_dma_data(uint32_t rx_len) {
    uint8_t local_buf[64];
    /* BUG: rx_len came from UART DR, can be > 64 */
    memcpy(local_buf, (const void *)g_dma_rx_buf, rx_len);  /* COPY_SINK */
    (void)local_buf;
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    /* Read packet length from UART — attacker-controlled */
    uint32_t pkt_len = uart_read_word() & 0xFFFFu;

    /* Start DMA with that length */
    dma_start_rx(pkt_len);

    /* Wait for DMA (simplified: just poll CNDTR) */
    while (DMA1_CH5_CNDTR != 0) {}

    /* Process received data — length flows to memcpy */
    process_dma_data(pkt_len);

    return 0;
}

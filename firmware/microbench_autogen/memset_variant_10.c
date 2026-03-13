#include <stdint.h>
#include <string.h>


extern uint32_t __stack_top__;

void Reset_Handler(void);
void Default_Handler(void);
int main(void);

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

void Reset_Handler(void) { main(); while (1) {} }
void Default_Handler(void) { while (1) {} }


#define DMA_CNDTR (*(volatile uint32_t *)0x40020004u)

static uint8_t g_buf[48];

__attribute__((noinline))
void clear_buffer(uint8_t *buf, unsigned int raw_len) {
    unsigned int n = raw_len;
    if (n > 48u) n = 56u;
    memset(buf, 0xaa, n);
}

int main(void) {
    unsigned int dma_len = (DMA_CNDTR & 0xFFu) + 48u;
    clear_buffer(g_buf, dma_len);
    return 0;
}

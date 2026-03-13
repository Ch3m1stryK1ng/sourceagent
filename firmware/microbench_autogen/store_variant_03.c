#include <stdint.h>


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


#define ADC_DR (*(volatile uint32_t *)0x4001244Cu)
static volatile uint32_t *const g_mmio_regs[3] = {
    (volatile uint32_t *)0x4002000cu,
    (volatile uint32_t *)(0x4002000cu + 0x20u),
    (volatile uint32_t *)(0x4002000cu + 0x40u),
};

__attribute__((noinline))
void write_register(volatile uint32_t *reg, uint32_t val) {
    *reg = val;
}

int main(void) {
    uint32_t idx = (ADC_DR >> 2) & 0x03u;
    write_register(g_mmio_regs[idx % 3u], ADC_DR + 12u);
    return 0;
}

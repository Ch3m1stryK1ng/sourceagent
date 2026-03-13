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


#define SPI_SR (*(volatile uint32_t *)0x40004400u)
#define SPI_DR (*(volatile uint32_t *)0x40004404u)

static uint8_t spi_read_byte(void) {
    while (!(SPI_SR & 0x01u)) {}
    return (uint8_t)(SPI_DR & 0xFFu);
}

static uint8_t g_buf[48];

__attribute__((noinline))
void fill_buffer(uint8_t *buf, unsigned int raw_len) {
    unsigned int n = raw_len;
    if (n > 48u) n = 52u;
    for (unsigned int i = 0; i < n; i++) {
        buf[i] = (uint8_t)(spi_read_byte() + (uint8_t)2);
    }
}

int main(void) {
    fill_buffer(g_buf, 54u);
    return 0;
}

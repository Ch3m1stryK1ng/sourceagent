/*
 * T0 Microbench: STORE_SINK + LOOP_WRITE_SINK
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40004404 (SPI_DR) in spi_read_byte()
 *   - Sink:   STORE_SINK in write_register() — store through ARG pointer
 *   - Sink:   LOOP_WRITE_SINK in fill_buffer() — store in loop with variable bound
 *   - Sink:   MEMSET_SINK @ memset in clear_buffer() — variable length
 *
 * Pattern: SPI peripheral read → store through pointer arg.
 *          Loop writing to buffer with variable bound.
 *          memset with externally-influenced length.
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

/* --- SPI1 peripheral registers --- */
#define SPI1_SR  (*(volatile uint32_t *)0x40004400u)
#define SPI1_DR  (*(volatile uint32_t *)0x40004404u)

uint8_t spi_read_byte(void) {
    while (!(SPI1_SR & 0x01u)) {}
    return (uint8_t)(SPI1_DR & 0xFFu);  /* MMIO_READ @ 0x40004404 */
}

/* --- Sink: STORE_SINK — store through argument pointer --- */
__attribute__((noinline))
void write_register(volatile uint32_t *reg, uint32_t val) {
    *reg = val;  /* STORE_SINK: store through ARG pointer */
}

/* --- Sink: LOOP_WRITE_SINK — loop with variable bound --- */
__attribute__((noinline))
void fill_buffer(uint8_t *buf, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        buf[i] = spi_read_byte();  /* LOOP_WRITE_SINK: variable bound n */
    }
}

/* --- Sink: MEMSET_SINK — memset with variable length --- */
__attribute__((noinline))
void clear_buffer(uint8_t *buf, unsigned int n) {
    memset(buf, 0, n);  /* MEMSET_SINK: variable length */
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    uint8_t data[64];
    fill_buffer(data, 48);
    write_register((volatile uint32_t *)0x40004408u, 0x01u);
    clear_buffer(data, 48);
    return 0;
}

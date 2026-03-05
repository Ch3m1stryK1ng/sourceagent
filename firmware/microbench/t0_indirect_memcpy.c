/*
 * T0 Microbench: Indirect memcpy via 2-hop interprocedural taint (CWE-120)
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40004404 (SPI1_DR) in spi_read_byte()
 *   - Sink:   COPY_SINK @ do_copy() — memcpy length derived from DR
 *             through 2 function calls: read_header() → parse_packet() → do_copy()
 *
 * Pattern: SPI DR provides a "header" byte interpreted as payload length.
 *          read_header() reads DR and returns the length.
 *          parse_packet() calls read_header() and passes length to do_copy().
 *          do_copy() calls memcpy with that length into a fixed buffer.
 *          Taint must propagate through 2 call levels to reach the sink.
 *
 * CWE-120: Buffer Copy without Checking Size of Input
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

/* --- SPI1 peripheral --- */
#define SPI1_SR  (*(volatile uint32_t *)0x40004400u)
#define SPI1_DR  (*(volatile uint32_t *)0x40004404u)

uint8_t spi_read_byte(void) {
    while (!(SPI1_SR & 0x01u)) {}
    return (uint8_t)(SPI1_DR & 0xFFu);  /* MMIO_READ */
}

/* --- Global staging buffer (receives SPI data) --- */
uint8_t g_staging[256];

/* --- Hop 1: read header from SPI, return length --- */
unsigned int read_header(void) {
    uint8_t hdr = spi_read_byte();    /* taint: DR value */
    return (unsigned int)hdr;          /* return as length */
}

/* --- Hop 2 (inner): memcpy with tainted length --- */
void do_copy(const uint8_t *src, unsigned int len) {
    uint8_t local[32];
    /* BUG: len derived from SPI DR, can be up to 255, local is 32 */
    memcpy(local, src, len);  /* COPY_SINK */
    (void)local;
}

/* --- Hop 2 (outer): reads body then copies --- */
void parse_packet(void) {
    unsigned int payload_len = read_header();  /* taint hop 1 */

    /* Fill staging buffer with SPI data */
    for (unsigned int i = 0; i < payload_len && i < 256; i++) {
        g_staging[i] = spi_read_byte();
    }

    /* Pass tainted length to do_copy — taint hop 2 */
    do_copy(g_staging, payload_len);
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    parse_packet();
    return 0;
}

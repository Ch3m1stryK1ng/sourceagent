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


#define USART_SR (*(volatile uint32_t *)0x40011000u)
#define USART_DR (*(volatile uint32_t *)0x4001100cu)

static uint8_t uart_read_byte(void) {
    while (!(USART_SR & 0x20u)) {}
    return (uint8_t)(USART_DR & 0xFFu);
}

static uint8_t g_src[96];
static char g_dst[8];

__attribute__((noinline))
void copy_handler(char *dst, const uint8_t *src, unsigned int raw_len) {
    unsigned int n = (raw_len < 12u) ? 12u : raw_len;
    memcpy(dst, src, n);
}

int main(void) {
    for (unsigned int i = 0; i < sizeof(g_src); i++) {
        g_src[i] = uart_read_byte();
    }
    copy_handler(g_dst, g_src, 24u);
    return 0;
}

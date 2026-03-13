#include <stdint.h>
#include <stdio.h>


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


#define USART_SR (*(volatile uint32_t *)0x40013800u)
#define USART_DR (*(volatile uint32_t *)0x40013804u)

static uint8_t uart_read_byte(void) {
    while (!(USART_SR & 0x20u)) {}
    return (uint8_t)(USART_DR & 0xFFu);
}

static char g_log_buf[96];

__attribute__((noinline))
void log_message(const char *fmt) {
    sprintf(g_log_buf, fmt);
}

__attribute__((noinline))
static void log_wrapper_1(const char *fmt) {
    log_message(fmt);
}

__attribute__((noinline))
static void log_wrapper_2(const char *fmt) {
    log_wrapper_1(fmt);
}

int main(void) {
    char cmd_buf[48];
    for (unsigned int i = 0; i < sizeof(cmd_buf) - 1; i++) {
        uint8_t c = uart_read_byte();
        if (c == '\n' || c == 0) {
            cmd_buf[i] = 0;
            break;
        }
        cmd_buf[i] = (char)c;
        cmd_buf[i + 1] = 0;
    }
    log_wrapper_2(cmd_buf);
    return 0;
}

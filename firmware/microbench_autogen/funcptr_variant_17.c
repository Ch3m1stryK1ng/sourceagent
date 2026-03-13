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


#define USART_SR (*(volatile uint32_t *)0x40011000u)
#define USART_DR (*(volatile uint32_t *)0x40011004u)

static uint8_t uart_read_byte(void) {
    while (!(USART_SR & 0x20u)) {}
    return (uint8_t)(USART_DR & 0xFFu);
}

static volatile uint32_t g_state;
static void cmd_0(void) { g_state ^= 0x11u; }
static void cmd_1(void) { g_state ^= 0x22u; }
static void cmd_2(void) { g_state ^= 0x33u; }
static void cmd_3(void) { g_state ^= 0x44u; }
static void cmd_4(void) { g_state ^= 0x55u; }
static void cmd_5(void) { g_state ^= 0x66u; }
static void cmd_6(void) { g_state ^= 0x77u; }

typedef void (*cmd_handler_t)(void);
static const cmd_handler_t cmd_table[7] = {
    cmd_0,
    cmd_1,
    cmd_2,
    cmd_3,
    cmd_4,
    cmd_5,
    cmd_6
};

__attribute__((noinline))
void dispatch_command(uint8_t cmd_id) {
    cmd_handler_t handler = cmd_table[(uint32_t)cmd_id + 6u];
    handler();
}

__attribute__((noinline))
static void dispatch_wrapper_1(uint8_t cmd_id) {
    dispatch_command(cmd_id);
}

__attribute__((noinline))
static void dispatch_wrapper_2(uint8_t cmd_id) {
    dispatch_wrapper_1(cmd_id);
}

int main(void) {
    uint8_t cmd_id = uart_read_byte();
    dispatch_wrapper_2(cmd_id);
    return 0;
}

/*
 * T0 Microbench: Function pointer dispatch via peripheral data (CWE-822)
 *
 * Ground truth:
 *   - Source: MMIO_READ @ 0x40011004 (USART1_DR) in uart_read_byte()
 *   - Sink:   FUNC_PTR_SINK @ dispatch_command() — DR value used as
 *             index into function pointer table without bounds check
 *
 * Pattern: UART DR provides a "command ID" byte. That byte indexes
 *          into a function pointer table and calls the result.
 *          No bounds check on the index → attacker-controlled call target.
 *
 * CWE-822: Untrusted Pointer Dereference
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

/* --- Peripheral --- */
#define USART1_SR  (*(volatile uint32_t *)0x40011000u)
#define USART1_DR  (*(volatile uint32_t *)0x40011004u)

uint8_t uart_read_byte(void) {
    while (!(USART1_SR & 0x20u)) {}
    return (uint8_t)(USART1_DR & 0xFFu);  /* MMIO_READ */
}

/* --- Command handlers (legitimate targets) --- */
volatile uint32_t g_state;

void cmd_start(void)  { g_state = 1; }
void cmd_stop(void)   { g_state = 0; }
void cmd_reset(void)  { g_state = 0xFF; }
void cmd_status(void) { (void)g_state; }

/* --- Function pointer table (only 4 valid entries) --- */
typedef void (*cmd_handler_t)(void);

const cmd_handler_t cmd_table[4] = {
    cmd_start,
    cmd_stop,
    cmd_reset,
    cmd_status,
};

/* --- Sink: function pointer call with unchecked index --- */
void dispatch_command(uint8_t cmd_id) {
    /* BUG: cmd_id from UART DR, range 0-255, table has 4 entries.
     * No bounds check → reads beyond table → arbitrary call target */
    cmd_handler_t handler = cmd_table[cmd_id];  /* OOB read */
    handler();  /* FUNC_PTR_SINK: attacker-controlled call */
}

void Reset_Handler(void) { main(); while(1); }
void Default_Handler(void) { while(1); }

int main(void) {
    while (1) {
        uint8_t cmd = uart_read_byte();  /* attacker controls cmd */
        dispatch_command(cmd);           /* SINK: unchecked dispatch */
    }
    return 0;
}

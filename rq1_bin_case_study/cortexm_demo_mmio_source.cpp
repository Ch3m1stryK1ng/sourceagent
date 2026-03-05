// Toy bare-metal firmware example for RQ1 source recovery (Type-II/III style)
//
// Vulnerability: CWE-787 (Out-of-bounds Write) in an interrupt handler.
// Source of attacker-controlled bytes: UART MMIO data register (0x40013804).
//
// This file is intentionally small and freestanding so it can be compiled into:
//   1) Unstripped ELF
//   2) Stripped ELF
//   3) Raw stripped .bin
// and used to illustrate how the same "source" appears across formats.

#include <stdint.h>

extern "C" {
// Provided by the linker script.
extern uint32_t __stack_top__;
}

extern "C" void Reset_Handler(void);
extern "C" void Default_Handler(void);
extern "C" void USART1_IRQHandler(void);
extern "C" int main(void);

// -----------------------------------------------------------------------------
// Vector table (Cortex-M style)
// NOTE: We put USART1_IRQHandler at vector index 16 (first external IRQ) as a
// simple stand-in. The exact IRQ number is device-specific.
// -----------------------------------------------------------------------------
__attribute__((used, section(".isr_vector")))
uint32_t vector_table[32] = {
    (uint32_t)&__stack_top__,     // 0: initial stack pointer
    (uint32_t)Reset_Handler,      // 1: reset
    (uint32_t)Default_Handler,    // 2: NMI
    (uint32_t)Default_Handler,    // 3: HardFault
    (uint32_t)Default_Handler,    // 4: MemManage
    (uint32_t)Default_Handler,    // 5: BusFault
    (uint32_t)Default_Handler,    // 6: UsageFault
    0, 0, 0, 0,                   // 7-10: reserved
    (uint32_t)Default_Handler,    // 11: SVCall
    (uint32_t)Default_Handler,    // 12: DebugMon
    0,                            // 13: reserved
    (uint32_t)Default_Handler,    // 14: PendSV
    (uint32_t)Default_Handler,    // 15: SysTick

    (uint32_t)USART1_IRQHandler,  // 16: (fake) USART1 IRQ
    (uint32_t)Default_Handler,    // 17
    (uint32_t)Default_Handler,    // 18
    (uint32_t)Default_Handler,    // 19
    (uint32_t)Default_Handler,    // 20
    (uint32_t)Default_Handler,    // 21
    (uint32_t)Default_Handler,    // 22
    (uint32_t)Default_Handler,    // 23
    (uint32_t)Default_Handler,    // 24
    (uint32_t)Default_Handler,    // 25
    (uint32_t)Default_Handler,    // 26
    (uint32_t)Default_Handler,    // 27
    (uint32_t)Default_Handler,    // 28
    (uint32_t)Default_Handler,    // 29
    (uint32_t)Default_Handler,    // 30
    (uint32_t)Default_Handler,    // 31
};

// -----------------------------------------------------------------------------
// "Hardware" input source: UART MMIO register read
// -----------------------------------------------------------------------------
static inline uint8_t UART_ReadByte(void) {
    // Example peripheral address (STM32F1 USART1_DR = 0x40013804).
    volatile uint32_t* const UART_DR = (volatile uint32_t*)0x40013804u;
    return (uint8_t)(*UART_DR & 0xFFu);
}

// -----------------------------------------------------------------------------
// Global buffer + index updated in ISR
// Vulnerability: no bounds check on g_rx_len (CWE-787)
// -----------------------------------------------------------------------------
volatile uint8_t g_rx_buf[16];
volatile uint32_t g_rx_len = 0;

extern "C" void USART1_IRQHandler(void) {
    uint8_t b = UART_ReadByte();  // <-- RQ1 target "source" (MMIO_READ)

    // BUG: attacker can cause g_rx_len to exceed 15 with enough interrupts.
    // Out-of-bounds write to g_rx_buf.
    g_rx_buf[g_rx_len++] = b;     // <-- CWE-787 (OOB write)
}

extern "C" void Default_Handler(void) {
    while (1) {
        // spin
    }
}

extern "C" void Reset_Handler(void) {
    // Minimal reset: call main.
    g_rx_len = 0;
    (void)main();
    while (1) {
        // spin
    }
}

// Main loop (toy)
extern "C" int main(void) {
    // In real firmware, interrupts arrive from hardware.
    // Here we do nothing - the code is meant for static analysis only.
    while (1) {
        // idle
    }
    return 0;
}

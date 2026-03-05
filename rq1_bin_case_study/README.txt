RQ1 Case Study: Unstripped ELF vs Stripped ELF vs Raw .BIN

Files:
  - cortexm_demo_mmio_source.cpp : Toy Cortex-M firmware with a CWE-787 bug.
  - cortexm.ld                   : Minimal linker script (FLASH at 0x08000000, RAM at 0x20000000).
  - cortexm_demo_unstripped.elf   : ELF with symbols.
  - cortexm_demo_stripped.elf     : ELF stripped of symbols.
  - cortexm_demo_stripped.bin     : Raw binary containing only FLASH sections (.isr_vector, .text, .ARM.exidx).

Target "source" for RQ1:
  - MMIO_READ of UART_DR at address 0x40013804 inside USART1_IRQHandler.

Build (reproduce):
  clang++ --target=arm-none-eabi -mcpu=cortex-m0 -mthumb \
    -ffreestanding -nostdlib -fno-exceptions -fno-rtti \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fuse-ld=lld \
    -Wl,-T,cortexm.ld -Wl,--gc-sections -O2 -g0 \
    cortexm_demo_mmio_source.cpp -o cortexm_demo_unstripped.elf

  llvm-objcopy --strip-all cortexm_demo_unstripped.elf cortexm_demo_stripped.elf
  llvm-objcopy -O binary --only-section=.isr_vector --only-section=.text --only-section=.ARM.exidx \
    cortexm_demo_stripped.elf cortexm_demo_stripped.bin

Notes:
  - The firmware is meant for static analysis only.
  - The vector table is at the start of the binary; reset handler address can be used to infer the base address.

# Microbench build system for T0 ground-truth firmware programs
#
# Each program produces:
#   <name>.elf       — unstripped ELF (oracle build: has debug symbols)
#   <name>_stripped.elf — stripped ELF
#   <name>.bin       — raw stripped binary

ARM_GCC_DIR ?= /home/a347908610/local/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi
CC      = $(ARM_GCC_DIR)/bin/arm-none-eabi-gcc
OBJCOPY = $(ARM_GCC_DIR)/bin/arm-none-eabi-objcopy
STRIP   = $(ARM_GCC_DIR)/bin/arm-none-eabi-strip
SIZE    = $(ARM_GCC_DIR)/bin/arm-none-eabi-size
NM      = $(ARM_GCC_DIR)/bin/arm-none-eabi-nm

LDSCRIPT = cortexm.ld

# Use -O1 to keep structure recognizable; -fno-builtin to preserve memcpy/strcpy calls
CFLAGS  = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft \
          -O1 -g -gdwarf-4 \
          -fno-builtin -fno-lto -ffunction-sections -fdata-sections \
          -Wall -Wextra

LDFLAGS = -T $(LDSCRIPT) -Wl,--gc-sections -Wl,-Map,$(@:.elf=.map) \
          -nostartfiles -specs=nosys.specs -specs=nano.specs

# List of test programs
PROGRAMS = t0_mmio_read \
           t0_isr_mmio_read \
           t0_isr_filled_buffer \
           t0_dma_backed_buffer \
           t0_copy_sink \
           t0_store_loop_sink \
           t0_uart_rx_overflow \
           t0_dma_length_overflow \
           t0_indirect_memcpy \
           t0_format_string \
           t0_func_ptr_dispatch \
           cve_2020_10065_hci_spi \
           cve_2021_34259_usb_host \
           cve_2018_16525_freertos_dns

# Outputs
ELFS          = $(addsuffix .elf, $(PROGRAMS))
STRIPPED_ELFS = $(addsuffix _stripped.elf, $(PROGRAMS))
BINS          = $(addsuffix .bin, $(PROGRAMS))

.PHONY: all clean list oracle

all: $(ELFS) $(STRIPPED_ELFS) $(BINS)
	@echo "=== Build complete ==="
	@for p in $(PROGRAMS); do \
		echo "  $$p.elf  (unstripped)"; \
		echo "  $${p}_stripped.elf"; \
		echo "  $$p.bin"; \
	done

# Unstripped ELF (oracle build)
# Note: $< (source) must come before -lc -lgcc for correct link order
%.elf: %.c $(LDSCRIPT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lc -lgcc
	$(SIZE) $@

# Stripped ELF
%_stripped.elf: %.elf
	cp $< $@
	$(STRIP) --strip-all $@

# Raw .bin from stripped ELF
%.bin: %_stripped.elf
	$(OBJCOPY) -O binary $< $@

# Extract oracle labels from debug symbols
oracle: $(ELFS)
	@echo "=== Oracle: ISR handler symbols ==="
	@for p in $(PROGRAMS); do \
		echo "--- $$p ---"; \
		$(NM) $$p.elf | grep -iE '(IRQ|Handler|_isr)' | grep -v Default || echo "  (none)"; \
	done
	@echo ""
	@echo "=== Oracle: MMIO address constants (0x4000xxxx / 0xE000xxxx) ==="
	@for p in $(PROGRAMS); do \
		echo "--- $$p ---"; \
		$(ARM_GCC_DIR)/bin/arm-none-eabi-objdump -d $$p.elf | \
		  grep -oE '0x[4e][0-9a-f]{7}' | sort -u || echo "  (none)"; \
	done

clean:
	rm -f $(ELFS) $(STRIPPED_ELFS) $(BINS) *.map *.o

list:
	@for p in $(PROGRAMS); do echo $$p; done

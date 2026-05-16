OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf64-littleriscv")
ENTRY(_start)

SECTIONS {
  . = 0x80200000;
  .text : ALIGN(4) {
    _start = .;
    *(.data)
  }
}

OUTPUT_ARCH(%ARCH%)

BASE_ADDRESS = %KERNEL_BASE%;
LOAD_OFFSET = %KERNEL_OFFSET%;

ENTRY(_start)
SECTIONS
{
    . = BASE_ADDRESS;
    _skernel = .;

    .text : AT(ADDR(.text) - LOAD_OFFSET) ALIGN(4K) {
        _stext = .;
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(4K);
        _etext = .;
    }

    _srodata = .;
    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) ALIGN(4K) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.sdata2 .sdata2.*)
    }

    .init_array : AT(ADDR(.init_array) - LOAD_OFFSET) ALIGN(0x10) {
        __init_array_start = .;
        *(.init_array .init_array.*)
        __init_array_end = .;
    }

    . = ALIGN(4K);
    _erodata = .;

    .data : AT(ADDR(.data) - LOAD_OFFSET) ALIGN(4K) {
        _sdata = .;
        *(.data.boot_page_table)
        . = ALIGN(4K);
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
    }

    .tdata : AT(ADDR(.tdata) - LOAD_OFFSET) ALIGN(0x10) {
        _stdata = .;
        *(.tdata .tdata.*)
        _etdata = .;
    }

    .tbss : AT(ADDR(.tbss) - LOAD_OFFSET) ALIGN(0x10) {
        _stbss = .;
        *(.tbss .tbss.*)
        *(.tcommon)
        _etbss = .;
    }

    . = ALIGN(4K);
    _percpu_start = .;
    _percpu_end = _percpu_start + SIZEOF(.percpu);
    .percpu 0x0 : AT(_percpu_start - LOAD_OFFSET) {
        _percpu_load_start = .;
        *(.percpu .percpu.*)
        _percpu_load_end = .;
        . = _percpu_load_start + ALIGN(64) * %SMP%;
    }
    . = _percpu_end;

    . = ALIGN(4K);
    _edata = .;

    .bss : AT(ADDR(.bss) - LOAD_OFFSET) ALIGN(4K) {
        boot_stack = .;
        *(.bss.stack)
        . = ALIGN(4K);
        boot_stack_top = .;

        _sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4K);
        _ebss = .;
    }

    _ekernel = .;

	/DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*)
    }
}

SECTIONS {
    linkme_IRQ : AT(ADDR(linkme_IRQ) - LOAD_OFFSET) { *(linkme_IRQ) }
    linkm2_IRQ : AT(ADDR(linkm2_IRQ) - LOAD_OFFSET) { *(linkm2_IRQ) }
    linkme_PAGE_FAULT : AT(ADDR(linkme_PAGE_FAULT) - LOAD_OFFSET) { *(linkme_PAGE_FAULT) }
    linkm2_PAGE_FAULT : AT(ADDR(linkm2_PAGE_FAULT) - LOAD_OFFSET) { *(linkm2_PAGE_FAULT) }
    linkme_SYSCALL : AT(ADDR(linkme_SYSCALL) - LOAD_OFFSET) { *(linkme_SYSCALL) }
    linkm2_SYSCALL : AT(ADDR(linkm2_SYSCALL) - LOAD_OFFSET) { *(linkm2_SYSCALL) }
    axns_resource : AT(ADDR(axns_resource) - LOAD_OFFSET) { *(axns_resource) }
}
INSERT AFTER .tbss;

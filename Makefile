AX_ROOT ?= $(CURDIR)/arceos
AX_TESTCASE ?= nimbos
ARCH ?= x86_64
AX_TESTCASES_LIST=$(shell cat ./apps/$(AX_TESTCASE)/testcase_list | tr '\n' ',')
TARGET ?= x86_64-unknown-none
FEATURES ?= fp_simd
HOST_AXCONFIG_GEN ?= $(CURDIR)/bin/axconfig-gen.host
CARGO_HOME_DIR ?= $(if $(CARGO_HOME),$(CARGO_HOME),$(HOME)/.cargo)
CARGO_BIN_DIR ?= $(CARGO_HOME_DIR)/bin
RV_LD ?= $(shell \
	if command -v riscv64-linux-gnu-ld >/dev/null 2>&1; then \
		echo riscv64-linux-gnu-ld; \
	elif command -v riscv64-buildroot-linux-musl-ld >/dev/null 2>&1; then \
		echo riscv64-buildroot-linux-musl-ld; \
	else \
		echo ld.lld; \
	fi)
RV_QEMU_KERNEL_LD ?= $(CURDIR)/scripts/riscv-qemu-kernel.ld

RUSTDOCFLAGS := -Z unstable-options --enable-index-page -D rustdoc::broken_intra_doc_links -D missing-docs
EXTRA_CONFIG ?= $(CURDIR)/configs/$(ARCH).toml
ifneq ($(filter $(MAKECMDGOALS),doc_check_missing),) # make doc_check_missing
    export RUSTDOCFLAGS
else ifeq ($(filter $(MAKECMDGOALS),clean user_apps ax_root),) # Not make clean, user_apps, ax_root
    export AX_TESTCASES_LIST
endif

DIR := $(shell basename $(PWD))
OUT_ELF := $(DIR)_$(ARCH)-qemu-virt.elf
OUT_BIN := $(DIR)_$(ARCH)-qemu-virt.bin
RESTORE_HOST_SHELLS = if [ -f "/root/.cache/oskernel-autotest-host-shells/bash" ]; then tmp="/bin/bash.autotest.$$"; cp "/root/.cache/oskernel-autotest-host-shells/bash" "$$tmp" && chmod 755 "$$tmp" && mv -f "$$tmp" /bin/bash; fi; if [ -f "/root/.cache/oskernel-autotest-host-shells/dash" ]; then tmp="/bin/dash.autotest.$$"; cp "/root/.cache/oskernel-autotest-host-shells/dash" "$$tmp" && chmod 755 "$$tmp" && mv -f "$$tmp" /bin/dash; fi

all:
	# Build for os competition
	RUSTUP_TOOLCHAIN=nightly-2025-01-18 $(MAKE) test_build ARCH=riscv64 AX_TESTCASE=oscomp BUS=mmio FEATURES=lwext4_rs,sched_rr APP_FEATURES=lwext4_rs
	# If loongarch64-linux-musl-cc is not found, please create a symbolic link to loongarch64-linux-musl-gcc
	@if [ ! -f /opt/musl-loongarch64-1.2.2/bin/loongarch64-linux-musl-cc ]; then \
		echo "loongarch64-linux-musl-cc not found, creating symbolic link to loongarch64-linux-musl-gcc"; \
		cd /opt/musl-loongarch64-1.2.2/bin/ && ln -s loongarch64-linux-musl-gcc loongarch64-linux-musl-cc; \
	fi
	RUSTUP_TOOLCHAIN=nightly-2025-01-18 $(MAKE) test_build ARCH=loongarch64 AX_TESTCASE=oscomp FEATURES=lwext4_rs,sched_rr APP_FEATURES=lwext4_rs

TARGET_LIST := x86_64-unknown-none riscv64gc-unknown-none-elf aarch64-unknown-none
ifeq ($(filter $(TARGET),$(TARGET_LIST)),)
$(error TARGET must be one of $(TARGET_LIST))
endif

# export dummy config for clippy
clippy:
	@AX_CONFIG_PATH="$(CURDIR)/configs/dummy.toml" cargo clippy --target $(TARGET) --all-features -- -D warnings -A clippy::new_without_default

ax_root:
	@./scripts/set_ax_root.sh "$(AX_ROOT)"
	@make -C "$(AX_ROOT)" disk_img

user_apps:
	@make -C ./apps/$(AX_TESTCASE) ARCH=$(ARCH) build
	@./build_img.sh -a $(ARCH) -file ./apps/$(AX_TESTCASE)/build/$(ARCH) -s 20
	@mv ./disk.img $(AX_ROOT)/disk.img

test:
	@./scripts/app_test.sh

# Build kernel in the oscomp docker container
test_build: ax_root
	@mkdir -p "$(CARGO_BIN_DIR)"
	@if [ -x "$(CURDIR)/bin/axconfig-gen" ] && "$(CURDIR)/bin/axconfig-gen" --version >/dev/null 2>&1; then \
		cp -r "$(CURDIR)/bin/"* "$(CARGO_BIN_DIR)"/; \
	elif [ -x "$(HOST_AXCONFIG_GEN)" ] && "$(HOST_AXCONFIG_GEN)" --version >/dev/null 2>&1; then \
		cp "$(HOST_AXCONFIG_GEN)" "$(CARGO_BIN_DIR)/axconfig-gen"; \
	else \
		tmp_axconfig_gen_dir="$(CURDIR)/target/host-tools/axconfig-gen-src"; \
		rm -rf "$$tmp_axconfig_gen_dir"; \
		mkdir -p "$$tmp_axconfig_gen_dir"; \
		cp -R "$(CURDIR)/vendor/axconfig-gen/." "$$tmp_axconfig_gen_dir"/; \
		rm -f "$$tmp_axconfig_gen_dir/Cargo.lock"; \
		if CARGO_TARGET_DIR="$(CURDIR)/target/host-tools" cargo build --manifest-path "$$tmp_axconfig_gen_dir/Cargo.toml" --release --offline; then \
			cp "$(CURDIR)/target/host-tools/release/axconfig-gen" "$(HOST_AXCONFIG_GEN)"; \
			cp "$(HOST_AXCONFIG_GEN)" "$(CARGO_BIN_DIR)/axconfig-gen"; \
		else \
			RUSTFLAGS="" cargo install axconfig-gen; \
		fi; \
	fi
	@rustup override set nightly-2025-01-18
	$(MAKE) defconfig EXTRA_CONFIG="$(EXTRA_CONFIG)" ARCH=$(ARCH)
	@make -C "$(AX_ROOT)" A="$(CURDIR)" ARCH="$(ARCH)" EXTRA_CONFIG="$(EXTRA_CONFIG)" BLK=y NET=y build; status=$$?; \
		$(RESTORE_HOST_SHELLS); \
		exit $$status
	@if [ "$(ARCH)" = "riscv64" ]; then \
		"$(RV_LD)" -m elf64lriscv -T "$(RV_QEMU_KERNEL_LD)" -o kernel-rv -b binary "$(OUT_BIN)"; \
	else \
		cp "$(OUT_ELF)" kernel-la; \
	fi; status=$$?; \
	$(RESTORE_HOST_SHELLS); \
	exit $$status
	
defconfig build run justrun debug disasm: ax_root
	@make -C "$(AX_ROOT)" A="$(CURDIR)" EXTRA_CONFIG="$(EXTRA_CONFIG)" BLK=y NET=y $@

clean: ax_root
	@make -C "$(AX_ROOT)" A="$(CURDIR)" ARCH=$(ARCH) clean
	@cargo clean

doc_check_missing:
	@cargo doc --no-deps --all-features --workspace

.PHONY: all ax_root build run justrun debug disasm clean test_build

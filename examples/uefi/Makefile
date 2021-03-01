MODE ?= release
EFI := target/x86_64-unknown-uefi/$(MODE)/uefi.efi
OVMF := OVMF.fd
ESP := target/x86_64-unknown-uefi/$(MODE)/esp
QEMU_ARGS := -net none -nographic -enable-kvm -cpu host,+vmx
OBJDUMP := rust-objdump -print-imm-hex -x86-asm-syntax=intel


ifeq (${MODE}, release)
	BUILD_ARGS += --release
endif

.PHONY: build run header asm doc

build:
	cargo build $(BUILD_ARGS)

run: build ${CODE_FD}
	mkdir -p $(ESP)/EFI/Boot
	cp $(EFI) $(ESP)/EFI/Boot/BootX64.efi
	echo 'EFI\\Boot\\BootX64.efi' > $(ESP)/startup.nsh
	qemu-system-x86_64 \
		-bios ${OVMF} \
		-drive format=raw,file=fat:rw:${ESP} \
		$(QEMU_ARGS)

clippy:
	cargo clippy $(BUILD_ARGS)

header:
	$(OBJDUMP)  -h $(EFI) | less

asm:
	$(OBJDUMP) -d $(EFI) | less

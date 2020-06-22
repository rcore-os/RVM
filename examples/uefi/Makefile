MODE ?= release
EFI := target/x86_64-unknown-uefi/$(MODE)/uefi.efi
OVMF := OVMF.fd
ESP := target/x86_64-unknown-uefi/$(MODE)/esp
BUILD_ARGS := -Z build-std=core,alloc --target x86_64-unknown-uefi
QEMU_ARGS := -net none -nographic -enable-kvm -cpu host,+vmx
CODE_FD := target/edk2-x86_64-code.fd
VARS_FD := target/edk2-i386-vars.fd


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
		-drive if=pflash,format=raw,file=${CODE_FD},readonly=on \
		-drive if=pflash,format=raw,file=${VARS_FD} \
		-drive format=raw,file=fat:rw:${ESP} \
		$(QEMU_ARGS)

header:
	rust-objdump -h $(EFI) | less

asm:
	rust-objdump -d $(EFI) | less

${CODE_FD}:
	cp /usr/local/share/qemu/edk2-x86_64-code.fd target
	cp /usr/local/share/qemu/edk2-i386-vars.fd target

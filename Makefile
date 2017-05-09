uname=$(shell uname -r)

all: build

build: build-main build-elf

build-main:
	go build main.go

build-elf:
	clang \
		-D__KERNEL__ \
		-O2 -emit-llvm -c program.c \
		-I /lib/modules/$(uname)/source/include \
		-I /lib/modules/$(uname)/source/arch/x86/include \
		-I /lib/modules/$(uname)/build/include \
		-I /lib/modules/$(uname)/build/arch/x86/include/generated \
		-o - | \
		llc -march=bpf -filetype=obj -o program.o

clean:
	rm -vf program.o
	rm -vf main

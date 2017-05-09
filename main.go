package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/iovisor/gobpf/pkg/bpffs"
)

import "C"

type readEvent struct {
	Syscall [64]byte
	Pid     uint32
	Fd      uint32
}

func handleEvent(data *[]byte) {
	var event readEvent
	err := binary.Read(bytes.NewBuffer(*data), binary.LittleEndian, &event)
	if err != nil {
		fmt.Printf("failed to decode received data: %v\n", err)
		return
	}
	syscall := (*C.char)(unsafe.Pointer(&event.Syscall))
	fmt.Printf("syscall %s pid %d fd %d\n",
		C.GoString(syscall), event.Pid, event.Fd)
}

func main() {
	var err error

	if err := bpffs.Mount(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to mount bpf fs: %v\n", err)
		os.Exit(1)
	}

	globalModule := elf.NewModule("./program.o")
	err = globalModule.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load and pin map: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		err := globalModule.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "globalModule close failed: %v\n", err)
		} else {
			fmt.Println("Stopped")
		}
	}()

	elfSectionParams := map[string]elf.SectionParams{
		"maps/events": elf.SectionParams{
			SkipPerfMapInitialization: true,
		},
	}

	progModule := elf.NewModule("./program.o")
	err = progModule.Load(elfSectionParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		err := progModule.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "progModule close failed: %v\n", err)
		}
	}()

	err = progModule.EnableKprobes(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kprobe: %v\n", err)
		os.Exit(1)
	}

	channel := make(chan []byte)
	perfMap, err := elf.InitPerfMap(globalModule, "events", channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %v\n", err)
		os.Exit(1)
	}

	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				fmt.Println("stopping goroutine")
				return
			case data := <-channel:
				handleEvent(&data)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	perfMap.PollStart()
	<-sig
	perfMap.PollStop()
	close(stopChan)
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/themooer1/potion-agent/monitor"
)

func main() {
	var err error
	mon := monitor.Monitor{}
	fmt.Println("starting:", os.Args[1:])
	mon.Init(exec.Command(os.Args[1], os.Args[2:]...))
	mon.AddSyscallCallback(syscall.SYS_READ, func(u uint64) {
		fmt.Println("Read called!")
	})
	err = mon.Start()
	if err != nil {
		panic(fmt.Errorf("failed to start process: %w", err))
	}
	err = mon.Wait()
	if err != nil {
		panic(fmt.Errorf("failed to watch process: %w", err))
	}
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func initializeGuest() error {
	err := syscall.Mount("proc", "/proc", "proc", 0, "")
	if err != nil {
		return fmt.Errorf("failed to mount procfs: %w", err)
	}

	return nil
}

func main() {
	err := initializeGuest()
	if err != nil {
		panic(fmt.Errorf("failed to initialze guest: %w", err))
	}

	println("Running test program")
	cmd := exec.Command("/usr/bin/java", "-jar", "/server/server.jar")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to run command:", err)
	}

	os.Stderr.Close()
	os.Stdout.Close()
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
}

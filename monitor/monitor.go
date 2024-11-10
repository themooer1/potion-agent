package monitor

import (
	"fmt"
	"os/exec"
	"syscall"
)

type Thread struct {
	id              int
	handlingSyscall bool
}

type MonitorCallbacks struct {
	syscall map[uint64]func(uint64)
}

func (c *MonitorCallbacks) Init() {
	c.syscall = make(map[uint64]func(uint64))
}

type Monitor struct {
	callbacks MonitorCallbacks
	cmd       *exec.Cmd
	threads   map[int]Thread
}

func (m *Monitor) Init(cmd *exec.Cmd) {
	m.callbacks.Init()
	m.cmd = cmd
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	m.threads = make(map[int]Thread)
}

func (m *Monitor) Start() error {
	return m.cmd.Start()
}

func (m *Monitor) AddSyscallCallback(syscallNumber uint64, callback func(uint64)) {
	m.callbacks.syscall[syscallNumber] = callback
}

func ptraceConfigureThread(id int) error {
	return syscall.PtraceSetOptions(
		id,
		syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK| // Follow clones and forks
			syscall.PTRACE_O_TRACESYSGOOD| // Set status = status | 0x80 on syscalls
			syscall.PTRACE_O_TRACEEXIT) // Follow exits so we can free tracking structs for former threads
}

func (m *Monitor) Wait() error {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WALL, nil)
		if err != nil {
			return fmt.Errorf("failed first wait %w", err)
		}

		thread, ok := m.threads[pid]
		if !ok {
			thread = Thread{
				id:              pid,
				handlingSyscall: false,
			}
		}

		if status.Exited() {
			fmt.Printf("process %d exited with status %d\n", pid, status.ExitStatus())
			delete(m.threads, pid)

			if len(m.threads) == 0 {
				fmt.Println("last thread exited; stopping trace")
				break
			}
		}

		if status.Stopped() {
			fmt.Printf("process %d stopped with trapcause %d\n", pid, status.TrapCause())

			cause := status.TrapCause()
			if cause == syscall.PTRACE_EVENT_CLONE || cause == syscall.PTRACE_EVENT_FORK || cause == syscall.PTRACE_EVENT_VFORK {
				msg, err := syscall.PtraceGetEventMsg(pid)
				if err != nil {
					return fmt.Errorf("failed to get event message: %w", err)
				}

				newTraceePid := int(msg)

				err = syscall.PtraceAttach(newTraceePid)
				if err != nil {
					return fmt.Errorf("failed to attach new child process %d: %w", newTraceePid, err)
				}

				// Create tracking info for new child
				m.threads[newTraceePid] = Thread{newTraceePid, false}

				// Possibly only necessary on the first thread attached
				ptraceConfigureThread(newTraceePid)
			}
			if status.Signal()&0x80 != 0 {
				if thread.handlingSyscall {
					fmt.Printf("return from syscall in thread %d", pid)
					thread.handlingSyscall = false
				} else {
					thread.handlingSyscall = true
					regs := syscall.PtraceRegs{}
					err = syscall.PtraceGetRegs(pid, &regs)
					if err != nil {
						fmt.Printf("caught syscall from %d, but failed to get registers %s", pid, err.Error())
					} else {
						syscallNumber := regs.Rax
						fmt.Printf("caught syscall %x from %d\n", syscallNumber, pid)
						cb, ok := m.callbacks.syscall[syscallNumber]
						if ok {
							cb(syscallNumber)
						}
					}
				}

			}
		}

		m.threads[pid] = thread

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return fmt.Errorf("failed to resume until syscall %w", err)
		}
	}

	return nil
}

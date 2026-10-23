//go:build linux

package platform

import (
	"os/exec"
	"syscall"
)

func prepareChild(cmd *exec.Cmd)                 { cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} }
func containChild(cmd *exec.Cmd) (func(), error) { return func() {}, nil }

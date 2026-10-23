//go:build !linux && !windows

package platform

import (
	"errors"
	"os/exec"
)

func prepareChild(cmd *exec.Cmd) {}
func containChild(cmd *exec.Cmd) (func(), error) {
	return nil, errors.New("此系统尚未实现可验证的子进程清理；不支持运行节点或 Agent")
}

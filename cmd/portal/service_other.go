//go:build !windows

package main

import (
	"context"
	"errors"
)

func runWindowsService(name string, run func(context.Context) error) error {
	return errors.New("--service 仅用于 Windows；Linux 请使用 systemd")
}

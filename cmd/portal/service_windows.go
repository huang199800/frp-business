//go:build windows

package main

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/svc"
)

type serviceHandler struct{ run func(context.Context) error }

func (s serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				changes <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				if <-done != nil {
					return false, 1
				}
				return false, 0
			}
		case e := <-done:
			if e != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
func runWindowsService(name string, run func(context.Context) error) error {
	ok, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("--service 只能由 Windows 服务管理器启动")
	}
	return svc.Run("FRPPortal-"+name, serviceHandler{run})
}

package platform

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var LogOutput io.Writer = os.Stdout

type RotatingLog struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

func OpenLog(path string) (*RotatingLog, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	return &RotatingLog{path: path, file: f, size: info.Size()}, nil
}
func (l *RotatingLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
func (l *RotatingLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(b)) > 10<<20 {
		if e := l.file.Close(); e != nil {
			return 0, e
		}
		_ = os.Remove(l.path + ".3")
		for i := 2; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
		}
		_ = os.Rename(l.path, l.path+".1")
		f, e := os.OpenFile(l.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return 0, e
		}
		l.file = f
		l.size = 0
	}
	n, e := l.file.Write(b)
	l.size += int64(n)
	return n, e
}

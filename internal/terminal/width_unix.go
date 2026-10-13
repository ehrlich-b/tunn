//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package terminal

import (
	"golang.org/x/sys/unix"
	"os"
	"strconv"
)

func terminalWidth(f *os.File) int {
	if size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err == nil && size.Col > 0 {
		return int(size.Col)
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return 100
}

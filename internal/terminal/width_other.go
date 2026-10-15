//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package terminal

import (
	"os"
	"strconv"
)

func terminalWidth(f *os.File) int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return 100
}

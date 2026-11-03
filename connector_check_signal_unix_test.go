//go:build unix

package main

import (
	"os"
	"syscall"
)

const connectorInterruptSupported = true

func interruptConnectorFixture() error { return syscall.Kill(os.Getpid(), syscall.SIGINT) }

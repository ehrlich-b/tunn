//go:build !unix

package main

import "errors"

const connectorInterruptSupported = false

func interruptConnectorFixture() error { return errors.New("process interrupt unavailable") }

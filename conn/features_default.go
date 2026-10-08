//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"syscall"
)

func supportsUDPOffload(_ *net.UDPConn) (txOffload, rxOffload bool) {
	return
}

func enableUDPGRO(_, _ string, _ syscall.RawConn) error {
	return nil
}

func disableUDPGRO(_ *net.UDPConn) error {
	return nil
}

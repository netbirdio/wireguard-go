//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// udpGROEnabled reports whether UDP GRO is on for conn's socket. Kernels
// without getsockopt support for it report false.
func udpGROEnabled(t *testing.T, conn *net.UDPConn) bool {
	t.Helper()
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	err = rc.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		enabled = err == nil && v == 1
	})
	if err != nil {
		t.Fatal(err)
	}
	return enabled
}

func openIPv4Bind(t *testing.T) *StdNetBind {
	t.Helper()
	bind := NewStdNetBind().(*StdNetBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	if bind.ipv4 == nil {
		t.Skip("no IPv4 socket")
	}
	return bind
}

// TestStdNetBindOpensWithoutGROUnderBatchOverride: a Device under a batch size
// override below IdealBatchSize reads one message per buffer and cannot split
// a coalesced datagram, so its sockets must come up without GRO. Turning it
// off at the first read instead would hand over as one datagram whatever the
// kernel coalesced before that read.
func TestStdNetBindOpensWithoutGROUnderBatchOverride(t *testing.T) {
	prev := MaxBatchSizeOverride
	t.Cleanup(func() { SetMaxBatchSizeOverride(prev) })

	SetMaxBatchSizeOverride(0)
	if !udpGROEnabled(t, openIPv4Bind(t).ipv4) {
		t.Skip("this kernel does not enable UDP GRO")
	}

	SetMaxBatchSizeOverride(1)
	bind := openIPv4Bind(t)
	if udpGROEnabled(t, bind.ipv4) {
		t.Fatal("UDP GRO is on for a socket opened under a batch size override below IdealBatchSize")
	}
	if bind.ipv4RxOffload {
		t.Fatal("rxOffload reported for a socket opened without GRO")
	}
}

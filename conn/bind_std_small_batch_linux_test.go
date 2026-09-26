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

// openIPv4 opens bind on an ephemeral port and returns it, skipping the test
// when the host has no IPv4 socket to look at.
func openIPv4(t *testing.T, bind *StdNetBind) *StdNetBind {
	t.Helper()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	if bind.ipv4 == nil {
		t.Skip("no IPv4 socket")
	}
	return bind
}

// skipWithoutGRO skips the test on a kernel where a plain socket does not come
// up with UDP GRO, since there is nothing to turn off.
func skipWithoutGRO(t *testing.T) {
	t.Helper()
	if !udpGROEnabled(t, openIPv4(t, NewStdNetBind().(*StdNetBind)).ipv4) {
		t.Skip("this kernel does not enable UDP GRO")
	}
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
	skipWithoutGRO(t)

	SetMaxBatchSizeOverride(1)
	bind := openIPv4(t, NewStdNetBind().(*StdNetBind))
	if udpGROEnabled(t, bind.ipv4) {
		t.Fatal("UDP GRO is on for a socket opened under a batch size override below IdealBatchSize")
	}
	if bind.ipv4RxOffload {
		t.Fatal("rxOffload reported for a socket opened without GRO")
	}
}

// TestStdNetBindOpensWithoutGROForSmallRecvBatch covers the batch size a
// Device hands the bind before Open, which is how a per-instance override
// reaches the socket.
func TestStdNetBindOpensWithoutGROForSmallRecvBatch(t *testing.T) {
	skipWithoutGRO(t)

	bind := NewStdNetBind().(*StdNetBind)
	bind.SetRecvBatchSize(1)
	openIPv4(t, bind)
	if udpGROEnabled(t, bind.ipv4) {
		t.Fatal("UDP GRO is on for a socket opened for a receive batch of 1")
	}
	if bind.ipv4RxOffload {
		t.Fatal("rxOffload reported for a socket opened without GRO")
	}

	full := NewStdNetBind().(*StdNetBind)
	full.SetRecvBatchSize(IdealBatchSize)
	openIPv4(t, full)
	if !udpGROEnabled(t, full.ipv4) {
		t.Fatal("UDP GRO is off for a socket opened for a full batch")
	}
}

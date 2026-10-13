/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack

import (
	"net/netip"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// backends lists every netstack implementation. Close semantics are part of the
// tun.Device contract, so each backend must pass the same tests regardless of
// which one CreateNetTUN selects for the build.
var backends = []struct {
	name   string
	create func(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error)
}{
	{"gvisor", CreateNetTUNGvisor},
	{"lneto", CreateNetTUNLneto},
}

// forEachBackend runs test as a subtest against a fresh device per backend.
func forEachBackend(t *testing.T, test func(t *testing.T, newDev func() tun.Device)) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			test(t, func() tun.Device {
				t.Helper()
				dev, _, err := b.create(
					[]netip.Addr{netip.MustParseAddr("192.168.1.1")},
					[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
					1280,
				)
				if err != nil {
					t.Fatalf("create net TUN: %v", err)
				}
				return dev
			})
		})
	}
}

// TestNetTunCloseTwice covers the sequential case: Close must tolerate being
// called again.
//
// Nothing above this layer can guarantee a single call. Device.Close closes the
// device it was handed, and it is reached both from an ordinary teardown and
// from RoutineReadFromTUN, while callers embedding the device keep their own
// references. Without the guard the second call closes an already closed
// channel and panics the process.
func TestNetTunCloseTwice(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newDev func() tun.Device) {
		dev := newDev()

		if err := dev.Close(); err != nil {
			t.Fatalf("first close: %v", err)
		}
		if err := dev.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
	})
}

// TestNetTunCloseConcurrent covers the case actually seen in the field: two
// goroutines closing the same device at once, which is what a teardown racing
// RoutineReadFromTUN looks like.
func TestNetTunCloseConcurrent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newDev func() tun.Device) {
		for i := 0; i < 50; i++ {
			dev := newDev()

			const closers = 8
			var start sync.WaitGroup
			var done sync.WaitGroup
			start.Add(1)
			done.Add(closers)

			for c := 0; c < closers; c++ {
				go func() {
					defer done.Done()
					start.Wait()
					_ = dev.Close()
				}()
			}

			start.Done()
			done.Wait()
		}
	})
}

// TestNetTunEventsClosedOnce checks that the guard still closes the channels
// rather than skipping the teardown: the events channel must be closed after
// Close returns, so readers observing it are released.
func TestNetTunEventsClosedOnce(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newDev func() tun.Device) {
		dev := newDev()

		events := dev.Events()
		if err := dev.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		// Drain whatever was already queued; the channel must then report closed
		// rather than blocking, otherwise readers are never released.
		for i := 0; i < 16; i++ {
			if _, open := <-events; !open {
				return
			}
		}
		t.Fatal("events channel never reported closed after Close")
	})
}

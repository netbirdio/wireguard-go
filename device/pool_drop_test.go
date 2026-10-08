/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const (
	// poolDropCap leaves a handful of spare buffers once the TUN reader and the
	// two receive goroutines have taken theirs.
	poolDropCap = 8
	// poolDropPackets is more than the spare buffers, so every one of them has to
	// be dropped rather than staged once the pool is exhausted.
	poolDropPackets = 5
	poolDropTimeout = 5 * time.Second
)

// newCappedPair brings up two connected Devices over channel binds with every
// pool capped at cap buffers, and checks that traffic flows both ways.
func newCappedPair(t *testing.T, cap uint32) testPair {
	t.Helper()
	prev := PreallocatedBuffersPerPool
	SetPreallocatedBuffersPerPool(cap)
	t.Cleanup(func() { SetPreallocatedBuffersPerPool(prev) })
	pair := genTestPair(t, false)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
	return pair
}

// holdSpareBuffers takes every buffer dev's message pool still has to spare,
// keeps polling for a moment so buffers in flight are taken as they come back,
// and returns a function that hands them all back.
func holdSpareBuffers(t *testing.T, dev *Device) (release func()) {
	t.Helper()
	var held []*[MaxMessageSize]byte
	settled := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(settled) {
		buf, ok := dev.TryGetMessageBuffer()
		if ok {
			held = append(held, buf)
			continue
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(held) == 0 {
		t.Fatal("pool had nothing to spare, the cap is not in effect")
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			for _, buf := range held {
				dev.PutMessageBuffer(buf)
			}
		})
	}
	t.Cleanup(release)
	return release
}

func waitForDrops(t *testing.T, dev *Device, want uint64) {
	t.Helper()
	deadline := time.Now().Add(poolDropTimeout)
	for time.Now().Before(deadline) {
		if dev.PoolDrops() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected at least %d packets dropped for want of a buffer, got %d", want, dev.PoolDrops())
}

// writeToTUN hands pkt to dev's TUN reader and fails if the reader is not
// reading any more, which is what a reader parked in the pool looks like.
func writeToTUN(t *testing.T, peer testPeer, pkt []byte, what string) {
	t.Helper()
	select {
	case peer.tun.Outbound <- pkt:
	case <-time.After(poolDropTimeout):
		t.Fatalf("TUN reader stopped reading: %s", what)
	}
}

func TestReadFromTUNDropsWhenPoolIsExhausted(t *testing.T) {
	pair := newCappedPair(t, poolDropCap)
	release := holdSpareBuffers(t, pair[0].dev)

	for i := 0; i < poolDropPackets; i++ {
		writeToTUN(t, pair[0], tuntest.Ping(pair[1].ip, pair[0].ip), fmt.Sprintf("packet %d with the pool exhausted", i))
	}
	waitForDrops(t, pair[0].dev, poolDropPackets)

	release()
	pair.Send(t, Pong, nil)
	pair.Send(t, Ping, nil)
}

func TestReceiveIncomingDropsWhenPoolIsExhausted(t *testing.T) {
	pair := newCappedPair(t, poolDropCap)
	release := holdSpareBuffers(t, pair[0].dev)

	for i := 0; i < poolDropPackets; i++ {
		writeToTUN(t, pair[1], tuntest.Ping(pair[0].ip, pair[1].ip), fmt.Sprintf("packet %d towards the exhausted peer", i))
	}
	waitForDrops(t, pair[0].dev, poolDropPackets)

	release()
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

func TestReceiveIncomingDropsHandshakesWhenPoolIsExhausted(t *testing.T) {
	prev := PreallocatedBuffersPerPool
	SetPreallocatedBuffersPerPool(poolDropCap)
	t.Cleanup(func() { SetPreallocatedBuffersPerPool(prev) })

	binds := bindtest.NewChannelBinds()
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], NewLogger(LogLevelError, "capped: "))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(uapiCfg("private_key", hex.EncodeToString(sk[:]), "listen_port", "0")); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	holdSpareBuffers(t, dev)

	// bindtest routes port 2 from binds[1] into binds[0]'s IPv4 receiver.
	to, err := binds[1].ParseEndpoint("127.0.0.1:2")
	if err != nil {
		t.Fatal(err)
	}
	initiation := make([]byte, MessageInitiationSize)
	binary.LittleEndian.PutUint32(initiation, MessageInitiationType)
	for i := 0; i < poolDropPackets; i++ {
		if err := binds[1].Send([][]byte{initiation}, to); err != nil {
			t.Fatal(err)
		}
	}
	waitForDrops(t, dev, poolDropPackets)
}

// TestStagingWithoutSessionLeavesRoomForOthers floods a peer whose handshake
// can never complete. Its staged packets may take half of the pool at most, so
// a peer with a session keeps sending and the reader keeps reading.
func TestStagingWithoutSessionLeavesRoomForOthers(t *testing.T) {
	pair := newCappedPair(t, 2*poolDropCap)

	peerSk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPk := peerSk.publicKey()
	deadIP := netip.MustParseAddr("1.0.0.9")
	// The channel bind rejects an endpoint it does not serve, so every handshake
	// initiation to this peer fails and its packets stay staged.
	if err := pair[0].dev.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(peerPk[:]),
		"endpoint", "127.0.0.1:9",
		"allowed_ip", deadIP.String()+"/32",
	)); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4*poolDropCap; i++ {
		writeToTUN(t, pair[0], tuntest.Ping(deadIP, pair[0].ip), fmt.Sprintf("packet %d for a peer without a session", i))
	}
	buf, ok := pair[0].dev.TryGetMessageBuffer()
	if !ok {
		t.Fatal("packets staged for a peer that cannot handshake took every buffer")
	}
	pair[0].dev.PutMessageBuffer(buf)
	if pair[0].dev.PoolDrops() == 0 {
		t.Fatal("no packet was dropped although the flood exceeded the staging share")
	}

	pair.Send(t, Pong, nil)
	pair.Send(t, Ping, nil)
}

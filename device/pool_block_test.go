/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// newCappedDevice brings up a Device whose pools are capped, with a single peer
// that has no endpoint and therefore never completes a handshake.
func newCappedDevice(t *testing.T, cap uint32) (*Device, *Peer) {
	t.Helper()

	prev := PreallocatedBuffersPerPool
	SetPreallocatedBuffersPerPool(cap)
	t.Cleanup(func() { SetPreallocatedBuffersPerPool(prev) })

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	peerSk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("peer private key: %v", err)
	}
	peerPk := peerSk.publicKey()

	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], NewLogger(LogLevelError, "capped: "))
	t.Cleanup(dev.Close)

	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=1.0.0.2/32\n",
		hex.EncodeToString(sk[:]), hex.EncodeToString(peerPk[:]))
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("configure device: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring device up: %v", err)
	}

	peer := dev.LookupPeer(peerPk)
	if peer == nil {
		t.Fatal("peer not configured")
	}
	return dev, peer
}

// drainMessageBuffers empties the message buffer pool and hands the buffers back
// when the test ends. Without the hand-back, Device.Close would wait forever on
// the device routines that are parked in the empty pool.
func drainMessageBuffers(t *testing.T, dev *Device) {
	t.Helper()

	var held []*[MaxMessageSize]byte
	for {
		buf, ok := dev.TryGetMessageBuffer()
		if !ok {
			break
		}
		held = append(held, buf)
	}
	if len(held) == 0 {
		t.Fatal("pool was already empty, the cap is not in effect")
	}
	t.Cleanup(func() {
		for _, buf := range held {
			dev.PutMessageBuffer(buf)
		}
	})
}

func TestWaitPoolTryGetAtCapacity(t *testing.T) {
	p := NewWaitPool(1, func() any { return new([1]byte) })

	first, ok := p.TryGet()
	if !ok {
		t.Fatal("TryGet on an empty tracked pool must succeed")
	}
	if _, ok := p.TryGet(); ok {
		t.Fatal("TryGet at capacity must report false instead of waiting")
	}

	p.Put(first)
	if _, ok := p.TryGet(); !ok {
		t.Fatal("TryGet must succeed again once a buffer is returned")
	}
}

func TestWaitPoolTryGetUntracked(t *testing.T) {
	p := NewWaitPool(0, func() any { return new([1]byte) })
	for i := 0; i < 3; i++ {
		if _, ok := p.TryGet(); !ok {
			t.Fatal("TryGet on an uncapped pool must always succeed")
		}
	}
}

// TestSendKeepaliveWithExhaustedPool is the regression test for the proxy
// deadlock: a keepalive that waits for a buffer does so inside a timer callback
// holding the timer's runningLock, which makes Peer.Stop - and therefore peer
// removal and Device.Close - impossible to complete.
func TestSendKeepaliveWithExhaustedPool(t *testing.T) {
	dev, peer := newCappedDevice(t, 64)

	// Bringing the device up can already have staged a packet; SendKeepalive is
	// a no-op while the staged queue is non-empty.
	peer.FlushStagedPackets()
	if len(peer.queue.staged) != 0 {
		t.Fatal("staged queue must be empty for the keepalive path to run")
	}

	drainMessageBuffers(t, dev)

	done := make(chan struct{})
	go func() {
		peer.SendKeepalive()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendKeepalive blocked on an exhausted buffer pool")
	}
}

// poolInUse reports how many buffers are checked out of a capped pool.
func poolInUse(p *WaitPool) uint32 {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.count
}

// stageBatch takes perBatch elements from the pools and stages them on peer.
func stageBatch(t *testing.T, dev *Device, peer *Peer, perBatch int) {
	t.Helper()

	container, ok := dev.TryGetOutboundElementsContainer()
	if !ok {
		t.Fatal("container pool exhausted before the test started")
	}
	for i := 0; i < perBatch; i++ {
		elem, ok := dev.TryNewOutboundElement()
		if !ok {
			t.Fatal("buffer pool exhausted before the test started")
		}
		container.elems = append(container.elems, elem)
	}
	peer.StagePackets(container)
}

// TestStagedSendResetsHandshakeAttempts pins the upstream and kernel rule that a
// new outbound packet starts a fresh handshake budget. Recovering the buffers a
// dead peer holds is StagePackets' job (see TestStagePacketsBoundedPerPeer), not
// a reason to change the retry policy.
func TestStagedSendResetsHandshakeAttempts(t *testing.T) {
	dev, peer := newCappedDevice(t, 64)
	stageBatch(t, dev, peer, 1)

	peer.timers.handshakeAttempts.Store(3)
	peer.SendStagedPackets()

	if got := peer.timers.handshakeAttempts.Load(); got != 0 {
		t.Fatalf("handshakeAttempts = %d, want 0: outbound traffic must reset the counter as upstream does", got)
	}
}

// TestStagePacketsBoundedPerPeer checks the kernel's MAX_STAGED_PACKETS rule: a
// peer with no session keeps at most MaxStagedPackets packets plus the batch
// that pushed it over, whatever the batch size, and the batches it drops go
// straight back to the pool.
func TestStagePacketsBoundedPerPeer(t *testing.T) {
	dev, peer := newCappedDevice(t, 4096)
	peer.FlushStagedPackets()

	const batches, perBatch = 40, 16
	before := poolInUse(dev.pool.messageBuffers)
	for b := 0; b < batches; b++ {
		stageBatch(t, dev, peer, perBatch)
	}

	pinned := poolInUse(dev.pool.messageBuffers) - before
	if pinned > MaxStagedPackets+perBatch {
		t.Fatalf("staged queue pins %d buffers, want at most %d", pinned, MaxStagedPackets+perBatch)
	}
	if pinned < MaxStagedPackets {
		t.Fatalf("staged queue pins %d buffers, want at least %d: the bound must not drop more than needed", pinned, MaxStagedPackets)
	}
	if got := peer.queue.stagedPackets.Load(); got < 0 || uint32(got) != pinned {
		t.Fatalf("stagedPackets = %d, want %d: the counter must track the pool", got, pinned)
	}

	peer.FlushStagedPackets()
	if after := poolInUse(dev.pool.messageBuffers); after != before {
		t.Fatalf("%d buffers out after flush, want %d: staged buffers must return to the pool", after, before)
	}
	if got := peer.queue.stagedPackets.Load(); got != 0 {
		t.Fatalf("stagedPackets = %d after flush, want 0", got)
	}
}

// TestSendKeepaliveWithFullOutboundQueue covers the other place a keepalive
// callback could park: handing its batch to the sequential sender. The sender
// is wedged on a batch whose encryption never finishes, the queue behind it is
// filled, and SendKeepalive must still return.
func TestSendKeepaliveWithFullOutboundQueue(t *testing.T) {
	pair := genTestPair(t, false)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	dev := pair[0].dev
	peer := dev.LookupPeer(onlyPeerKey(t, dev))

	// Every container is locked, as a batch awaiting encryption would be, so
	// the sender blocks on the first and the rest fill the queue. Unlocking
	// them on the way out lets the sender drain before the device closes.
	held := make([]*QueueOutboundElementsContainer, 0, QueueOutboundSize+1)
	t.Cleanup(func() {
		for _, c := range held {
			c.Unlock()
		}
	})
	for full := false; !full; {
		c := dev.GetOutboundElementsContainer()
		c.Lock()
		select {
		case peer.queue.outbound.c <- c:
			held = append(held, c)
		default:
			c.Unlock()
			dev.PutOutboundElementsContainer(c)
			full = true
		}
	}

	peer.FlushStagedPackets()

	done := make(chan struct{})
	go func() {
		peer.SendKeepalive()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendKeepalive blocked on a full outbound queue")
	}
}

// onlyPeerKey returns the public key of the device's single configured peer.
func onlyPeerKey(t *testing.T, dev *Device) NoisePublicKey {
	t.Helper()

	dev.peers.RLock()
	defer dev.peers.RUnlock()

	if len(dev.peers.keyMap) != 1 {
		t.Fatalf("expected exactly one peer, got %d", len(dev.peers.keyMap))
	}
	for pk := range dev.peers.keyMap {
		return pk
	}
	return NoisePublicKey{}
}

// waitPoolDrained blocks until the message buffer pool has no capacity left.
func waitPoolDrained(t *testing.T, dev *Device, within time.Duration) {
	t.Helper()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		buf, ok := dev.TryGetMessageBuffer()
		if !ok {
			return
		}
		dev.PutMessageBuffer(buf)
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("buffer pool never drained; the traffic generator is not filling the staged queue")
}

// TestRemovePeerWithPoolDrainedByADeadPeer is the functional counterpart of the
// unit tests above: two real devices, a real handshake, real traffic and real
// timers, asserting the property the deadlock broke.
//
// The shape is the one seen in production. One peer cannot handshake, so the
// packets aimed at it stay staged and drain the device's capped pool. A second
// peer has a live session, so its staged queue is empty and its keepalive timer
// does allocate - and parks in the exhausted pool while holding the timer's
// runningLock. Removing that peer needs the same lock through DelSync, so it
// can never complete. With the fix the keepalive is skipped and the removal
// returns.
func TestRemovePeerWithPoolDrainedByADeadPeer(t *testing.T) {
	prev := PreallocatedBuffersPerPool
	SetPreallocatedBuffersPerPool(32)
	t.Cleanup(func() { SetPreallocatedBuffersPerPool(prev) })

	pair := genTestPair(t, false)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	dev := pair[0].dev

	// Lift the cap on the way out so the wedged device can be closed: without
	// it a failing run would hang in Close instead of reporting.
	t.Cleanup(func() { dev.SetPreallocatedBuffersPerPool(0) })

	live := onlyPeerKey(t, dev)
	if err := dev.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(live[:]),
		"persistent_keepalive_interval", "1",
	)); err != nil {
		t.Fatalf("set keepalive on the live peer: %v", err)
	}

	deadSk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("dead peer key: %v", err)
	}
	deadPk := deadSk.publicKey()
	if err := dev.IpcSet(uapiCfg(
		"public_key", hex.EncodeToString(deadPk[:]),
		"endpoint", "127.0.0.1:9",
		"allowed_ip", "1.0.0.9/32",
	)); err != nil {
		t.Fatalf("add the unreachable peer: %v", err)
	}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		dst := netip.MustParseAddr("1.0.0.9")
		src := netip.MustParseAddr("1.0.0.1")
		for {
			select {
			case pair[0].tun.Outbound <- tuntest.Ping(dst, src):
			case <-stop:
				return
			}
		}
	}()

	waitPoolDrained(t, dev, 10*time.Second)

	// Let a keepalive tick land on the drained pool. Before the fix the first
	// one parks and never returns, so this is not a race: once parked, parked.
	time.Sleep(2500 * time.Millisecond)

	removed := make(chan error, 1)
	go func() {
		removed <- dev.IpcSet(uapiCfg(
			"public_key", hex.EncodeToString(live[:]),
			"remove", "true",
		))
	}()

	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("remove peer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("removing a peer never completed: a keepalive callback is parked in the buffer pool and DelSync is waiting on its timer")
	}
}

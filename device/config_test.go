/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type idleTUN struct {
	events chan tun.Event
	closed chan struct{}
}

func newIdleTUN() *idleTUN {
	return &idleTUN{events: make(chan tun.Event), closed: make(chan struct{})}
}

func (t *idleTUN) File() *os.File { return nil }

func (t *idleTUN) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *idleTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (t *idleTUN) MTU() (int, error) { return 1420, nil }

func (t *idleTUN) Name() (string, error) { return "idle", nil }

func (t *idleTUN) Events() <-chan tun.Event { return t.events }

func (t *idleTUN) Close() error {
	close(t.closed)
	close(t.events)
	return nil
}

func (t *idleTUN) BatchSize() int { return 1 }

func newConfigTestDevice(t *testing.T) *Device {
	t.Helper()

	dev := NewDevice(newIdleTUN(), conn.NewDefaultBind(), NewLogger(LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	if err := dev.SetPrivateKey(randomPrivateKey(t)); err != nil {
		t.Fatalf("set private key: %v", err)
	}
	return dev
}

func randomPrivateKey(t *testing.T) NoisePrivateKey {
	t.Helper()

	var sk NoisePrivateKey
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("random key: %v", err)
	}
	sk.clamp()
	return sk
}

func randomPublicKey(t *testing.T) NoisePublicKey {
	t.Helper()

	sk := randomPrivateKey(t)
	return sk.publicKey()
}

func testEndpoint(t *testing.T, dev *Device, addr string) conn.Endpoint {
	t.Helper()

	ep, err := dev.Bind().ParseEndpoint(addr)
	if err != nil {
		t.Fatalf("parse endpoint %s: %v", addr, err)
	}
	return ep
}

func uapiPeerBlocks(t *testing.T, dev *Device) map[NoisePublicKey][]string {
	t.Helper()

	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("ipc get: %v", err)
	}
	blocks := make(map[NoisePublicKey][]string)
	var current *NoisePublicKey
	for _, line := range strings.Split(strings.TrimSpace(dump), "\n") {
		if value, ok := strings.CutPrefix(line, "public_key="); ok {
			var pk NoisePublicKey
			if err := pk.FromHex(value); err != nil {
				t.Fatalf("parse dumped key: %v", err)
			}
			current = &pk
			continue
		}
		if current != nil {
			blocks[*current] = append(blocks[*current], line)
		}
	}
	return blocks
}

func TestConfigurePeerMatchesUAPI(t *testing.T) {
	dev := newConfigTestDevice(t)
	typedKey, uapiKey := randomPublicKey(t), randomPublicKey(t)
	var psk NoisePresharedKey
	if _, err := rand.Read(psk[:]); err != nil {
		t.Fatalf("random psk: %v", err)
	}
	keepalive := 25 * time.Second
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.1.0.0/16")}

	err := dev.ConfigurePeer(typedKey, PeerConfig{
		PresharedKey:        &psk,
		Endpoint:            testEndpoint(t, dev, "127.0.0.1:1234"),
		PersistentKeepalive: &keepalive,
		AllowedIPs:          prefixes,
	})
	if err != nil {
		t.Fatalf("configure peer: %v", err)
	}

	uapi := fmt.Sprintf("public_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:1234\npersistent_keepalive_interval=25\nallowed_ip=10.0.0.2/32\nallowed_ip=10.2.0.0/16\n",
		hex.EncodeToString(uapiKey[:]), hex.EncodeToString(psk[:]))
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("ipc set: %v", err)
	}

	blocks := uapiPeerBlocks(t, dev)
	typedLines, typedAllowed := splitAllowedIPLines(blocks[typedKey])
	uapiLines, uapiAllowed := splitAllowedIPLines(blocks[uapiKey])
	if !slices.Equal(typedLines, uapiLines) {
		t.Fatalf("typed and UAPI peers differ:\n%v\n%v", typedLines, uapiLines)
	}
	if !slices.Contains(typedLines, "endpoint=127.0.0.1:1234") {
		t.Fatalf("endpoint missing from dump: %v", typedLines)
	}
	if !slices.Equal(typedAllowed, []string{"allowed_ip=10.0.0.1/32", "allowed_ip=10.1.0.0/16"}) {
		t.Fatalf("typed peer allowed IPs: %v", typedAllowed)
	}
	if !slices.Equal(uapiAllowed, []string{"allowed_ip=10.0.0.2/32", "allowed_ip=10.2.0.0/16"}) {
		t.Fatalf("UAPI peer allowed IPs: %v", uapiAllowed)
	}
}

func splitAllowedIPLines(lines []string) (rest, allowed []string) {
	for _, line := range lines {
		if strings.HasPrefix(line, "allowed_ip=") {
			allowed = append(allowed, line)
			continue
		}
		rest = append(rest, line)
	}
	return rest, allowed
}

func TestConfigurePeerUpdateOnlySkipsAbsentPeer(t *testing.T) {
	dev := newConfigTestDevice(t)
	pk := randomPublicKey(t)

	if err := dev.ConfigurePeer(pk, PeerConfig{UpdateOnly: true, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}); err != nil {
		t.Fatalf("configure peer: %v", err)
	}
	if dev.LookupPeer(pk) != nil {
		t.Fatal("update-only must not create a peer")
	}
	if got := len(dev.Peers()); got != 0 {
		t.Fatalf("peers on device: %d, want 0", got)
	}
}

func TestConfigurePeerRejectsOutOfRangeKeepalive(t *testing.T) {
	dev := newConfigTestDevice(t)

	for _, keepalive := range []time.Duration{-time.Second, (math.MaxUint16 + 1) * time.Second} {
		pk := randomPublicKey(t)
		if err := dev.ConfigurePeer(pk, PeerConfig{PersistentKeepalive: &keepalive}); err == nil {
			t.Fatalf("keepalive %v: want error", keepalive)
		}
		if dev.LookupPeer(pk) != nil {
			t.Fatalf("keepalive %v: rejected config must not create a peer", keepalive)
		}
	}

	pk := randomPublicKey(t)
	keepalive := math.MaxUint16*time.Second + 500*time.Millisecond
	if err := dev.ConfigurePeer(pk, PeerConfig{PersistentKeepalive: &keepalive}); err != nil {
		t.Fatalf("configure peer: %v", err)
	}
	if got := dev.LookupPeer(pk).persistentKeepaliveInterval.Load(); got != math.MaxUint16 {
		t.Fatalf("keepalive interval: %d, want %d", got, math.MaxUint16)
	}
}

func TestConfigurePeerIgnoresOwnKey(t *testing.T) {
	dev := newConfigTestDevice(t)

	if err := dev.ConfigurePeer(dev.PublicKey(), PeerConfig{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}); err != nil {
		t.Fatalf("configure peer: %v", err)
	}
	if got := len(dev.Peers()); got != 0 {
		t.Fatalf("peers on device: %d, want 0", got)
	}
}

func TestConfigurePeerAllowedIPMergeAndReplace(t *testing.T) {
	dev := newConfigTestDevice(t)
	pk := randomPublicKey(t)
	a, b, c := netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("192.168.0.0/24")

	if err := dev.ConfigurePeer(pk, PeerConfig{AllowedIPs: []netip.Prefix{a}}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	if err := dev.ConfigurePeer(pk, PeerConfig{AllowedIPs: []netip.Prefix{b}}); err != nil {
		t.Fatalf("merge allowed ip: %v", err)
	}
	peer := dev.LookupPeer(pk)
	if got := peer.AllowedIPs(); !slices.Equal(got, []netip.Prefix{a, b}) {
		t.Fatalf("merged allowed IPs: %v, want [%v %v]", got, a, b)
	}

	if err := dev.ConfigurePeer(pk, PeerConfig{AllowedIPs: []netip.Prefix{c}, ReplaceAllowedIPs: true}); err != nil {
		t.Fatalf("replace allowed ips: %v", err)
	}
	if got := peer.AllowedIPs(); !slices.Equal(got, []netip.Prefix{c}) {
		t.Fatalf("replaced allowed IPs: %v, want [%v]", got, c)
	}

	peer.SetAllowedIPs([]netip.Prefix{a, b})
	if got := peer.AllowedIPs(); !slices.Equal(got, []netip.Prefix{a, b}) {
		t.Fatalf("set allowed IPs: %v, want [%v %v]", got, a, b)
	}
}

func TestAllowedIPHandoverBetweenPeers(t *testing.T) {
	dev := newConfigTestDevice(t)
	keyA, keyB := randomPublicKey(t), randomPublicKey(t)
	shared := netip.MustParsePrefix("10.20.0.0/16")

	if err := dev.ConfigurePeer(keyA, PeerConfig{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), shared}}); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := dev.ConfigurePeer(keyB, PeerConfig{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}); err != nil {
		t.Fatalf("create B: %v", err)
	}
	peerA, peerB := dev.LookupPeer(keyA), dev.LookupPeer(keyB)

	peerB.AddAllowedIP(shared)
	if slices.Contains(peerA.AllowedIPs(), shared) {
		t.Fatal("the prefix must have moved away from A")
	}
	if !slices.Contains(peerB.AllowedIPs(), shared) {
		t.Fatal("B must hold the prefix")
	}

	if peerA.RemoveAllowedIP(shared) {
		t.Fatal("A no longer owns the prefix, the removal must report false")
	}
	if !slices.Contains(peerB.AllowedIPs(), shared) {
		t.Fatal("A's removal must not touch B's prefix")
	}
	if !peerB.RemoveAllowedIP(shared) {
		t.Fatal("B owns the prefix, the removal must report true")
	}
	if peerB.RemoveAllowedIP(shared) {
		t.Fatal("a second removal must report false")
	}
	if dev.allowedips.Lookup(netip.MustParseAddr("10.20.1.1").AsSlice()) != nil {
		t.Fatal("the prefix must be gone from the routing table")
	}
}

func TestClearEndpointKeepsPeerAndMarksNextEndpointAsChange(t *testing.T) {
	dev := newConfigTestDevice(t)
	pk := randomPublicKey(t)
	prefix := netip.MustParsePrefix("10.0.0.1/32")

	if err := dev.ConfigurePeer(pk, PeerConfig{Endpoint: testEndpoint(t, dev, "127.0.0.1:1234"), AllowedIPs: []netip.Prefix{prefix}}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	peer := dev.LookupPeer(pk)
	peer.rxBytes.Store(42)

	peer.ClearEndpoint()

	if peer.Endpoint() != nil {
		t.Fatal("endpoint must be cleared")
	}
	if dev.LookupPeer(pk) != peer {
		t.Fatal("the peer object must survive the endpoint removal")
	}
	if got := peer.AllowedIPs(); !slices.Equal(got, []netip.Prefix{prefix}) {
		t.Fatalf("allowed IPs after clear: %v, want [%v]", got, prefix)
	}
	if peer.RxBytes() != 42 {
		t.Fatal("counters must survive the endpoint removal")
	}

	if !peer.setEndpoint(testEndpoint(t, dev, "127.0.0.1:5678")) {
		t.Fatal("the first endpoint after a clear must count as a change")
	}
	if peer.setEndpoint(testEndpoint(t, dev, "127.0.0.1:5678")) {
		t.Fatal("the same endpoint again must not count as a change")
	}
	if !peer.setEndpoint(testEndpoint(t, dev, "127.0.0.1:9999")) {
		t.Fatal("a different endpoint must count as a change")
	}
}

func TestSetEndpointOnFreshPeerIsNotAChange(t *testing.T) {
	dev := newConfigTestDevice(t)
	pk := randomPublicKey(t)

	if err := dev.ConfigurePeer(pk, PeerConfig{}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	if dev.LookupPeer(pk).setEndpoint(testEndpoint(t, dev, "127.0.0.1:1234")) {
		t.Fatal("the first endpoint of a fresh peer must not count as a change")
	}
}

func TestPeerGetters(t *testing.T) {
	dev := newConfigTestDevice(t)
	pk := randomPublicKey(t)
	var psk NoisePresharedKey
	psk[0] = 1

	if err := dev.ConfigurePeer(pk, PeerConfig{PresharedKey: &psk, Endpoint: testEndpoint(t, dev, "127.0.0.1:1234")}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	peer := dev.LookupPeer(pk)

	if peer.PublicKey() != pk {
		t.Fatal("public key mismatch")
	}
	if peer.PresharedKey() != psk {
		t.Fatal("preshared key mismatch")
	}
	if got := peer.Endpoint().DstToString(); got != "127.0.0.1:1234" {
		t.Fatalf("endpoint: %s", got)
	}
	if !peer.LastHandshake().IsZero() {
		t.Fatal("no handshake happened yet")
	}

	peer.txBytes.Store(7)
	peer.rxBytes.Store(9)
	now := time.Now()
	peer.lastHandshakeNano.Store(now.UnixNano())
	if peer.TxBytes() != 7 || peer.RxBytes() != 9 {
		t.Fatalf("counters: tx=%d rx=%d", peer.TxBytes(), peer.RxBytes())
	}
	if !peer.LastHandshake().Equal(now) {
		t.Fatalf("last handshake: %v, want %v", peer.LastHandshake(), now)
	}
}

func TestDeviceGetters(t *testing.T) {
	dev := newConfigTestDevice(t)

	if err := dev.SetListenPort(51820); err != nil {
		t.Fatalf("set listen port: %v", err)
	}
	if got := dev.ListenPort(); got != 51820 {
		t.Fatalf("listen port: %d", got)
	}
	if err := dev.BindSetMark(7); err != nil {
		t.Fatalf("set mark: %v", err)
	}
	if got := dev.FirewallMark(); got != 7 {
		t.Fatalf("fwmark: %d", got)
	}
	if dev.PublicKey() != dev.staticIdentity.privateKey.publicKey() {
		t.Fatal("device public key mismatch")
	}

	keys := []NoisePublicKey{randomPublicKey(t), randomPublicKey(t), randomPublicKey(t)}
	for _, pk := range keys {
		if err := dev.ConfigurePeer(pk, PeerConfig{}); err != nil {
			t.Fatalf("create peer: %v", err)
		}
	}
	peers := dev.Peers()
	if len(peers) != len(keys) {
		t.Fatalf("peers: %d, want %d", len(peers), len(keys))
	}
	for _, peer := range peers {
		if !slices.Contains(keys, peer.PublicKey()) {
			t.Fatalf("unexpected peer %v in snapshot", peer.PublicKey())
		}
	}
}

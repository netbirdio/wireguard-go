/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type PeerConfig struct {
	PresharedKey        *NoisePresharedKey
	Endpoint            conn.Endpoint
	PersistentKeepalive *time.Duration
	AllowedIPs          []netip.Prefix
	ReplaceAllowedIPs   bool
	UpdateOnly          bool
}

func (device *Device) ConfigurePeer(pk NoisePublicKey, cfg PeerConfig) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.staticIdentity.RLock()
	own := device.staticIdentity.publicKey.Equals(pk)
	device.staticIdentity.RUnlock()
	if own {
		return nil
	}

	state := ipcSetPeer{Peer: device.LookupPeer(pk)}
	if state.Peer == nil && cfg.UpdateOnly {
		return nil
	}
	var keepaliveSecs uint32
	if cfg.PersistentKeepalive != nil {
		secs, err := keepaliveSeconds(*cfg.PersistentKeepalive)
		if err != nil {
			return err
		}
		keepaliveSecs = secs
	}
	if state.Peer == nil {
		peer, err := device.NewPeer(pk)
		if err != nil {
			return err
		}
		state.Peer = peer
		state.created = true
	}

	if cfg.PresharedKey != nil {
		state.setPresharedKey(*cfg.PresharedKey)
	}
	if cfg.Endpoint != nil {
		state.endpointChanged = state.setEndpoint(cfg.Endpoint)
	}
	if cfg.PersistentKeepalive != nil {
		state.pkaOn = state.setPersistentKeepalive(keepaliveSecs)
	}
	if cfg.ReplaceAllowedIPs {
		device.allowedips.replaceForPeer(state.Peer, cfg.AllowedIPs)
	} else {
		for _, prefix := range cfg.AllowedIPs {
			device.allowedips.Insert(prefix, state.Peer)
		}
	}
	state.handlePostConfig()
	return nil
}

func (device *Device) Peers() []*Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	peers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	return peers
}

func (device *Device) SetListenPort(port uint16) error {
	device.net.Lock()
	device.net.port = port
	device.net.Unlock()
	return device.BindUpdate()
}

func (device *Device) ListenPort() uint16 {
	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.port
}

func (device *Device) FirewallMark() uint32 {
	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.fwmark
}

func (device *Device) PublicKey() NoisePublicKey {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	return device.staticIdentity.publicKey
}

func (peer *Peer) PublicKey() NoisePublicKey {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.remoteStatic
}

func (peer *Peer) PresharedKey() NoisePresharedKey {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.presharedKey
}

func (peer *Peer) Endpoint() conn.Endpoint {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	return peer.endpoint.val
}

func (peer *Peer) ClearEndpoint() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	peer.endpoint.val = nil
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.disableRoaming = false
	peer.endpoint.cleared = true
}

func (peer *Peer) AddAllowedIP(prefix netip.Prefix) {
	peer.device.allowedips.Insert(prefix, peer)
}

func (peer *Peer) RemoveAllowedIP(prefix netip.Prefix) bool {
	return peer.device.allowedips.Remove(prefix, peer)
}

func (peer *Peer) SetAllowedIPs(prefixes []netip.Prefix) {
	peer.device.allowedips.replaceForPeer(peer, prefixes)
}

func (peer *Peer) AllowedIPs() []netip.Prefix {
	var prefixes []netip.Prefix
	peer.device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
		prefixes = append(prefixes, prefix)
		return true
	})
	return prefixes
}

func (peer *Peer) RxBytes() uint64 {
	return peer.rxBytes.Load()
}

func (peer *Peer) TxBytes() uint64 {
	return peer.txBytes.Load()
}

func (peer *Peer) LastHandshake() time.Time {
	nano := peer.lastHandshakeNano.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

func (peer *Peer) setPresharedKey(psk NoisePresharedKey) {
	peer.handshake.mutex.Lock()
	defer peer.handshake.mutex.Unlock()
	peer.handshake.presharedKey = psk
}

func (peer *Peer) setEndpoint(endpoint conn.Endpoint) bool {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	changed := peer.endpoint.cleared ||
		(peer.endpoint.val != nil && peer.endpoint.val.DstToString() != endpoint.DstToString())
	peer.endpoint.val = endpoint
	peer.endpoint.cleared = false
	return changed
}

func (peer *Peer) setPersistentKeepalive(secs uint32) bool {
	old := peer.persistentKeepaliveInterval.Swap(secs)
	return old == 0 && secs != 0
}

func keepaliveSeconds(interval time.Duration) (uint32, error) {
	secs := interval / time.Second
	if interval < 0 || secs > math.MaxUint16 {
		return 0, fmt.Errorf("invalid persistent keepalive interval: %v", interval)
	}
	return uint32(secs), nil
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// recordingBind is a channel bind that remembers the batch size the Device
// hands it before Open.
type recordingBind struct {
	conn.Bind
	recvBatch int
}

func (b *recordingBind) SetRecvBatchSize(n int) {
	b.recvBatch = n
}

// TestBindUpdateHandsTheBindItsBatchSize: a bind that opens its sockets
// differently for small batches has to learn the Device's batch size before
// Open, and a per-instance override must reach it the same way as the global
// one.
func TestBindUpdateHandsTheBindItsBatchSize(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	bind := &recordingBind{Bind: binds[0]}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bind, NewLogger(LogLevelError, "batch: "))
	t.Cleanup(dev.Close)

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(uapiCfg("private_key", hex.EncodeToString(sk[:]), "listen_port", "0")); err != nil {
		t.Fatal(err)
	}
	dev.SetMaxBatchSize(7)
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	if bind.recvBatch != 7 {
		t.Fatalf("bind learned a batch size of %d before Open, want 7", bind.recvBatch)
	}
}

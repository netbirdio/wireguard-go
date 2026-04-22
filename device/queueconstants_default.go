//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

const (
	QueueStagedSize    = conn.IdealBatchSize
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	MaxSegmentSize     = (1 << 16) - 1 // largest possible UDP datagram
)

// PreallocatedBuffersPerPool caps the number of buffers held by each per-Device
// pool. Zero disables the cap and allows unbounded growth (upstream default).
// Use SetPreallocatedBuffersPerPool to change this before calling NewDevice.
var PreallocatedBuffersPerPool uint32 = 0

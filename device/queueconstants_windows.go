/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

const (
	QueueStagedSize    = 128
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	MaxSegmentSize     = 65535 // Match with WINTUN_MAX_IP_PACKET_SIZE macro definition
)

// PreallocatedBuffersPerPool caps the number of buffers held by each per-Device
// pool. Zero disables the cap and allows unbounded growth (upstream default).
// Use SetPreallocatedBuffersPerPool to change this before calling NewDevice.
var PreallocatedBuffersPerPool uint32 = 0

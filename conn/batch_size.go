/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// MaxBatchSizeOverride mirrors device.MaxBatchSizeOverride for the binds. A
// Device created under the override reads that many datagrams per call, and a
// socket opened for it must never use GRO: a coalesced read needs the tail of
// a full IdealBatchSize message array as scratch space and up to
// udpSegmentMaxDatagrams buffers per message, which such reads never provide.
// Set it through device.SetMaxBatchSizeOverride before a bind is opened.
var MaxBatchSizeOverride uint32

// SetMaxBatchSizeOverride sets MaxBatchSizeOverride; zero disables it.
func SetMaxBatchSizeOverride(n uint32) {
	MaxBatchSizeOverride = n
}

// batchSizeOverrideBelowIdeal reports whether Devices read batches smaller
// than IdealBatchSize, in which case sockets are opened without GRO.
func batchSizeOverrideBelowIdeal() bool {
	return MaxBatchSizeOverride > 0 && MaxBatchSizeOverride < IdealBatchSize
}

// RecvBatchSizer is implemented by binds that open their sockets differently
// for a Device reading batches smaller than IdealBatchSize. The Device calls
// SetRecvBatchSize with its batch size before Open.
type RecvBatchSizer interface {
	SetRecvBatchSize(n int)
}

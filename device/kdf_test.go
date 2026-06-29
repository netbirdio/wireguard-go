/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func assertEquals(t *testing.T, a, b string) {
	if a != b {
		t.Fatal("expected", a, "=", b)
	}
}

func TestKDF(t *testing.T) {
	tests := []KDFTest{
		{
			key:   "746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "f3e814d720c521d5b4981694adbb32e7355d4b641a118795af8babb2d5aa2862",
			t1:    "029b2d4e38e167d135fc5f65d767b99f2fc9ecaa97ec122b1940a85c405ad7f9",
			t2:    "5712a222294c2bdceb90db65d2669d44f88d123409d2a28155faccdaae3b09ad",
		},
		{
			key:   "776972656775617264",
			input: "776972656775617264",
			t0:    "4ec610b654b994a0f14311907a22d83673c8b017c9bf818f42921906ec7f3630",
			t1:    "11048bbc593ded4bd2f8309aa05cac38fe3f61bf4990c11f7042010540feb410",
			t2:    "a929174a48d4902dc31be8bf1c3dbe911a7cb70d718076345b41e85fecc15842",
		},
		{
			key:   "",
			input: "",
			t0:    "eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe18",
			t1:    "1e59c2ec0fe6e7e7ac2613b6ab65342a83379969da234240cded3777914db907",
			t2:    "5568c74fdb8fc92331d5c59e1e2dd77a8c2c63aba7cf2d3457f8ee8620462f8a",
		},
	}

	var t0, t1, t2 [sha256.Size]byte

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF3(&t0, &t1, &t2, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		t2s := hex.EncodeToString(t2[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
		assertEquals(t, t2s, test.t2)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF2(&t0, &t1, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF1(&t0, key, input)
		t0s := hex.EncodeToString(t0[:])
		assertEquals(t, t0s, test.t0)
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"

	"golang.org/x/crypto/curve25519"
)

const (
	mac128Size    = 16 // 128-bit MAC size for cookie protocol
	aeadKeySize   = 32 // AES-256-GCM key size
	aeadNonceSize = 12 // AES-GCM standard nonce size
	aeadTagSize   = 16 // AES-GCM authentication tag size
)

// newAESGCM returns an AES-256-GCM AEAD cipher for the given 32-byte key.
func newAESGCM(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

// truncatedHash wraps a hash.Hash and truncates its output to mac128Size bytes.
type truncatedHash struct {
	hash.Hash
}

func (h *truncatedHash) Sum(b []byte) []byte {
	full := h.Hash.Sum(nil)
	return append(b, full[:mac128Size]...)
}

func (h *truncatedHash) Size() int {
	return mac128Size
}

// newHMACSHA256_128 returns a hash.Hash computing HMAC-SHA256 truncated to 16 bytes.
func newHMACSHA256_128(key []byte) hash.Hash {
	return &truncatedHash{hmac.New(sha256.New, key)}
}

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[sha256.Size]byte, key, in0 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[sha256.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[sha256.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

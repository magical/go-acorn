// Package acorn implements the ACORN-128 authenticated encryption algorithm
// designed by Hongjun Wu, as specified in
//
//     https://competitions.cr.yp.to/round3/acornv3.pdf
//
// ACORN was one of the six winners of the CAESAR competition:
// It is the second choice for use case 1 (lightwight applications in resource-constrained evironments).
// If you are not operating in a resource-constrained environment, AES-GCM is probably a better choice.
//
// ACORN is claimed to be secure provided that the following conditions are met:
//
//     1. The key should be generated in a secure and random way
//
//     2. A key, nonce pair should not be used to protect more than one message
//
//     3. If verification fails, the decrypted plaintext and wrong authentication tag
//        should not be given as output
//
// Please note that repeating a nonce may allow an attacker to trivially forge arbitrary messages.
//
package acorn

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	KeySize   = 128 / 8
	NonceSize = 128 / 8
	TagSize   = 128 / 8
)

type aead struct {
	key [4]uint32
}

// New returns a ACORN instance that uses the given 128-bit key.
// If the key is not the correct length, NewAEAD will panic.
func NewAEAD(key []byte) cipher.AEAD {
	var a aead
	if len(key) != KeySize {
		panic("acorn: invalid key length")
	}
	return &aead{
		key: [4]uint32{
			binary.LittleEndian.Uint32(key[0*4:]),
			binary.LittleEndian.Uint32(key[1*4:]),
			binary.LittleEndian.Uint32(key[2*4:]),
			binary.LittleEndian.Uint32(key[3*4:]),
		},
	}
	return &a
}

func (a *aead) NonceSize() int {
	return NonceSize
}

func (a *aead) Overhead() int {
	return TagSize
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var s state
	if len(nonce) != NonceSize {
		panic("acorn: invalid nonce length")
	}
	s.init(&a.key, nonce)
	s.process(additionalData)
	ci := s.crypt(plaintext, 0)
	tag := s.finalize()
	dst = append(dst, ci...)
	dst = append(dst, tag...)
	return dst
}

var errDecryption = errors.New("acorn: decryption failed")

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var s state
	s.init(&a.key, nonce)
	s.process(additionalData)
	n := len(ciphertext) - TagSize
	data := ciphertext[:n]
	tag := ciphertext[n:]
	pl := s.crypt(data, one)
	expectedTag := s.finalize()
	if subtle.ConstantTimeCompare(tag, expectedTag) == 0 {
		return dst, errDecryption
	}
	dst = append(dst, pl...)
	return dst, nil
}

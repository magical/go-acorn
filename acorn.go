// Copyright © 2019 Andrew Ekstedt. See LICENSE for details.

package acorn

import "encoding/binary"

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

type state struct {
	s230, s193, s154, s107, s61, s0 uint64
}

// performs 8 stateupdates. m, ca, and cb should be 8 bits long.
func (s *state) update8(m, ca, cb uint32) uint32 {

	s244 := uint32(s.s230 >> 14)
	s235 := uint32(s.s230 >> 5)
	s196 := uint32(s.s193 >> 3)
	s160 := uint32(s.s154 >> 6)
	s111 := uint32(s.s107 >> 4)
	s66 := uint32(s.s61 >> 5)
	s23 := uint32(s.s0 >> 23)
	s12 := uint32(s.s0 >> 12)
	s0 := uint32(s.s0)

	// feedback the 6 LFSRs

	// x289 isn't XORed with itself now because it
	// will be later when we shift it into s230

	x289 := (s235 ^ uint32(s.s230)) & 0xFF

	s230 := (uint32(s.s230) ^ s196 ^ uint32(s.s193)) & 0xFF
	s193 := (uint32(s.s193) ^ s160 ^ uint32(s.s154)) & 0xFF
	s154 := (uint32(s.s154) ^ s111 ^ uint32(s.s107)) & 0xFF
	s107 := (uint32(s.s107) ^ s66 ^ uint32(s.s61)) & 0xFF
	s61 := (uint32(s.s61) ^ s23 ^ s0) & 0xFF

	// n.b. we must use the six feedback variables only
	// for the specific bit that they name, not for any nearby
	// bits. this is because in the single-step update function,
	// the named bits are used after the feedback is applied,
	// but nearby bits are used before those bits are shifted in
	// to replace them, which is before the feedback is applied.

	// calculate keystream and feedback bit

	ks := (s12 ^ s154 ^ maj(s235, s61, s193) ^ ch(s230, s111, s66)) & 0xFF
	f := (s0 ^ ^s107 ^ maj(s244, s23, s160) ^ (ca & s196) ^ (cb & ks)) & 0xFF

	s293 := (f ^ m) & 0xFF

	// update the state
	s.s230 = s.s230>>8 ^ uint64(x289)<<(289-230-8) ^ uint64(s293)<<(293-230-8)
	s.s193 = s.s193>>8 ^ uint64(s230)<<(230-193-8)
	s.s154 = s.s154>>8 ^ uint64(s193)<<(193-154-8)
	s.s107 = s.s107>>8 ^ uint64(s154)<<(154-107-8)
	s.s61 = s.s61>>8 ^ uint64(s107)<<(107-61-8)
	s.s0 = s.s0>>8 ^ uint64(s61)<<(61-8)

	return uint32(ks)
}

func (s *state) update32(m, ca, cb uint32) uint32 {
	// same as update8, but with 32-bit shifts and masks instead of 8 bits.
	// this is about as far as you can go before the feedback starts to compound.

	s244 := uint32(s.s230 >> 14)
	s235 := uint32(s.s230 >> 5)
	s196 := uint32(s.s193 >> 3)
	s160 := uint32(s.s154 >> 6)
	s111 := uint32(s.s107 >> 4)
	s66 := uint32(s.s61 >> 5)
	s23 := uint32(s.s0 >> 23)
	s12 := uint32(s.s0 >> 12)
	s0 := uint32(s.s0)

	// feedback the 6 LFSRs

	x289 := (s235 ^ uint32(s.s230))

	s230 := (uint32(s.s230) ^ s196 ^ uint32(s.s193))
	s193 := (uint32(s.s193) ^ s160 ^ uint32(s.s154))
	s154 := (uint32(s.s154) ^ s111 ^ uint32(s.s107))
	s107 := (uint32(s.s107) ^ s66 ^ uint32(s.s61))
	s61 := (uint32(s.s61) ^ s23 ^ s0)

	// calculate keystream and feedback bit

	ks := (s12 ^ s154 ^ maj(s235, s61, s193) ^ ch(s230, s111, s66))
	f := (s0 ^ ^s107 ^ maj(s244, s23, s160) ^ (ca & s196) ^ (cb & ks))

	s293 := f ^ m

	// update the state
	s.s230 = s.s230>>32 ^ uint64(x289)<<(289-230-32) ^ uint64(s293)<<(293-230-32)
	s.s193 = s.s193>>32 ^ uint64(s230)<<(230-193-32)
	s.s154 = s.s154>>32 ^ uint64(s193)<<(193-154-32)
	s.s107 = s.s107>>32 ^ uint64(s154)<<(154-107-32)
	s.s61 = s.s61>>32 ^ uint64(s107)<<(107-61-32)
	s.s0 = s.s0>>32 ^ uint64(s61)<<(61-32)

	return ks
}

func (s *state) reset() {
	*s = state{}
}

const one = ^uint32(0)

func (s *state) init(k *[4]uint32, iv []uint8) {
	s.reset()
	if len(iv)*8 != 128 {
		panic("acorn: invalid iv length")
	}
	for i := range k {
		s.update32(uint32(k[i]), one, one)
	}
	for i := range iv {
		s.update8(uint32(iv[i]), one, one)
	}
	s.update32(uint32(k[0])^0x01, one, one)
	for i := 32; i < 1536; i += 32 {
		s.update32(uint32(k[i%128/32]), one, one)
	}
}

func (s *state) pad(cb uint32) {
	s.update32(0x01, one, cb)
	for i := 32; i < 128; i += 32 {
		s.update32(0x00, one, cb)
	}
	for i := 128; i < 256; i += 32 {
		s.update32(0x00, 0, cb)
	}
}

func (s *state) process(ad []uint8) {
	for _, x := range ad {
		s.update8(uint32(x), one, one)
	}
	s.pad(one)
}

func (s *state) crypt(dst, src []uint8, mode uint32) {
	i := 0
	for ; i+4 <= len(src); i += 4 {
		x := binary.LittleEndian.Uint32(src[i:])
		ks := s.update32(uint32(x), one, mode)
		x ^= ks
		binary.LittleEndian.PutUint32(dst[i:], x)
	}
	for ; i < len(src); i++ {
		x := src[i]
		ks := s.update8(uint32(x), one, mode)
		dst[i] = x ^ uint8(ks)
	}
	s.pad(0)
}

func (s *state) finalize(tag []uint8) []uint8 {
	for i := 0; i < 640; i += 32 {
		s.update32(0, one, one)
	}
	for i := range tag[:16] {
		ks := s.update8(0, one, one)
		tag[i] = uint8(ks)
	}
	return tag
}

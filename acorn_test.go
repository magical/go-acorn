package acorn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

var sink uint32

func TestAcorn(t *testing.T) {
	k := []byte(strings.Repeat("password", 2))
	iv := []byte(strings.Repeat("randomiv", 2))
	p := []byte("message")

	var s state
	s.init(u32key(k), iv)
	s.process(nil)
	s.crypt(p, 0)

	tag := hex.EncodeToString(s.finalize())
	expectedTag := "f6881c28983aff930ad198968a401846"
	if tag != expectedTag {
		t.Errorf("got %s, want %s", tag, expectedTag)
	}
}

func BenchmarkUpdate8(b *testing.B) {
	b.SetBytes(1)
	var s state
	var ks uint32
	for i := 0; i < b.N; i++ {
		ks = s.update8(0, 0xFF, 0xFF)
	}
	sink = ks
}

func BenchmarkUpdate32(b *testing.B) {
	b.SetBytes(4)
	var s state
	var ks uint32
	for i := 0; i < b.N; i++ {
		const m = ^uint32(0)
		ks = s.update32(0, m, m)
	}
	sink = ks
}

func BenchmarkSeal(b *testing.B) {
	bench := func(b *testing.B, bytes int) {
		k := []byte(strings.Repeat("password", 2))
		iv := []byte(strings.Repeat("randomiv", 2))
		p := make([]byte, bytes)
		b.ReportAllocs()
		b.SetBytes(int64(len(p)))
		a := NewAEAD(k)
		var x byte
		var dst []byte
		for i := 0; i < b.N; i++ {
			dst = a.Seal(dst[:0], iv, p, nil)
			x ^= dst[0]
		}
		sink = uint32(x)
	}
	b.Run("8", func(b *testing.B) { bench(b, 8) })
	b.Run("4096", func(b *testing.B) { bench(b, 4096) })
}

func u32key(key []byte) *[4]uint32 {
	return &[4]uint32{
		binary.LittleEndian.Uint32(key[0*4:]),
		binary.LittleEndian.Uint32(key[1*4:]),
		binary.LittleEndian.Uint32(key[2*4:]),
		binary.LittleEndian.Uint32(key[3*4:]),
	}
}

func encrypt(k, iv, text []byte) []byte {
	var s state
	s.init(u32key(k), iv)
	s.process(nil)
	ci := s.crypt(text, 0)
	tag := s.finalize()
	return append(ci, tag...)
}

var testVectors = []struct {
	key        []uint8
	plaintext  []uint8
	ciphertext []uint8
	authdata   []uint8
	iv         []uint8
	tag        []uint8
}{
	{
		key: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		plaintext:  []uint8{},
		ciphertext: []uint8{},
		authdata:   []uint8{},
		iv: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		tag: []uint8{0x83, 0x5e, 0x53, 0x17, 0x89, 0x6e, 0x86, 0xb2,
			0x44, 0x71, 0x43, 0xc7, 0x4f, 0x6f, 0xfc, 0x1e},
	},
	{
		key: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		plaintext:  []uint8{0x01},
		ciphertext: []uint8{0x2b},
		authdata:   []uint8{},
		iv: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		tag: []uint8{0x4b, 0x60, 0x64, 0x0e, 0x26, 0xf0, 0xa9, 0x9d,
			0xd0, 0x1f, 0x93, 0xbf, 0x63, 0x49, 0x97, 0xcb},
	},
	{
		key: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		plaintext:  []uint8{},
		ciphertext: []uint8{},
		authdata:   []uint8{0x01},
		iv: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		tag: []uint8{0x98, 0x2e, 0xf7, 0xd1, 0xbb, 0xa7, 0xf8, 0x9a,
			0x15, 0x75, 0x29, 0x7a, 0x09, 0x5c, 0xd7, 0xf2},
	},
	{
		key: []uint8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext: []uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		ciphertext: []uint8{0x86, 0x80, 0x1f, 0xa8, 0x9e, 0x33, 0xd9, 0x92,
			0x35, 0xdd, 0x4d, 0x1a, 0x72, 0xce, 0x00, 0x1a},
		authdata: []uint8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		iv: []uint8{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
			0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d},
		tag: []uint8{0xd9, 0xc6, 0x6b, 0x4a, 0xdb, 0x3c, 0xde, 0x07,
			0x3e, 0x63, 0x50, 0xcc, 0x7e, 0x23, 0x7e, 0x01},
	},
	{
		key: []uint8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext: []uint8{0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31,
			0x38, 0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69,
			0x70, 0x77, 0x7e, 0x85, 0x8c, 0x93, 0x9a, 0xa1,
			0xa8, 0xaf, 0xb6, 0xbd, 0xc4, 0xcb, 0xd2, 0xd9,
			0xe0, 0xe7, 0xee, 0xf5, 0xfc, 0x03, 0x0a, 0x11,
			0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49,
			0x50, 0x57, 0x5e, 0x65, 0x6c, 0x73, 0x7a, 0x81,
			0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9,
			0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea, 0xf1,
			0xf8},
		ciphertext: []uint8{0xe7, 0xef, 0x31, 0x63, 0x78, 0x44, 0x46, 0x44,
			0x70, 0x5c, 0x43, 0x81, 0xc8, 0x88, 0x83, 0x3b,
			0x6d, 0x62, 0xa7, 0x49, 0x00, 0x5a, 0xb8, 0xfa,
			0x14, 0x6a, 0x85, 0x90, 0x4d, 0x5e, 0x5a, 0xb7,
			0x7c, 0x57, 0x58, 0x21, 0x58, 0x39, 0x5d, 0x8f,
			0xe6, 0xb6, 0x66, 0xe6, 0xc8, 0x51, 0x77, 0x64,
			0x8a, 0xeb, 0x77, 0x84, 0xcf, 0x2e, 0xea, 0xed,
			0x3c, 0x22, 0xe7, 0xe9, 0x6b, 0xf5, 0x90, 0x09,
			0xcd, 0x7a, 0xd2, 0x1b, 0xa5, 0xdf, 0x1a, 0x0f,
			0xc0},
		authdata: []uint8{0x00, 0x05, 0x0a, 0x0f, 0x14, 0x19, 0x1e, 0x23,
			0x28, 0x2d, 0x32, 0x37, 0x3c, 0x41, 0x46, 0x4b,
			0x50, 0x55, 0x5a, 0x5f, 0x64, 0x69, 0x6e, 0x73,
			0x78, 0x7d, 0x82, 0x87, 0x8c, 0x91, 0x96, 0x9b,
			0xa0, 0xa5, 0xaa, 0xaf, 0xb4, 0xb9, 0xbe},
		iv: []uint8{0x00, 0x03, 0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15,
			0x18, 0x1b, 0x1e, 0x21, 0x24, 0x27, 0x2a, 0x2d},
		tag: []uint8{0x51, 0xb4, 0xbd, 0x86, 0xc6, 0x8c, 0xcf, 0x06,
			0x82, 0xf5, 0x69, 0x5d, 0x26, 0x67, 0xd5, 0x35},
	},
}

func TestSeal(t *testing.T) {
	for i, tt := range testVectors {
		a := NewAEAD(tt.key)
		dst := a.Seal(nil, tt.iv, tt.plaintext, tt.authdata)
		ciphertext := dst[:len(tt.ciphertext)]
		tag := dst[len(tt.ciphertext):]
		if !bytes.Equal(ciphertext, tt.ciphertext) {
			t.Errorf("Seal test #%d: ciphertext = %x, want %x", i, ciphertext, tt.ciphertext)
		}
		if !bytes.Equal(tag, tt.tag) {
			t.Errorf("Seal test #%d: tag = %x, want %x", i, tag, tt.ciphertext)
		}
	}
}

func TestOpen(t *testing.T) {
	for i, tt := range testVectors {
		a := NewAEAD(tt.key)
		var ciphertext []uint8
		ciphertext = append(ciphertext, tt.ciphertext...)
		ciphertext = append(ciphertext, tt.tag...)
		dst, err := a.Open(nil, tt.iv, ciphertext, tt.authdata)
		if err != nil {
			t.Errorf("Open test #%d: unexpected error: %v", i, err)
		} else if !bytes.Equal(dst, tt.plaintext) {
			t.Errorf("Seal test #%d = %x, want %x", i, dst, tt.plaintext)
		}
	}
}

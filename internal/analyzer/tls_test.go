package analyzer

import (
	"encoding/binary"
	"testing"
)

// clientHello собирает минимальный корректный TLS ClientHello с заданным SNI.
func clientHello(sni string) []byte {
	return clientHelloWithSNI(sni, true)
}

// clientHelloWithSNI собирает минимальный ClientHello.
// При withServerName = false расширение server_name не добавляется,
// вместо него кладётся безобидное supported_versions.
func clientHelloWithSNI(sni string, withServerName bool) []byte {
	name := []byte(sni)

	var exts []byte
	if withServerName {
		exts = append(exts, 0x00, 0x00) // extension_type = server_name
		extLen := 5 + len(name)
		exts = append(exts, byte(extLen>>8), byte(extLen))
		listLen := 3 + len(name)
		exts = append(exts, byte(listLen>>8), byte(listLen))
		exts = append(exts, 0x00) // name_type = host_name
		exts = append(exts, byte(len(name)>>8), byte(len(name)))
		exts = append(exts, name...)
	} else {
		exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions
	}

	body := make([]byte, 0, 2+32+1+4+2+2+len(exts))
	body = append(body, 0x03, 0x03) // legacy_version
	for i := 0; i < 32; i++ {
		body = append(body, byte(i)) // random
	}
	body = append(body, 0x00)       // session_id length = 0
	body = append(body, 0x00, 0x02) // cipher_suites length
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // ClientHello
	n := len(body)
	handshake = append(handshake, byte(n>>16), byte(n>>8), byte(n))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01) // handshake, TLS 1.0 record version
	n = len(handshake)
	record = append(record, byte(n>>8), byte(n))
	record = append(record, handshake...)
	return record
}

// oversizedRecord берёт корректный ClientHello и завышает заявленную длину
// TLS-записи так, что она выходит за пределы буфера.
func oversizedRecord() []byte {
	b := clientHello("example.com")
	recLen := binary.BigEndian.Uint16(b[3:5])
	binary.BigEndian.PutUint16(b[3:5], recLen+64)
	return b
}

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name   string
		in     []byte
		want   string
		wantOK bool
	}{
		{"simple name", clientHello("example.com"), "example.com", true},
		{"dotted name", clientHello("a.b.c"), "a.b.c", true},
		{"empty payload", []byte{}, "", false},
		{"short record", []byte{0x16, 0x03, 0x03}, "", false},
		{"application data", append([]byte{0x17}, clientHello("example.com")[1:]...), "", false},
		{"record longer than buffer", oversizedRecord(), "", false},
		{"no server_name extension", clientHelloWithSNI("example.com", false), "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractSNI(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("extractSNI() ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("extractSNI() = %q, want %q", got, tc.want)
			}
		})
	}
}

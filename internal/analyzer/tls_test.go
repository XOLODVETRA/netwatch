package analyzer

import (
	"encoding/binary"
	"testing"
)

// helloOptions управляет тем, какие расширения попадут в ClientHello.
type helloOptions struct {
	serverName bool // добавить расширение server_name (тип 0)
	decoyFirst bool // поставить постороннее расширение перед server_name
}

// clientHello собирает минимальный корректный TLS ClientHello с заданным SNI.
func clientHello(sni string) []byte {
	return clientHelloOpts(sni, helloOptions{serverName: true})
}

// decoyExtension возвращает постороннее расширение с «имя-подобным» телом:
// список из одной записи (host_name, длина 3, "foo").
//
// Тело намеренно длиннее 5 байт и структурно совпадает с server_name, чтобы
// тест на отсутствие SNI был опровержимым: если убрать проверку типа расширения,
// extractSNI разберёт "foo" вместо того, чтобы пропустить расширение.
func decoyExtension() []byte {
	name := []byte("foo")
	bodyLen := 5 + len(name) // list_len(2) + name_type(1) + name_len(2) + имя

	ext := make([]byte, 0, 4+bodyLen)
	ext = append(ext, 0x00, 0x2b) // extension_type = supported_versions (не 0)
	ext = append(ext, byte(bodyLen>>8), byte(bodyLen))
	listLen := 3 + len(name)
	ext = append(ext, byte(listLen>>8), byte(listLen))
	ext = append(ext, 0x00) // name_type = host_name
	ext = append(ext, byte(len(name)>>8), byte(len(name)))
	ext = append(ext, name...)
	return ext
}

// serverNameExtension собирает расширение server_name (тип 0) для sni.
func serverNameExtension(sni string) []byte {
	name := []byte(sni)
	bodyLen := 5 + len(name) // list_len(2) + name_type(1) + name_len(2) + имя

	ext := make([]byte, 0, 4+bodyLen)
	ext = append(ext, 0x00, 0x00) // extension_type = server_name
	ext = append(ext, byte(bodyLen>>8), byte(bodyLen))
	listLen := 3 + len(name)
	ext = append(ext, byte(listLen>>8), byte(listLen))
	ext = append(ext, 0x00) // name_type = host_name
	ext = append(ext, byte(len(name)>>8), byte(len(name)))
	ext = append(ext, name...)
	return ext
}

// clientHelloOpts собирает минимальный корректный ClientHello:
// record 0x16/0x0301, handshake 0x01, version 0x0303, 32 байта random,
// session id 0, один cipher suite, compression 0 и список расширений.
func clientHelloOpts(sni string, opt helloOptions) []byte {
	var exts []byte
	// Приманка идёт первой — либо вместо server_name, либо перед ним.
	if !opt.serverName || opt.decoyFirst {
		exts = append(exts, decoyExtension()...)
	}
	if opt.serverName {
		exts = append(exts, serverNameExtension(sni)...)
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
	// Без server_name в списке остаётся только имя-подобная приманка "foo".
	decoyOnly := clientHelloOpts("", helloOptions{})
	// Приманка стоит до server_name: цикл обязан пропустить её и продолжить поиск.
	decoyThenSNI := clientHelloOpts("example.com", helloOptions{serverName: true, decoyFirst: true})

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
		{"decoy extension only", decoyOnly, "", false},
		{"decoy extension before server_name", decoyThenSNI, "example.com", true},
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

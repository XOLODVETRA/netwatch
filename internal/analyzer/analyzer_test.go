package analyzer

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/XOLODVETRA/netwatch/internal/config"
	"github.com/XOLODVETRA/netwatch/internal/models"
	"github.com/XOLODVETRA/netwatch/internal/store"
)

func TestExtractHost(t *testing.T) {
	// Граница проходит по 253 байтам: 253 — валидно, 254 — уже нет.
	host253 := strings.Repeat("a", 253)
	host254 := strings.Repeat("a", 254)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"http request", "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n", "example.org"},
		{"two spaces after colon", "Host:  example.org", "example.org"},
		{"empty value", "Host:\r\n", ""},
		{"no host header", "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n", ""},
		{"host of 253 chars", "Host: " + host253 + "\r\n", host253},
		{"host longer than 253", "Host: " + host254 + "\r\n", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractHost([]byte(tc.in)); got != tc.want {
				t.Fatalf("extractHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEndpointLess(t *testing.T) {
	ipA := netip.MustParseAddr("192.0.2.10")
	ipB := netip.MustParseAddr("198.51.100.20")

	tests := []struct {
		name string
		x    models.Endpoint
		y    models.Endpoint
		want bool
	}{
		{
			name: "same ip lower port is less",
			x:    models.Endpoint{IP: ipA, Port: 80},
			y:    models.Endpoint{IP: ipA, Port: 443},
			want: true,
		},
		{
			name: "same ip higher port is not less",
			x:    models.Endpoint{IP: ipA, Port: 443},
			y:    models.Endpoint{IP: ipA, Port: 80},
			want: false,
		},
		{
			name: "different ip compares by ip",
			x:    models.Endpoint{IP: ipA, Port: 65000},
			y:    models.Endpoint{IP: ipB, Port: 1},
			want: true,
		},
		{
			name: "different ip reversed",
			x:    models.Endpoint{IP: ipB, Port: 1},
			y:    models.Endpoint{IP: ipA, Port: 65000},
			want: false,
		},
		{
			name: "equal endpoints are not less",
			x:    models.Endpoint{IP: ipA, Port: 443},
			y:    models.Endpoint{IP: ipA, Port: 443},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointLess(tc.x, tc.y); got != tc.want {
				t.Fatalf("endpointLess(%v, %v) = %v, want %v", tc.x, tc.y, got, tc.want)
			}
		})
	}
}

// mustPacket собирает IPv4/TCP-пакет через serialize + разбор gopacket.
func mustPacket(t *testing.T, src, dst string, srcPort, dstPort uint16) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(src).To4(),
		DstIP:    net.ParseIP(dst).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func TestFlowKeyCanonical(t *testing.T) {
	a := New(store.New(config.Default(), nil))

	// Один и тот же поток в двух направлениях.
	forward := mustPacket(t, "192.0.2.10", "198.51.100.20", 51000, 443)
	backward := mustPacket(t, "198.51.100.20", "192.0.2.10", 443, 51000)

	fwd, ok := a.parse(forward)
	if !ok {
		t.Fatal("parse() отбросил пакет клиент→сервер")
	}
	rev, ok := a.parse(backward)
	if !ok {
		t.Fatal("parse() отбросил пакет сервер→клиент")
	}

	if fwd.Key.A != rev.Key.A {
		t.Errorf("Key.A = %v и %v, ожидались одинаковые", fwd.Key.A, rev.Key.A)
	}
	if fwd.Key.B != rev.Key.B {
		t.Errorf("Key.B = %v и %v, ожидались одинаковые", fwd.Key.B, rev.Key.B)
	}
	if fwd.Key.Proto != rev.Key.Proto {
		t.Errorf("Key.Proto = %q и %q, ожидались одинаковые", fwd.Key.Proto, rev.Key.Proto)
	}
	if fwd.Key != rev.Key {
		t.Errorf("Key = %v и %v, ожидался канонический ключ", fwd.Key, rev.Key)
	}

	// Ключ канонический: A — всегда меньший endpoint, независимо от направления.
	wantA := models.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 51000}
	wantB := models.Endpoint{IP: netip.MustParseAddr("198.51.100.20"), Port: 443}
	if fwd.Key.A != wantA {
		t.Errorf("Key.A = %v, want %v", fwd.Key.A, wantA)
	}
	if fwd.Key.B != wantB {
		t.Errorf("Key.B = %v, want %v", fwd.Key.B, wantB)
	}

	if fwd.SrcIP == rev.SrcIP {
		t.Errorf("SrcIP = %v в обоих направлениях, ожидались разные", fwd.SrcIP)
	}
	if fwd.DstIP == rev.DstIP {
		t.Errorf("DstIP = %v в обоих направлениях, ожидались разные", fwd.DstIP)
	}
	if fwd.Key.Proto != "tcp" {
		t.Errorf("Key.Proto = %q, want %q", fwd.Key.Proto, "tcp")
	}
}

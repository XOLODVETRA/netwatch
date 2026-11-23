// Package analyzer разбирает пакеты и превращает их в агрегируемые сэмплы.
package analyzer

import (
	"bytes"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"netwatch/internal/models"
	"netwatch/internal/store"
)

// Analyzer переводит пакеты gopacket в сэмплы для хранилища.
type Analyzer struct {
	store *store.Store
}

// New создаёт анализатор, пишущий в st.
func New(st *store.Store) *Analyzer {
	return &Analyzer{store: st}
}

// Process разбирает один пакет и передаёт сэмпл в хранилище.
func (a *Analyzer) Process(pkt gopacket.Packet) {
	sample, ok := a.parse(pkt)
	if !ok {
		return
	}
	a.store.Ingest(sample)
}

func (a *Analyzer) parse(pkt gopacket.Packet) (models.Sample, bool) {
	var srcIP, dstIP netip.Addr
	var proto string

	switch net := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		srcIP, dstIP = toAddr(net.SrcIP), toAddr(net.DstIP)
		proto = ipProtoName(net.Protocol)
	case *layers.IPv6:
		srcIP, dstIP = toAddr(net.SrcIP), toAddr(net.DstIP)
		proto = ipProtoName(net.NextHeader)
	default:
		// ARP и прочий non-IP трафик пока не учитываем.
		return models.Sample{}, false
	}
	if !srcIP.IsValid() || !dstIP.IsValid() {
		return models.Sample{}, false
	}

	var srcPort, dstPort uint16
	var payload []byte
	switch tr := pkt.TransportLayer().(type) {
	case *layers.TCP:
		srcPort, dstPort = uint16(tr.SrcPort), uint16(tr.DstPort)
		payload = tr.Payload
	case *layers.UDP:
		srcPort, dstPort = uint16(tr.SrcPort), uint16(tr.DstPort)
		payload = tr.Payload
	}

	length := pkt.Metadata().Length
	if length <= 0 {
		length = len(pkt.Data())
	}

	app := classifyApp(srcPort, dstPort)
	domain := ""
	var names []models.NameRecord

	switch app {
	case "tls":
		if sni, ok := extractSNI(payload); ok {
			domain = sni
		}
	case "http":
		domain = extractHost(payload)
	case "dns":
		if msg, ok := decodeDNS(payload); ok {
			if len(msg.Questions) > 0 {
				domain = string(msg.Questions[0].Name)
			}
			for _, ans := range msg.Answers {
				if len(ans.IP) == 0 || len(ans.Name) == 0 {
					continue
				}
				ip := toAddr(ans.IP)
				if ip.IsValid() {
					names = append(names, models.NameRecord{IP: ip, Name: string(ans.Name)})
				}
			}
		}
	}

	epA, epB := models.Endpoint{IP: srcIP, Port: srcPort}, models.Endpoint{IP: dstIP, Port: dstPort}
	if endpointLess(epB, epA) {
		epA, epB = epB, epA
	}

	return models.Sample{
		Key:     models.FlowKey{A: epA, B: epB, Proto: proto},
		Bytes:   uint64(length),
		Packets: 1,
		App:     app,
		Domain:  domain,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
		Time:    pkt.Metadata().Timestamp,
		Names:   names,
	}, true
}

// toAddr приводит net.IP к компактному сравниваемому виду netip.Addr.
func toAddr(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4))
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func endpointLess(x, y models.Endpoint) bool {
	if c := x.IP.Compare(y.IP); c != 0 {
		return c < 0
	}
	return x.Port < y.Port
}

func ipProtoName(p layers.IPProtocol) string {
	switch p {
	case layers.IPProtocolTCP:
		return "tcp"
	case layers.IPProtocolUDP:
		return "udp"
	case layers.IPProtocolICMPv4, layers.IPProtocolICMPv6:
		return "icmp"
	default:
		return "other"
	}
}

// classifyApp определяет сервис по портам в обе стороны.
func classifyApp(srcPort, dstPort uint16) string {
	for _, port := range [2]uint16{dstPort, srcPort} {
		switch port {
		case 53:
			return "dns"
		case 80:
			return "http"
		case 443:
			return "tls"
		case 22:
			return "ssh"
		case 67, 68:
			return "dhcp"
		case 123:
			return "ntp"
		case 5353:
			return "mdns"
		case 1900:
			return "ssdp"
		case 3389:
			return "rdp"
		case 139, 445:
			return "smb"
		}
	}
	return "other"
}

// extractHost вытаскивает значение заголовка Host из HTTP-запроса.
func extractHost(payload []byte) string {
	const marker = "Host:"
	idx := bytes.Index(payload, []byte(marker))
	if idx < 0 {
		return ""
	}
	rest := bytes.TrimLeft(payload[idx+len(marker):], " \t")
	end := bytes.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	host := string(rest[:end])
	if len(host) > 253 {
		return ""
	}
	return host
}

// decodeDNS разбирает DNS-сообщение из UDP-пакета.
func decodeDNS(payload []byte) (*layers.DNS, bool) {
	var msg layers.DNS
	if err := msg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, false
	}
	return &msg, true
}

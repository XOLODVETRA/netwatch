//go:build !pcap

// Заглушка для сборок без тега pcap: живой захват недоступен,
// но анализ pcap-файлов работает как обычно.
package capture

import (
	"fmt"

	"github.com/gopacket/gopacket"
)

// LiveSource без реализации.
type LiveSource struct{}

// OpenLive всегда возвращает ErrNoPcap.
func OpenLive(string, int32, bool, string) (*LiveSource, error) {
	return nil, fmt.Errorf("%w: сборка без тега pcap (Linux: libpcap-dev + gcc, Windows: Npcap)", ErrNoPcap)
}

func (s *LiveSource) NextPacket() (gopacket.Packet, error) { return nil, ErrNoPcap }

func (s *LiveSource) Close() error { return nil }

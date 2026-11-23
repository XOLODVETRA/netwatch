//go:build !pcap

// Заглушка для сборок без тега pcap: живой захват недоступен,
// но анализ pcap-файлов работает как обычно.
package capture

import (
	"errors"

	"github.com/gopacket/gopacket"
)

// ErrNoPcap возвращается, когда сборка выполнена без тега pcap.
var ErrNoPcap = errors.New("живой захват недоступен: пересоберите с тегом сборки pcap " +
	"(Linux: libpcap-dev + gcc, Windows: Npcap SDK + gcc)")

// LiveSource без реализации.
type LiveSource struct{}

// OpenLive всегда возвращает ErrNoPcap.
func OpenLive(string, int32, bool, string) (*LiveSource, error) { return nil, ErrNoPcap }

func (s *LiveSource) NextPacket() (gopacket.Packet, error) { return nil, ErrNoPcap }

func (s *LiveSource) Close() error { return nil }

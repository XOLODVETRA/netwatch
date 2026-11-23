// Package capture абстрагирует источник пакетов: живой интерфейс или pcap-файл.
package capture

import (
	"errors"
	"io"

	"github.com/gopacket/gopacket"
)

// Source — источник пакетов.
type Source interface {
	// NextPacket возвращает следующий пакет или io.EOF, когда файл кончился.
	NextPacket() (gopacket.Packet, error)
	Close() error
}

// IsEOF сообщает, что источник исчерпан.
func IsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

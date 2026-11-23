//go:build pcap

// Живой захват через libpcap/Npcap. Подключается сборкой с тегом pcap:
//
//	go build -tags pcap ./cmd/netwatch
//
// Linux: нужны libpcap-dev и gcc. Windows: достаточно Npcap (runtime),
// gopacket вызывает wpcap.dll напрямую.
package capture

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// LiveSource читает пакеты с сетевого интерфейса через pcap.
type LiveSource struct {
	handle *pcap.Handle
}

// OpenLive открывает интерфейс для захвата.
func OpenLive(iface string, snaplen int32, promiscuous bool, filter string) (*LiveSource, error) {
	handle, err := pcap.OpenLive(iface, snaplen, promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("открытие интерфейса %q: %w", iface, err)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("BPF-фильтр %q: %w", filter, err)
		}
	}
	return &LiveSource{handle: handle}, nil
}

func (s *LiveSource) NextPacket() (gopacket.Packet, error) {
	data, _, err := s.handle.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return gopacket.NewPacket(data, s.handle.LinkType(), gopacket.Default), nil
}

func (s *LiveSource) Close() error {
	s.handle.Close()
	return nil
}

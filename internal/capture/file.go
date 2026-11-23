package capture

import (
	"fmt"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

// FileSource читает пакеты из pcap-файла. Работает без прав администратора.
type FileSource struct {
	file *os.File
	r    *pcapgo.Reader
}

// OpenFile открывает pcap-файл для чтения.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("открытие pcap-файла: %w", err)
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("чтение pcap-заголовка %s: %w", path, err)
	}
	return &FileSource{file: f, r: r}, nil
}

func (s *FileSource) NextPacket() (gopacket.Packet, error) {
	data, _, err := s.r.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return gopacket.NewPacket(data, s.r.LinkType(), gopacket.Default), nil
}

func (s *FileSource) Close() error {
	return s.file.Close()
}

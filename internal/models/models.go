// Package models содержит общие типы данных: потоки, хосты, снимки статистики.
package models

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Endpoint — конец потока: IP-адрес и порт (0 для протоколов без портов).
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	if e.Port == 0 {
		return e.IP.String()
	}
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(int(e.Port)))
}

// FlowKey — канонический ключ потока. A всегда «меньше» B,
// чтобы оба направления складывались в один поток.
type FlowKey struct {
	A     Endpoint
	B     Endpoint
	Proto string
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s <-> %s (%s)", k.A, k.B, k.Proto)
}

// Sample — одна обработанная анализатором запись о пакете.
type Sample struct {
	Key     FlowKey
	Bytes   uint64
	Packets uint64
	App     string
	Domain  string
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   string
	Time    time.Time
	Names   []NameRecord
}

// NameRecord — пара IP→имя из DNS-ответа.
type NameRecord struct {
	IP   netip.Addr
	Name string
}

// FlowView — поток для отображения.
type FlowView struct {
	Key       FlowKey
	Bytes     uint64
	Packets   uint64
	Apps      []Count
	Domain    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// HostView — хост для отображения.
type HostView struct {
	IP       netip.Addr
	Name     string
	InBytes  uint64
	OutBytes uint64
	Bytes    uint64
	Packets  uint64
}

// Count — имя и значение счётчика.
type Count struct {
	Name  string
	Value uint64
}

// Alert — событие безопасности или аномалии.
type Alert struct {
	Time     time.Time
	Kind     string
	Severity string // info | warn | crit
	Message  string
}

// Snapshot — снимок состояния для отрисовки.
type Snapshot struct {
	Source       string
	Uptime       time.Duration
	TotalBytes   uint64
	TotalPackets uint64
	RateBPS      float64
	RatePPS      float64
	FlowsTotal   int
	Protocols    []Count
	Apps         []Count
	TopFlows     []FlowView
	TopHosts     []HostView
	TopDomains   []Count
	Alerts       []Alert
}

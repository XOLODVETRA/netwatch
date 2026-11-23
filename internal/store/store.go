// Package store накапливает статистику по потокам, хостам и доменам в памяти.
package store

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"netwatch/internal/config"
	"netwatch/internal/models"
)

const (
	rateBuckets = 60               // по одной корзине на секунду
	rateWindow  = 10 * time.Second // окно расчёта текущей скорости
	maxAlerts   = 100
)

type flowState struct {
	key       models.FlowKey
	bytes     uint64
	packets   uint64
	apps      map[string]uint64
	domain    string
	firstSeen time.Time
	lastSeen  time.Time
}

type hostState struct {
	ip       netip.Addr
	inBytes  uint64
	outBytes uint64
	packets  uint64
}

// Option — функциональная опция Store.
type Option func(*Store)

// WithClock подменяет часы — удобно в тестах.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// Store — потокобезопасное хранилище статистики.
type Store struct {
	mu  sync.Mutex
	cfg config.Config
	now func() time.Time

	flows   map[models.FlowKey]*flowState
	hosts   map[netip.Addr]*hostState
	proto   map[string]uint64
	apps    map[string]uint64
	domains map[string]uint64
	names   map[netip.Addr]string
	local   map[netip.Addr]bool

	totalBytes   uint64
	totalPackets uint64
	start        time.Time

	bytesBuckets   [rateBuckets]uint64
	packetsBuckets [rateBuckets]uint64
	bucketTimes    [rateBuckets]time.Time

	alerts []models.Alert

	portHits       map[netip.Addr]map[uint16]time.Time
	portAlertedAt  map[netip.Addr]time.Time
	bigFlowAlerted map[models.FlowKey]time.Time
}

// New создаёт Store. local — адреса этой машины, нужны для in/out разбивки.
func New(cfg config.Config, local []netip.Addr, opts ...Option) *Store {
	s := &Store{
		cfg:            cfg,
		now:            time.Now,
		flows:          make(map[models.FlowKey]*flowState),
		hosts:          make(map[netip.Addr]*hostState),
		proto:          make(map[string]uint64),
		apps:           make(map[string]uint64),
		domains:        make(map[string]uint64),
		names:          make(map[netip.Addr]string),
		local:          make(map[netip.Addr]bool),
		portHits:       make(map[netip.Addr]map[uint16]time.Time),
		portAlertedAt:  make(map[netip.Addr]time.Time),
		bigFlowAlerted: make(map[models.FlowKey]time.Time),
	}
	for _, ip := range local {
		if ip.IsValid() {
			s.local[ip.Unmap()] = true
		}
	}
	for _, o := range opts {
		o(s)
	}
	s.start = s.now()
	return s
}

// Ingest добавляет информацию об одном пакете.
func (s *Store) Ingest(sample models.Sample) {
	now := sample.Time
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tick(now, sample.Bytes, sample.Packets)

	f := s.flows[sample.Key]
	if f == nil {
		f = &flowState{
			key:       sample.Key,
			apps:      make(map[string]uint64),
			firstSeen: now,
		}
		s.flows[sample.Key] = f
	}
	f.bytes += sample.Bytes
	f.packets += sample.Packets
	f.lastSeen = now
	if sample.App != "" {
		f.apps[sample.App] += sample.Bytes
	}
	if sample.Domain != "" {
		f.domain = sample.Domain
	}

	s.proto[sample.Proto] += sample.Bytes
	if sample.App != "" {
		s.apps[sample.App] += sample.Bytes
	}
	if sample.Domain != "" {
		s.domains[sample.Domain]++
	}
	for _, nr := range sample.Names {
		s.names[nr.IP] = nr.Name
	}

	s.totalBytes += sample.Bytes
	s.totalPackets += sample.Packets

	s.updateHosts(sample)
	s.detectPortScan(sample, now)
	s.detectBigFlow(f, now)
}

// Prune убирает устаревшие потоки и записи детекторов.
func (s *Store) Prune() {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.cfg.FlowTTL)
	for k, f := range s.flows {
		if f.lastSeen.Before(cutoff) {
			delete(s.flows, k)
		}
	}

	hitCutoff := now.Add(-s.cfg.Alerts.PortScanWindow)
	for src, ports := range s.portHits {
		for port, t := range ports {
			if t.Before(hitCutoff) {
				delete(ports, port)
			}
		}
		if len(ports) == 0 {
			delete(s.portHits, src)
		}
	}
	if len(s.bigFlowAlerted) > 1000 {
		flowCutoff := now.Add(-s.cfg.Alerts.LargeFlowCooldown)
		for k, t := range s.bigFlowAlerted {
			if t.Before(flowCutoff) {
				delete(s.bigFlowAlerted, k)
			}
		}
	}
}

// Snapshot возвращает снимок состояния для отрисовки.
func (s *Store) Snapshot(topN int, source string) models.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	snap := models.Snapshot{
		Source:       source,
		Uptime:       now.Sub(s.start).Round(time.Second),
		TotalBytes:   s.totalBytes,
		TotalPackets: s.totalPackets,
		RateBPS:      s.rate(s.bytesBuckets[:], now),
		RatePPS:      s.rate(s.packetsBuckets[:], now),
		FlowsTotal:   len(s.flows),
		Protocols:    topCounts(s.proto, topN),
		Apps:         topCounts(s.apps, topN),
		TopDomains:   topCounts(s.domains, topN),
	}

	flows := make([]models.FlowView, 0, len(s.flows))
	for _, f := range s.flows {
		flows = append(flows, models.FlowView{
			Key:       f.key,
			Bytes:     f.bytes,
			Packets:   f.packets,
			Apps:      topCounts(f.apps, 3),
			Domain:    f.domain,
			FirstSeen: f.firstSeen,
			LastSeen:  f.lastSeen,
		})
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Bytes != flows[j].Bytes {
			return flows[i].Bytes > flows[j].Bytes
		}
		return flows[i].Key.String() < flows[j].Key.String()
	})
	if len(flows) > topN {
		flows = flows[:topN]
	}
	snap.TopFlows = flows

	hosts := make([]models.HostView, 0, len(s.hosts))
	for ip, h := range s.hosts {
		hosts = append(hosts, models.HostView{
			IP:       ip,
			Name:     s.names[ip],
			InBytes:  h.inBytes,
			OutBytes: h.outBytes,
			Bytes:    h.inBytes + h.outBytes,
			Packets:  h.packets,
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Bytes != hosts[j].Bytes {
			return hosts[i].Bytes > hosts[j].Bytes
		}
		return hosts[i].IP.String() < hosts[j].IP.String()
	})
	if len(hosts) > topN {
		hosts = hosts[:topN]
	}
	snap.TopHosts = hosts

	show := len(s.alerts)
	if show > 20 {
		show = 20
	}
	snap.Alerts = make([]models.Alert, 0, show)
	for i := len(s.alerts) - 1; i >= len(s.alerts)-show; i-- {
		snap.Alerts = append(snap.Alerts, s.alerts[i])
	}
	return snap
}

// tick раскладывает байты и пакеты по секундным корзинам.
func (s *Store) tick(now time.Time, bytes, packets uint64) {
	sec := now.Truncate(time.Second)
	idx := int(sec.Unix() % int64(rateBuckets))
	if !s.bucketTimes[idx].Equal(sec) {
		s.bytesBuckets[idx] = 0
		s.packetsBuckets[idx] = 0
		s.bucketTimes[idx] = sec
	}
	s.bytesBuckets[idx] += bytes
	s.packetsBuckets[idx] += packets
}

func (s *Store) updateHosts(sample models.Sample) {
	srcLocal := s.local[sample.SrcIP]
	dstLocal := s.local[sample.DstIP]

	add := func(ip netip.Addr, inbound bool) {
		if !ip.IsValid() || ip.IsLoopback() || ip == sample.SrcIP && ip == sample.DstIP {
			return
		}
		h := s.hosts[ip]
		if h == nil {
			h = &hostState{ip: ip}
			s.hosts[ip] = h
		}
		if inbound {
			h.inBytes += sample.Bytes
		} else {
			h.outBytes += sample.Bytes
		}
		h.packets += sample.Packets
	}

	switch {
	case srcLocal && !dstLocal:
		add(sample.DstIP, false)
	case !srcLocal && dstLocal:
		add(sample.SrcIP, true)
	case !srcLocal && !dstLocal:
		add(sample.SrcIP, false)
		add(sample.DstIP, true)
	default:
		// Обе стороны локальные: LAN-трафик, показываем у обоих.
		add(sample.SrcIP, false)
		add(sample.DstIP, true)
	}
}

func (s *Store) detectPortScan(sample models.Sample, now time.Time) {
	if sample.Proto != "tcp" && sample.Proto != "udp" {
		return
	}
	if sample.DstPort == 0 || !sample.SrcIP.IsValid() {
		return
	}
	src := sample.SrcIP
	ports := s.portHits[src]
	if ports == nil {
		ports = make(map[uint16]time.Time)
		s.portHits[src] = ports
	}
	cutoff := now.Add(-s.cfg.Alerts.PortScanWindow)
	for port, t := range ports {
		if t.Before(cutoff) {
			delete(ports, port)
		}
	}
	ports[sample.DstPort] = now

	if len(ports) < s.cfg.Alerts.PortScanPorts {
		return
	}
	if last, ok := s.portAlertedAt[src]; ok && now.Sub(last) < s.cfg.Alerts.PortScanCooldown {
		return
	}
	s.portAlertedAt[src] = now
	s.pushAlert(models.Alert{
		Time:     now,
		Kind:     "portscan",
		Severity: "warn",
		Message: fmt.Sprintf("%s обращается к %d портам за %s",
			src, len(ports), s.cfg.Alerts.PortScanWindow),
	})
}

func (s *Store) detectBigFlow(f *flowState, now time.Time) {
	limit := s.cfg.Alerts.LargeFlowMB << 20
	if limit == 0 || f.bytes < limit {
		return
	}
	if last, ok := s.bigFlowAlerted[f.key]; ok && now.Sub(last) < s.cfg.Alerts.LargeFlowCooldown {
		return
	}
	s.bigFlowAlerted[f.key] = now
	s.pushAlert(models.Alert{
		Time:     now,
		Kind:     "bigflow",
		Severity: "info",
		Message:  fmt.Sprintf("большой поток %s: %s", f.key, humanBytes(f.bytes)),
	})
}

func (s *Store) pushAlert(a models.Alert) {
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > maxAlerts {
		s.alerts = append([]models.Alert(nil), s.alerts[len(s.alerts)-maxAlerts:]...)
	}
}

func (s *Store) rate(buckets []uint64, now time.Time) float64 {
	cutoff := now.Add(-rateWindow)
	var sum uint64
	for i, b := range buckets {
		if b == 0 {
			continue
		}
		if s.bucketTimes[i].After(cutoff) {
			sum += b
		}
	}
	return float64(sum) / rateWindow.Seconds()
}

func topCounts(m map[string]uint64, n int) []models.Count {
	out := make([]models.Count, 0, len(m))
	for name, value := range m {
		out = append(out, models.Count{Name: name, Value: value})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func humanBytes(v uint64) string {
	if v < 1024 {
		return fmt.Sprintf("%d Б", v)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ"}
	f := float64(v)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

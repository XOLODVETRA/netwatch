package store

import (
	"net/netip"
	"testing"
	"time"

	"github.com/XOLODVETRA/netwatch/internal/config"
	"github.com/XOLODVETRA/netwatch/internal/models"
)

// testKey — один и тот же поток во всех тестах.
func testKey() models.FlowKey {
	return models.FlowKey{
		A:     models.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 51000},
		B:     models.Endpoint{IP: netip.MustParseAddr("198.51.100.20"), Port: 443},
		Proto: "tcp",
	}
}

// sample собирает сэмпл напрямую, без pcap.
// Time оставлен нулевым: Ingest подставит время из внедрённых часов.
func sample(key models.FlowKey, bytes uint64, domain, app string) models.Sample {
	return models.Sample{
		Key:     key,
		Bytes:   bytes,
		Packets: 1,
		App:     app,
		Domain:  domain,
		SrcIP:   key.A.IP,
		DstIP:   key.B.IP,
		Proto:   key.Proto,
	}
}

// freshKey — второй поток с другим клиентским портом.
func freshKey() models.FlowKey {
	return models.FlowKey{
		A:     models.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 51001},
		B:     models.Endpoint{IP: netip.MustParseAddr("198.51.100.20"), Port: 443},
		Proto: "tcp",
	}
}

// newTestStore создаёт хранилище на управляемых часах.
// Часы читают *now при каждом вызове, поэтому сдвиг fixed виден Store сразу.
func newTestStore(cfg config.Config, now *time.Time) *Store {
	return New(cfg, nil, WithClock(func() time.Time { return *now }))
}

func TestAggregatesFlow(t *testing.T) {
	fixed := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	st := newTestStore(config.Default(), &fixed)

	key := testKey()
	st.Ingest(sample(key, 100, "", "tls"))
	st.Ingest(sample(key, 50, "", "tls"))

	snap := st.Snapshot(10, "test")
	if snap.FlowsTotal != 1 {
		t.Fatalf("FlowsTotal = %d, want 1", snap.FlowsTotal)
	}
	if snap.TotalBytes != 150 {
		t.Fatalf("TotalBytes = %d, want 150", snap.TotalBytes)
	}
	if snap.TotalPackets != 2 {
		t.Fatalf("TotalPackets = %d, want 2", snap.TotalPackets)
	}
	if len(snap.TopFlows) != 1 {
		t.Fatalf("len(TopFlows) = %d, want 1", len(snap.TopFlows))
	}
	if snap.TopFlows[0].Bytes != 150 || snap.TopFlows[0].Packets != 2 {
		t.Fatalf("TopFlows[0] = %d байт / %d пакетов, want 150 / 2",
			snap.TopFlows[0].Bytes, snap.TopFlows[0].Packets)
	}
}

func TestPruneForgetsOldFlow(t *testing.T) {
	cfg := config.Default()
	// База в будущем: если Store возьмёт time.Now() вместо внедрённых часов,
	// проверка «на половине TTL поток жив» упадёт.
	t0 := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	fixed := t0
	st := newTestStore(cfg, &fixed)

	old := testKey()
	st.Ingest(sample(old, 100, "", "tls"))
	if got := st.Snapshot(10, "test").FlowsTotal; got != 1 {
		t.Fatalf("после Ingest: FlowsTotal = %d, want 1", got)
	}

	// Половина TTL — поток ещё жив.
	fixed = t0.Add(cfg.FlowTTL / 2)
	st.Prune()
	if got := st.Snapshot(10, "test").FlowsTotal; got != 1 {
		t.Fatalf("Prune на половине TTL: FlowsTotal = %d, want 1", got)
	}

	// Свежий поток появляется уже после сдвига часов.
	fresh := freshKey()
	st.Ingest(sample(fresh, 200, "", "http"))
	if got := st.Snapshot(10, "test").FlowsTotal; got != 2 {
		t.Fatalf("после второго Ingest: FlowsTotal = %d, want 2", got)
	}

	// Прыжок за TTL: старый поток протухает, свежий обязан выжить.
	fixed = t0.Add(cfg.FlowTTL + time.Minute)
	st.Prune()

	snap := st.Snapshot(10, "test")
	if snap.FlowsTotal != 1 {
		t.Fatalf("после Prune за TTL: FlowsTotal = %d, want 1", snap.FlowsTotal)
	}
	if len(snap.TopFlows) != 1 || snap.TopFlows[0].Key != fresh {
		t.Fatalf("после Prune остался %v, want %v", snap.TopFlows, fresh)
	}
	if snap.TotalBytes != 300 {
		t.Fatalf("TotalBytes = %d, want 300 (Prune не трогает общие счётчики)", snap.TotalBytes)
	}
}

func TestDomainsAndAppsCounted(t *testing.T) {
	fixed := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	st := newTestStore(config.Default(), &fixed)

	key := testKey()
	st.Ingest(sample(key, 100, "example.com", "tls"))
	st.Ingest(sample(key, 50, "example.com", "tls"))

	snap := st.Snapshot(10, "test")
	if len(snap.TopDomains) == 0 {
		t.Fatal("TopDomains пуст, want example.com")
	}
	if snap.TopDomains[0].Name != "example.com" {
		t.Fatalf("TopDomains[0].Name = %q, want %q", snap.TopDomains[0].Name, "example.com")
	}
	if snap.TopDomains[0].Value != 2 {
		t.Fatalf("TopDomains[0].Value = %d, want 2", snap.TopDomains[0].Value)
	}

	var gotTLS bool
	for _, app := range snap.Apps {
		if app.Name == "tls" {
			gotTLS = true
		}
	}
	if !gotTLS {
		t.Fatalf("Apps = %v, want запись tls", snap.Apps)
	}
}

// TestHostDirectionsRelativeToLocal фиксирует правило updateHosts.
// С непустым списком локальных адресов при одном локальном конце
// в таблицу попадает только удалённый, а его «исходящий» — трафик
// от локальной машины; если локальных концов нет или оба локальные,
// источник считается исходящим, а получатель — входящим.
func TestHostDirectionsRelativeToLocal(t *testing.T) {
	fixed := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	local := netip.MustParseAddr("192.0.2.10")
	remote := netip.MustParseAddr("198.51.100.20")
	key := testKey() // A = local:51000, B = remote:443

	st := New(cfg, []netip.Addr{local}, WithClock(func() time.Time { return fixed }))
	st.Ingest(sample(key, 100, "", "tls"))

	hosts := hostsByIP(st.Snapshot(10, "test"))
	if _, ok := hosts[local]; ok {
		t.Fatalf("локальный адрес %s не должен попадать в таблицу хостов", local)
	}
	got, ok := hosts[remote]
	if !ok {
		t.Fatalf("удалённый хост %s отсутствует в таблице", remote)
	}
	if got.InBytes != 0 || got.OutBytes != 100 {
		t.Fatalf("локальный источник: remote in/out = %d/%d, want 0/100", got.InBytes, got.OutBytes)
	}

	// Обратное направление: удалённый источник, локальный получатель.
	back := sample(key, 50, "", "tls")
	back.SrcIP, back.DstIP = remote, local
	st.Ingest(back)

	got = hostsByIP(st.Snapshot(10, "test"))[remote]
	if got.InBytes != 50 || got.OutBytes != 100 {
		t.Fatalf("после обратного пакета: remote in/out = %d/%d, want 50/100", got.InBytes, got.OutBytes)
	}

	// Ни один конец не локальный: источник — исходящий, получатель — входящий.
	st = New(cfg, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, WithClock(func() time.Time { return fixed }))
	st.Ingest(sample(key, 100, "", "tls"))

	hosts = hostsByIP(st.Snapshot(10, "test"))
	a, b := hosts[local], hosts[remote]
	if a.InBytes != 0 || a.OutBytes != 100 {
		t.Fatalf("без локальных концов: источник in/out = %d/%d, want 0/100", a.InBytes, a.OutBytes)
	}
	if b.InBytes != 100 || b.OutBytes != 0 {
		t.Fatalf("без локальных концов: получатель in/out = %d/%d, want 100/0", b.InBytes, b.OutBytes)
	}

	// Оба конца локальные: источник — исходящий, получатель — входящий,
	// в таблице оба.
	st = New(cfg, []netip.Addr{local, remote}, WithClock(func() time.Time { return fixed }))
	st.Ingest(sample(key, 100, "", "tls"))

	hosts = hostsByIP(st.Snapshot(10, "test"))
	a, b = hosts[local], hosts[remote]
	if a.InBytes != 0 || a.OutBytes != 100 {
		t.Fatalf("оба конца локальные: источник in/out = %d/%d, want 0/100", a.InBytes, a.OutBytes)
	}
	if b.InBytes != 100 || b.OutBytes != 0 {
		t.Fatalf("оба конца локальные: получатель in/out = %d/%d, want 100/0", b.InBytes, b.OutBytes)
	}
}

func hostsByIP(snap models.Snapshot) map[netip.Addr]models.HostView {
	out := make(map[netip.Addr]models.HostView, len(snap.TopHosts))
	for _, h := range snap.TopHosts {
		out[h.IP] = h
	}
	return out
}

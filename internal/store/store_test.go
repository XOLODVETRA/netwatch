package store

import (
	"net/netip"
	"testing"
	"time"

	"netwatch/internal/config"
	"netwatch/internal/models"
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

// newTestStore создаёт хранилище на управляемых часах.
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
	t0 := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	fixed := t0
	st := newTestStore(cfg, &fixed)

	st.Ingest(sample(testKey(), 100, "example.com", "tls"))
	if got := st.Snapshot(10, "test").FlowsTotal; got != 1 {
		t.Fatalf("до Prune: FlowsTotal = %d, want 1", got)
	}

	fixed = t0.Add(cfg.FlowTTL + time.Minute)
	st.Prune()

	if got := st.Snapshot(10, "test").FlowsTotal; got != 0 {
		t.Fatalf("после Prune: FlowsTotal = %d, want 0", got)
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

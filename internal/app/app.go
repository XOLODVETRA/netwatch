// Package app связывает конфиг, захват, анализатор, хранилище и рендер.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netwatch/internal/analyzer"
	"netwatch/internal/capture"
	"netwatch/internal/config"
	"netwatch/internal/netutil"
	"netwatch/internal/render"
	"netwatch/internal/store"
)

// Run запускает netwatch и возвращает управление после остановки.
func Run(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	local, err := netutil.LocalIPs()
	if err != nil {
		return fmt.Errorf("локальные адреса: %w", err)
	}

	st := store.New(cfg, local)
	an := analyzer.New(st)

	src, err := openSource(cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		readLoop(ctx, src, an)
	}()

	rnd := render.New(os.Stdout, cfg.NoClear)
	source := sourceName(cfg)
	ticker := time.NewTicker(cfg.Refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = src.Close()
			<-done
			drawFinal(rnd, st, cfg, source)
			return nil
		case <-done:
			drawFinal(rnd, st, cfg, source)
			return nil
		case <-ticker.C:
			st.Prune()
			rnd.Draw(st.Snapshot(cfg.TopN, source))
		}
	}
}

func readLoop(ctx context.Context, src capture.Source, an *analyzer.Analyzer) {
	for {
		pkt, err := src.NextPacket()
		if err != nil {
			if capture.IsEOF(err) || ctx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "ошибка захвата: %v\n", err)
			return
		}
		an.Process(pkt)
	}
}

func openSource(cfg config.Config) (capture.Source, error) {
	if cfg.File != "" {
		return capture.OpenFile(cfg.File)
	}
	src, err := capture.OpenLive(cfg.Interface, cfg.SnapLen, cfg.Promiscuous, cfg.Filter)
	if err != nil {
		if errors.Is(err, capture.ErrNoPcap) {
			return nil, fmt.Errorf("%w\nАнализ pcap-файла доступен без зависимостей: netwatch -file dump.pcap", err)
		}
		return nil, err
	}
	return src, nil
}

func sourceName(cfg config.Config) string {
	if cfg.File != "" {
		return "файл: " + cfg.File
	}
	return "интерфейс: " + cfg.Interface
}

func drawFinal(rnd *render.Renderer, st *store.Store, cfg config.Config, source string) {
	snap := st.Snapshot(cfg.TopN, source)
	rnd.Draw(snap)
	fmt.Printf("\nГотово. Источник: %s. Всего %d байт, %d пакетов за %s.\n",
		source, snap.TotalBytes, snap.TotalPackets, snap.Uptime)
}

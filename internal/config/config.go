// Package config задаёт значения по умолчанию и загружает YAML-конфигурацию.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AlertConfig — пороги и задержки детектора аномалий.
type AlertConfig struct {
	// LargeFlowMB — объём потока, начиная с которого срабатывает событие.
	LargeFlowMB uint64 `yaml:"large_flow_mb"`
	// LargeFlowCooldown — пауза между повторными событиями о больших потоках.
	LargeFlowCooldown time.Duration `yaml:"large_flow_cooldown"`
	// PortScanPorts — сколько разных портов за окно считается сканированием.
	PortScanPorts int `yaml:"port_scan_ports"`
	// PortScanWindow — окно, в котором считаются порты.
	PortScanWindow time.Duration `yaml:"port_scan_window"`
	// PortScanCooldown — пауза между повторными событиями сканирования.
	PortScanCooldown time.Duration `yaml:"port_scan_cooldown"`
}

// Config — все настройки netwatch.
type Config struct {
	// Interface — имя интерфейса для живого захвата.
	Interface string `yaml:"interface"`
	// File — путь к pcap-файлу; если задан, интерфейс игнорируется.
	File string `yaml:"file"`
	// SnapLen — максимальный размер захватываемого пакета.
	SnapLen int32 `yaml:"snaplen"`
	// Promiscuous — слушать весь трафик сегмента.
	Promiscuous bool `yaml:"promiscuous"`
	// Filter — BPF-фильтр в синтаксисе tcpdump.
	Filter string `yaml:"filter"`
	// Refresh — период перерисовки экрана.
	Refresh time.Duration `yaml:"refresh"`
	// TopN — число строк в каждом топе.
	TopN int `yaml:"top_n"`
	// FlowTTL — через сколько забывать неактивный поток.
	FlowTTL time.Duration `yaml:"flow_ttl"`
	// NoClear — не очищать экран и не использовать цвета.
	NoClear bool `yaml:"no_clear"`
	// Alerts — настройки детектора аномалий.
	Alerts AlertConfig `yaml:"alerts"`
}

// Default возвращает конфигурацию с разумными значениями по умолчанию.
func Default() Config {
	return Config{
		SnapLen:     65535,
		Promiscuous: true,
		Refresh:     time.Second,
		TopN:        10,
		FlowTTL:     5 * time.Minute,
		Alerts: AlertConfig{
			LargeFlowMB:       50,
			LargeFlowCooldown: 5 * time.Minute,
			PortScanPorts:     20,
			PortScanWindow:    10 * time.Second,
			PortScanCooldown:  60 * time.Second,
		},
	}
}

// Load читает YAML-файл поверх уже заполненного Config (обычно Default()).
func Load(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("чтение конфига: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("разбор конфига %s: %w", path, err)
	}
	return nil
}

// Validate проверяет, что настройки осмысленны.
func (c Config) Validate() error {
	if c.File == "" && c.Interface == "" {
		return fmt.Errorf("укажите интерфейс (-iface) или файл (-file)")
	}
	if c.Refresh <= 0 {
		return fmt.Errorf("refresh должен быть больше нуля")
	}
	if c.TopN <= 0 {
		return fmt.Errorf("top_n должен быть больше нуля")
	}
	if c.FlowTTL <= 0 {
		return fmt.Errorf("flow_ttl должен быть больше нуля")
	}
	if c.Alerts.PortScanPorts < 1 {
		return fmt.Errorf("alerts.port_scan_ports должен быть больше нуля")
	}
	if c.Alerts.PortScanWindow <= 0 {
		return fmt.Errorf("alerts.port_scan_window должен быть больше нуля")
	}
	return nil
}

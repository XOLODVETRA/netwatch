// Command netwatch — монитор трафика локальной сети.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"netwatch/internal/app"
	"netwatch/internal/config"
	"netwatch/internal/netutil"
)

func main() {
	cfg := config.Default()

	configPath := flag.String("config", "", "путь к YAML-конфигу (например, configs/netwatch.yaml)")

	var (
		ifaceFlag   string
		fileFlag    string
		filterFlag  string
		refreshFlag time.Duration
		topFlag     int
		noClearFlag bool
		listFlag    bool
	)
	flag.StringVar(&ifaceFlag, "iface", "", "сетевой интерфейс для захвата (по умолчанию первый подходящий)")
	flag.StringVar(&fileFlag, "file", "", "анализировать pcap-файл вместо интерфейса")
	flag.StringVar(&filterFlag, "filter", "", "BPF-фильтр в синтаксисе tcpdump (например, \"tcp port 443\")")
	flag.DurationVar(&refreshFlag, "refresh", 0, "период обновления экрана (например, 1s)")
	flag.IntVar(&topFlag, "top", 0, "число строк в топах")
	flag.BoolVar(&noClearFlag, "no-clear", false, "не очищать экран и не использовать цвета (для pipe/логов)")
	flag.BoolVar(&listFlag, "list", false, "показать интерфейсы и выйти")
	flag.Parse()

	if *configPath != "" {
		if err := config.Load(*configPath, &cfg); err != nil {
			fail(err)
		}
	}

	overrides := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { overrides[f.Name] = true })

	if overrides["iface"] {
		cfg.Interface = ifaceFlag
	}
	if overrides["file"] {
		cfg.File = fileFlag
	}
	if overrides["filter"] {
		cfg.Filter = filterFlag
	}
	if overrides["refresh"] {
		cfg.Refresh = refreshFlag
	}
	if overrides["top"] {
		cfg.TopN = topFlag
	}
	if overrides["no-clear"] {
		cfg.NoClear = noClearFlag
	}

	if listFlag {
		listInterfaces()
		return
	}

	if cfg.File == "" && cfg.Interface == "" {
		cfg.Interface = netutil.FirstInterface()
		if cfg.Interface == "" {
			fail(fmt.Errorf("не удалось выбрать интерфейс автоматически: укажите -iface"))
		}
	}

	if err := app.Run(cfg); err != nil {
		fail(err)
	}
}

func listInterfaces() {
	list, err := netutil.Interfaces()
	if err != nil {
		fail(err)
	}
	for _, iface := range list {
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		addrs := "—"
		if len(iface.Addrs) > 0 {
			addrs = fmt.Sprintf("%v", iface.Addrs)
		}
		fmt.Printf("%-40s %-4s %s\n", iface.Name, state, addrs)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ошибка:", err)
	os.Exit(1)
}

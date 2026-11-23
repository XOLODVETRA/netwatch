package config

import "testing"

func TestDefaultValid(t *testing.T) {
	cfg := Default()
	cfg.Interface = "eth0"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default() с заполненным Interface не прошёл Validate(): %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	// base возвращает заведомо валидную конфигурацию, которую портит mutate.
	base := func() Config {
		cfg := Default()
		cfg.Interface = "eth0"
		return cfg
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "empty interface and file",
			mutate: func(c *Config) {
				c.Interface = ""
				c.File = ""
			},
		},
		{
			name:   "zero refresh",
			mutate: func(c *Config) { c.Refresh = 0 },
		},
		{
			name:   "zero top n",
			mutate: func(c *Config) { c.TopN = 0 },
		},
		{
			name:   "zero flow ttl",
			mutate: func(c *Config) { c.FlowTTL = 0 },
		},
		{
			name:   "zero port scan ports",
			mutate: func(c *Config) { c.Alerts.PortScanPorts = 0 },
		},
		{
			name:   "zero port scan window",
			mutate: func(c *Config) { c.Alerts.PortScanWindow = 0 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() вернул nil, ожидалась ошибка")
			}
		})
	}
}

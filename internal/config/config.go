package config

import (
	"os"
	"log/slog"

	"github.com/tae2089/trace"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface  string `yaml:"interface"`
	Masquerade bool   `yaml:"masquerade"`
	ExternalIP string `yaml:"external_ip,omitempty"`
	SNAT       []Rule `yaml:"snat"`
	DNAT       []Rule `yaml:"dnat"`
}

type Rule struct {
	SrcIP    string `yaml:"src_ip,omitempty"`
	DstIP    string `yaml:"dst_ip,omitempty"`
	SrcPort  uint16 `yaml:"src_port,omitempty"`
	DstPort  uint16 `yaml:"dst_port,omitempty"`
	Protocol string `yaml:"protocol"`
	TransIP  string `yaml:"trans_ip"`
	TransPort uint16 `yaml:"trans_port"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, trace.Wrap(err)
	}

	slog.Info("Configuration loaded successfully", slog.String("path", path))
	return &cfg, nil
}

package config

import (
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Interface:   "eth0",
				ExternalIP:  "1.2.3.4",
				InternalNet: "192.168.1.0/24",
				GCInterval:  "1m",
				TCPTimeout:  "24h",
				UDPTimeout:  "5m",
			},
			wantErr: false,
		},
		{
			name: "missing interface",
			config: Config{
				ExternalIP: "1.2.3.4",
			},
			wantErr: true,
		},
		{
			name: "invalid external-ip",
			config: Config{
				Interface:  "eth0",
				ExternalIP: "invalid-ip",
			},
			wantErr: true,
		},
		{
			name: "invalid internal-net",
			config: Config{
				Interface:   "eth0",
				InternalNet: "192.168.1.0/100",
			},
			wantErr: true,
		},
		{
			name: "invalid duration",
			config: Config{
				Interface:  "eth0",
				GCInterval: "invalid-duration",
			},
			wantErr: true,
		},
		{
			name: "invalid SNAT rule",
			config: Config{
				Interface: "eth0",
				SNAT: []Rule{
					{
						SrcIP:    "invalid-ip",
						Protocol: "tcp",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid DNAT rule protocol",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						Protocol: "invalid",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

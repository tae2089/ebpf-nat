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
		{
			name: "invalid metrics port zero",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    0,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid metrics port too high",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    70000,
				},
			},
			wantErr: true,
		},
		{
			name: "valid metrics port",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
				},
			},
			wantErr: false,
		},
		{
			name: "IPv6 external-ip rejected",
			config: Config{
				Interface:  "eth0",
				ExternalIP: "::1",
			},
			wantErr: true,
		},
		{
			name: "DNAT rule missing trans-ip",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						DstIP:    "1.2.3.4",
						DstPort:  80,
						Protocol: "tcp",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid DNAT rule",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						DstIP:     "1.2.3.4",
						DstPort:   80,
						Protocol:  "tcp",
						TransIP:   "192.168.1.100",
						TransPort: 8080,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SNAT rule with IPv6 trans-ip rejected",
			config: Config{
				Interface: "eth0",
				SNAT: []Rule{
					{
						Protocol: "tcp",
						TransIP:  "::1",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "zero gc-interval rejected",
			config: Config{
				Interface:  "eth0",
				GCInterval: "0s",
			},
			wantErr: true,
		},
		{
			name: "negative tcp-timeout rejected",
			config: Config{
				Interface:  "eth0",
				TCPTimeout: "-1s",
			},
			wantErr: true,
		},
		{
			name: "max-sessions too small rejected",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 3,
			},
			wantErr: true,
		},
		{
			name: "max-sessions at minimum boundary accepted",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 8,
			},
			wantErr: false,
		},
		{
			name: "max-sessions zero (use default) accepted",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 0,
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type generic",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "generic",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type aws",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "aws",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type gcp",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "gcp",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type auto",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "auto",
			},
			wantErr: false,
		},
		{
			name: "invalid ip-detect-type rejected",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "azure",
			},
			wantErr: true,
		},
		{
			name: "empty ip-detect-type accepted",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "",
			},
			wantErr: false,
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

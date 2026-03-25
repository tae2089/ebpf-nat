package config

import (
	"fmt"
	"net"
	"time"
)

type Config struct {
	Interface       string
	Masquerade      bool
	ExternalIP      string
	InternalNet     string // e.g., "192.168.1.0/24" for SAV
	IPDetectType    string // generic, aws, gcp, auto
	GCInterval      string // e.g., "1m"
	TCPTimeout      string // e.g., "24h"
	UDPTimeout      string // e.g., "5m"
	MaxMSS          uint16 // TCP MSS clamping
	MaxSessions     uint32 // Maximum NAT sessions
	BatchUpdateSize uint32 // Batch update size for session restoration
	SessionFile     string // path to save/restore sessions
	Metrics         MetricsConfig
	SNAT            []Rule
	DNAT            []Rule
}

func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if c.ExternalIP != "" {
		ip := net.ParseIP(c.ExternalIP)
		if ip == nil {
			return fmt.Errorf("invalid external-ip: %s", c.ExternalIP)
		}
		if ip.To4() == nil {
			return fmt.Errorf("external-ip must be IPv4: %s", c.ExternalIP)
		}
	}

	if c.InternalNet != "" {
		if _, _, err := net.ParseCIDR(c.InternalNet); err != nil {
			return fmt.Errorf("invalid internal-net CIDR: %w", err)
		}
	}

	durations := []struct {
		name  string
		value string
	}{
		{"gc-interval", c.GCInterval},
		{"tcp-timeout", c.TCPTimeout},
		{"udp-timeout", c.UDPTimeout},
	}

	for _, d := range durations {
		if d.value != "" {
			dur, err := time.ParseDuration(d.value)
			if err != nil {
				return fmt.Errorf("invalid %s duration: %w", d.name, err)
			}
			if dur <= 0 {
				return fmt.Errorf("invalid %s duration: must be positive, got %s", d.name, d.value)
			}
		}
	}

	if c.MaxSessions > 0 && c.MaxSessions < 8 {
		return fmt.Errorf("max-sessions must be at least 8, got %d", c.MaxSessions)
	}

	if c.IPDetectType != "" {
		switch c.IPDetectType {
		case "generic", "aws", "gcp", "auto":
			// valid
		default:
			return fmt.Errorf("invalid ip-detect-type: %s (must be generic, aws, gcp, or auto)", c.IPDetectType)
		}
	}

	if c.Metrics.Enabled && (c.Metrics.Port < 1 || c.Metrics.Port > 65535) {
		return fmt.Errorf("invalid metrics-port: %d (must be 1-65535)", c.Metrics.Port)
	}

	for i, r := range c.SNAT {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid SNAT rule #%d: %w", i, err)
		}
	}

	for i, r := range c.DNAT {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid DNAT rule #%d: %w", i, err)
		}
	}

	return nil
}

type MetricsConfig struct {
	Enabled bool
	Address string
	Port    int
}

type Rule struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	TransIP   string
	TransPort uint16
}

func (r *Rule) Validate() error {
	if r.SrcIP != "" && r.SrcIP != "0.0.0.0" && net.ParseIP(r.SrcIP) == nil {
		return fmt.Errorf("invalid src-ip: %s", r.SrcIP)
	}
	if r.DstIP != "" && r.DstIP != "0.0.0.0" && net.ParseIP(r.DstIP) == nil {
		return fmt.Errorf("invalid dst-ip: %s", r.DstIP)
	}
	if r.TransIP == "" {
		return fmt.Errorf("trans-ip is required")
	}
	if ip := net.ParseIP(r.TransIP); ip == nil {
		return fmt.Errorf("invalid trans-ip: %s", r.TransIP)
	} else if ip.To4() == nil {
		return fmt.Errorf("trans-ip must be IPv4: %s", r.TransIP)
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "TCP" && r.Protocol != "UDP" {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", r.Protocol)
	}
	return nil
}

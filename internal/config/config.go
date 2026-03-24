package config

type Config struct {
	Interface    string
	Masquerade   bool
	ExternalIP   string
	IPDetectType string // generic, aws, gcp, auto
	GCInterval   string // e.g., "1m"
	TCPTimeout   string // e.g., "24h"
	UDPTimeout   string // e.g., "5m"
	MaxMSS       uint16 // TCP MSS clamping
	MaxSessions  uint32 // Maximum NAT sessions
	SessionFile  string // path to save/restore sessions
	Metrics      MetricsConfig
	SNAT         []Rule
	DNAT         []Rule
}

type MetricsConfig struct {
	Enabled bool
	Address string
	Port    int
}

type Rule struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	TransIP  string
	TransPort uint16
}

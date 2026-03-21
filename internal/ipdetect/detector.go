package ipdetect

import (
	"context"
	"net"
)

// Detector is an interface for public IP detection methods.
type Detector interface {
	GetPublicIP(ctx context.Context) (net.IP, error)
	Name() string
}

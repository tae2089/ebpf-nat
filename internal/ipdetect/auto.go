package ipdetect

import (
	"context"
	"fmt"
	"log/slog"
	"net"
)

// AutoDetector iterates through a list of detectors and returns the first success.
type AutoDetector struct {
	Detectors []Detector
}

func NewDefaultAutoDetector() *AutoDetector {
	return &AutoDetector{
		Detectors: []Detector{
			NewAWSDetector(),
			NewGCPDetector(),
			NewGenericDetector(),
		},
	}
}

func (d *AutoDetector) Name() string {
	return "Auto"
}

func (d *AutoDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	var errs []error
	for _, detector := range d.Detectors {
		ip, err := detector.GetPublicIP(ctx)
		if err == nil {
			slog.Info("Public IP detected", 
				slog.String("detector", detector.Name()), 
				slog.String("ip", ip.String()))
			return ip, nil
		}
		slog.Debug("Detection failed, trying next", 
			slog.String("detector", detector.Name()), 
			slog.Any("error", err))
		errs = append(errs, fmt.Errorf("%s: %w", detector.Name(), err))
	}

	return nil, fmt.Errorf("all detection methods failed: %v", errs)
}

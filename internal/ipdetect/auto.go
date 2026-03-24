package ipdetect

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
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
	var lastErr error
	
	// Try each detector with limited retries for transient network issues
	for _, detector := range d.Detectors {
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				wait := time.Duration(attempt*attempt) * time.Second
				slog.Debug("Retrying IP detection", 
					slog.String("detector", detector.Name()), 
					slog.Int("attempt", attempt+1),
					slog.Duration("wait", wait))
				
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
			}

			ip, err := detector.GetPublicIP(ctx)
			if err == nil {
				slog.Info("Public IP detected", 
					slog.String("detector", detector.Name()), 
					slog.String("ip", ip.String()))
				return ip, nil
			}
			lastErr = err
			slog.Debug("Detection attempt failed", 
				slog.String("detector", detector.Name()), 
				slog.Int("attempt", attempt+1),
				slog.Any("error", err))
		}
	}

	return nil, fmt.Errorf("all detection methods failed. Last error: %w", lastErr)
}

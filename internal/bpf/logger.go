package bpf

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"
)

// StartTracePipeLogger reads from /sys/kernel/debug/tracing/trace_pipe and logs to slog.
// This requires root privileges and is intended for development/debug mode.
func StartTracePipeLogger(ctx context.Context) {
	tracePipe := "/sys/kernel/debug/tracing/trace_pipe"
	
	f, err := os.Open(tracePipe)
	if err != nil {
		slog.Warn("Failed to open trace_pipe. Debug logs from BPF will not be available.", 
			slog.Any("error", err))
		return
	}
	defer f.Close()

	slog.Info("Started BPF trace_pipe logger", slog.String("path", tracePipe))

	scanner := bufio.NewScanner(f)
	
	// Create a channel to handle context cancellation
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		f.Close() // This will break the scanner.Scan()
		close(done)
	}()

	for scanner.Scan() {
		line := scanner.Text()
		// Format: <task>-<pid> [<cpu>] <flags> <timestamp>: <message>
		// We can simplify this for the console
		parts := strings.Split(line, ": ")
		if len(parts) > 1 {
			msg := strings.TrimSpace(parts[1])
			slog.Info("BPF_TRACE", slog.String("msg", msg))
		} else {
			slog.Info("BPF_TRACE", slog.String("raw", line))
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		slog.Error("Error reading trace_pipe", slog.Any("error", err))
	}
}

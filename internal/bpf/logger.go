package bpf

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"sync"
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

	var closeOnce sync.Once
	closeFile := func() {
		closeOnce.Do(func() {
			if err := f.Close(); err != nil {
				slog.Warn("Failed to close trace_pipe", slog.Any("error", err))
			}
		})
	}
	defer closeFile()

	slog.Info("Started BPF trace_pipe logger", slog.String("path", tracePipe))

	scanner := bufio.NewScanner(f)

	// ctx 취소 시 파일을 닫아 scanner.Scan()을 중단시킨다.
	go func() {
		<-ctx.Done()
		closeFile()
	}()

	for scanner.Scan() {
		line := scanner.Text()
		slog.Info("BPF_TRACE", slog.String("raw", line))
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		slog.Error("Error reading trace_pipe", slog.Any("error", err))
	}
}

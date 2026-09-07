package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/horrible-gh/Outpost/internal/patrol"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := patrol.NewRunner(patrol.RunnerConfig{
		Interval:  time.Hour,
		Timeout:   30 * time.Second,
		Journal:   "outpost-journal.jsonl",
		RunOnBoot: true,
	})

	if err := runner.Run(ctx); err != nil {
		slog.Error("outpost stopped with error", "error", err)
		os.Exit(1)
	}
}

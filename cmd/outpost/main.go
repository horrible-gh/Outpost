package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/horrible-gh/Outpost/internal/patrol"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "web console listen address")
	interval := flag.Duration("interval", time.Hour, "patrol interval")
	journal := flag.String("journal", "outpost-journal.jsonl", "journal JSONL path")
	timeout := flag.Duration("timeout", 30*time.Second, "maximum patrol duration")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := patrol.NewRunner(patrol.RunnerConfig{
		Interval:  *interval,
		Timeout:   *timeout,
		Journal:   *journal,
		RunOnBoot: true,
	})
	web := patrol.NewWebServer(*listen, runner)

	errCh := make(chan error, 2)
	go func() { errCh <- runner.Run(ctx) }()
	go func() { errCh <- web.Run(ctx) }()

	slog.Info("outpost started", "listen", *listen, "interval", interval.String(), "journal", *journal)
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			slog.Error("outpost stopped with error", "error", err)
			stop()
			os.Exit(1)
		}
	}
}

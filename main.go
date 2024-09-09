package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
	"patrickpichler.dev/ebpf-net-tracer/pkg/ebpftracer"
)

func main() {
	stdoutLog := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	tracer := ebpftracer.New(stdoutLog, ebpftracer.TracerConfig{})
	if err := tracer.Load(); err != nil {
		log.Fatal(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := start(ctx, tracer)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()

	println("running...")
	<-sigs

	cancel()
}

func start(ctx context.Context, tracer *ebpftracer.Tracer) error {
	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		return tracer.RunStatLoop(ctx)
	})

	return errg.Wait()
}

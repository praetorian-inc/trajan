package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A second Ctrl-C must still kill a wedged shutdown.
	go func() {
		<-ctx.Done()
		stop()
	}()
	Execute(ctx)
}

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Every phase already honors ctx; without this the cancellation plumbing
	// never fires and Ctrl-C kills the process mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	Execute(ctx)
}

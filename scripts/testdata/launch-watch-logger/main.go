package main

import (
	"context"
	"log/slog"
	"os"
	"time"
)

func main() {
	h := slog.NewTextHandler(os.Stdout, nil)
	r := slog.NewRecord(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC), slog.LevelError, "failed to send magic link email", 0)
	r.AddAttrs(slog.String("email", "o'brien@example.com"), slog.String("error", "SMTP \"failure\"\nretry"))
	_ = h.Handle(context.Background(), r)
}

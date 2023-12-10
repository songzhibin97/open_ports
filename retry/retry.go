package retry

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/songzhibin97/gkit/distributed/retry"
)

func DoRetry(name string, call func() error, filter func(err error) bool, count ...int) error {
	count = append(count, 3)
	var err error
	for i := 1; i <= count[0]; i++ {
		err = call()
		if err == nil {
			return nil
		}
		if filter != nil && filter(err) {
			return err
		}
		slog.Debug("retry task failed", slog.String("name", name), slog.Int("retry", i), slog.Int("count", count[0]), slog.Any("error", err))
		time.Sleep(time.Duration(retry.FibonacciNext(i)) * time.Second)
	}
	return fmt.Errorf("name %s retry failed %w", name, err)
}

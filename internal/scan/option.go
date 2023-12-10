package scan

import "time"

type Config struct {
	Timeout time.Duration
	Retry   int
	Buffer  int
}

func NewDefaultConfig() *Config {
	return &Config{
		Timeout: 5 * time.Second,
		Retry:   3,
		Buffer:  10000,
	}
}

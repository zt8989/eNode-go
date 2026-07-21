package natsim

import "log"

// Logger is the minimal logging surface the simulators need. *log.Logger
// satisfies it, so the CLIs pass log.Default(); tests pass a t.Logf adapter so
// program input/output is captured per test.
type Logger interface {
	Printf(format string, v ...any)
}

// loggerOrDefault returns l, or log.Default() when l is nil, so callers can
// leave Logger unset.
func loggerOrDefault(l Logger) Logger {
	if l != nil {
		return l
	}
	return log.Default()
}

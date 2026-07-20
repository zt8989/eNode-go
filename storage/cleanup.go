package storage

import (
	"time"

	"enode/logging"
)

// StartCleanup runs a stale-row sweep on a ticker and returns a stop function,
// mirroring ed2k.NATTraversalHandler.StartCleanup.
//
// This is what makes the (online, time_*) indexes worth having. Nothing ever
// deleted a client row before, so the table grew for the lifetime of the
// deployment and every count or sweep scanned every client the server had ever
// seen — an index on a monotonically growing table only defers that cost.
//
// The first sweep runs after one interval rather than immediately, so a restart
// loop cannot turn startup into repeated full-table maintenance.
func StartCleanup(engine Engine, interval, maxAge time.Duration, opts CleanupOptions) func() {
	if interval <= 0 {
		interval = defaultCleanupInterval
	}
	if maxAge <= 0 {
		maxAge = defaultCleanupMaxAge
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runCleanup(engine, maxAge, opts)
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

const (
	defaultCleanupInterval = time.Hour
	defaultCleanupMaxAge   = 24 * time.Hour
)

// runCleanup performs one sweep and reports what it removed. The counts are
// logged unconditionally: a cleanup that deletes rows silently is worse than no
// cleanup at all, because nothing distinguishes it from data loss.
func runCleanup(engine Engine, maxAge time.Duration, opts CleanupOptions) {
	start := time.Now()
	result, err := engine.CleanupStale(maxAge, opts)
	if err != nil {
		logging.Errorf("storage cleanup failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
		return
	}
	if result.Clients == 0 && result.Sources == 0 && result.Files == 0 {
		logging.Debugf("storage cleanup: nothing stale (maxAge=%s, took %s)",
			maxAge, time.Since(start).Round(time.Millisecond))
		return
	}
	logging.Infof("storage cleanup removed clients=%d sources=%d files=%d (maxAge=%s, took %s)",
		result.Clients, result.Sources, result.Files, maxAge,
		time.Since(start).Round(time.Millisecond))
}

//go:build darwin || windows

package relay

// Linux is currently the only platform where the relay owns a progress-aware
// kernel-copy loop. Other systems retain the configured-buffer path instead of
// silently accepting io.Copy's platform-dependent fallback buffer.
func prepareZeroCopy(Stream, Stream) zeroCopyPlan { return nil }

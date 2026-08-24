# Repository Agent Instructions

## Required pre-commit validation

Before committing, run `make check` from the repository root in a Linux
environment and require it to pass. When working from Windows, also run
`go test ./...` natively on Windows to catch platform-specific failures.

Do not commit with a failing check. A check may be skipped only when the user
explicitly authorizes it; report every skipped check in the final response.

## Socket timeout tests

Keep socket-timeout getsockopt assertions HZ-independent (whole seconds);
cover fractional conversion at the Timeval (`timevalFromSpec`) level, not via
kernel round-trip. The kernel stores SO_RCVTIMEO/SO_SNDTIMEO in jiffies, so a
fractional timeout is not a stable readback across HZ=100/250/1000.

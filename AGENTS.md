# Repository Agent Instructions

## Required pre-commit validation

Before committing, run `make check` from the repository root in a Linux
environment and require it to pass. When working from Windows, also run
`go test ./...` natively on Windows to catch platform-specific failures.

Do not commit with a failing check. A check may be skipped only when the user
explicitly authorizes it; report every skipped check in the final response.

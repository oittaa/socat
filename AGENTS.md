# Repository Agent Instructions

## Required pre-commit validation

Before creating any commit, run every check below from the repository root and
require all of them to pass:

1. `make lint`
2. `make gosec`
3. `make test`
4. `make e2e`

Do not commit with a failing check. Fix the failure and rerun the affected check,
then rerun the complete list before committing. A check may be skipped only when
the user explicitly authorizes it; report any skipped check in the final response.

Run network-dependent builds and end-to-end tests in a Linux environment. When
working from Windows, also run `go test ./...` natively on Windows before the
commit so platform-specific unit-test failures are caught.

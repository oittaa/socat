# Repository Agent Instructions

## Classic socat compatibility

Stay a drop-in replacement for classic socat
(`git://repo.or.cz/socat.git`, https://repo.or.cz/socat.git) unless a
change is a documented security exception.

Security-related deviations belong in README ("Intentional differences
from classic socat" / "Unsupported / security-related") and in a code
comment at the call site.

If a change would diverge from classic behavior for any other reason,
ask before implementing it.

## Required pre-commit validation

Before committing, run `make check` from the repository root in a Linux
environment and require it to pass. When working from Windows, also run
`go test ./...` natively on Windows to catch platform-specific failures.

Do not commit with a failing check. A check may be skipped only when the user
explicitly authorizes it; report every skipped check in the final response.

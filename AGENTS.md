# Repository Agent Instructions

## Classic socat compatibility

Stay a drop-in replacement for classic socat
(`git://repo.or.cz/socat.git`, https://repo.or.cz/socat.git) unless a
change is a documented security exception.

Use the latest released tag from the official repository as the primary
compatibility baseline, and also check current master for newer behavior.
Cite the exact tag or commit used. Do not use third-party mirrors when the
official repository is available. If the latest release and master differ,
report the difference before implementing.

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

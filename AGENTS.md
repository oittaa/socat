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

Also read the official man page from that same repository. `doc/socat.yo`
is the YODL source (https://repo.or.cz/socat.git/blob_plain/HEAD:/doc/socat.yo
is current master). Prefer `git show <tag>:doc/socat.yo` for the same tag
or commit used as the C-source baseline. The rendered HTML is
http://www.dest-unreach.org/socat/doc/socat.html. Do not use third-party
man-page mirrors when these are available.

The man page is the documented option interface, including types such as
`[=<bool>]` (value `"0"` or `"1"`; omitted value means `"1"`). Classic C
call sites sometimes only test whether the option is present. If the man
page and the C parser disagree, report the difference before implementing;
do not copy a presence-only check as the documented boolean interface.

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

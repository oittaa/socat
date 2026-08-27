package classiccatalog

// EXEC / FORK child options. FeatureEXEC is Unix-only. dash/login and
// setpgid/pgid are implemented on Unix (hidden on Windows with EXEC).
var expectedMissingExec = map[string]Gap{}

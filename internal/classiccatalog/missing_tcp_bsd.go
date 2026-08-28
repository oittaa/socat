package classiccatalog

// No BSD TCP options are implementation backlog on the tested targets.
// Classic compile-gates rfc1323/stdurg for AIX and sack-disable/
// signature-enable for OpenBSD; foreign.go records their public spellings.
var expectedMissingTCPBSD = map[string]Gap{}

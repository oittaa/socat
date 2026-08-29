package classiccatalog

// IPv6 recv-extension flags are implemented on Linux and Darwin.
// Remaining TYPE_INT blob/send-side names live in unsupportedBlobIP6.
var expectedMissingIP6 = map[string]Gap{}

package version

// Version is the whalevet release version. It is intended to be overwritten
// at build time via -ldflags "-X .../internal/version.Version=<version>".
var Version = "dev"

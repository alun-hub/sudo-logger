package version

// Version is set at build time via -ldflags "-X sudo-logger/internal/version.Version=vX.Y.Z".
// Falls back to "dev" when built without goreleaser.
var Version = "dev"

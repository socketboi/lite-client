module qstand

go 1.26.0

require (
	github.com/apernet/quic-go v0.0.0
	golang.org/x/crypto v0.54.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

// The vendored fork, not upstream quic-go: hysteria runs on apernet's, and a comparison against a
// different QUIC library would be checking something nobody ships.
replace github.com/apernet/quic-go => ../../../vendor/quic-go

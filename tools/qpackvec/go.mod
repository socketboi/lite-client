module qpackvec

// As vendor/hysteria/app/go.mod, whose Go builds the reference client.
go 1.26

require github.com/quic-go/qpack v0.6.0

require golang.org/x/net v0.58.0 // indirect

replace github.com/quic-go/qpack => ../../vendor/qpack

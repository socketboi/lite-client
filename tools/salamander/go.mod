module salamandervec

go 1.25.0

require github.com/apernet/hysteria/extras/v2 v2.0.0

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/apernet/hysteria/extras/v2 => ../../vendor/hysteria/extras

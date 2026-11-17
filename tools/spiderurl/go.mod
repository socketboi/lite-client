module spiderurlvec

go 1.27

require (
	golang.org/x/net v0.57.0
	golang.org/x/text v0.41.0
)

replace golang.org/x/net => ../.goroot-x/net

replace golang.org/x/text => ../.goroot-x/text

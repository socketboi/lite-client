module unitables

go 1.27

require (
	golang.org/x/net v0.47.0
	golang.org/x/text v0.32.0
)

replace golang.org/x/net => ../.goroot-x/net

replace golang.org/x/text => ../.goroot-x/text

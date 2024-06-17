package main

import (
	"github.com/potoo0/configurable-http-proxy/cmd"
	"github.com/potoo0/configurable-http-proxy/lib"
)

var (
	Tag string
	// Build is the git sha of this binaries build.
	Build string
)

func main() {
	if Tag != "" {
		lib.CHPVersion.Tag = Tag
	}
	if Build != "" {
		lib.CHPVersion.Build = Build
	}

	cmd.Execute()
}

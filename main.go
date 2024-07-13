package main

import (
	"github.com/potoo0/configurable-http-proxy/cmd"
	"github.com/potoo0/configurable-http-proxy/lib"
)

var Tag string

func main() {
	lib.CHPVersion.Update(Tag, "")

	cmd.Execute()
}

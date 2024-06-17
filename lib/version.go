package lib

import "fmt"

// Version represents the current version of configurable-http-proxy.
type Version struct {
	Tag   string
	Build string
}

// CHPVersion is the current version of configurable-http-proxy.
var CHPVersion = Version{
	Tag:   "0.0.1",
	Build: "$Id$",
}

func (v Version) String() string {
	return fmt.Sprintf("Version: %s\nBuild:   %s", v.Tag, v.Build)
}

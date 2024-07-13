package lib

import (
	"fmt"
	"runtime/debug"
)

// Version represents the current version of configurable-http-proxy.
type Version struct {
	Tag   string
	Build string
}

// CHPVersion is the current version of configurable-http-proxy.
var CHPVersion = &Version{
	Tag:   "(devel)",
	Build: "$Id$",
}

func (v *Version) String() string {
	return fmt.Sprintf("Version: %s\nBuild:   %s", v.Tag, v.Build)
}

func (v *Version) Update(tag, build string) {
	if tag != "" {
		v.Tag = tag
	}

	// fetch build info from debug.BuildInfo(vcs.revision) if it is not set
	if build == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					build = setting.Value
					break
				}
			}
		}
	}

	if build != "" {
		v.Build = build
	}
}

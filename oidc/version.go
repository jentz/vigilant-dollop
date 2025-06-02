package oidc

import (
	"runtime/debug"
	"strings"
	"time"
)

var (
	Version = "unknown"
)

type vcsInfo struct {
	revision   string
	lastCommit time.Time
	dirty      bool
}

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	parts := make([]string, 0, 3)

	if info.Main.Version != "" {
		// If the main module version is set, we use it as the version.
		parts = append(parts, info.Main.Version)
	}

	var vcs = vcsInfo{}
	for _, kv := range info.Settings {
		if kv.Value == "" {
			continue
		}
		switch kv.Key {
		case "vcs.revision":
			vcs.revision = kv.Value
		case "vcs.time":
			vcs.lastCommit, _ = time.Parse(time.RFC3339, kv.Value)
		case "vcs.modified":
			vcs.dirty = kv.Value == "true"
		}
	}

	if vcs.revision != "" {
		parts = append(parts, "rev")
		commit := vcs.revision
		if len(commit) > 7 {
			commit = commit[:7]
		}
		parts = append(parts, commit)
		if vcs.dirty {
			parts = append(parts, "dirty")
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "unknown")
	}
	Version = strings.Join(parts, "-")
}

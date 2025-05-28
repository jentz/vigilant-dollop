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

	var vcsInfo = vcsInfo{}
	for _, kv := range info.Settings {
		if kv.Value == "" {
			continue
		}
		switch kv.Key {
		case "vcs.revision":
			vcsInfo.revision = kv.Value
		case "vcs.time":
			vcsInfo.lastCommit, _ = time.Parse(time.RFC3339, kv.Value)
		case "vcs.modified":
			vcsInfo.dirty = kv.Value == "true"
		}
	}

	if vcsInfo.revision != "" {
		parts = append(parts, "rev")
		commit := vcsInfo.revision
		if len(commit) > 7 {
			commit = commit[:7]
		}
		parts = append(parts, commit)
		if vcsInfo.dirty {
			parts = append(parts, "dirty")
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "unknown")
	}
	Version = strings.Join(parts, "-")
}

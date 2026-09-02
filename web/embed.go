// Package web embeds the built PWA so the server ships as a single binary.
//
// The Go file lives beside the frontend sources because go:embed cannot reach
// outside its own package directory — embedding from internal/ui would need the
// build to copy web/dist across first. The frontend toolchain ignores .go files,
// so the two coexist without interfering.
//
// dist/ is produced by `bun run build` (see mise.toml's web:build task) and is
// git-ignored apart from a .gitkeep, which is there because go:embed fails at
// compile time on a directory that does not exist. A binary built without
// running the frontend build therefore compiles fine and serves a
// "UI not built" placeholder at runtime.
package web

import (
	"embed"
	"io/fs"
)

// The all: prefix includes files whose names begin with "." or "_", which is
// what lets the tracked .gitkeep satisfy the embed on a clean checkout.
//
//go:embed all:dist
var dist embed.FS

// Dist returns the built PWA rooted at dist/, so callers see "index.html"
// rather than "dist/index.html".
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: the embed above guarantees the directory exists.
		panic(err)
	}
	return sub
}

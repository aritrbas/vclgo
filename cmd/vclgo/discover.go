package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// resolvePreloadPath finds libvclgo_preload.so. Order:
//  1. $VCLGO_PRELOAD
//  2. <launcher_dir>/libvclgo_preload.so
//  3. <launcher_dir>/../lib/libvclgo_preload.so
func resolvePreloadPath() (string, error) {
	if p := os.Getenv("VCLGO_PRELOAD"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return filepath.Abs(p)
		}
		return "", fmt.Errorf("VCLGO_PRELOAD=%s: not readable", p)
	}
	root, err := launcherRoot()
	if err != nil {
		return "", err
	}
	for _, cand := range []string{
		filepath.Join(root, "libvclgo_preload.so"),
		filepath.Join(root, "..", "lib", "libvclgo_preload.so"),
	} {
		if _, err := os.Stat(cand); err == nil {
			return filepath.Abs(cand)
		}
	}
	return "", fmt.Errorf("libvclgo_preload.so not found (set VCLGO_PRELOAD)")
}

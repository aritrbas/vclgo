package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
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

// resolveDispatcherPath finds libvclgo_dispatcher.so. Order:
//  1. $VCLGO_DISPATCHER
//  2. <launcher_dir>/libvclgo_dispatcher.so       (installed layout)
//  3. <launcher_dir>/../lib/libvclgo_dispatcher.so
func resolveDispatcherPath() (string, error) {
	if p := os.Getenv("VCLGO_DISPATCHER"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("VCLGO_DISPATCHER=%s: not readable", p)
	}
	root, err := launcherRoot()
	if err != nil {
		return "", err
	}
	for _, cand := range []string{
		filepath.Join(root, "libvclgo_dispatcher.so"),
		filepath.Join(root, "..", "lib", "libvclgo_dispatcher.so"),
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("libvclgo_dispatcher.so not found (set VCLGO_DISPATCHER)")
}

// resolveInterceptorPath finds frida/interceptor.js. Order:
//  1. $VCLGO_INTERCEPTOR
//  2. <launcher_dir>/../frida/interceptor.js       (dev tree)
//  3. <launcher_dir>/../share/vclgo/interceptor.js (installed layout)
func resolveInterceptorPath() (string, error) {
	if p := os.Getenv("VCLGO_INTERCEPTOR"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("VCLGO_INTERCEPTOR=%s: not readable", p)
	}
	root, err := launcherRoot()
	if err != nil {
		return "", err
	}
	for _, cand := range []string{
		filepath.Join(root, "..", "frida", "interceptor.js"),
		filepath.Join(root, "..", "share", "vclgo", "interceptor.js"),
	} {
		if _, err := os.Stat(cand); err == nil {
			abs, _ := filepath.Abs(cand)
			return abs, nil
		}
	}
	return "", fmt.Errorf("interceptor.js not found (set VCLGO_INTERCEPTOR)")
}

// resolveFrida locates the `frida` CLI. Users can override with VCLGO_FRIDA.
//
// PATH lookup first (covers 99% of cases), then a small set of well-known
// user-level install locations. The extra candidates matter under `sudo`
// on Debian/Ubuntu, whose sudoers `Defaults secure_path=` overrides the
// invoking user's PATH (even with `sudo -E`), so `pip install --user
// frida-tools`-provisioned binaries are invisible to a naive LookPath.
func resolveFrida() (string, error) {
	if p := os.Getenv("VCLGO_FRIDA"); p != "" {
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("VCLGO_FRIDA=%s: not executable", p)
	}
	if p, err := exec.LookPath("frida"); err == nil {
		return p, nil
	}
	// Fallback: common per-user install locations that sudo's secure_path
	// hides. Try HOME first, then SUDO_USER's HOME if we appear to be
	// running under sudo.
	var homes []string
	if h := os.Getenv("HOME"); h != "" {
		homes = append(homes, h)
	}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		if usr, err := user.Lookup(u); err == nil && usr.HomeDir != "" {
			homes = append(homes, usr.HomeDir)
		}
	}
	for _, h := range homes {
		cand := filepath.Join(h, ".local", "bin", "frida")
		if st, err := os.Stat(cand); err == nil && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("frida CLI not found on PATH or ~/.local/bin; " +
		"install with `pip install --user frida-tools` or set VCLGO_FRIDA")
}

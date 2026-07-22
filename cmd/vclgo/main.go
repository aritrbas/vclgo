// Command vclgo launches dynamically linked Go binaries through the native
// LD_PRELOAD/seccomp (Approach #3) or LD_PRELOAD/frida-gum-fastpath
// (Approach #4) backend. The retired Frida Interceptor.attach + JavaScript
// backend (Approach #2) has been removed; see docs/why_frida_dropped.md.
//
//	vclgo run ./my-go-app [args...]
//	vclgo validate ./my-go-app
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const usage = `vclgo — transparent VPP/VCL launcher for unmodified Go binaries.

Usage:
  vclgo run      <binary> [args...]      Run with native VCL interception.
  vclgo validate <binary>                Check native preload compatibility.

Environment:
  VCL_CONFIG       Path to vcl.conf; unset selects kernel passthrough.
  VCLGO_WORKERS    Permanent VCL owner threads (auto by default).
  VCLGO_NOTIFIERS  Seccomp notification threads (auto by default).
  VCLGO_LOG        0=errors, 1=lifecycle (default), 2=call diagnostics.
  VCLGO_PRELOAD    Override path to libvclgo_preload.so.

Native requirements:
  A dynamically linked linux/amd64 Go executable, seccomp user notification,
  matching VPP/VCL libraries, and multi-thread-workers in vcl.conf when
  VCLGO_WORKERS is greater than one.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	switch sub {
	case "run":
		if err := cmdRun(args); err != nil {
			fatal(err)
		}
	case "validate":
		if err := cmdValidate(args); err != nil {
			fatal(err)
		}
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "vclgo: unknown subcommand %q\n\n", sub)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vclgo: "+err.Error())
	os.Exit(1)
}

// launcherRoot resolves the directory that contains the launcher binary.
// Used for auto-discovery of the preload .so.
func launcherRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve launcher path: %w", err)
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Dir(real), nil
}

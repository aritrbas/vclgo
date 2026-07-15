package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func cmdRun(args []string) error {
	switch backend := os.Getenv("VCLGO_BACKEND"); backend {
	case "", "native", "preload":
		return cmdRunPreload(args)
	case "frida":
		return cmdRunFrida(args)
	default:
		return fmt.Errorf("unsupported VCLGO_BACKEND=%q (use native or frida)", backend)
	}
}

func cmdRunPreload(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vclgo run <binary> [args...]")
	}
	if err := validateBinary(args[0]); err != nil {
		return err
	}
	target, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}

	preload, err := resolvePreloadPath()
	if err != nil {
		return err
	}
	preloadValue := preload
	if inherited := os.Getenv("LD_PRELOAD"); inherited != "" {
		preloadValue += ":" + inherited
	}

	cmd := exec.Command(target, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = replaceEnv(os.Environ(), "LD_PRELOAD", preloadValue)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn target: %w", err)
	}
	pgid := cmd.Process.Pid

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-pgid, s)
			}
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	/* The target is the process-group leader. Clean up only descendants that
	   survived it; this prevents repeated tests from leaving VCL clients. */
	if syscall.Kill(-pgid, 0) == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if syscall.Kill(-pgid, 0) != nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

func replaceEnv(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func cmdRunFrida(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vclgo run <binary> [args...]")
	}
	bin := args[0]
	extra := args[1:]

	if err := validateBinary(bin); err != nil {
		return err
	}

	frida, err := resolveFrida()
	if err != nil {
		return fmt.Errorf("locate frida CLI: %w (install with `pip install frida-tools`)", err)
	}
	disp, err := resolveDispatcherPath()
	if err != nil {
		return err
	}
	interceptor, err := resolveInterceptorPath()
	if err != nil {
		return err
	}

	// `frida -f BIN -l SCRIPT -- BIN_ARG1 BIN_ARG2` spawns BIN with SCRIPT
	// loaded before any user code runs. The `--` separator forwards the
	// remaining tokens to the spawned process's argv.
	//
	// Flags:
	//   --runtime=v8    Use V8 for the JS runtime (perf + parity with tests).
	//   -q              Quiet mode: no interactive REPL, no prompts.
	//   -t inf          In quiet mode, stay attached forever — otherwise
	//                   frida exits immediately after loading -l/-e, which
	//                   would tear the target down before it ran.
	//
	// Frida ≥ 16 removed the `--no-pause` flag (and reversed the default):
	// the spawned target now runs unless `--pause` is explicitly given.
	// We therefore rely on the default resume behaviour.
	fridaArgs := []string{
		"-f", bin,
		"-l", interceptor,
		"--runtime=v8",
		"-q", "-t", "inf",
	}
	if len(extra) > 0 {
		fridaArgs = append(fridaArgs, "--")
		fridaArgs = append(fridaArgs, extra...)
	}

	cmd := exec.Command(frida, fridaArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"VCLGO_DISPATCHER="+disp,
	)
	// Silence Python's I/O buffering so the target's stdout is streamed.
	cmd.Env = append(cmd.Env, "PYTHONUNBUFFERED=1")

	// Put frida (and everything it spawns — the Python interpreter and the
	// Frida-spawned target Go binary) into its OWN process group. Without
	// this, killing the frida process leaves the Frida-spawned target as
	// an orphan running under init/systemd, and `vclgo run` becomes a
	// process-leak factory across every test run. See docs/analysis_bugs.md
	// S1-12 for the observed leftover-process tree that motivated this.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn frida: %w", err)
	}
	// From here on out, cmd.Process.Pid is also the pgid (Setpgid + Pgid=0
	// makes the child its own group leader). Sending a signal to the
	// NEGATED pid delivers it to the whole group.
	pgid := cmd.Process.Pid

	// Forward common signals so Ctrl-C etc. propagates through the WHOLE
	// Frida process group (frida.py + the target it spawned).
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-pgid, s)
			}
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	// Belt-and-braces cleanup: even on normal exit of `frida` itself, the
	// Frida-spawned target may still be alive if `frida -t inf` was
	// detached uncleanly. Nudge the group with TERM, wait briefly, then
	// KILL. `errors.Is(..., ESRCH)` == group already gone, which is the
	// happy path.
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pgid, 0); err != nil {
			break // group is gone
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

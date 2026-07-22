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

// cmdRun launches the target Go binary through the native LD_PRELOAD backend.
// The retired Frida Interceptor backend (Approach #2) has been removed from
// the codebase; only the native preload path (Approach #3 seccomp / Approach
// #4 fastpath, both selected inside the preload itself) remains.
func cmdRun(args []string) error {
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

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

func cmdAttach(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vclgo attach <pid>")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid pid %q", args[0])
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

	// Note: attach mode inherits whatever state the running Go process is
	// in. Sessions the app has already opened via kernel sockets stay on
	// the kernel; only NEW socket() calls get routed to VPP.
	//
	// See cmdRun() for the Frida-flag rationale (`-q -t inf` replaces the
	// pre-16 `--no-pause`, keeps the REPL suppressed, stays attached until
	// the target exits or the user sends SIGINT).
	fridaArgs := []string{
		"-p", strconv.Itoa(pid),
		"-l", interceptor,
		"--runtime=v8",
		"-q", "-t", "inf",
	}
	cmd := exec.Command(frida, fridaArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"VCLGO_DISPATCHER="+disp,
		"PYTHONUNBUFFERED=1",
	)
	// Isolate frida in its own process group so we can nuke the whole
	// group on shutdown; see spawn.go for the full rationale (S1-12).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn frida: %w", err)
	}
	pgid := cmd.Process.Pid
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
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
	// Ensure the whole group is reaped even if `frida` exits without
	// tearing its own python helpers down.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

package main

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// validateBinary verifies the constraints imposed by LD_PRELOAD and the
// x86-64 seccomp filter. Native interception does not require Go symbols.
func validateBinary(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return err
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s: not an executable file", absolute)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("%s: setuid/setgid executables suppress LD_PRELOAD", absolute)
	}

	file, err := elf.Open(absolute)
	if err != nil {
		return fmt.Errorf("%s: not an ELF binary: %w", absolute, err)
	}
	defer file.Close()

	if _, err := buildinfo.ReadFile(absolute); err != nil {
		return fmt.Errorf("%s: does not appear to be a Go binary: %w",
			absolute, err)
	}
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 {
		return fmt.Errorf("%s: native preload requires a linux/amd64 Go executable",
			absolute)
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return fmt.Errorf("%s: unsupported ELF executable type %v",
			absolute, file.Type)
	}

	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return nil
		}
	}
	return fmt.Errorf("%s: statically linked; LD_PRELOAD cannot load vclgo "+
		"(build with external linking enabled)", absolute)
}

func cmdValidate(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vclgo validate <binary>")
	}
	if err := validateBinary(args[0]); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

# frida/ has no C artifacts in Phase 1; the interceptor.js is loaded directly
# by the `vclgo` launcher. This Makefile exists for symmetry with the top-level
# orchestrator.
#
# Phase 2 plan:
#   Move each hook body from interceptor.js into a Frida CModule (native code
#   loaded into the target process, invoked from JS via NativeFunction).
#   That is a ~2x throughput win because it eliminates the JS trampoline on
#   every hooked syscall. See docs/architecture.md §"Phase 2 changes" and
#   docs/phase1_frida.md §"Deferred to Phase 2" for the rollout plan; this
#   Makefile will grow a `cmodule:` target that produces
#   bin/interceptor_cmodule.so and a JS shim that loads it.

.PHONY: all clean
all:
	@true
clean:
	@true

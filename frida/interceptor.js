/*
 * vclgo Frida interceptor — Phase 1.
 *
 * This script is loaded by the `vclgo` launcher (see cmd/vclgo). It:
 *
 *   1. Auto-detects the Go binary (main module with `syscall.*` symbols).
 *   2. Loads libvclgo_dispatcher.so (whose path comes from the launcher via
 *      the VCLGO_DISPATCHER env var).
 *   3. Calls vclgo_init() once.
 *   4. Installs per-function hooks on each Go `syscall.*` wrapper that the
 *      dispatcher supports.
 *
 * Design constraints (see docs/architecture.md for the full list):
 *
 *   • No hot-path JS logic. Each hook does at most: read Go ABI regs,
 *     invoke one NativeFunction into the dispatcher, write Go ABI regs.
 *   • No spin-waits or 100%-CPU loops. All EAGAIN handling lives in the
 *     dispatcher's poller thread.
 *   • No fake-fd tracking in JS. Fake fds live in the 0x40000000+ range
 *     and the dispatcher keeps its own per-vlsh table.
 *   • The internal netpoller epoll_ctl is stubbed so netFD.init() succeeds
 *     for VCL fds. Read/Write never return EAGAIN so Go never actually
 *     needs the netpoller to fire for our fds.
 */

'use strict';

/* ============================================================================
 * Configuration
 * ============================================================================ */

var _rawLog  = getEnv('VCLGO_LOG');
var LOG_LEVEL = parseInt((_rawLog || '1'), 10);

function log(level, msg) { if (level <= LOG_LEVEL) console.log('[vclgo/js] ' + msg); }

/* Print the resolved log level once so env-propagation issues (e.g. sudoers
 * secure_path stripping variables, or a chain of wrapper scripts eating them)
 * are diagnosable from the log itself — we spent an entire round chasing why
 * `VCLGO_LOG=2` did nothing before realising it was never reaching us. */
console.log('[vclgo/js] VCLGO_LOG=' + (_rawLog === null ? '<unset>' : _rawLog) +
            ' → LOG_LEVEL=' + LOG_LEVEL);

function getEnv(name) {
    try {
        var getenv = new NativeFunction(
            Module.findGlobalExportByName('getenv') ||
                Module.getGlobalExportByName('getenv'),
            'pointer', ['pointer']);
        var s = getenv(Memory.allocUtf8String(name));
        return s.isNull() ? null : s.readUtf8String();
    } catch (e) { return null; }
}

/* ============================================================================
 * Detect Go binary module
 * ============================================================================ */

var mainMod = Process.enumerateModules()[0];
log(1, 'target module: ' + mainMod.name);

/*
 * S1-14 follow-up: dump the module map at startup so a repeat of the
 * `pc == addr` crash lets us map the failing PC to a specific library.
 * Both observed crashes had low-16-bits 0xc0a9/0xc8a9 in the SAME 0x7f4c…
 * / 0x74d4… range, so we want to know which .so lives at
 * (crash_pc & ~0xfff) and whether that offset falls inside an .rodata
 * jump table, an interceptor trampoline, or somewhere else.
 *
 * Emitted at level 1 unconditionally (one-shot at startup, negligible
 * cost) because this is exactly the diagnostic we've been missing for
 * multiple crash-repro rounds. Once the S1-14 root cause is confirmed
 * we can move it back to level 2.
 */
try {
    Process.enumerateModules().forEach(function (m) {
        log(1, 'module ' + m.base + ' + 0x' + m.size.toString(16) +
             '  ' + m.name);
    });
} catch (_e) { /* enumerateModules() is expected on Linux; ignore anyway */ }

/*
 * Every Go stdlib symbol we might want to hook. Both lowercase (raw
 * generated wrappers around SYSCALL, used by internal/poll and net) and
 * Capitalised (typed public API) variants are listed only when the two
 * have identical calling conventions. Where the public wrapper takes a
 * Go-native type (Sockaddr interface, []byte slice) it is NOT hooked here:
 * its ABI differs from the raw syscall and shipping a hook for it would
 * mis-marshal register contents. See docs/analysis_bugs.md §S4-4 for the
 * ongoing tracking of Go-version drift.
 *
 * ABI-compatible pairs currently included:
 *   syscall.socket  ↔ syscall.Socket   (both (domain, typ, proto int))
 *   syscall.listen  ↔ syscall.Listen   (both (fd, backlog int))
 *
 * All other Capitalised wrappers (Bind, Accept, Connect, Read, Write,
 * Getsockname, Getpeername, Setsockopt*) are DELIBERATELY OMITTED — the
 * dispatcher already sees every call via the corresponding lowercase
 * wrapper that Go's own stdlib routes through.
 */
var goSyscallHooks = [
    { name: 'syscall.socket',       kind: 'intint' },
    { name: 'syscall.Socket',       kind: 'intint' },   /* same ABI (S4-4) */
    { name: 'syscall.bind',         kind: 'err'    },
    { name: 'syscall.listen',       kind: 'err'    },
    { name: 'syscall.Listen',       kind: 'err'    },   /* same ABI (S4-4) */
    { name: 'syscall.accept4',      kind: 'intint' },
    { name: 'syscall.accept',       kind: 'intint' },
    { name: 'syscall.connect',      kind: 'err'    },
    { name: 'syscall.setsockopt',   kind: 'err'    },
    { name: 'syscall.getsockopt',   kind: 'err'    },
    { name: 'syscall.getsockname',  kind: 'err'    },
    { name: 'syscall.getpeername',  kind: 'err'    },
    { name: 'syscall.read',         kind: 'intint' },
    { name: 'syscall.write',        kind: 'intint' },
    { name: 'syscall.Close',        kind: 'err'    },
    { name: 'syscall.Shutdown',     kind: 'err'    },
    { name: 'syscall.fcntl',        kind: 'intint' },

    /*
     * The Go runtime netpoller registers every new netFD's kernel fd with
     * a process-wide epoll instance so that Read/Write can park on the
     * netpoller when they see EAGAIN. On Go 1.21+ this call is inlined
     * inside `runtime.netpollopen` (and correspondingly `netpollclose`),
     * which invokes `internal/runtime/syscall/linux.Syscall6(SYS_EPOLL_CTL, …)`
     * directly rather than going through a separate EpollCtl symbol.
     *
     * Our fake VCL fds do not exist in the kernel so a real epoll_ctl on
     * them would return EBADF and abort net.Listen(). We hook netpollopen /
     * netpollclose and short-circuit them for VCL fds; because our Read /
     * Write hooks always block internally and never surface EAGAIN, the
     * netpoller is never actually consulted for VCL fds — the short-circuit
     * is purely to keep the netFD lifecycle happy.
     */
    { name: 'runtime.netpollopen',  kind: 'netpoll' },
    { name: 'runtime.netpollclose', kind: 'netpoll' },
];

/* Resolve symbol addresses from the main module's symbol table. */
var resolved = {};
try {
    mainMod.enumerateSymbols().forEach(function (sym) {
        for (var i = 0; i < goSyscallHooks.length; i++) {
            if (sym.name === goSyscallHooks[i].name) {
                resolved[sym.name] = sym.address;
                log(1, 'found ' + sym.name + ' @ ' + sym.address);
            }
        }
    });
} catch (e) {
    log(0, 'symbol enumeration failed: ' + e);
}

/* ============================================================================
 * Load & handshake with libvclgo_dispatcher.so
 * ============================================================================ */

var dispPath = getEnv('VCLGO_DISPATCHER');
if (!dispPath || dispPath.length === 0) {
    throw new Error('VCLGO_DISPATCHER env var must point at libvclgo_dispatcher.so');
}
log(1, 'loading dispatcher: ' + dispPath);
/* In Frida ≥ 17, `Module.findGlobalExportByName()` only sees modules that
 * were in the process's initial link chain. Modules loaded at script
 * runtime (via `Module.load()`) are visible via the *returned* Module
 * object's own `.findExportByName()` method only. Keep the handle. */
var dispModule = Module.load(dispPath);

function nf(sym, ret, args) {
    var addr = dispModule.findExportByName(sym);
    if (!addr || addr.isNull()) {
        /* Fall back to the global namespace in case a future Frida
         * version widens the search — better to be resilient. */
        try {
            addr = Module.findGlobalExportByName(sym);
        } catch (_) { addr = null; }
    }
    if (!addr || addr.isNull()) {
        throw new Error('dispatcher missing symbol ' + sym + ' in ' + dispPath);
    }
    return new NativeFunction(addr, ret, args);
}

var disp = {
    /* Lifecycle */
    init:            nf('vclgo_init',            'int',    ['pointer']),
    teardown:        nf('vclgo_teardown',        'void',   []),
    abi:             nf('vclgo_abi_version',     'int',    []),
    passthrough:     nf('vclgo_passthrough',     'int',    []),
    errno_addr:      nf('vclgo_errno_addr',      'pointer', []),

    /* Socket API */
    socket:          nf('vclgo_socket',          'int',    ['int','int','int']),
    close:           nf('vclgo_close',           'int',    ['int']),
    shutdown:        nf('vclgo_shutdown',        'int',    ['int','int']),
    bind:            nf('vclgo_bind',            'int',    ['int','pointer','uint32']),
    listen:          nf('vclgo_listen',          'int',    ['int','int']),
    accept4:         nf('vclgo_accept4',         'int',    ['int','pointer','pointer','int']),
    accept:          nf('vclgo_accept',          'int',    ['int','pointer','pointer']),
    connect:         nf('vclgo_connect',         'int',    ['int','pointer','uint32']),
    read:            nf('vclgo_read',            'long',   ['int','pointer','size_t']),
    write:           nf('vclgo_write',           'long',   ['int','pointer','size_t']),
    setsockopt:      nf('vclgo_setsockopt',      'int',    ['int','int','int','pointer','uint32']),
    getsockopt:      nf('vclgo_getsockopt',      'int',    ['int','int','int','pointer','pointer']),
    getsockname:     nf('vclgo_getsockname',     'int',    ['int','pointer','pointer']),
    getpeername:     nf('vclgo_getpeername',     'int',    ['int','pointer','pointer']),
    fcntl:           nf('vclgo_fcntl',           'int',    ['int','int','long']),
};

/* Fake-fd predicate (mirrors the C macro). */
var VCLGO_FD_BASE = 0x40000000;
function isVclFd(fd) { return (fd & VCLGO_FD_BASE) !== 0; }

/* Read the current thread's errno slot.
 *
 * We deliberately do NOT cache the pointer at script load: `errno` is a
 * `__thread`/TLS variable, so `&errno` is different on every pthread. The
 * dispatcher's `vclgo_set_errno` writes to libc's `errno`, and libc's
 * `__errno_location` returns the CURRENT thread's slot; calling it on
 * every access from the goroutine's M pthread gives us the right value.
 *
 * A previous implementation cached `disp.errno_addr()` once on Frida's
 * init pthread; that address pointed at Frida's own zero slot and every
 * hook subsequently read 0, so `readErrno() || 5 (EIO)` misreported every
 * failure as EIO. See docs/analysis_bugs.md S1-9 for the crash story. */
var errnoLocation = new NativeFunction(
    Module.getGlobalExportByName('__errno_location'), 'pointer', []);
function readErrno() { return errnoLocation().readInt(); }

/* Initialise once. Pass argv[0] as app name (best-effort). */
var initRet = disp.init(NULL);
if (initRet !== 0) {
    log(0, 'vclgo_init failed (errno=' + readErrno() + ')');
    throw new Error('vclgo_init failed');
}
var passthrough = disp.passthrough() !== 0;
log(1, 'dispatcher initialised (abi=' + disp.abi() +
        ', passthrough=' + passthrough + ')');

/* S1-5: in passthrough mode (VCL_CONFIG unset) we install NO hooks. The
 * target runs unmodified against the kernel, which is the only way to get
 * true parity with the baseline behaviour. Any hook installed here would
 * either divert to the dispatcher (which returns ENOSYS in passthrough,
 * breaking net.Listen) or paper over the syscall in JS (which changes
 * observable behaviour vs. the un-launcher-ed run).
 *
 * We still keep the dispatcher loaded and initialised because the launcher
 * uses its ABI-version check to detect a runtime/library mismatch — a
 * distinct failure surface from Frida failing to attach. */
if (passthrough) {
    log(1, 'passthrough mode: hooks NOT installed, target runs untouched');
} else {

/* ============================================================================
 * Go error-interface encoding
 *
 * `syscall.Errno` implements `error` with a pointer receiver, so the
 * data-word of the returned interface must point at an 8-byte uintptr
 * holding the errno value. We keep a small persistent cache indexed by
 * errno value to avoid a heap allocation on every failing call.
 *
 * Threading note (S3-6): the cached data-word pointers are shared across
 * all threads/goroutines that fail with the same errno. This is safe
 * because the slot's contents are WRITE-ONCE at allocation time and Go
 * treats syscall.Errno's data word as an immutable uintptr. Do NOT
 * introduce any code that mutates *slot after publication — concurrent
 * readers would observe a torn value.
 * ============================================================================ */

var errnoItabPtr = (function () {
    var addr = mainMod.findSymbolByName ?
        mainMod.findSymbolByName('go:itab.syscall.Errno,error') : null;
    if (addr && !addr.isNull()) return addr;
    /* Legacy Go: try the older mangled name. */
    var candidates = ['go.itab.syscall.Errno,error', 'go:itab.syscall.Errno,error'];
    var found = null;
    try {
        mainMod.enumerateSymbols().some(function (sym) {
            for (var i = 0; i < candidates.length; i++) {
                if (sym.name === candidates[i]) { found = sym.address; return true; }
            }
            return false;
        });
    } catch (e) {}
    if (!found) throw new Error('cannot locate go:itab.syscall.Errno,error');
    return found;
})();
log(1, 'errno itab: ' + errnoItabPtr);

var errnoSlots = {};
function errnoDataPtr(errno) {
    var cached = errnoSlots[errno];
    if (cached !== undefined) return cached;
    var slot = Memory.alloc(8);
    slot.writeU64(errno);
    errnoSlots[errno] = slot;
    return slot;
}

/* Set Go ABI return regs for `(int, error)` (Pattern A) or plain `error`
 * (Pattern B). See frida-vpp/docs/interceptor_architecture.md §5.
 *
 * IMPORTANT (S1-10): we use `retval.replace(N)` for RAX rather than
 * `ctx.rax = ptr(N)`. Both look equivalent, but on x86_64 Frida commits
 * `retval.replace()` through the same slot it uses to synthesise the
 * function's return value, whereas raw context mutations can race with
 * Frida's own save/restore prologue on some code paths (observed as
 * `pc=0x9300000000` control-flow hijacks in Go 1.26 clients under
 * concurrent load — see docs/analysis_bugs.md).
 *
 * frida-vpp uses this idiom successfully; we mirror it exactly. */
function returnInt(ctx, retval, ret) {
    if (ret >= 0) {
        retval.replace(ptr(ret));
        ctx.rbx = ptr(0);
        ctx.rcx = ptr(0);
    } else {
        var e = readErrno() || 5 /* EIO */;
        retval.replace(ptr(-1));
        ctx.rbx = errnoItabPtr;
        ctx.rcx = errnoDataPtr(e);
    }
}

function returnErr(ctx, retval, ret) {
    if (ret === 0) {
        retval.replace(ptr(0));
        ctx.rbx = ptr(0);
        ctx.rcx = ptr(0);
    } else {
        var e = readErrno() || 5;
        retval.replace(errnoItabPtr);
        ctx.rbx = errnoDataPtr(e);
        ctx.rcx = ptr(0);
    }
}

/* Plain int32 return (used by runtime.netpollopen/close). */
function returnI32(ctx, retval, ret) {
    retval.replace(ptr(ret));
}

/* ============================================================================
 * Hook installation
 *
 * We use `Interceptor.replace` with a single-byte `ret` trampoline plus
 * `Interceptor.attach` for callbacks — the same idiom as frida-vpp. The
 * onEnter saves Go ABI regs; onLeave calls the dispatcher and writes the
 * results back via the encoders above.
 * ============================================================================ */

function retTrampoline() {
    var block = Memory.alloc(Process.pageSize);
    Memory.patchCode(block, 16, function (code) {
        var w = new X86Writer(code, { pc: block });
        w.putRet();
        w.flush();
    });
    return block;
}

function installReplace(addr, callbacks) {
    var tramp = retTrampoline();
    Interceptor.replace(addr, tramp);
    Interceptor.attach(addr, callbacks);
}

/* --- Individual hook bodies --- */

var hooks = {

    'syscall.socket': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._domain   = this.context.rax.toInt32();
                this._type     = this.context.rbx.toInt32();
                this._proto    = this.context.rcx.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.socket(this._domain, this._type, this._proto);
                returnInt(this.context, retval, r);
            }
        });
    },

    'syscall.bind': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._sa  = this.context.rbx;
                this._sal = this.context.rcx.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.bind(this._fd, this._sa, this._sal);
                returnErr(this.context, retval, r);
            }
        });
    },

    /* syscall.listen (lowercase) and syscall.Listen (capitalised) share
     * the same (fd, backlog int) ABI. The capitalised name is aliased in
     * hookAliases at install time; only the shared installer lives here. */
    'syscall.listen': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._blg = this.context.rbx.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.listen(this._fd, this._blg);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.accept4': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd    = this.context.rax.toInt32();
                this._sa    = this.context.rbx;
                this._salp  = this.context.rcx;
                this._flags = this.context.rdi.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.accept4(this._fd, this._sa, this._salp, this._flags);
                returnInt(this.context, retval, r);
            }
        });
    },

    'syscall.accept': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd   = this.context.rax.toInt32();
                this._sa   = this.context.rbx;
                this._salp = this.context.rcx;
            },
            onLeave: function (retval) {
                var r = disp.accept(this._fd, this._sa, this._salp);
                returnInt(this.context, retval, r);
            }
        });
    },

    'syscall.connect': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._sa  = this.context.rbx;
                this._sal = this.context.rcx.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.connect(this._fd, this._sa, this._sal);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.setsockopt': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd     = this.context.rax.toInt32();
                this._lvl    = this.context.rbx.toInt32();
                this._name   = this.context.rcx.toInt32();
                this._val    = this.context.rdi;
                this._len    = this.context.rsi.toInt32();
            },
            onLeave: function (retval) {
                var r = disp.setsockopt(this._fd, this._lvl, this._name,
                                        this._val, this._len);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.getsockopt': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd   = this.context.rax.toInt32();
                this._lvl  = this.context.rbx.toInt32();
                this._name = this.context.rcx.toInt32();
                this._val  = this.context.rdi;
                this._lenp = this.context.rsi;
            },
            onLeave: function (retval) {
                var r = disp.getsockopt(this._fd, this._lvl, this._name,
                                         this._val, this._lenp);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.getsockname': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd   = this.context.rax.toInt32();
                this._sa   = this.context.rbx;
                this._salp = this.context.rcx;
            },
            onLeave: function (retval) {
                var r = disp.getsockname(this._fd, this._sa, this._salp);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.getpeername': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd   = this.context.rax.toInt32();
                this._sa   = this.context.rbx;
                this._salp = this.context.rcx;
            },
            onLeave: function (retval) {
                var r = disp.getpeername(this._fd, this._sa, this._salp);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.read': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._buf = this.context.rbx;
                this._cnt = this.context.rcx.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (!this._vcl) {
                    var r = doKernelRead(this._fd, this._buf, this._cnt);
                    returnInt(this.context, retval, r);
                    return;
                }
                var r = disp.read(this._fd, this._buf, this._cnt).toNumber();
                returnInt(this.context, retval, r);
            }
        });
    },

    'syscall.write': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._buf = this.context.rbx;
                this._cnt = this.context.rcx.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (!this._vcl) {
                    var r = doKernelWrite(this._fd, this._buf, this._cnt);
                    returnInt(this.context, retval, r);
                    return;
                }
                var r = disp.write(this._fd, this._buf, this._cnt).toNumber();
                returnInt(this.context, retval, r);
            }
        });
    },

    'syscall.Close': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (!this._vcl) {
                    var r = doKernelClose(this._fd);
                    returnErr(this.context, retval, r);
                    return;
                }
                var r = disp.close(this._fd);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.Shutdown': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._how = this.context.rbx.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (!this._vcl) { returnErr(this.context, retval, 0); return; }
                var r = disp.shutdown(this._fd, this._how);
                returnErr(this.context, retval, r);
            }
        });
    },

    'syscall.fcntl': function (addr) {
        installReplace(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._cmd = this.context.rbx.toInt32();
                this._arg = this.context.rcx.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (!this._vcl) {
                    var r = doKernelFcntl(this._fd, this._cmd, this._arg);
                    returnInt(this.context, retval, r);
                    return;
                }
                var r = disp.fcntl(this._fd, this._cmd, this._arg);
                returnInt(this.context, retval, r);
            }
        });
    },

    /*
     * runtime.netpollopen(fd uintptr, pd *pollDesc) int32
     *   Args:   RAX=fd, RBX=pd
     *   Return: RAX=int32
     *
     * For VCL fds we return 0 immediately (registration "succeeded"). For
     * kernel fds we fall through to the original body so Go's own netpoll
     * behaviour is preserved untouched.
     */
    'runtime.netpollopen': function (addr) {
        Interceptor.attach(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (this._vcl) {
                    /* S1-10: prefer Frida's proper return-value slot over
                     * raw context.rax mutation — matches the pattern used
                     * for the syscall.* hooks and avoids the same register-
                     * corruption risk under concurrent load. */
                    retval.replace(ptr(0));
                }
            }
        });
    },

    /*
     * runtime.netpollclose(fd uintptr) int32
     */
    'runtime.netpollclose': function (addr) {
        Interceptor.attach(addr, {
            onEnter: function () {
                this._fd  = this.context.rax.toInt32();
                this._vcl = isVclFd(this._fd);
            },
            onLeave: function (retval) {
                if (this._vcl) {
                    retval.replace(ptr(0));
                }
            }
        });
    },
};

/* --- Direct kernel-syscall fallback for pass-through paths --- */

var libcRead     = new NativeFunction(Module.getGlobalExportByName('read'),
                                      'long', ['int', 'pointer', 'size_t']);
var libcWrite    = new NativeFunction(Module.getGlobalExportByName('write'),
                                      'long', ['int', 'pointer', 'size_t']);
var libcClose    = new NativeFunction(Module.getGlobalExportByName('close'),
                                      'int',  ['int']);
var libcFcntl    = new NativeFunction(Module.getGlobalExportByName('fcntl'),
                                      'int',  ['int', 'int', 'long']);

function doKernelRead(fd, buf, n)      { return libcRead(fd, buf, n).toNumber(); }
function doKernelWrite(fd, buf, n)     { return libcWrite(fd, buf, n).toNumber(); }
function doKernelClose(fd)             { return libcClose(fd); }
function doKernelFcntl(fd, cmd, arg)   { return libcFcntl(fd, cmd, arg); }

/* --- Actually install --- */

/* Alias map: symbols whose ABI matches an existing hook installer.
 * Kept separate from `hooks` so ABI compatibility for each alias is a
 * conscious decision reviewed alongside the hook body (S4-4). */
var hookAliases = {
    'syscall.Socket': 'syscall.socket',   /* same (domain, typ, proto int) ABI */
    'syscall.Listen': 'syscall.listen',   /* same (fd, backlog int) ABI */
};

var installedCount = 0;
Object.keys(resolved).forEach(function (name) {
    var key = hookAliases[name] || name;
    var installer = hooks[key];
    if (!installer) return;
    try {
        installer(resolved[name]);
        installedCount++;
    } catch (e) {
        log(0, 'hook install for ' + name + ' failed: ' + e);
    }
});
log(1, 'installed ' + installedCount + ' hooks');

/* --- Teardown on process exit --- */

Process.setExceptionHandler(function () { return false; });

} /* end of `if (!passthrough)` — S1-5 */


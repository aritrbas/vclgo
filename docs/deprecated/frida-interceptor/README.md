# Approach #2 archive: Frida Interceptor

This directory preserves the retired high-level Frida
`Interceptor.attach`/JavaScript design. No corresponding implementation is
present in the current build.

- [why_frida_dropped.md](why_frida_dropped.md) explains the structural Go
  ABI, stack, unwinder, netpoll, and VCL TLS failures.
- [phase1_frida.md](phase1_frida.md) preserves the defect and retirement
  record.

The use of native Frida-Gum in Approach #4 is a different mechanism. See the
[current architecture](../../architecture.md).

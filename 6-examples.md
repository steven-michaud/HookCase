# Example Hook Libraries

Here are some examples of how HookCase hook libraries can be used to
reverse engineer features of the macOS/OS X operating system.  The
details are specific to OS X 10.11 (El Capitan) and up, or sometimes
to macOS 10.12 (Sierra) or macOS 10.13 (High Sierra) and up.  Source
code for these hook libaries is available under
[`Examples`](Examples/).

The
[secinit](examples-secinit.md) and [Kernel logging](examples-kernel-logging.md)
examples don't currently work on macOS 10.15 (Catalina). The reason is
that Catalina's system files live on a special partition that is
mounted read-only, and I don't yet know of a reasonable
workaround. Even on macOS 10.14 (Mojave) and below, you will need
either to disable system integrity protection (SIP) altogether
(`csrutil disable`) or turn off both "kernel extension protection" and
"filesystem protection" (`csrutil enable --without kext --without
fs`).

* [Dynamic patch hooks](examples-dynamic-hooking.md)
* [xpcproxy trampoline](examples-xpcproxy.md)
* [secinit subsystem](examples-secinit.md)
* [System events](examples-events.md)
* [Kernel logging](examples-kernel-logging.md)


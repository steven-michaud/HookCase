# Example Hook Libraries

Here are some examples of how HookCase hook libraries can be used to
reverse engineer features of the macOS/OS X operating system.  The
details are specific to OS X 10.11 (El Capitan) and up, or sometimes
to macOS 10.12 (Sierra) or macOS 10.13 (High Sierra) and up.  Source
code for these hook libaries is available under
[`Examples`](Examples/).

The
[secinit](examples-secinit.md) and [Kernel logging](examples-kernel-logging.md)
won't work if you enable system integrity protection (SIP) without
"kernel extension protection" (`csrutil enable --without kext`).  This
is because these examples involve changing system files and writing to
system directories.  However, they will work fine if you turn off both
"kernel extension protection" and "filesystem protection" (`csrutil
enable --without kext --without fs`).

* [Dynamic patch hooks](examples-dynamic-hooking.md)
* [xpcproxy trampoline](examples-xpcproxy.md)
* [secinit subsystem](examples-secinit.md)
* [System events](examples-events.md)
* [Kernel logging](examples-kernel-logging.md)


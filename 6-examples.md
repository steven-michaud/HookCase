# Example Hook Libraries

Here are some examples of how HookCase hook libraries can be used to
reverse engineer features of the macOS/OS X operating system.  The
details are specific to OS X 10.11 (El Capitan) and up, or sometimes
to macOS 10.12 (Sierra) or macOS 10.13 (High Sierra) and up.  Source
code for these hook libaries is available under
[`Examples`](Examples/).

The
[secinit](examples-secinit.md) and [Kernel logging](examples-kernel-logging.md)
examples require changing system files and writing to system
directories.  So they won't work unless you disable system integrity
protection (SIP) altogether (`csrutil disable`), or at least disable
"filesystem protection" (`csrutil enable --without kext --without
fs`).  On macOS 10.15 (Catalina) you also need to remount the
partition that contains system files with read-write permissions
(`sudo mount -uw /`).  Catalina's system files live on a special
partition that is by default mounted read-only. The effect of the
`sudo mount -uw /` command is temporary, and only lasts until you
reboot your computer.

The [secinit](examples-secinit.md) and [Kernel logging](examples-kernel-logging.md)
examples currently don't work at all on macOS 11 (Big Sur).  System
files are in a separate partition, as on macOS 10.15.  But in addition
to the previous protections, this partition is now a
["Signed System Volume"](https://developer.apple.com/news/?id=3xpv8r2m)
I don't yet know of a safe, easily undoable workaround for this.

* [Dynamic patch hooks](examples-dynamic-hooking.md)
* [Watchpoints](examples-watchpoints.md)
* [xpcproxy trampoline](examples-xpcproxy.md)
* [secinit subsystem](examples-secinit.md)
* [System events](examples-events.md)
* [Kernel logging](examples-kernel-logging.md)


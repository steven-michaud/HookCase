# Using

To use HookCase (once it's loaded into the kernel) you need to write
an "interpose library" (aka a "hook library") containing hook
functions for the methods you wish to hook.  The syntax is very
similar to that of `DYLD_INSERT_LIBRARIES` interpose libraries.
There's a annotated template in
[`HookLibraryTemplate`](HookLibraryTemplate/), and there are more
examples under [`Examples`](Examples/).

Once you have a hook library, you need to set environment variables to
load it into a new process and to determine how it behaves there.

Here are the environment variables that HookCase pays attention to:

* `HC_INSERT_LIBRARY` - Full path to hook library

* `HC_ADDKIDS` - Colon-separated list of full paths to additional children

* `HC_NOKIDS` - Don't effect child processes

* `HC_NO_NUMERICAL_ADDRS` - Disable numerical address naming convention

By default, if HookCase sets hooks in a parent process, it will also
set them in all its child processes.  But if you set `HC_NOKIDS` (to
any value), HookCase only effects the parent process (not its
children).

You'll generally not want to set `HC_NOKIDS`.  These days many
applications use multiple processes, and it's particularly useful to
be able to log activity in child processes at the same time as you do
so in their parent.  But note that, even with `HC_NOKIDS` unset, this
really only works properly on OS X 10.11 (El Capitan) and up.  The
child processes of Apple applications (like Safari) are often XPC
services, which don't inherit their parent's environment.  HookCase
can keep track of "XPC children", but only on OS X 10.11 and up (not
on OS X 10.10 (Yosemite) or 10.9 (Mavericks)).

Sometimes a process that isn't a child of the parent process is
engaged in an interaction that you're trying to debug -- often some
kind of server process. If you can arrange for this process to start
(or restart) after the parent process has started, you can make
`HookCase.kext` treat it like a child of the parent process and load
the same hook library into it as gets loaded into the parent process
and its "real" children. Use `HC_ADDKIDS` to load your hook library
into one or more additional "child" processes, and potentially also
into their own children. `HC_NOKIDS` is ignored for the processes
explicitly listed in `HC_ADDKIDS`. But it can be used to stop your
hook library getting loaded into these "child" processes' own
children.

In order to load a hook library into a system server/daemon, previous
versions of HookCase required you to alter `plist` files that govern
their behavior (in `/System/Library/LaunchDaemons` or
`/System/Library/LaunchAgents`). As of macOS 11 (Big Sur), Apple has
made this almost impossible. Now you can work around the problem by
using `HC_ADDKIDS`. I've rewritten two of HookCase's examples to use
`HC_ADDKIDS` -- the [secinit subsystem example](examples-secinit.md)
and the [kernel logging example](examples-kernel-logging.md).

Recent versions of HookCase support creating a patch hook for an
(un-named) method at a particular address in a given module.  (For
more information see
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L1284).)
So, for example, creating a patch hook for a function named
"sub_123abc" would (by default) specify that the hook should be
inserted at offset 0x123abc (hexadecimal notation) in the module.  But
this convention prevents you from creating a patch hook for a method
that's actually named "sub_123abc" (in its module's symbol table).  To
do so, you'll need turn off this behavior by setting the
`HC_NO_NUMERICAL_ADDRS` environment variable.

HookCase now supports dynamically adding patch hooks for raw function
pointers. This is useful in hooks for methods that use callbacks --
for example `CFMachPortCreate()` and `CFRunLoopObserverCreate()`. It's
best to patch callbacks in their "create" methods, before they start
being used. Otherwise there's some danger of a race condition,
especially if the callback can be used on different threads from the
one that calls add_patch_hook(). For more information see
[dynamic_patch_example() in the hook library template](HookLibraryTemplate/hook.mm#L1245)
and [the dynamic patch hooks example](examples-dynamic-hooking.md).

HookCase now supports watchpoints. You can set a watchpoint on a range
of memory and get information on the code that writes to it or reads
from it -- for example a stack trace of the access and the id of the
thread on which it ran. You can also set a watchpoint that catches
only write accesses. Watchpoint support is imprecise: You set one on a
page of memory (typically 4096 bytes), not on a particular byte. So it
won't catch all memory accesses to that page -- only the first
one. And it has limitations: It's only appropriate for page-aligned
blocks of memory -- for example those shared between processes, or
between the kernel and a process. But it can be useful for reverse
engineering the use of shared memory blocks -- for example the
"sideband buffer" that's used by OpenGL accelerated graphics. For more
information see
[config_watcher() in the hook library template](HookLibraryTemplate/hook.mm#L1118),
[Hooked_watcher_example() in the hook library template](HookLibraryTemplate/hook.mm#L1301)
and [the watchpoints example](examples-watchpoints.md).

# What's New in Version 7.3

HookCase 7.3 now works with the
[OpenCore Legacy Patcher](https://github.com/dortania/OpenCore-Legacy-Patcher).
This environment is something of a torture test for HookCase. It
needed several new sanity checks. But it also needs a *much* larger
kernel stack size. For more information see
[Using the OpenCore Legacy Patcher](3-installing.md#using-the-opencore-legacy-patcher)

# What's New in Version 7.2.1

HookCase 7.2.1 has further improvements in watchpoint support. There
are now three different kinds, including two that can catch both read
and write accesses.

# What's New in Version 7.2

HookCase 7.2 has improved support for watchpoints. Its documentation
describes their use and limitations more precisely.
The [watchpoints example](examples-watchpoints.md) has been expanded.

# What's New in Version 7.1.3

macOS 13.3 broke HookCase by making changes to an internal structure
(`struct proc`) that normally only happen in a major release. HookCase
7.1.3 works around these changes.

# What's New in Version 7.1.2

As of macOS 12 (Monterey) Apple supports two new kinds of sandboxing
-- system call filtering and message filtering. These can interfere
with hook library logging and the production of stack traces. So
HookCase 7.1.2 disables them for processes that contain a hook
library.

macOS Monterey changed how `dyld` calls C++ and Objective-C
initializers, such that initializers for the hook library and its
dependents are no longer called automatically. HookCase 6.0 introduced
a workaround -- call the hook library's initializers explicitly. But
doing this doesn't also trigger calls to all of its dependent
frameworks' initializers. HookCase 7.1.2 introduces a different
workaround, which does ensure that all the relevant initializers are
called. This resolves
[Issue #44](https://github.com/steven-michaud/HookCase/issues/44).

HookCase 7.1.2 fixes issues with `execv()` and `fork()`. This resolves
[Issue #45](https://github.com/steven-michaud/HookCase/issues/45).

As best I can tell system call filtering and message filtering aren't
(yet) documented. But the `*.sb` file syntax can be seen in a
[WebKit file](https://opensource.apple.com/source/WebKit2/WebKit2-7611.3.10.1.3/WebProcess/com.apple.WebProcess.sb.in.auto.html)
Search on "syscall-unix", "syscall-mach" and "apply-message-filter".

# What's New in Version 7.1.1

macOS 13 (Ventura) made changes to some system dylibs and frameworks
that break HookCase's support for setting interpose hooks on methods
called from them. I didn't notice this at first, since interpose hooks
still worked in some system modules. But the bug was reported at
[Issue #40](https://github.com/steven-michaud/HookCase/issues/40),
and I've now implemented a workaround in HookCase 7.1.1.

As of macOS 12 (Monterey), HookCase uses a mach-o module's "__got"
section to implement interpose hooks. "GOT" stands for "global offset
table". It's also called the lazy pointer table. It contains the
addresses of functions in other modules. It's used to resolve calls to
these functions. Interpose hooks are set by overwriting entries in the
lazy pointer table.

As of macOS 13 (Ventura), some modules' "__got" sections have been
"optimized" away, and no longer contain usable information. The lazy
pointer tables haven't disappeared: They've just been moved to new
locations, where they can be shared by more than one module. But
they're now only (indirectly) accessible via something called the
stubs table. HookCase 7.1.1 knows how to use the stubs table to
implement interpose hooks.

# What's New in Version 7.1

HookCase 7.1 now supports a powerful new feature -- the `HC_ADDKIDS`
enviroment variable. Sometimes you're trying to debug the interaction
between an application and some kind of server or daemon process. The
daemon isn't a child of the application. So it would have been
difficult or impossible to use previous versions of HookCase to load a
hook library into it. But if you can arrange for the daemon to restart
while the application is running, you can use `HC_ADDKIDS` to get
`HookCase.kext` to count it as one of the application's children, and
load into the daemon the same hook library as was loaded into the
application.

I've rewritten two of HookCase's examples to take advantage of this
new feature -- the [secinitd subsystem example](examples-secinit.md)
and the [kernel logging example](examples-kernel-logging.md). The
previous versions of both examples had stopped working as of macOS 11.

HookCase 7.1 is also significantly better at working with dynamic
patch hooks and virtual serial ports (as provided by
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger)).

# What's New in Version 7.0

HookCase 7.0 now supports macOS 13 (Ventura).

It also makes some changes to better support
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger).
Specifically, it stops hook libraries from triggering sandbox errors
when opening virtual serial ports created by this utility.

# What's New in Version 6.0.5

HookCase 6.0.5 introduces a new way to "catch" logging output from
hook libraries: As an option, you can now redirect it to a virtual
serial port created by
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger).
This helps get around inherent problems logging from a hook library,
and Apple's increasing efforts to block even system logging in such an
environment. This change resolves
[Issue #39](https://github.com/steven-michaud/HookCase/issues/39).

Version 6.0.5 also makes minor changes to the code `HookCase.kext`
uses to track the parentage of potentially "hookable" processes, to
make it more resilient.

Here's [more information on how to use PySerialPortLogger](HookLibraryTemplate/hook.mm#L322).

# What's New in Version 6.0.4

macOS 12.5 and macOS 10.15.7 build 19H2026 both broke HookCase. The
Catalina breakage was minor and easily fixed. The Monterey breakage
was larger, and once again resulted from a change of the kind that
normally only happens in major releases. This time none of the
internal kernel structures used by HookCase were altered. But the
interpretation of `vm_map_entry.vme_object` did change -- from a
union of simple pointers to one of "packed" pointers.

For more information see
[Issue #35](https://github.com/steven-michaud/HookCase/issues/35)
and [Issue #36](https://github.com/steven-michaud/HookCase/issues/36).

# What's New in Version 6.0.3

macOS 12.4 once again broke HookCase, by making changes that normally
only happen in major releases. This time none of the breakage was
caused by changes to internal kernel structures (though some of those
used by HookCase did change). Instead it was caused by two changes in
behavior. HookCase 6.0.3 works around them.

For more information see
[Issue #34](https://github.com/steven-michaud/HookCase/issues/34).

# What's New in Version 6.0.2

macOS 12.3 once again broke HookCase, by making changes that normally
only happen in major release. These included several changes to
internal kernel structures. HookCase 6.0.2 works around these changes.

For more information see
[Issue #33](https://github.com/steven-michaud/HookCase/issues/33).

# What's New in Version 6.0.1

macOS 12.1 broke HookCase, by making lots of changes to internal
kernel structures, of the kind that normally only happen in a major
release. HookCase 6.0.1 alters its copies of these structures to
reflect the changes.

It also fixes incorrect entries in two of the kernel structures used
on macOS 12.0.1. This flaw didn't effect the behavior of HookCase 6.0
on macOS 12.0.1: Not realizing the flaw was my own, I added code to
HookCase 6.0 to work around it. These workarounds are no longer
necessary, and have been removed.

For more information see
[Issue #31](https://github.com/steven-michaud/HookCase/issues/31).

# What's New in Version 6.0

HookCase now supports macOS 12 (Monterey).

Note that, on macOS 12, as on macOS 11, HookCase now requires the
`keepsyms=1` boot arg. To set this you'll need to turn off SIP at least
temporarily.

`sudo nvram boot-args="keepsyms=1"`

# What's New in Version 5.0.5

macOS 11.4 broke HookCase, just like macOS 11.3 did. macOS 11.4 made
further changes to `struct thread`, of a kind that normally only takes
place in a new major release. These changes caused a kernel panic
every time you tried to load a hook library into an application. The
problem is fixed by HookCase 5.0.5. `struct thread` is one of several
kernel structures that HookCase needs to access directly. For more
information see
[Issue #28](https://github.com/steven-michaud/HookCase/issues/28).

# What's New in Version 5.0.4

This version of HookCase fixes a bug that caused intermittent
instability, though not kernel panics. I fixed it by tweaking the
[code at the heart of HookCase's watchpoint support](HookCase/HookCase/HookCase.cpp#L14850).
See [Issue #26](https://github.com/steven-michaud/HookCase/issues/26)
for more information.

HookCase's watchpoint code is quite complex. So if you see any sort of
instability short of kernel panics, especially if it resembles what's
reported at Issue #26, you should try
[disabling watchpoint support](HookCase/HookCase/HookCase.cpp#L15799).

# What's New in Version 5.0.3

This release deals with changes in macOS 11.3 that broke HookCase. The
11.3 update changed two kernel structures whose fields HookCase needs
to access directly. Major changes were made to `struct task`, and
`struct thread` seems to have been completely redesigned. This kind of
change normally only takes place in a new major release, so HookCase
wasn't "expecting" it. HookCase now does separate version checks for
macOS 11 and macOS 11.3. This fixes
[Issue #27](https://github.com/steven-michaud/HookCase/issues/27).

# What's New in Version 5.0.2

This version of HookCase fixes a bug that caused some interpose hooks
to be skipped on macOS 11 (Big Sur)
([Issue #24](https://github.com/steven-michaud/HookCase/issues/24)).
HookCase uses a structure called the lazy pointer table to implement
interpose hooks. In the past it was always located in the `__DATA`
segment. But in Big Sur it's sometimes located in the `__DATA_CONST`
segment. HookCase now looks for it in both places.

# What's New in Version 5.0.1

This version of HookCase fixes a bug that caused intermittent kernel
panics in `set_interpose_hooks_for_module()`
([Issue #22](https://github.com/steven-michaud/HookCase/issues/22)).
They seem to have been particularly likely to occur with hook
libraries containing lots of interpose hooks, particularly ones that
are invoked both before and after the CoreFoundation framework is
initialized.

# What's New in Version 5.0

HookCase now supports macOS 11 (Big Sur).

Note that, on macOS 11, HookCase now requires the `keepsyms=1` boot
arg. To set this you'll need to turn off SIP at least temporarily.

`sudo nvram boot-args="keepsyms=1"`

# What's New in Version 4.1.1

This version of HookCase contains several tweaks to its watchpoint
support. Together they merit a bump in the version number. The most
significant of them are:

[Remove all watchers on process exit](https://github.com/steven-michaud/HookCase/commit/d2d82e3020f6cefb2a475589fe3cfc44107a3be3)

[Make watchpoint example work with multiple graphics cards at once](https://github.com/steven-michaud/HookCase/commit/a6001614115270219860ffd811555a55fa36091b)

[Check if a watchpoint has already been set or unset](https://github.com/steven-michaud/HookCase/commit/4d205078f97e5277294c799811a66b3adba13e88)

# What's New in Version 4.1

This version of HookCase supports watchpoints. You can now set a
watchpoint on a location in memory and gather information (including a
stack trace) about the code that writes to that location.  For more
information see
[config_watcher() in the hook library template](HookLibraryTemplate/hook.mm#L1118),
[Hooked_watcher_example() in the hook library template](HookLibraryTemplate/hook.mm#L1301)
and [the watchpoints example](examples-watchpoints.md).

# What's New in Version 4.0.5

This version of HookCase fixes a bug which caused some patch hooks not
to work properly. If the original function didn't have a standard
prologue, the hook's call to `reset_hook()` would fail and the hook
would only be called once. For more information see
[Issue #17](https://github.com/steven-michaud/HookCase/issues/17)

# What's New in Version 4.0.4

My version 4.0.3 patch didn't fix that kernel panic, either (the one
in `vn_authorize_open_existing()`). Now I really think I've found the
problem -- one that dates back to the earliest HookCase release. It's
only by chance that it didn't become visible earlier. I've done a week
of hard testing without seeing any more kernel panics. For more
information see
[Really really fix kernel panic reported at issue #14](https://github.com/steven-michaud/HookCase/commit/8cf8a444aacea7c1cd752f09407224458cf190b6)
and
[Issue #14](https://github.com/steven-michaud/HookCase/issues/14).

# What's New in Version 4.0.3

It turns out my version 4.0.2 patch didn't fix one of the kernel
panics it was supposed to. This version's patch really does fix it, as
best I can tell after several days of testing. See
[Issue #14](https://github.com/steven-michaud/HookCase/issues/14).

# What's New in Version 4.0.2

This version of HookCase fixes two intermittent kernel panics. For
more information see [Issue #14](https://github.com/steven-michaud/HookCase/issues/14).

# What's New in Version 4.0.1

This version of HookCase documents how to use `sudo mount -uw /` to
temporarily make system files and directories writable on macOS
Catalina (10.15). It also updates
[one of the examples](Examples/secinit/) for Catalina.

# What's New in Version 4.0

HookCase now supports macOS Catalina (10.15).

# What's New in Version 3.3.1

This version of HookCase tightens up the code that supports
dynamically adding patch hooks. Among other things, it completely
fixes a race condition that effected interactions between a hook
library and the HookCase kernel extension, particularly in the
get_dynamic_caller() methods. (Previous code just minimized its
effect.) For more information see the following commit:

[Actual fix for race condition in get_dynamic_caller() and elsewhere](https://github.com/steven-michaud/HookCase/commit/7d6b56ac070eaab758c13a75b8cd8f6ada1b5978)

# What's New in Version 3.3

HookCase now supports dynamically adding patch hooks for raw function
pointers. This is useful in hooks for methods that use callbacks --
for example CFMachPortCreate() and CFRunLoopObserverCreate(). For more
information see
[dynamic_patch_example() in the hook library template](HookLibraryTemplate/hook.mm#L1245)
and [the dynamic patch hooks example](examples-dynamic-hooking.md).

# What's New in Version 3.2.1

Version 3.2.1 fixes some bugs, and restores support for the debug
kernel on macOS 10.14. For more information see
[Issue #11](https://github.com/steven-michaud/HookCase/issues/11)
and the following commit:

[Resume resetting iotier_override, and restore support for debug kernel on 10.14](https://github.com/steven-michaud/HookCase/commit/30dd592df4f4792e5487d6e53d72eb585fd10028)

# What's New in Version 3.2

Version 3.2 works around changes in macOS 10.14.5 that broke
HookCase. These were part of Apple's workaround for Intel's MDS bug.
For more information see
[Issue #9](https://github.com/steven-michaud/HookCase/issues/9).

# What's New in Version 3.1

HookCase now supports enabling all parts of "system integrity
protection" (SIP) but the protection against loading unsigned kernel
extensions.

Though Apple has never documented it, since OS X 10.11 (El Capitan)
it's been possible to
[enable parts of SIP](https://forums.developer.apple.com/thread/17452).
So, for example, you can use the following command (when booted from
the recovery partition) to enable everything but "kernel extension
protection":

        csrutil enable --without kext

I only became aware of this recently, thanks to the reporter of
[Issue #7](https://github.com/steven-michaud/HookCase/issues/7).
That bug report also revealed problems using HookCase on macOS 10.14
(Mojave) with this configuration.  Version 3.1 fixes these problems.

Note that, for HookCase to work properly on macOS 10.14 with this
configuration, you will need to codesign your hook libraries (using
something like `codesign -s "Your Name" hook.dylib`).  For this you'll
need to get a Mac Developer codesigning certificate from Apple,
presumably by joining their
[Apple Developer Program](https://developer.apple.com/programs/).

# What's New in Version 3.0

HookCase now supports macOS Mojave (10.14).

But Mojave's Debug kernel is currently very flaky -- lots of panics,
with and without HookCase.  So support for the Debug kernel
[has been disabled](HookCase/HookCase/HookCase.cpp#L511), at least
temporarily.

# What's New in Version 2.1

HookCase now works properly with VMware Fusion running as a host. This
required changing the range of software interrupts used internally by
HookCase (from `0x20-0x23` to `0x30-0x33`). See
[Issue #5](https://github.com/steven-michaud/HookCase/issues/5) for
more information.

To make existing hook libraries fully compatible with version 2.1,
their reset_hook() methods will need to be changed to use `int 0x32`
instead of `int 0x22`, as follows:

        void reset_hook(void *hook)
        {
          __asm__ ("int %0" :: "N" (0x32));
        }

# What's New in Version 2.0

* HookCase now supports macOS High Sierra (10.13).

* HookCase now supports creating a patch hook for an (un-named) method
at a particular address in a given module.  This means that HookCase
can now hook methods that aren't in their module's symbol table.  For
more information see
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L1284).

* Version 2.0 [fixes a bug](HookCase/HookCase/HookCase.cpp#L12533) that
prevented interpose hooks from working outside the shared cache of
system modules.

* Version 2.0
[fixes a previously undiscovered edge case](HookCase/HookCase/HookCase.cpp#L14292)
of an Apple kernel panic bug that was partially fixed in version 1.

* Version 2.0
[fixes a premature-release bug](Examples/events/hook.mm#L1611)
in the "System Events" example's hook library.

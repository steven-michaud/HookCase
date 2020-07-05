# What's New in Version 4.1

This version of HookCase supports watchpoints. You can now set a
watchpoint on a location in memory and gather information (including a
stack trace) about the code that writes to that location.  For more
information see
[config_watcher() in the hook library template](HookLibraryTemplate/hook.mm#L793),
[Hooked_watcher_example() in the hook library template](HookLibraryTemplate/hook.mm#L929)
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
[dynamic_patch_example() in the hook library template](HookLibraryTemplate/hook.mm#L873)
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
[has been disabled](HookCase/HookCase/HookCase.cpp#L371), at least
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
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L912).

* Version 2.0 [fixes a bug](HookCase/HookCase/HookCase.cpp#L9349) that
prevented interpose hooks from working outside the shared cache of
system modules.

* Version 2.0
[fixes a previously undiscovered edge case](HookCase/HookCase/HookCase.cpp#L10830)
of an Apple kernel panic bug that was partially fixed in version 1.

* Version 2.0
[fixes a premature-release bug](Examples/events/hook.mm#L1335)
in the "System Events" example's hook library.

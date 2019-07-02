# What's New in Version 3.3

HookCase now supports dynamically adding patch hooks for raw function
pointers. This is useful in hooks for methods that use callbacks --
for example CFMachPortCreate() and CFRunLoopObserverCreate(). For more
information see
[dynamic_patch_example() in the hook library template](HookLibraryTemplate/hook.mm#L831)
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
[has been disabled](HookCase/HookCase/HookCase.cpp#L364), at least
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
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L870).

* Version 2.0 [fixes a bug](HookCase/HookCase/HookCase.cpp#L8886) that
prevented interpose hooks from working outside the shared cache of
system modules.

* Version 2.0
[fixes a previously undiscovered edge case](HookCase/HookCase/HookCase.cpp#L10384)
of an Apple kernel panic bug that was partially fixed in version 1.

* Version 2.0
[fixes a premature-release bug](Examples/events/hook.mm#L1336)
in the "System Events" example's hook library.

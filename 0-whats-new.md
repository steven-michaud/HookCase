# What's New in Version 3.0

HookCase now supports macOS Mojave (10.14).

But Mojave's Debug kernel is currently very flaky -- lots of panics,
with and without HookCase.  So support for the Debug kernel
[has been disabled](HookCase/HookCase/HookCase.cpp#L309), at least
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
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L817).

* Version 2.0 [fixes a bug](HookCase/HookCase/HookCase.cpp#L8504) that
prevented interpose hooks from working outside the shared cache of
system modules.

* Version 2.0
[fixes a previously undiscovered edge case](HookCase/HookCase/HookCase.cpp#L9809)
of an Apple kernel panic bug that was partially fixed in version 1.

* Version 2.0
[fixes a premature-release bug](Examples/events/hook.mm#L1277)
in the "System Events" example's hook library.

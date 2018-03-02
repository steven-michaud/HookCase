# What's New in Version 2.0

* HookCase now supports macOS High Sierra (10.13).

* HookCase now supports creating a patch hook for an (un-named) method
at a particular address in a given module.  This means that HookCase
can now hook methods that aren't in their module's symbol table.  For
more information see
[Hooked_sub_123abc() in the hook library template](HookLibraryTemplate/hook.mm#L810).

* Version 2.0 [fixes a bug](HookCase/HookCase/HookCase.cpp#L8144) that
prevented interpose hooks from working outside the shared cache of
system modules.

* Version 2.0
[fixes a previously undiscovered edge case](HookCase/HookCase/HookCase.cpp#L9409)
of an Apple kernel panic bug that was partially fixed in version 1.

* Version 2.0
[fixes a premature-release bug](Examples/events/hook.mm#L1179)
in the "System Events" example's hook library.

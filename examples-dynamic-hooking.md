# Dynamic patch hooks

As of version 3.3, HookCase now supports dynamically adding patch
hooks for raw function pointers. This is useful in hooks for methods
that use callbacks -- for example CFMachPortCreate() and
CFRunLoopObserverCreate().

Hooks for these methods, and their callbacks, are implemented
by the example hook library under
[`Examples/dynamic-hooking`](Examples/dynamic-hooking/). Build the
library, then use it with any complex application (say a web browser)
to see how it works.

For example:

        HC_INSERT_LIBRARY=/full/path/to/hook.dylib /Applications/Safari.app/Contents/MacOS/Safari


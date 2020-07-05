# More About HookCase

Apple's `DYLD_INSERT_LIBRARIES` environment variable is used to load
an "interpose library" into a process before any of its other modules.
The interpose library contains "hooks" for methods implemented
elsewhere.  Once the process is up and running, each hook is called
instead of the original method that it hooks.  Then the hook can call
the original method (if that's how it's been written).  Typically a
hook logs calls to its original method (including its parameters and
return value, plus maybe a stack trace).  It can also be used to alter
the behavior of the original method, or to replace it entirely.

`DYLD_INSERT_LIBRARIES`'s hooks are what we call "interpose hooks".
They're implemented by changing pointers in tables used to dynamically
link methods called from other modules.  So they can only be used to
hook "cross-module" calls to exported methods.

HookCase supports interpose hooks.  But it also supports another, more
powerful kind of hook that we call "patch hooks".  These can hook
calls to a method named in its module's symbol table, including ones
that come from the same module.  They can also hook calls to an
unnamed method (one that isn't in its module's symbol table), by
specifying the method's address in its module.  So they can be used
with non-exported (aka private) methods (named and unnamed) -- ones
not intended for use by external modules.

Patch hooks are so-called because we set them up by "patching" the
beginning of an original method with a software interrupt instruction
(`int 0x30`).  HookCase's kernel extension handles the interrupt to
implement the hook.  This is analogous to what a debugger does when it
sets a breakpoint (though it uses `int 3` instead of `int 0x30`).
Software interrupts are mostly not used on BSD-style operating systems
like macOS and OS X, so we have plenty to choose among.  For now we're
using those in the range `0x30-0x35`.

Whatever their disadvantages, interpose hooks are very performant.
They're implemented by changing a pointer, so they impose no
performance penalty whatsoever (aside from the cost of whatever
additional code runs inside the hook).  Patch hooks can be
substantially less performant -- if we have to unset the breakpoint on
every call to the hook, then reset it afterwards (and protect these
operations from race conditions).  But this isn't needed for methods
that start with a standard C/C++ prologue in machine code (which is
most of them).  So most patch hooks run with only a very small
performance penalty (that of a single software interrupt).

HookCase is compatible with `DYLD_INSERT_LIBRARIES`, and doesn't stomp
on any of the changes it may have been used to make.  So a
`DYLD_INSERT_LIBRARIES` hook will always override the "same" HookCase
interpose hook.  This is because Apple often uses
`DYLD_INSERT_LIBRARIES` internally, in ways it doesn't document.
HookCase would likely break Apple functionality if it could override
Apple's hooks.  But this doesn't apply to patch hooks.  Since Apple
doesn't use them, we don't need to worry about overriding any that
Apple may have set.  If an interpose hook doesn't seem to work, try a
patch hook instead.  (Unless you write them to do so, neither
interpose hooks nor patch hooks inherently change the behavior of the
methods they hook.)

HookCase is compatible with `lldb` and `gdb`:  Any process with
HookCase's interpose or patch hooks can run inside these debuggers.
But you may encounter trouble if you set a breakpoint and a patch hook
on the same method, or try to step through code that contains a patch
hook.

Apple's support for `DYLD_INSERT_LIBRARIES` is implemented in
[`/usr/lib/dyld`](https://opensource.apple.com/source/dyld/dyld-655.1.1/).
A (shared) copy of this module gets loaded into the image of every new
process before it starts running.  `dyld`'s `man` page calls it the
"dynamic link editor", and it's what runs first (starting from
`_dyld_start` in `dyld`'s
[`src/dyldStartup.s`](https://opensource.apple.com/source/dyld/dyld-655.1.1/src/dyldStartup.s.auto.html))
as a new process starts up.  Once `dyld` has finished its work, it
jumps to the new process's `main()` method.

HookCase is a kernel extension (`HookCase.kext`), which can't call
user-mode code directly.  So we can't just replace `dyld` with code in
HookCase.  But we can read and alter the memory image of any running
process.  And we can "set up" user-mode calls to take place after
we've returned to user mode from kernel mode.  So we can hook methods
in `dyld`, and "call" code in it indirectly.  The best time to
intervene is after `dyld` has finished most of its initialization, but
before any of the new process's "own" code has run (including its C++
initializers).  This is when `dyld`'s
`dyld::initializeMainExecutable()` method runs.  So we hook that
method as a process starts up, perform our own initialization, then
allow the original `dyld::InitializeMainExecutable()` method to run
(which, among other things, runs the process's C++ initializers).

For more information, the best place to start is the
[long series of comments](HookCase/HookCase/HookCase.cpp#L6617)
in `HookCase.cpp` before the definition of `C_64_REDZONE_LEN`.

# System events

System events are created by the OS and passed to applications with
user interfaces.  There are two basic kinds -- "high level" and "low
level".  High-level events are
[Apple events](https://developer.apple.com/legacy/library/documentation/AppleScript/Conceptual/AppleEvents/intro_aepg/intro_aepg.html),
which may be used for application scripting.  They're delivered to
applications via the Mach messaging system (as described under "AE
Mach API" in the `AE` framework's `AEMach.h`).  Low-level events are
everything else -- things like keyboard and mouse events.
Applications pull them from `WindowServer` (a system daemon from the
`CoreGraphics` framework).

It can be extremely useful to know what kinds of events are delivered
to applications, and how they get there.  The hook library in
[`Examples/events`](Examples/events/) provides a comprehensive
overview.  To get a more detailed view of particular kinds of events,
you'll want to comment out some hooks and add more logging.

The [`Examples/events`](Examples/events/) hook library is also a good
example of the additional work needed to successfully hook
non-exported methods in 32-bit mode.  These often use a non-standard
ABI to speed things up -- something called `fastcc`.  If we hook such
methods, our hooks will crash unless we also use that ABI.  The basic
rules are to put the first two integer/pointer parameters into `ECX`
and `EDX`, and to put floating point parameters into the `XMM`
registers.  Also, `fastcc` is never used with `varargs` functions.
But it's only for internal use, and is deliberately non-standardized.
Moreover clang chooses on its own which methods to "optimize" using
`fastcc`.

So working with `fastcc` can be tricky.  For every private method you
wish to hook in 32-bit mode, you'll need to use a disassembler (like
[Hopper Disassembler](http://www.hopperapp.com/)) to check whether or
not it uses `fastcc`.  One also needs to build hook libraries with tools
that are as compatible as possible with those used to build the OS
itself.  I've had good luck with the
[LLVM 3.9.0 Clang download](http://releases.llvm.org/3.9.0/clang+llvm-3.9.0-x86_64-apple-darwin.tar.xz)
on OS X 10.11 and macOS 10.12, and the
[LLVM 4.0.0 Clang download](http://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-apple-darwin.tar.xz)
on macOS 10.13.

32-bit binaries only build on macOS 10.13 (HighSierra) and below. So
you won't need any of these special tools on macOS 10.14 (Mojave) and
above.

Do the following (with various applications) to see the events hook
library in action.  As always, on OS X 10.12 (Sierra) and above you'll
want to run the Console app before starting.  Filter on "events".
Most output should be visible in the Terminal window, though.

        HC_INSERT_LIBRARY=/full/path/to/hook.dylib /Applications/Safari.app/Contents/MacOS/Safari


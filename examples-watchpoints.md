# Watchpoints

As of version 4.1, HookCase now supports watchpoints. This is useful
for finding out which functions write to a particular location in
memory -- for example the "sideband buffer" that's used to implement
accelerated OpenGL graphics.

The watchpoint example [`Examples/watchpoints`](Examples/watchpoints/)
contains two hooks. One implements a trivial example of watchpoint
use, for purposes of illustration and testing. The other shows how
watchpoints can be used to reverse engineer the sideband buffer. The
first hook works on any system with any application. The second (and
more interesting) hook only works on systems with hardware
acceleration, and in applications that use OpenGL (for example Firefox
and Chrome, but not Safari).

Build the example using `make`, then use it with a recent Firefox
Nightly to see how it works. (Firefox and Chrome releases have their
symbols stripped, but Firefox Nightlies don't. So stack traces of
Firefox Nightlies contain much more information.)

        HC_INSERT_LIBRARY=/full/path/to/hook.dylib "/Applications/Firefox Nightly.app/Contents/MacOS/firefox"

Firefox Nightlies are available for download
[here](https://nightly.mozilla.org/).

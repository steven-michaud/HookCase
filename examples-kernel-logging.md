# Apple Bug in Kernel Logging

## The Bug

Apple implemented a new logging subsystem on macOS Sierra (10.12) and
up.  It's controlled by the `/usr/libexec/diagnosticd daemon`, which
gets launched on demand at the behest of log message clients like the
"Console" and "log" apps.  While at least one `diagnosticd` client is
active, various other subsystems send log messages to `diagnosticd`,
which it in turn passes to its clients.  `diagnosticd` also monitors
`/dev/oslog_stream` for messages from the kernel.

This new logging subsystem has a bug (or design flaw) in how logging
from kernel extensions is handled:  All logging is suppressed from
kernel extensions whose `start()` method fails.

Note that there's a workaround, which involves installing a serial
port and using `kprintf()` to write to it.  For more information see
[HookCase_start()](HookCase/HookCase/HookCase.cpp#L11113).

The root of the problem is that the messages received by Apple's new
logging subsystem no longer contain full strings.  Instead each
message is "encoded" with partial information, which requires
additional information to decode.  This additional information is
stored in a "uuiddb", or uuid database, which only contains entries
for "recognized" executables (applications and kernel extensions).  No
executable is "recognized" until it's been successfully loaded at
least once.

The uuid database is stored in directories and files under
`/var/db/uuidtext/`.  Each "recognized executable" has a file in this
database, which (among other things) stores every string that might be
used in a message sent to the logging subsystem by that executable.
The database is organized by the executable's UUID.  Apple's linker
(`ld`) generates an executable's UUID
[mostly from a checksum of that executable (search on "OutputFile::computeContentUUID")](https://opensource.apple.com/source/ld64/ld64-274.2/src/ld/OutputFile.cpp.auto.html)
So an executable's UUID changes every time you change its code, but
mostly only then.  And so, generally speaking, no executable that
fails to load will have an entry in the "uuid database".

Loading and starting are separate operations for kernel extensions,
either of which might succeed or fail.  But under normal
circumstances, a kext's `start()` method is called immediately after
it's been successfully loaded (in `OSKext::load()`).  And if the
kext's `start()` method fails, it immediately gets unloaded again (by
a call to `OSKext::removeKext()` from
`OSKext::loadKextWithIdentifier()`).  diagnosticd knows that a kext
has been loaded when it receives a "metadata" message to that effect
via `/dev/oslog_stream`.  It then queries the newly loaded kext, and
if need be creates a new entry for it in the uuid database.  But
output only appears at `/dev/oslog_stream` after a considerable delay.
So if a kext's `start()` method fails, it will already have been
unloaded by the time `diagnosticd` tries to query it to get
information for the uuid database.  `diagnosticd` does receive log
messages from kexts whose `start()` method failed.  But it can't
decode them without information from the uuid database, and so doesn't
pass them along to any of its clients (the "log" or "Console" apps).

I can think of several ways to fix this bug.  One would be to delay
unloading a kext for some time after its `start()` method fails, so
`diagnosticd` can find it when it tries to decode messages from it.
But that would be cumbersome -- how would the kernel know when the
kext should be unloaded?  It'd be better to allow components of the
new logging subsystem to once again send logging messages that contain
full strings, which wouldn't need to be decoded upon receipt by
`diagnosticd`.  Maybe Apple could provide a special method just for
this purpose, which kext developers could use for error conditions
that will cause the `start()` method to fail.

## Using HookCase to Diagnose the Bug

[This example](Examples/kernel-logging/) contains a "hello world"
kernel extension, [KernelLogging](Examples/kernel-logging/KernelLogging/),
which can be used to test logging.  It also contains two hook
libraries -- one
([`logger-hook.dylib`](Examples/kernel-logging/logger-hook.mm))
for client logging apps like "Console", and the other
([`diagnosticd-hook.dylib`](Examples/kernel-logging/diagnosticd-hook.mm))
for the `diagnosticd` daemon.

Build KernelLogging by running `xcodebuild` in
[`Examples/kernel-logging/KernelLogging`](Examples/kernel-logging/KernelLogging/).
Note that you can define `FAIL_START` or not, depending on whether you
want its `start()` method to fail or succeed.  Once KernelLogging is
built, change to the `build/Release` subdirectory and copy it to a
directory from which it can be loaded into the kernel:

        sudo cp -R KernelLogging.kext /usr/local/sbin/

`logger-hook.dylib` is easy to load, for example by doing the
following in the Terminal app.  Its output will be written to your
Terminal window.

        HC_INSERT_LIBRARY=/full/path/to/logger-hook.dylib /Applications/Utilities/Console.app/Contents/MacOS/Console

`diagnosticd` is a system daemon, so it's a bit more effort to make it
load a hook library.  Furthermore, logging doesn't work at all from
`diagnosticd` (possibly because it controls the logging subsystem).
So `diagnosticd-hook.dylib` writes all its output to a serial port.
This is easiest to set up in a virtual machine.  For more information
see [diagnosticd-hook.mm](Examples/kernel-logging/diagnosticd-hook.mm#L231).
Note that user-mode code and the kernel can't both access the serial
port at the same time.

1. Make sure no `diagnosticd` client app is running (the Console app
   or the log app).

2. Copy `diagnosticd-hook.dylib` to an appropriate location:

        sudo cp diagnosticd-hook.dylib /usr/libexec/

3. Make a backup copy of the `com.apple.diagnosticd.plist` in
   `/System/Library/LaunchDaemons/` that governs `diagnosticd`'s
   behavior:

        sudo cp -p com.apple.diagnosticd.plist com.apple.diagnosticd.plist.org

4. Create another copy of `com.apple.diagnosticd.plist` for use with
   HookCase, then edit it as follows:

        sudo cp com.apple.diagnosticd.plist com.apple.diagnosticd.plist.debug

        sudo [emacs or vi] com.apple.diagnosticd.plist.debug

5. In your editor, add the following key-value combination to the
   `EnvironmentVariables` dictionary in the file (which will probably
   already exist), and copy it over the original file:

        <key>HC_INSERT_LIBRARY</key>
        <string>/usr/libexec/diagnosticd-hook.dylib</string>

        sudo cp com.apple.diagnosticd.plist.debug com.apple.diagnosticd.plist

6. Unload and reload `diagnosticd`, to make it pick up
   `diagnosticd-hook.dylib`:

        sudo launchctl unload /System/Library/LaunchDaemons/com.apple.diagnosticd.plist
        sudo launchctl load /System/Library/LaunchDaemons/com.apple.diagnosticd.plist

7. Run either the Console app or the log app.  Without at least one of
   its clients running, `diagnosticd` receives no input.

You can now load and unload KernelLogging, to see how `diagnosticd`
behaves.  All of `diagnosticd-hook.dylib`'s output will go to a serial
port, if you've installed one.  Otherwise there won't be any output.

        sudo kextutil /usr/local/sbin/KernelLogging.kext
        sudo kextunload -b org.smichaud.KernelLogging

When you're done experimenting, quit Console and/or log and do the
following in `/System/Library/LaunchDaemons` to unload
`diagnosticd-hook.dylib`:

        sudo cp -p com.apple.diagnosticd.plist.org com.apple.diagnosticd.plist
        sudo launchctl unload /System/Library/LaunchDaemons/com.apple.diagnosticd.plist
        sudo launchctl load /System/Library/LaunchDaemons/com.apple.diagnosticd.plist


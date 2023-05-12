# Apple Bug in Kernel Logging

## The Bug

Apple implemented a new logging subsystem on macOS Sierra (10.12) and
up -- the ["unified logging system"](https://developer.apple.com/documentation/os/logging).
It's controlled by the `/usr/libexec/diagnosticd` daemon, which gets
launched on demand at the behest of log message clients like the
"Console" and "log" apps. While at least one `diagnosticd` client is
active, various other subsystems send log messages to `diagnosticd`,
which it in turn passes to its clients. `diagnosticd` also monitors
`/dev/oslog_stream` for messages from the kernel.

This new logging subsystem has a bug (or design flaw) in how logging
from kernel extensions is handled:  All logging is suppressed from
kernel extensions whose `start()` method fails.

Note that there's a workaround, which involves installing a serial
port and using `kprintf()` to write to it. For more information see
[HookCase_start()](HookCase/HookCase/HookCase.cpp#L15933).

The root of the problem is that the messages received by Apple's new
logging subsystem no longer contain any strings. Each message is
"encoded" with partial information, which requires additional
information to decode. This additional information is stored in a
"uuiddb", or uuid database, which only contains entries for
"recognized" executables (applications and kernel extensions). No
executable is "recognized" until it's been successfully loaded at
least once.

The uuid database is stored in directories and files under
`/var/db/uuidtext/`. Each "recognized executable" has a file in this
database, which (among other things) stores every string that might be
used in a message sent to the logging subsystem by that executable.
The database is organized by the executable's UUID. Apple's linker
(`ld`) generates an executable's UUID
[mostly from a checksum of that executable (search on "OutputFile::computeContentUUID")](https://opensource.apple.com/source/ld64/ld64-274.2/src/ld/OutputFile.cpp.auto.html)
So an executable's UUID changes every time you change its code, but
mostly only then. And so, generally speaking, no executable that
fails to load will have an entry in the "uuid database".

Loading and starting are separate operations for kernel extensions,
either of which might succeed or fail. But under normal circumstances,
a kext's `start()` method is called immediately after it's been
successfully loaded (in `OSKext::load()`). And if the kext's `start()`
method fails, it immediately gets unloaded again (by a call to
`OSKext::removeKext()` from `OSKext::loadKextWithIdentifier()`).
`diagnosticd` knows that a kext has been loaded when it receives a
"metadata" message to that effect via `/dev/oslog_stream`. It then
queries the newly loaded kext, and if need be creates a new entry for
it in the uuid database. But output only appears at
`/dev/oslog_stream` after a considerable delay. So if a kext's
`start()` method fails, it will already have been unloaded by the time
`diagnosticd` tries to query it to get information for the uuid
database. `diagnosticd` does receive log messages from kexts whose
`start()` method failed. But it can't decode them without information
from the uuid database, and so doesn't pass them along to any of its
clients (the "log" or "Console" apps).

I can think of several ways to fix this bug. One would be to delay
unloading a kext for some time after its `start()` method fails, so
`diagnosticd` can find it when it tries to decode messages from it.
But that would be cumbersome -- how would the kernel know when the
kext should be unloaded? It'd be better to allow components of the new
logging subsystem to once again send logging messages that contain
full strings, which wouldn't need to be decoded upon receipt by
`diagnosticd`. Their use could be limited to before the `start()`
method has succeeded or failed. Failing that, Apple could provide a
list of canned error messages to be used to indicate various kinds of
failure -- for example "Unsupported version of macOS" or "Unexpected
error".

## Using HookCase to Diagnose the Bug

[This example](Examples/kernel-logging/) contains a "hello world"
kernel extension, [KernelLogging](Examples/kernel-logging/KernelLogging/),
which can be used to test logging. It also contains a hook library to
be loaded into logging apps like Console and (via `HC_ADDKIDS`) into
the `diagnosticd` daemon.

Build KernelLogging by running `xcodebuild` in
[`Examples/kernel-logging/KernelLogging`](Examples/kernel-logging/KernelLogging/).
Note that you can define `FAIL_START` or not, depending on whether you
want its `start()` method to fail or succeed. Once KernelLogging is
built, change to the `build/Release` subdirectory and copy it to a
directory from which it can be loaded into the kernel:

```
sudo cp -R KernelLogging.kext /usr/local/sbin/
```

Then build the hook library. You'll first need to configure it to
redirect its output to a virtual serial port like
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger),
[here](Examples/kernel-logging/hook.mm#L337). Otherwise you won't see
any output from `diagnosticd`.

To load this example's hook library into both the application you're
testing with (say Console) and the `diagnosticd` daemon, you need to
first restart the daemon and then kill it. Then running Console will
cause it to be restarted yet again with the hook library loaded.

```
% sudo launchctl kickstart -kp system/com.apple.diagnosticd
service spawned with pid: [pid]
% sudo kill -9 [pid]
```

Now run the Console app:

```
HC_ADDKIDS=/usr/libexec/diagnosticd HC_INSERT_LIBRARY=/full/path/to/hook.dylib /System/Applications/Utilities/Console.app/Contents/MacOS/Console
```

Before you click "Start Streaming" in the Console window, set the
filter (under "Search", in the upper right) to Process Equals
"kernel". This should reduce the hook library's output to manageable
proportions, and exclude most irrelevant content.

Now load and unload `KernelLogging.kext`, to see how `diagnosticd`
behaves. Note that the first time you try to load a newly built or
altered `KernelLogging.kext`, you'll be forced to approve it and
restart your computer (on macOS 11 and up).

```
% sudo kmutil load -p /usr/local/sbin/KernelLogging.kext
% sudo kmutil unload -b org.smichaud.KernelLogging
```

Once you're done testing, quit Console and restart `diagnosticd` yet
again by doing the following. This latest instance of `diagnosticd`
will no longer have the hook library loaded into it.

```
sudo launchctl kickstart -kp system/com.apple.diagnosticd
```


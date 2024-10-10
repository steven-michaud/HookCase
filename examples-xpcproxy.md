# xpcproxy trampoline

`/usr/libexec/xpcproxy` is a "trampoline" that's used by `launchd` to
launch XPC services.  `xpcproxy` is spawned from `launchd` (using
`posix_spawnp()`).  It uses `xpc_pipe_routine()` to communicate back
to `launchd` to get the information needed to spawn the XPC service --
notably the path to the XPC service executable and the values that
should be set in its environment.  Then `xpcproxy` uses
`posix_spawn()` with a special flag (`POSIX_SPAWN_SETEXEC`) to `exec`
the XPC service over itself (so that the XPC service keeps the same
process id as `xpcproxy`).

You can see all this in action by building and using the hook library
under [`Examples/xpcproxy`](Examples/xpcproxy/).  There's more
information in the hook library's comments.

Once the hook library is built, you should use it with an application
(like Safari) that uses XPC services.  Here's one way to do that, from
a Terminal session.  Note that all the logging will go to the Console
app, which on macOS 10.12 (Sierra) and above needs to be running
before you do the following.  Use "xpcproxy" to filter the Console
app's output. Alternatively, you can use `serialportlogger` from
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger)
and
[define VIRTUAL_SERIAL_PORT in the hook library](Examples/xpcproxy/hook.mm#L302).

        HC_INSERT_LIBRARY=/full/path/to/hook.dylib open /Applications/Safari.app

Since the first two XPC services are launched almost immediately, the
logs for these services can get interleaved, and hard to read.  To get
a log that's easier to read, visit some web page a few seconds after
launching Safari -- which will result in another XPC service being
launched.

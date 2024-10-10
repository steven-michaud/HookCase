# secinit subsystem

The "secinit subsystem" (if we may call it that) has two parts:

  * `/usr/libexec/secinitd` -- a system daemon that (according to its
    `man` page) "initializes the runtime security policies for
    processes".  A more precise and accurate description is that it
    serves requests to configure and turn on the
    [App Sandbox](https://developer.apple.com/library/mac/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html).

  * `/usr/lib/system/libsystem_secinit.dylib` -- a component of
    `/usr/lib/libSystem.dylib` whose code runs automatically as
    `libSystem.dylib` is initialized, or in other words as every Mach
    binary starts up.

Part of `libsystem_secinit.dylib`'s initialization code
(`_libsecinit_setup_secinitd_client()`) calls
`xpc_copy_entitlements_for_pid()` to find out if the current process has
any entitlements.  If it doesn't, or if the entitlements don't include
one of the following three keys set to "true", then nothing more
happens.

        com.apple.security.app-sandbox
        com.apple.security.app-sandbox.optional
        com.apple.security.app-protection

If any of these keys is "true", that means the current process wants
to use the
[App Sandbox](https://developer.apple.com/library/mac/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html).
This is a high level way to configure and enable Apple's sandbox,
using
[entitlements](https://developer.apple.com/library/content/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AboutEntitlements.html).
In this case `_libsecinit_setup_secinitd_client()` goes on to call
`xpc_pipe_routine()` to send a message to "com.apple.secinitd" via XPC
(in other words to the `secinitd` system daemon).  The message
contains (among other things) the process's entitlements.  Normally
`secinitd` will respond, and its response will appear in
`xpc_pipe_routine()`'s 'reply' parameter.  Among other things, this
reply will include a blob of Scheme byte code compiled from the
sandbox-specific parts of the current process's entitlements.  Then
`_libsecinit_setup_app_sandbox()` will call `__mac_syscall()` with
'call' set to '0' and 'arg' pointing (among other things) to the blob
of Scheme byte code.  This initializes and turns on Apple's sandbox.
(For some reason this doesn't happen on macOS 13 and above.  I haven't
yet figured out why.)

On the server side, `secinitd` runs as the currently logged in user
and sits waiting for requests from "secinitd clients".  When a new
client process makes a connection, `secinitd` calls
`xpc_connection_set_event_handler()` to set an event handler for it,
and the handler gets called on the first message -- the one sent via
`xpc_pipe_routine()` from the client.  The handler checks if a
"container" has already been created for the client.  If so, it sends
back the contents using `xpc_connection_send_message()`.

Containers are stored in directories under `~/Library/Containers`,
each named for an application that uses the App Sandbox (for example
"com.apple.calculator").  If a directory doesn't exist, `secinitd`
needs to (re)generate it.  Among other things this involves a call to
`sandbox_compile_entitlements()`.

The hook library in [`Examples/secinit`](Examples/secinit/) gets
loaded into whichever application you're testing with, and also into
`secinitd` (via `HC_ADDKIDS`). In this kind of environment it's best
to configure it to redirect its output to a virtual serial port like
[PySerialPortLogger](https://github.com/steven-michaud/PySerialPortLogger),
[here](Examples/secinit/hook.mm#L348).

Multiple instances of `secinitd` may already be running, each serving
a different purpose. So first you need to identify the one you'll use
in these tests -- the one for the domain of the user you're currently
logged in as.

The first step is to (re)start `secinitd` for your domain. The command
will return the `pid` of the new instance. Then you'll kill this
instance, so that running Calculator will cause it to be restarted yet
again with the hook library loaded.

```
% launchctl kickstart -p user/${UID}/com.apple.secinitd
service spawned with pid: [pid]
% kill -9 [pid]
```

Now run the Calculator app (or whichever app you're testing with):

```
HC_ADDKIDS=/usr/libexec/secinitd HC_INSERT_LIBRARY=/full/path/to/hook.dylib open /System/Applications/Calculator.app
```

To see `sandbox_compile_entitlements()` in action, first delete the
`secinitd` client's Containers directory. For example:

```
rm -rf ~/Library/Containers/com.apple.calculator
```

It's also possible to do all the above "automatically" via a shell
script, as follows:

```
HC_ADDKIDS=/usr/libexec/secinitd HC_INSERT_LIBRARY=/full/path/to/hook.dylib ./runtest.sh
```

Also test with other applications that may or may not be `secinitd`
clients, to see what happens. Examples of applications that have
entitlements and use the App Sandbox are Calculator and Notes. Firefox
and Google Chrome have entitlements but don't use the App Sandbox --
instead they use Apple's sandbox at a lower level by calling
`sandbox_init_with_parameters()`. Safari also used to do this, but now
uses the App Sandbox.

When you're done testing, quit all the applications containing the
hook library and restart `secinitd` for your domain one more time by
doing the following. This latest instance of `secinitd` will no longer
have the hook library loaded into it.

```
% launchctl kickstart -p user/${UID}/com.apple.secinitd
service spawned with pid: [pid]
% kill -9 [pid]
```


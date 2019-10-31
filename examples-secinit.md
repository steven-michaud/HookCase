# secinit subsystem

As mentioned earlier, this example won't work unless you disable
system integrity protection (SIP) altogether (`csrutil disable`), or
at least disable "filesystem protection" (`csrutil enable --without
kext --without fs`).  On macOS 10.15 (Catalina) you also need to
remount the partition that contains system files with read-write
permissions (`sudo mount -uw /`).

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

[`Examples/secinit`](Examples/secinit/) includes two hook libraries,
one ([`secinitd-hook.dylib`](Examples/secinit/secinitd-hook.mm)) for
`secinitd` and the other ([`hook.dylib`](Examples/secinit/hook.mm))
for its possible clients.

As `secinitd` is a system daemon, making it load a hook library takes
a bit of work:

1. Copy `secinitd-hook.dylib` to an appropriate location:

        sudo cp secinitd-hook.dylib /usr/libexec/

2. Make a backup copy of the `com.apple.secinitd.plist` file in
   `/System/Library/LaunchAgents` that governs `secinitd`'s behavior
   as an "agent" for the currently logged in user.

        sudo cp -p com.apple.secinitd.plist com.apple.secinitd.plist.org

3. Create another copy of `com.apple.secinitd.plist` for use with
   HookCase, then edit it as follows:

        sudo cp com.apple.secinitd.plist com.apple.secinitd.plist.debug

        sudo [emacs or vi] com.apple.secinitd.plist.debug

4. In your editor, add the following section to the "debug" plist
   file's top level `dict` structure, then copy it over the original
   file.

        <key>EnvironmentVariables</key>
        <dict>
          <key>HC_INSERT_LIBRARY</key>
          <string>/usr/libexec/secinitd-hook.dylib</string>
        </dict>

        sudo cp com.apple.secinitd.plist.debug com.apple.secinitd.plist

5. Unload and reload `secinitd` as a user agent, to make it pick up
   `secinitd-hook.dylib`:

        launchctl unload -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist
        launchctl load -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist

Now run applications that may or may not be `secinitd` clients, to see
what happens.  Examples of applications that have entitlements and use
the App Sandbox are Calculator and Notes.  Safari is an application
that has entitlements but doesn't use the App Sandbox (instead its XPC
children use Apple's sandbox at a lower level by calling
`sandbox_init_with_parameters()`).  Google Chrome and Firefox don't
have entitlements at all (though the children of both also use Apple's
sandbox via `sandbox_init_with_parameters()`).

A lot of the logging output will go to the Console, including
everything from `secinitd-hook.dylib`.  If you're testing on macOS
10.12 (Sierra) or above, run the Console before you run any `secinitd`
client.  Use "secinit" to filter the Console app's output.

For example:

        HC_INSERT_LIBRARY=/full/path/to/hook.dylib /Applications/Calculator.app/Contents/MacOS/Calculator

To see `sandbox_compile_entitlements()` in action, first delete the
secinitd client's Containers directory.  For example:

        rm -rf ~/Library/Containers/com.apple.calculator

When you're done experimenting, do the following in
`/System/Library/LaunchAgents` to unload `secinitd-hook.dylib`:

        sudo cp -p com.apple.secinitd.plist.org com.apple.secinitd.plist
        launchctl unload -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist
        launchctl load -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist

You should probably also restore system integrity protection (`csrutil
enable --without kext`).  On Catalina, the partition that contains
system files will automatically be remounted read-only after your
computer is rebooted.

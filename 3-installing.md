# Installing

On OS X 10.10 (Yosemite) and up, to load `HookCase.kext` you'll need
to turn off Apple's protection against loading unsigned or
"inappropriately" signed kernel extensions.  (From Apple's point of
view, the only "appropriately" signed kernel extensions are those
signed with a special kernel extension signing certificate -- in
practice almost exclusively Apple's own kernel extensions.)  On OS X
10.11 (El Capitan) and up, to do this you'll need to at least partly
turn off "system integrity protection" (SIP, also known as "rootless
mode").

Apple documents turning SIP completely off or completely on.  But it's
also possible
[to only enable parts of it](https://forums.developer.apple.com/thread/17452).
For example, it's possible to turn on everything but the protection
against loading unsigned kernel extensions.  This is the most secure
configuation that's still compatible with HookCase.  But using it on
macOS 10.14 (Mojave) and above will require you to codesign your hook
libraries.

## On OS X 10.10:

1. From the command line run `nvram boot-args` to see if you already
   have some boot-args.  Then run the following command:

        sudo nvram boot-args="<existing-boot-args> kext-dev-mode=1"

2. Reboot your computer.

## On OS X 10.11 and up:

1. Boot into your Recovery partition by restarting your computer and
   pressing `Command-R` immediately after you hear the Mac startup
   sound.  Release these keys when you see the Apple logo.

2. Choose Utilties : Terminal, then run one of the the following at
   the command line.  The first command disables SIP completely.  The
   second enables everything but protection against loading unsigned
   kernel extensions.  The third also disables file-system protection.

        csrutil disable

        csrutil enable --without kext

        csrutil enable --without kext --without fs

3. Quit Terminal and reboot your computer.

Now copy `HookCase.kext` to the `/usr/local/sbin/` directory.  You may
need to create this directory.  Make sure it's owned by `root:wheel`.

`sudo cp -R HookCase.kext /usr/local/sbin`

## On macOS 10.15 and below:

On macOS 10.15 (Catalina) and below, you need only a single command to
load `HookCase.kext` into the kernel:

`sudo kextutil /usr/local/sbin/HookCase.kext`

Because it won't have been signed using a kernel extension signing
certificate, you'll see the following error (or something like it):

        Diagnostics for HookCase.kext:
        Code Signing Failure: code signature is invalid
        kext-dev-mode allowing invalid signature -67050 0xFFFFFFFFFFFEFA16
          for kext "HookCase.kext"
        kext signature failure override allowing invalid signature -67050
          0xFFFFFFFFFFFEFA16 for kext "/usr/local/sbin/HookCase.kext"

Run `kextstat` to see that it did load.

To unload `HookCase.kext` from the kernel, run the following command:

`sudo kextunload -b org.smichaud.HookCase`

## On macOS 11 and above:

Things are more complicated on macOS 11 (Big Sur) and above.  As of
this version of macOS, HookCase requires the `keepsyms=1` boot arg.
And third party kernel extensions must be loaded into the "auxiliary
kext collection" before they can be loaded into the kernel.  Along the
way you'll need to explicitly give permission for `HookCase.kext` to
be loaded, then reboot your computer.  macOS 11 also uses a new set of
command line utilties to load and unload kernel extensions.

1. Change your boot args as follows. To do this, you will need to
disable SIP at least temporarily. Reboot your computer to make the
change take effect.

`sudo nvram boot-args="keepsyms=1"`

2. Run the following command at a Terminal prompt:

`sudo kmutil load -p /usr/local/sbin/HookCase.kext`

3. After a few seconds, a "System Extension Updated" dialog will
appear telling you that the HookCase system extension has been
updated.  Click on the "Open Security Preferences" button.

4. In the "Security & Privacy" preference panel, first "click the lock
to make changes", then click on the "Allow" button next to HookCase.
Another dialog will appear telling you that "a restart is required
before new system extensions can be used".  The default choice is "Not
Now", and it's best to choose that.  Wierdness can happen if you
restart immediately.  I usually close all open applications and then
restart.

5. After your computer has restarted, open a Terminal prompt and once
again enter the following command.  It should immediately load
`HookCase.kext` into the kernel.

`sudo kmutil load -p /usr/local/sbin/HookCase.kext`

Run `kextstat` to see that it did load.

Run one of the following commands to unload `HookCase.kext` from the
kernel:

`sudo kmutil unload -p /usr/local/sbin/HookCase.kext`

`sudo kumtil unload -b org.smichaud.HookCase`

`HookCase.kext` will not be loaded automatically when you once again
restart your computer.  You will need to load it (and unload it)
manually as per step 4.

## Increasing the kernel stack size

For some reason, HookCase 5.0 and above sometimes require that you
increase the kernel stack size.  I've seen kernel stack underflows
hooking methods in 32-bit applications (like TextWrangler) on older
versions of macOS (which still support them).  The symptom of a kernel
stack underflow is a double-fault kernel panic with CR2 set to an
address on the stack.  One way to increase the kernel stack size is as
follows.  `kernel_stack_pages` default to `4`.  You will need to
disable SIP at least temporarily to make changes to your "kernel boot
args".

1. `sudo nvram boot-args="keepsyms=1 kernel_stack_pages=6"`

2. Reboot your computer.

## Using the [OpenCore Legacy Patcher](https://github.com/dortania/OpenCore-Legacy-Patcher)

As of version 7.3, HookCase now works with OCLP. But it requires a
*substantial* increase in the kernel stack size (to at least 16
pages). And you need to use a non-standard way to set it, or any other
kernel boot arg. In fact you need to directly edit the OCLP
`config.plist` settings file on the EFI partition.

1. Run `diskutil list` to display all the partitions on your system,
mounted and unmounted. For each "physical" disk you should find
something like the following. Note the device name of the EFI
partition on the "physical" disk from which you've currently
booted. In the following it's `disk0s1`. I will use this as an example
in the following instructions.

```
/dev/disk0 (internal, physical):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *1.0 TB     disk0
   1:                        EFI EFI                     209.7 MB   disk0s1
   ...
```

2. Run `diskutil mount disk0s1`. This should mount the EFI partition
at `/Volumes/EFI`. Then `cd /Volumes/EFI/EFI/OC`.

3. Note the `config.plist` file, which should contain a section like
the following.

```
<key>NVRAM</key>
<dict>
    <key>Add</key>
    <dict>
        ...
        <key>7C436110-AB2A-4BBB-A880-FE41995C9F82</key>
        <dict>
            <key>boot-args</key>
            <string>keepsyms=1 debug=0x100 ipc_control_port_options=0 -nokcmismatchpanic amfi=0x80</string>
            ...
        </dict>
    </dict>
    ...
</dict>
```

4. Edit it so it looks like this:

```
<key>NVRAM</key>
<dict>
    <key>Add</key>
    <dict>
        ...
        <key>7C436110-AB2A-4BBB-A880-FE41995C9F82</key>
        <dict>
            <key>boot-args</key>
            <string>keepsyms=1 debug=0x100 ipc_control_port_options=0 -nokcmismatchpanic amfi=0x80 kernel_stack_pages=16</string>
            ...
        </dict>
    </dict>
    ...
</dict>
```

5. Reboot your computer.

6. Once your computer has finished rebooting, run `sysctl
kern.stack_size`. It should return `kern.stack_size 65536`.

# Important

Any changes you've made to the `config.plist` file will disappear when
you use the OpenCore-patcher app to change settings. You'll need to
follow these instructions once again to (re)set the
`kernel_stack_pages` kernel boot arg.

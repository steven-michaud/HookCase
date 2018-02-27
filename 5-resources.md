# Resources

Here are the resources I found most useful writing HookCase.  You'll
also need them (or something like them) to write hook libraries for
HookCase, and to interpret the results you get from them.

## Documentation

#### Apple documentation

  * [Mac debugging techniques](http://developer.apple.com/technotes/tn2004/tn2124.html)
  * [Current documents, search by title](https://developer.apple.com/library/mac/navigation/)
  * ["Retired" documents, search by title](http://developer.apple.com/legacy/library/navigation/)

#### Calling conventions (stack frames and registers)

Basic information is scattered through the
[Mac debugging techniques article](http://developer.apple.com/technotes/tn2004/tn2124.html).
Much fuller information is available here:

  * [X86_64 Stack Frame Layout](http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/)
  * [X86 Calling Conventions](https://en.wikipedia.org/wiki/X86_calling_conventions)
  * [OS X ABI Function Call Guide](https://developer.apple.com/library/content/documentation/DeveloperTools/Conceptual/LowLevelABI/000-Introduction/introduction.html)
  * [AMD64 Processor ABI](https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf)
  * [AMD64 Processor ABI (alternate site)](http://x86-64.org/documentation/abi.pdf)

#### X86/X86_64 assembler instructions

  * [X86 Instruction Listings](http://en.wikipedia.org/wiki/X86_instruction_listings)
  * [X86 Assembly Control Flow](https://en.wikibooks.org/wiki/X86_Assembly/Control_Flow)
  * [Intel Instruction Set Reference](http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)

## Other Resources

#### [class-dump](http://stevenygard.com/projects/class-dump/)

This excellent utility dumps the equivalent of full header
information from an Objective-C binary.

#### Disassemblers

I can't find any decent open-source disassemblers, but Hopper
Disassembler is excellent and not too expensive.  It's very good at
following cross-references, so that (for example) you can find both a
method's implementation and the code it's called from, or a string and
the methods that use it.  It's well suited to reconstructing a C/C++
method's parameters and return values.

[Hopper Disassembler](http://www.hopperapp.com/)

You can also get a reasonably good assembly code listing of a
particular function in a binary using

`otool -t -v -V -p function_name binary | less`

#### [Apple Open Source](http://opensource.apple.com/)

OS X isn't open source.  But this site has source code (sometimes
incomplete) for a lot of its components, which can provide crucial
information on the undocumented stuff that shows up in hook library
calls and stack traces.  It doesn't contain source code for any kernel
extensions, but it does have source for the kernel itself (the `xnu`
kernel).  I found this extremely useful writing `HookCase.kext`.

#### CoreSymbolication framework

This is an undocumented Apple framework, available on SnowLeopard (OS
X 10.6) and up, that can be used to programmatically examine the call
stack in a running program -- for example to display a trace of the
current call stack.

The best guides on how to use this are my hook library template in
`HookLibraryTemplate` and the examples under `Examples`.

#### gdb

`gdb` is Apple's default command-line debugger on OS X 10.8.5 and below.
I don't know of any really good documentation on it.  I generally rely
on its internal documentation and search on the web (as the need
arises) for whatever that doesn't cover.

The
[Mac Debugging Techniques article](http://developer.apple.com/technotes/tn2004/tn2124.html)
does have a lot of information on Apple-specific additions to `gdb`,
though.

#### lldb

`lldb` is Apple's default command-line debugger on OS X 10.9.5 and up.
It has even less documentation than `gdb`, and the internal
documentation only covers the basics.

I find I rely heavily on the
[LLDB to GDB Command Map](http://lldb.llvm.org/lldb-gdb.html)

#### [Kernel Debug Kits](http://developer.apple.com/download/more/)

These in effect let you load a Mach kernel running on a remote machine
(the target computer) into `lldb` running in a Terminal window on your
local machine (the development computer).  Apple's documentation is
poor, and there are technical restrictions that can make it cumbersome
to use.  But there are times when there's no substitute for doing
this.

It's probably best to start by reading
[Debugging a Kernel Extension with GDB](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptDebugger/debug_tutorial.html).
This is badly out of date, but it's reasonably well written and gives
you a good overview.  Then read the ReadMe file that comes with the
version of the Kernel Debug Kit that you'll be using.  The Kernel
Debug Kit gets installed on the development computer (where you'll be
running `lldb`), and must match the version of OS X or macOS on the
target computer.  The development computer should also be running the
same version of Apple's OS, but this isn't absolutely necessary.

Apple's instructions won't work with a target computer that's a
virtual machine.  But with a slightly modified procedure, remote
kernel debugging works with a VMware Fusion virtual machine.

  * Make sure the target virtual machine isn't running, then add the
    following two lines to the `.vmx` config file in its `.vmwarevm`
    package directory:

        debugStub.listen.guest64 = "TRUE"
        debugStub.listen.guest64.remote = "TRUE"

  * Download [x86_64_target_definition.py](http://llvm.org/svn/llvm-project/lldb/trunk/examples/python/x86_64_target_definition.py)
    to some convenient location on your development computer.

  * On the development computer, run the following two commands:

        lldb /Library/Developer/KDKs/KDK_[version].kdk/System/Library/Kernels/kernel
        settings set plugin.process.gdb-remote.target-definition-file /path/to/x86_64_target_definition.py

  * Then enter one of the following commands instead of `kdp-remote
    {name_or_ip_address}`.  Use the first if your development computer
    is the VMware Fusion host.  Use the second if it's some other
    computer.

        gdb-remote 8864
        gdb-remote [fusionhost]:8864

For more information see the following:

[Using the VMware Fusion GDB stub for kernel debugging with LLDB](http://ddeville.me/2015/08/using-the-vmware-fusion-gdb-stub-for-kernel-debugging-with-lldb)

[VMware](http://wiki.osdev.org/VMware)


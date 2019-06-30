# Building

HookCase requires a compatible version of OS X -- OS X 10.9
(Mavericks) through macOS 10.14 (Mojave).  Building it also requires a
relatively recent version of XCode.  I recommend building on the
version of OS X where you'll be using HookCase, and using the most
recent version of XCode available for that version.  But the version
of XCode you use must contain an SDK matching the version of macOS/OS
X on which you're building.  Check in the
`Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs`
directory of your XCode.app package.

Building `HookCase.kext` should be straightforward.  I ususally just
run `xcodebuild` from the command line.  This drops a release build
into the project's `build/Release/` subdirectory.

Building some hook libraries requires additional tools, like `llvm-as`
and `llc`, which aren't provided with XCode.  But they do come with
third party distros like
[the LLVM 3.9.0 Clang download](http://releases.llvm.org/3.9.0/clang+llvm-3.9.0-x86_64-apple-darwin.tar.xz) or
[the LLVM 4.0.0 Clang download](http://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-apple-darwin.tar.xz).

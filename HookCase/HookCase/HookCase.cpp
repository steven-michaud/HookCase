// The MIT License (MIT)
//
// Copyright (c) 2024 Steven Michaud
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// HookCase.kext is a macOS/OS X kernel extension that reimplements and extends
// Apple's DYLD_INSERT_LIBRARIES functionality (as described here:
// https://books.google.com/books?id=K8vUkpOXhN4C&pg=PA73&lpg=PA73&dq="dyld+interposing"+Singh.)
// It also removes all the restrictions that Apple has placed upon it.  So
// HookCase.kext can be used with an app that has entitlements, is setuid or
// setgid, or has a __restrict section in a __RESTRICT segment.  But to load
// HookCase.kext you need to turn off Apple's System Integrity Protection at
// least partially
// (https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/KernelExtensions/KernelExtensions.html).
// So it's not easy to use for nefarious purposes.
//
// Apple's DYLD_INSERT_LIBRARIES environment variable allows you to hook calls
// made from one module to methods exported from other, dynamically
// loaded modules (by changing pointers in the first module's symbol table).
// HookCase.kext supports this kind of hook, which we call an "interpose hook".
// But it also supports an even more powerful technique, which can be used to
// hook any method in any module (even non-exported ones, and even those that
// don't have an entry in their own module's symbol table).  This we call a
// "patch hook", since it requires that we "patch" the beginning of the
// original method with an assembly language "int 0x30" instruction.  This is
// analogous to what a debugger does when it sets a breakpoint (though it uses
// "int 3" instead of "int 0x30").
//
// Patch hooks can sometimes be substantially less performant than interpose
// hooks, because sometimes we need to "unset" the breakpoint on every call to
// the hook, then "reset" it afterwards (and to protect these operations from
// race conditions).  But this isn't needed for methods that start with a
// standard C/C++ prologue in machine code (which is most of them).  So most
// patch hooks run with only a very small performance penalty (that of a
// single software interrupt), aside from the cost of whatever additional code
// runs inside the hook.  (Interpose hooks run with no performance penalty at
// all.)
//
// As with Apple's DYLD_INSERT_LIBRARIES functionality, to use HookCase.kext
// on a process you need to write a "hook library" (aka "interpose library")
// and set an environment variable (HC_INSERT_LIBRARY) to its full path.
// There is a hook library template under "HookLibraryTemplate", and further
// examples under "Examples".  Since environment variables are (generally)
// passed to child processes, HookCase.kext by default works on a process and
// all its children.  Though this can be turned off (by setting the HC_NOKIDS
// environment variable), it can be quite useful now that many apps use
// multiple processes.  Child processes lauched via XPC don't inherit their
// parent's environment.  But (on OS X 10.11 and up) HookCase.kext knows which
// XPC children have been launched from a given parent process, so it can use
// the values of HC_INSERT_LIBRARY and HC_NOKIDS in the parent to determine
// what (if anything) gets hooked in the XPC children.
//
// Software interrupts are mostly not used on BSD-style operating systems like
// macOS and OS X.  This can be seen from the contents of the xnu kernel's
// osfmk/x86_64/idt_table.h.  The unused interrupts are marked there as
// "INTERRUPT(0xNN)".  (But note that the ranges 0xD0-0xFF, 0x50-0x5F and
// 0x40-0x4F are reserved for APIC interrupts (see the xnu kernel's
// osfmk/i386/lapic.h).  And VMWare uses at least one interrupt in the range
// 0x20-0x2F.)  So we're reasonably safe reserving the range 0x30-0x37 for our
// own use, though we currently only use 0x30-0x35.  And aside from plenty of
// them being available, there are other advantages to using interrupts as
// breakpoints:  They're short (they take up just two bytes of machine code),
// but provide more information than other instructions of equal length (like
// syscall, which doesn't have different "interrupt numbers").  Software
// interrupts work equally well from user mode and kernel mode (again unlike
// syscall).  Interrupts also (like syscall) have very good support for making
// the transition between different privilege levels (for example between user
// mode and kernel mode).

// HookCase.kext is compatible with DYLD_INSERT_LIBRARIES, and doesn't stomp on
// any of the changes it may have been used to make.  So a
// DYLD_INSERT_LIBRARIES hook will always override the "same" HookCase.kext
// interpose hook.  This is because Apple often uses DYLD_INSERT_LIBRARIES
// internally, in ways it doesn't document.  HookCase.kext would likely break
// Apple functionality if it could override Apple's hooks.  But this doesn't
// apply to patch hooks, which are an entirely different kind of beast.  If an
// interpose hook doesn't seem to work, try a patch hook instead.

// HookCase.kext is compatible with lldb and gdb:  Any process with
// HookCase.kext's interpose or patch hooks can run inside these debuggers.
// But you may encounter trouble if you set a breakpoint and a patch hook on
// the same method, or try to step through code that contains a patch hook.

// Apple only supports a subset of C/C++ for kernel extensions.  Apple
// documents some of the features which are disallowed[1], but not all of
// them.  Apple's list of disallowed features includes exceptions, multiple
// inheritance, templates and RTTI.  But complex initialization of local
// variables is also disallowed -- for example structure initialization and
// variable initialization in a "for" statement (e.g. "for (int i = 1; ; )").
// You won't always get a compiler warning if you use one of these disallowed
// features.  And you may not always see problems using the resulting binary.
// But in at least some cases you will see mysterious kernel panics.
//
// [1]https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Features/Features.html#//apple_ref/doc/uid/TP0000012-TPXREF105

#include <libkern/libkern.h>

#include <AvailabilityMacros.h>

#include <sys/types.h>
#include <sys/kernel_types.h>
#include <mach/mach_types.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/spawn.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <kern/host.h>
#include <mach-o/loader.h>
// This definition is missing from loader.h on some macOS versions
#define S_INIT_FUNC_OFFSETS 0x16
#include <mach-o/nlist.h>
#include <libkern/OSAtomic.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>

#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSSerialize.h>
#include <IOKit/IOLib.h>

#define MH_FILESET 0xc /* set of mach-o's */

#include "HookCase.h"

#define toupper(c) ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))

#ifndef MAX_CPUS
#define MAX_CPUS 64
#endif

extern "C" int atoi(const char *str);

typedef struct pmap *pmap_t;
extern pmap_t kernel_pmap;
extern vm_map_t kernel_map;

extern "C" void vm_kernel_unslide_or_perm_external(vm_offset_t addr,
                                                   vm_offset_t *up_addr);

extern "C" ppnum_t pmap_find_phys(pmap_t map, addr64_t va);

extern "C" lck_rw_type_t lck_rw_done(lck_rw_t *lck);

extern "C" void *get_bsdtask_info(task_t);

/*------------------------------*/

// "kern.osrelease" is what's returned by 'uname -r', which uses a different
// numbering system than the "standard" one.  These defines translate from
// that (kernel) system to the "standard" one.

#define MAC_OS_X_VERSION_10_9_HEX  0x00000D00
#define MAC_OS_X_VERSION_10_10_HEX 0x00000E00
#define MAC_OS_X_VERSION_10_11_HEX 0x00000F00
#define MAC_OS_X_VERSION_10_12_HEX 0x00001000
#define MAC_OS_X_VERSION_10_13_HEX 0x00001100
#define MAC_OS_X_VERSION_10_14_HEX 0x00001200
#define MAC_OS_X_VERSION_10_15_HEX 0x00001300
#define MAC_OS_X_VERSION_11_HEX    0x00001400
#define MAC_OS_X_VERSION_12_HEX    0x00001500
#define MAC_OS_X_VERSION_13_HEX    0x00001600
#define MAC_OS_X_VERSION_14_HEX    0x00001700
#define MAC_OS_X_VERSION_15_HEX    0x00001800

char *gOSVersionString = NULL;
size_t gOSVersionStringLength = 0;

int32_t OSX_Version()
{
  static int32_t version = -1;
  if (version != -1) {
    return version;
  }

  version = 0;
  sysctlbyname("kern.osrelease", NULL, &gOSVersionStringLength, NULL, 0);
  gOSVersionString = (char *) IOMalloc(gOSVersionStringLength);
  char *version_string = (char *) IOMalloc(gOSVersionStringLength);
  if (!gOSVersionString || !version_string) {
    return version;
  }
  if (sysctlbyname("kern.osrelease", gOSVersionString,
                   &gOSVersionStringLength, NULL, 0) < 0)
  {
    IOFree(version_string, gOSVersionStringLength);
    return version;
  }
  strncpy(version_string, gOSVersionString, gOSVersionStringLength);

  char *version_string_iterator = version_string;
  const char *part; int i;
  for (i = 0; i < 3; ++i) {
    part = strsep(&version_string_iterator, ".");
    if (!part) {
      break;
    }
    version += (atoi(part) << ((2 - i) * 4));
  }

  IOFree(version_string, gOSVersionStringLength);
  return version;
}

// Build ids for macOS all start with a three-character alphanumeric value
// which corresponds to the version number (major and minor together) -- for
// example "13A" for "10.9", "13B" for "10.9.1" and "22G" for "13.5.X" and
// "13.6.X". Following this is the build number, which restarts from zero for
// each new three-character value.
unsigned long build_id_to_ulong(const char *build_id)
{
  if (!build_id) {
    return -1UL;
  }

  size_t i;
  static const char *alpha_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const char *number_chars = "0123456789";

  size_t total_length = strlen(build_id);
  char *holder = (char *) IOMalloc(total_length + 1);
  if (!holder) {
    return -1UL;
  }
  strncpy(holder, build_id, total_length + 1);
  char *remaining = holder;

  unsigned long retval = 0UL;

  char *major_version_str = strsep(&remaining, alpha_chars);
  size_t major_version_length = strlen(major_version_str);
  if (!remaining || (major_version_length == 0)) {
    retval = -1UL;
  } else {
    for (i = 0; i < major_version_length; ++i) {
      if ((major_version_str[i] < '0') || (major_version_str[i] > '9')) {
        retval = -1UL;
        break;
      }
    }
    if (retval != -1UL) {
      unsigned long major_version = strtoul(major_version_str, NULL, 10);
      if (major_version > UINT_MAX) {
        retval = -1UL;
      } else {
        retval |= (major_version << 32);
      }
    }
  }

  size_t minor_version_length = 0;
  if (remaining && (retval != -1UL)) {
    --remaining;
    remaining[0] = build_id[major_version_length];
    char *minor_version_str = strsep(&remaining, number_chars);
    minor_version_length = strlen(minor_version_str);
    if (!remaining || (minor_version_length == 0)) {
      retval = -1UL;
    } else {
      for (i = 0; i < minor_version_length; ++i) {
        if ((minor_version_str[i] < 'A') || (minor_version_str[i] > 'Z')) {
          retval = -1UL;
          break;
        }
      }
      if (retval != -1UL) {
        unsigned long minor_version = strtoul(minor_version_str, NULL, 36);
        if (minor_version > UINT_MAX) {
          retval = -1UL;
        } else {
          retval |= (minor_version << 16);
        }
      }
    }
  }

  if (remaining && (retval != -1UL)) {
    --remaining;
    remaining[0] = build_id[major_version_length + minor_version_length];
    char *build_num_str = remaining;
    size_t build_num_length = strlen(build_num_str);
    if (build_num_length == 0) {
      retval = -1UL;
    } else {
      for (i = 0; i < build_num_length; ++i) {
        if ((build_num_str[i] < '0') || (build_num_str[i] > '9')) {
          retval = -1UL;
          break;
        }
      }
      if (retval != -1UL) {
        unsigned long build_num = strtoul(build_num_str, NULL, 10);
        if (build_num > UINT_MAX) {
          retval = -1UL;
        } else {
          retval |= build_num;
        }
      }
    }
  }

  IOFree(holder, total_length + 1);

  return retval;
}

unsigned long macOS_build_id()
{
  static unsigned long retval = -1UL;
  if (retval == -1UL) {
    size_t build_id_string_length;
    sysctlbyname("kern.osversion", NULL, &build_id_string_length, NULL, 0);
    char *build_id_string = (char *) IOMalloc(build_id_string_length);
    if (!build_id_string) {
      return -1UL;
    }
    if (sysctlbyname("kern.osversion", build_id_string,
                     &build_id_string_length, NULL, 0) == 0)
    {
      retval = build_id_to_ulong(build_id_string);
    }
    IOFree(build_id_string, build_id_string_length);
  }
  return retval;
}

bool OSX_Mavericks()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_9_HEX);
}

bool OSX_Yosemite()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_10_HEX);
}

bool OSX_ElCapitan()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_11_HEX);
}

bool macOS_Sierra()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_12_HEX);
}

bool macOS_HighSierra()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_13_HEX);
}

bool macOS_HighSierra_less_than_4()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_13_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 10.13.4 is actually "17.5.0"
  return ((OSX_Version() & 0xFF) < 0x50);
}

// Build 17G7020 is a post-10.13.6 security fix.
bool macOS_HighSierra_less_than_17G7020()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_13_HEX)) {
    return false;
  }

  // The output of "uname -r" for macOS 10.13.6 is actually "17.7.0"
  if ((OSX_Version() & 0xFF) < 0x70) {
    return false;
  }

  static long build_num = -1;
  if (build_num == -1) {
    size_t build_id_string_length;
    sysctlbyname("kern.osversion", NULL, &build_id_string_length, NULL, 0);
    char *build_id_string = (char *) IOMalloc(build_id_string_length);
    if (!build_id_string) {
      return false;
    }
    // Build ids for macOS 10.13.6 all start with "17G".  Remove that and
    // use the rest as a build number.
    if (sysctlbyname("kern.osversion", build_id_string,
                     &build_id_string_length, NULL, 0) == 0)
    {
      const char *build_num_string = build_id_string + 3;
      build_num = strtol(build_num_string, NULL, 10);
    }
    IOFree(build_id_string, build_id_string_length);
    if (build_num == -1) {
      return false;
    }
  }

  return (build_num < 7020);
}

bool macOS_Mojave()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_14_HEX);
}

bool macOS_Mojave_less_than_2()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_14_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) < 0x20);
}

bool macOS_Mojave_less_than_5()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_14_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 10.14.5 is actually "18.6.0"
  return ((OSX_Version() & 0xFF) < 0x60);
}

bool macOS_Catalina()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_15_HEX);
}

bool macOS_Catalina_less_than_5()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_15_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) < 0x50);
}

bool macOS_Catalina_5_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_15_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) >= 0x50);
}

bool macOS_BigSur()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_11_HEX);
}

bool macOS_BigSur_less_than_3()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_11_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 11.3 is actually "20.4.0", and
  // for 11.2.3 is "20.3.0".
  return ((OSX_Version() & 0xFF) < 0x40);
}

bool macOS_BigSur_4_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_11_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 11.4 is actually "20.5.0", and
  // for 11.3 is "20.4.0".
  return ((OSX_Version() & 0xFF) >= 0x50);
}

bool macOS_Monterey()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX);
}

bool macOS_Monterey_less_than_1()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.1 is actually "21.2.0".
  return ((OSX_Version() & 0xFF) < 0x20);
}

bool macOS_Monterey_1_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.1 is actually "21.2.0".
  return ((OSX_Version() & 0xFF) >= 0x20);
}

bool macOS_Monterey_less_than_3()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.3 is actually "21.4.0".
  return ((OSX_Version() & 0xFF) < 0x40);
}

bool macOS_Monterey_3_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.3 is actually "21.4.0".
  return ((OSX_Version() & 0xFF) >= 0x40);
}

bool macOS_Monterey_less_than_4()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.4 is actually "21.5.0".
  return ((OSX_Version() & 0xFF) < 0x50);
}

bool macOS_Monterey_4_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.4 is actually "21.5.0".
  return ((OSX_Version() & 0xFF) >= 0x50);
}

bool macOS_Monterey_less_than_5()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.5 is actually "21.6.0".
  return ((OSX_Version() & 0xFF) < 0x60);
}

bool macOS_Monterey_5_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 12.5 is actually "21.6.0".
  return ((OSX_Version() & 0xFF) >= 0x60);
}

// The build number for macOS 12.7.1 is 21G920.
bool macOS_Monterey_less_than_7_1()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }

  // The output of "uname -r" for macOS 12.7.X is "21.6.0"
  if ((OSX_Version() & 0xFF) > 0x60) {
    return false;
  }

  unsigned long build_id = macOS_build_id();
  return ((build_id != -1UL) &&
          (build_id < build_id_to_ulong("21G920")));
}

// The build number for macOS 12.7.1 is 21G920.
bool macOS_Monterey_7_1_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_12_HEX)) {
    return false;
  }

  // The output of "uname -r" for macOS 12.7.X is "21.6.0"
  if ((OSX_Version() & 0xFF) < 0x60) {
    return false;
  }

  unsigned long build_id = macOS_build_id();
  return ((build_id != -1UL) &&
          (build_id >= build_id_to_ulong("21G920")));
}

bool macOS_Ventura()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_13_HEX);
}

bool macOS_Ventura_less_than_3()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_13_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 13.3 is actually "22.4.0".
  return ((OSX_Version() & 0xFF) < 0x40);
}

bool macOS_Ventura_3_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_13_HEX)) {
    return false;
  }
  // The output of "uname -r" for macOS 13.3 is actually "22.4.0".
  return ((OSX_Version() & 0xFF) >= 0x40);
}

// The build number for macOS 13.6.1 is 22G313.
bool macOS_Ventura_less_than_6_1()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_13_HEX)) {
    return false;
  }

  // The output of "uname -r" for macOS 13.6.X is "22.6.0"
  if ((OSX_Version() & 0xFF) > 0x60) {
    return false;
  }

  unsigned long build_id = macOS_build_id();
  return ((build_id != -1UL) &&
          (build_id < build_id_to_ulong("22G313")));
}

// The build number for macOS 13.6.1 is 22G313.
bool macOS_Ventura_6_1_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_13_HEX)) {
    return false;
  }

  // The output of "uname -r" for macOS 13.6.X is "22.6.0"
  if ((OSX_Version() & 0xFF) < 0x60) {
    return false;
  }

  unsigned long build_id = macOS_build_id();
  return ((build_id != -1UL) &&
          (build_id >= build_id_to_ulong("22G313")));
}

bool macOS_Sonoma()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_14_HEX);
}

bool macOS_Sonoma_less_than_1()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_14_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) < 0x10);
}

bool macOS_Sonoma_1_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_14_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) >= 0x10);
}

bool macOS_Sonoma_less_than_4()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_14_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) < 0x40);
}

bool macOS_Sonoma_4_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_14_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) >= 0x40);
}

bool macOS_Sequoia()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_15_HEX);
}

bool macOS_Sequoia_less_than_4()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_15_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) < 0x40);
}

bool macOS_Sequoia_4_or_greater()
{
  if (!((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_15_HEX)) {
    return false;
  }
  return ((OSX_Version() & 0xFF) >= 0x40);
}

bool OSX_Version_Unsupported()
{
  return (((OSX_Version() & 0xFF00) < MAC_OS_X_VERSION_10_9_HEX) ||
          ((OSX_Version() & 0xFF00) > MAC_OS_X_VERSION_15_HEX));
}

typedef struct kthread_key {
  void *values[MAX_CPUS];
} kthread_key_t;

void kthread_key_init(kthread_key_t *key)
{
  bzero(key, sizeof(kthread_key_t));
}

void *kthread_getspecific(kthread_key_t *key)
{
  return key->values[get_cpu_number()];
}

void kthread_setspecific(kthread_key_t *key, void *value)
{
  key->values[get_cpu_number()] = value;
}

// When using the debug kernel, set "kernel_stack_pages=6" in the boot args
// (1.5 times its default value).  Otherwise we can run out of stack space, at
// least on ElCapitan.  A sign of this is a double-fault with CR2 set to an
// address on the stack.

// It is *not* safe to use the value of the kcsuffix boot-arg to determine
// what kind of kernel is running.  There are other ways of choosing which
// kernel to run, and sometimes the value of kcsuffix is ignored.

char *g_kernel_version = NULL;

typedef char *(*strnstr_t)(char *s, const char *find, size_t slen);
static strnstr_t strnstr_ptr = NULL;

typedef enum {
  kernel_type_unknown =      0,
  kernel_type_release =      1,
  kernel_type_development =  2,
  kernel_type_debug =        3,
  kernel_type_unset =       -1,
} kernel_type;

void *kernel_dlsym(const char *symbol);

kernel_type get_kernel_type()
{
  static kernel_type type = kernel_type_unset;
  if (type != kernel_type_unset) {
    return type;
  }

  if (!g_kernel_version) {
    g_kernel_version = (char *)
      kernel_dlsym("_version");
    if (!g_kernel_version) {
      return kernel_type_unknown;
    }
  }
  if (!strnstr_ptr) {
    strnstr_ptr = (strnstr_t)
      kernel_dlsym("_strnstr");
    if (!strnstr_ptr) {
      return kernel_type_unknown;
    }
  }

  if (strnstr_ptr(g_kernel_version, "RELEASE", strlen(g_kernel_version))) {
    type = kernel_type_release;
  } else if (strnstr_ptr(g_kernel_version, "DEVELOPMENT", strlen(g_kernel_version))) {
    type = kernel_type_development;
  } else if (strnstr_ptr(g_kernel_version, "DEBUG", strlen(g_kernel_version))) {
    type = kernel_type_debug;
  } else {
    type = kernel_type_unknown;
  }

  // The DEBUG kernel is currently very flaky on macOS 10.14, to the extent
  // that we need to disable support for it.  There are lots of panics, with
  // and without HookCase.  In fact all that's needed to trigger a panic is to
  // start Safari, visit apple.com, then quit it.  These panics all have the
  // error "Assertion failed: object->vo_purgeable_volatilizer == NULL".
  //
  // The macOS 10.14 DEBUG kernel is still a bit flaky (as of 10.14.5), but
  // it's not nearly so bad as before.
#if (0)
  if (macOS_Mojave()) {
    if (type == kernel_type_debug) {
      type = kernel_type_unknown;
    }
  }
#endif

  return type;
}

bool kernel_type_is_release()
{
  return (get_kernel_type() == kernel_type_release);
}

bool kernel_type_is_development()
{
  return (get_kernel_type() == kernel_type_development);
}

bool kernel_type_is_debug()
{
  return (get_kernel_type() == kernel_type_debug);
}

bool kernel_type_is_unknown()
{
  return (get_kernel_type() == kernel_type_unknown);
}

#define VM_MIN_KERNEL_ADDRESS ((vm_offset_t) 0xFFFFFF8000000000UL)
#define VM_MIN_KERNEL_AND_KEXT_ADDRESS (VM_MIN_KERNEL_ADDRESS - 0x80000000ULL)
#define VM_MAX_USER_PAGE_ADDRESS ((user_addr_t)0x00007FFFFFFFF000ULL)

// The system kernel (stored in /System/Library/Kernels on OS X 10.10 and up)
// is (in some senses) an ordinary Mach-O binary.  You can use 'otool -hv' to
// show its Mach header, and 'otool -lv' to display its "load commands" (all
// of its segments and sections).  From the output of 'otool -lv' it's
// apparent that the kernel (starting with its Mach header) is meant to be
// loaded at 0xFFFFFF8000200000.  But recent versions of OS X implement ASLR
// (Address Space Layout Randomization) for the kernel -- they "slide" all
// kernel addresses by a random value (determined at startup).  So in order
// to find the address of the kernel (and of its Mach header), we also need to
// know the value of this "kernel slide".

#define KERNEL_HEADER_ADDR 0xFFFFFF8000200000

vm_offset_t g_kernel_slide = 0;
struct mach_header_64 *g_kernel_header = NULL;

// Find the address of the kernel's Mach header.
bool find_kernel_header()
{
  if (g_kernel_header) {
    return true;
  }

#if (defined(MAC_OS_X_VERSION_10_11)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  // vm_kernel_unslide_or_perm_external() is only available on OS X 10.11 and up.
  if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() ||
      macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    vm_offset_t func_address = (vm_offset_t) vm_kernel_unslide_or_perm_external;
    vm_offset_t func_address_unslid = 0;
    vm_kernel_unslide_or_perm_external(func_address, &func_address_unslid);
    vm_offset_t slide = func_address - func_address_unslid;
    // On macOS Big Sur and up, 'slide' is set to the the "kernel cache
    // slide" -- an offset to the location of the "kernel cache", which
    // contains the kernel and a bunch of kernel extensions. The kernel
    // itself is inside this "cache". Find it to determine the "kernel slide".
    if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
        macOS_Monterey() || macOS_BigSur())
    {
      bool kernel_header_found = false;
      vm_offset_t slide_increment;
      // The 0x100000 limit and 0x1000 increment were determined by trial
      // and error.
      for (slide_increment = 0; slide_increment < 0x100000;
           slide_increment += 0x1000)
      {
        addr64_t addr = KERNEL_HEADER_ADDR + slide + slide_increment;
        // pmap_find_phys() returns 0 if 'addr' isn't a valid address.
        if (!pmap_find_phys(kernel_pmap, addr)) {
          continue;
        }
        struct mach_header_64 *header = (struct mach_header_64 *) addr;
        if ((header->magic != MH_MAGIC_64) ||
            (header->cputype != CPU_TYPE_X86_64) ||
            (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
            (header->filetype != MH_EXECUTE) ||
            !(header->flags & (MH_NOUNDEFS | MH_PIE)))
        {
          continue;
        }
        g_kernel_slide = slide + slide_increment;
        kernel_header_found = true;
        break;
      }
      if (!kernel_header_found) {
        return false;
      }
    } else {
      g_kernel_slide = slide;
    }
  } else {
#endif
    bool kernel_header_found = false;
    vm_offset_t slide;
    // The 0x10000 increment was determined by trial and error.
    for (slide = 0; slide < 0x100000000; slide += 0x10000) {
      addr64_t addr = KERNEL_HEADER_ADDR + slide;
      // pmap_find_phys() returns 0 if 'addr' isn't a valid address.
      if (!pmap_find_phys(kernel_pmap, addr)) {
        continue;
      }
      struct mach_header_64 *header = (struct mach_header_64 *) addr;
      if ((header->magic != MH_MAGIC_64) ||
          (header->cputype != CPU_TYPE_X86_64) ||
          (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
          (header->filetype != MH_EXECUTE) ||
          !(header->flags & (MH_NOUNDEFS | MH_PIE)))
      {
        continue;
      }
      g_kernel_slide = slide;
      kernel_header_found = true;
      break;
    }
    if (!kernel_header_found) {
      return false;
    }
#if (defined(MAC_OS_X_VERSION_10_11)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  }
#endif

  g_kernel_header = (struct mach_header_64 *)
    (KERNEL_HEADER_ADDR + g_kernel_slide);

  return true;
}

// Fill the whole structure with 0xFF to indicate that it hasn't yet been
// initialized.
typedef struct _symbol_table_info {
  vm_offset_t symbolTableOffset;
  vm_offset_t stringTableOffset;
  uint32_t symbols_index;
  uint32_t symbols_count;
} symbol_table_info_t;

void *kernel_module_dlsym(struct mach_header_64 *header, const char *symbol,
                          symbol_table_info_t *info)
{
  if (!header || !symbol) {
    return NULL;
  }

  // Sanity check
  if (!pmap_find_phys(kernel_pmap, (addr64_t) header)) {
    return NULL;
  }
  if ((header->magic != MH_MAGIC_64) ||
      (header->cputype != CPU_TYPE_X86_64) ||
      (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
      ((header->filetype != MH_EXECUTE) &&
       (header->filetype != MH_KEXT_BUNDLE)) ||
      ((header->flags & MH_NOUNDEFS) == 0))
  {
    return NULL;
  }

  vm_offset_t symbolTableOffset = 0;
  vm_offset_t stringTableOffset = 0;
  uint32_t symbols_index = 0;
  uint32_t symbols_count = 0;
  uint32_t all_symbols_count = 0;

  // Find the symbol table, if need be
  if (info && info->symbolTableOffset != -1L) {
    symbolTableOffset = info->symbolTableOffset;
    stringTableOffset = info->stringTableOffset;
    symbols_index = info->symbols_index;
    symbols_count = info->symbols_count;
  } else {
    vm_offset_t linkedit_fileoff_increment = 0;
    bool found_symbol_table = false;
    bool found_linkedit_segment = false;
    bool found_symtab_segment = false;
    bool found_dysymtab_segment = false;
    uint32_t num_commands = header->ncmds;
    const struct load_command *load_command = (struct load_command *)
      ((vm_offset_t)header + sizeof(struct mach_header_64));
    uint32_t i;
    for (i = 1; i <= num_commands; ++i) {
      uint32_t cmd = load_command->cmd;
      switch (cmd) {
        case LC_SEGMENT_64: {
          if (found_linkedit_segment) {
            return NULL;
          }
          struct segment_command_64 *command =
            (struct segment_command_64 *) load_command;
          const char *linkedit_segname = "__LINKEDIT";
          if (!strncmp(command->segname, linkedit_segname,
                       strlen(linkedit_segname) + 1))
          {
            linkedit_fileoff_increment = command->vmaddr - command->fileoff;
            found_linkedit_segment = true;
          }
          break;
        }
        case LC_SYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct symtab_command *command =
            (struct symtab_command *) load_command;
          symbolTableOffset = command->symoff + linkedit_fileoff_increment;
          stringTableOffset = command->stroff + linkedit_fileoff_increment;
          all_symbols_count = command->nsyms;
          found_symtab_segment = true;
          // It seems that either LC_SYMTAB's nsyms will be set or LC_DSYMTAB's
          // iextdefsym and nextdefsym, but not both. Loaded kexts use nsyms,
          // but the kernel itself uses iextdefsym and nextdefsym. If nsyms is
          // set, LC_DYSYMTAB is no longer needed. And as of the macOS 10.15.5
          // supplemental update it's absent altogether in kexts.
          if (all_symbols_count) {
            symbols_index = 0;
            symbols_count = all_symbols_count;
            found_dysymtab_segment = true;
          }
          break;
        }
        case LC_DYSYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          if (!all_symbols_count) {
            struct dysymtab_command *command =
              (struct dysymtab_command *) load_command;
            symbols_index = command->iextdefsym;
            symbols_count = symbols_index + command->nextdefsym;
          }
          found_dysymtab_segment = true;
          break;
        }
        default: {
          if (found_linkedit_segment) {
            return NULL;
          }
          break;
        }
      }
      if (found_linkedit_segment && found_symtab_segment && found_dysymtab_segment) {
        found_symbol_table = true;
        break;
      }
      load_command = (struct load_command *)
        ((vm_offset_t)load_command + load_command->cmdsize);
    }
    if (!found_symbol_table) {
      return NULL;
    }
    if (info) {
      info->symbolTableOffset = symbolTableOffset;
      info->stringTableOffset = stringTableOffset;
      info->symbols_index = symbols_index;
      info->symbols_count = symbols_count;
    }
  }

  // If we're in a kernel extension, the symbol and string tables won't be
  // accessible unless the "keepsyms=1" kernel boot arg has been specified.
  // Use this check to fail gracefully in this situation.
  if (!pmap_find_phys(kernel_pmap, (addr64_t) symbolTableOffset) ||
      !pmap_find_phys(kernel_pmap, (addr64_t) stringTableOffset))
  {
    return NULL;
  }
  // Search the symbol table
  uint32_t i;
  for (i = symbols_index; i < symbols_count; ++i) {
    struct nlist_64 *symbolTableItem = (struct nlist_64 *)
      (symbolTableOffset + i * sizeof(struct nlist_64));

    uint8_t type = symbolTableItem->n_type;
    if ((type & N_STAB) || ((type & N_TYPE) != N_SECT)) {
      continue;
    }
    uint8_t sect = symbolTableItem->n_sect;
    if (!sect) {
      continue;
    }
    const char *stringTableItem = (char *)
      (stringTableOffset + symbolTableItem->n_un.n_strx);
    if (stringTableItem &&
        !strncmp(stringTableItem, symbol, strlen(symbol) + 1))
    {
      return (void *) symbolTableItem->n_value;
    }
  }

  return NULL;
}

// The running kernel contains a valid symbol table.  We can use this to find
// the address of any "external" kernel symbol, including those considered
// "private".  'symbol' should be exactly what's listed in the symbol table,
// including the "extra" leading underscore.
void *kernel_dlsym(const char *symbol)
{
  if (!find_kernel_header()) {
    return NULL;
  }

  static symbol_table_info_t kernel_symbol_info;
  static bool found_symbol_table = false;
  if (!found_symbol_table) {
    memset((void *) &kernel_symbol_info, 0xFF, sizeof(kernel_symbol_info));
  }

  void *retval =
    kernel_module_dlsym(g_kernel_header, symbol, &kernel_symbol_info);

  if (kernel_symbol_info.symbolTableOffset != -1L) {
    found_symbol_table = true;
  }

  return retval;
}

typedef OSDictionary *(*OSKext_copyLoadedKextInfo_t)(OSArray *kextIdentifiers,
                                              OSArray *infoKeys);
static OSKext_copyLoadedKextInfo_t OSKext_copyLoadedKextInfo = NULL;

#define kOSBundleLoadAddressKey "OSBundleLoadAddress"

// Loaded kernel extensions also contain valid symbol tables.  But unless the
// "keepsyms=1" kernel boot arg has been specified, they have been made
// inaccessible in OSKext::jettisonLinkeditSegment().
void *kext_dlsym(const char *bundle_id, const char *symbol)
{
  if (!OSKext_copyLoadedKextInfo) {
    OSKext_copyLoadedKextInfo = (OSKext_copyLoadedKextInfo_t)
      kernel_dlsym("__ZN6OSKext18copyLoadedKextInfoEP7OSArrayS1_");
    if (!OSKext_copyLoadedKextInfo) {
      return NULL;
    }
  }

  if (!bundle_id || !symbol) {
    return NULL;
  }

  const OSString *id_string = OSString::withCString(bundle_id);
  if (!id_string) {
    return NULL;
  }
  OSArray *id_array =
    OSArray::withObjects((const OSObject **) &id_string, 1, 0);
  if (!id_array) {
    id_string->release();
    return NULL;
  }
  OSDictionary *kext_info =
    OSDynamicCast(OSDictionary, OSKext_copyLoadedKextInfo(id_array, 0));
  if (!kext_info) {
    id_string->release();
    id_array->release();
    return NULL;
  }
  OSNumber *load_address =
    OSDynamicCast(OSNumber, kext_info->getObject(kOSBundleLoadAddressKey));
  if (!load_address) {
    OSDictionary *more_kext_info =
      OSDynamicCast(OSDictionary, kext_info->getObject(bundle_id));
    kext_info = more_kext_info;
    if (kext_info) {
      load_address =
        OSDynamicCast(OSNumber, kext_info->getObject(kOSBundleLoadAddressKey));
    }
  }
  if (!load_address) {
    id_string->release();
    id_array->release();
    return NULL;
  }

  struct mach_header_64 *kext_header = (struct mach_header_64 *)
    (load_address->unsigned64BitValue() + g_kernel_slide);

  void *retval = kernel_module_dlsym(kext_header, symbol, NULL);

  id_string->release();
  id_array->release();

  return retval;
}

// The system call table (aka the sysent table) is used by the kernel to
// process system calls from userspace.  Apple tries to hide it, but not
// very effectively.  We need to hook several entries in the table.

typedef int32_t sy_call_t(struct proc *, void *, int *);
typedef void sy_munge_t(void *); // For OS X 10.10 and above
typedef void sy_munge_t_mavericks(const void *, void *); // For OS X 10.9

struct sysent {          // system call table, OS X 10.10 and above
  sy_call_t *sy_call;    // implementing function
  sy_munge_t *sy_arg_munge32; // system call arguments munger for 32-bit process
  int32_t  sy_return_type; // system call return types
  int16_t  sy_narg;      // number of args
  uint16_t sy_arg_bytes; // Total size of args in bytes for 32-bit system calls
};

struct sysent_mavericks {// system call table, OS X 10.9
  sy_call_t *sy_call;    // implementing function
  sy_munge_t_mavericks *sy_arg_munge32; // arguments munger for 32-bit process
  sy_munge_t_mavericks *sy_arg_munge64; // arguments munger for 64-bit process
  int32_t  sy_return_type; // system call return types
  int16_t  sy_narg;      // number of args
  uint16_t sy_arg_bytes; // Total size of args in bytes for 32-bit system calls
};

void *g_sysent_table = NULL;

bool find_sysent_table()
{
  if (g_sysent_table) {
    return true;
  }
  if (!find_kernel_header()) {
    return false;
  }

  // The first three entries of the sysent table point to these functions.
  sy_call_t *nosys = (sy_call_t *) kernel_dlsym("_nosys");
  sy_call_t *exit = (sy_call_t *) kernel_dlsym("_exit");
  sy_call_t *fork = (sy_call_t *) kernel_dlsym("_fork");
  if (!nosys || !exit || !fork) {
    return false;
  }

  uint32_t num_data_sections = 0;
  struct section_64 *data_sections = NULL;
  const char *data_segment_name;
  const char *const_section_name;
  if (macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    data_segment_name = "__DATA_CONST";
    const_section_name = "__const";
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    data_segment_name = "__CONST";
    const_section_name = "__constdata";
  } else {
    data_segment_name = "__DATA";
    const_section_name = "__const";
  }

  // The definition of the sysent table is "const struct sysent sysent[]",
  // so we look for it in the __DATA segment's __const section (on ElCapitan
  // and below), or in the __CONST segment's __constdata section (on Sierra
  // through Mojave), or in the __DATA_CONST segment's __const section (on
  // Catalina and above). Note that this section's contents have been set
  // read-only, which we need to work around below in hook_sysent_call().
  uint32_t num_commands = g_kernel_header->ncmds;
  const struct load_command *load_command = (struct load_command *)
    ((vm_offset_t)g_kernel_header + sizeof(struct mach_header_64));
  bool found_data_segment = false;
  uint32_t i;
  for (i = 1; i <= num_commands; ++i) {
    uint32_t cmd = load_command->cmd;
    switch (cmd) {
      case LC_SEGMENT_64: {
        struct segment_command_64 *command =
          (struct segment_command_64 *) load_command;
        if (!strncmp(command->segname, data_segment_name,
                     strlen(data_segment_name) + 1))
        {
          num_data_sections = command->nsects;
          data_sections = (struct section_64 *)
            ((vm_offset_t)command + sizeof(struct segment_command_64));
          found_data_segment = true;
        }
        break;
      }
      default: {
        break;
      }
    }
    if (found_data_segment) {
      break;
    }
    load_command = (struct load_command *)
      ((vm_offset_t)load_command + load_command->cmdsize);
  }
  if (!found_data_segment) {
    return false;
  }

  vm_offset_t const_section = 0;
  vm_offset_t const_section_size = 0;

  bool found_const_section = false;
  for (i = 0; i < num_data_sections; ++i) {
    if (!strncmp(data_sections[i].sectname, const_section_name,
                 strlen(const_section_name) + 1))
    {
      const_section = data_sections[i].addr;
      const_section_size = data_sections[i].size;
      found_const_section = true;
      break;
    }
  }
  if (!found_const_section) {
    return false;
  }

  bool found_sysent_table = false;
  vm_offset_t offset;
  for (offset = 0; offset < const_section_size; offset += 16) {
    struct sysent *table = (struct sysent *) (const_section + offset);
    if (table->sy_call != nosys) {
      continue;
    }
    vm_offset_t next_entry_offset = sizeof(sysent);
    if (OSX_Mavericks()) {
      next_entry_offset = sizeof(sysent_mavericks);
    }
    struct sysent *next_entry = (struct sysent *)
      ((vm_offset_t)table + next_entry_offset);
    if (next_entry->sy_call != exit) {
      continue;
    }
    next_entry = (struct sysent *)
      ((vm_offset_t)next_entry + next_entry_offset);
    if (next_entry->sy_call != fork) {
      continue;
    }
    g_sysent_table = table;
    found_sysent_table = true;
    break;
  }

  return found_sysent_table;
}

typedef void (*disable_preemption_t)(void);
typedef void (*enable_preemption_t)(void);
static disable_preemption_t disable_preemption = NULL;
static enable_preemption_t enable_preemption = NULL;

bool hook_sysent_call(uint32_t offset, sy_call_t *hook, sy_call_t **orig)
{
  if (orig) {
    *orig = NULL;
  }
  if (!find_sysent_table() || !hook) {
    return false;
  }

  static int *pnsysent = NULL;
  if (!pnsysent) {
    pnsysent = (int *) kernel_dlsym("_nsysent");
    if (!pnsysent) {
      return false;
    }
  }
  if (offset >= *pnsysent) {
    return false;
  }

  sy_call_t *orig_local = NULL;
  void *orig_addr = NULL;
  if (OSX_Mavericks()) {
    struct sysent_mavericks *table = (struct sysent_mavericks *) g_sysent_table;
    orig_local = table[offset].sy_call;
    orig_addr = &(table[offset].sy_call);
  } else {
    struct sysent *table = (struct sysent *) g_sysent_table;
    orig_local = table[offset].sy_call;
    orig_addr = &(table[offset].sy_call);
  }

  boolean_t org_int_level = ml_set_interrupts_enabled(false);
  disable_preemption();
  uintptr_t org_cr0 = get_cr0();
  set_cr0(org_cr0 & ~CR0_WP);

  bool retval = true;

  if (!OSCompareAndSwapPtr((void *) orig_local, (void *) hook,
                           (void **) orig_addr))
  {
    retval = false;
  }

  set_cr0(org_cr0);
  enable_preemption();
  ml_set_interrupts_enabled(org_int_level);

  if (orig && retval) {
    *orig = orig_local;
  }

  return retval;
}

// HookCase.kext's behavior is determined using environment variables.  If a
// process has one of these variables set, HookCase.kext behaves accordingly
// in that process.

// HC_INSERT_LIBRARY -- Full path to hook library
//
// If this is set, HookCase.kext tries to load the hook library into the
// process, and to set whatever hooks are specified in the __hook section of
// its __DATA segment.

// HC_ADDKIDS -- Colon-separated list of full paths to additional children
//
// These processes, if they start (or restart) while the main process is
// running, are added to the list of that process's children. HookCase.kext
// tries to load the parent process's hook library into each of them.
// Overrides HC_NOKIDS for all the processes explicitly listed in HC_ADDKIDS,
// but not for any of their children. If HC_NOKIDS isn't set, also effects the
// children (including XPC children) of the processes in HC_ADDKIDS.

// HC_NOKIDS -- Operate on a single process, excluding its children
//
// By default HookCase.kext operates on a parent process and all its child
// processes, including XPC children.  Set this to make it only effect the
// parent process. Can be partially overridden by HC_ADDKIDS.

// HC_NO_NUMERICAL_ADDRS -- Disable numerical address naming convention
//
// By default, HookCase.kext supports a naming convention for patch hooks that
// allows one to create a hook for an (un-named) method at a particular
// address in a given module.  So, for example, creating a patch hook for a
// function named "sub_123abc" would specify that the hook should be inserted
// at offset 0x123abc (hexadecimal notation) in the module.  But this
// convention prevents you from creating a patch hook for a method that's
// actually named "sub_123abc" (in its module's symbol table).  To do so,
// you'll need to set this environment variable.

#define HC_INSERT_LIBRARY_ENV_VAR "HC_INSERT_LIBRARY"
#define HC_ADDKIDS_ENV_VAR "HC_ADDKIDS"
#define HC_NOKIDS_ENV_VAR "HC_NOKIDS"
#define HC_NO_NUMERICAL_ADDRS_ENV_VAR "HC_NO_NUMERICAL_ADDRS"

#define HC_PATH_SIZE PATH_MAX
typedef char hc_path_t[HC_PATH_SIZE];

typedef struct vm_map_copy *vm_map_copy_t;
extern "C" void vm_map_deallocate(vm_map_t map);

typedef struct vm_map_entry *vm_map_entry_t;
typedef struct vm_object *vm_object_t;
typedef struct vm_object_fault_info *vm_object_fault_info_t;

typedef struct uthread *uthread_t;

typedef struct vm_page *vm_page_t;

typedef struct vm_shared_region *vm_shared_region_t;

// From the xnu kernel's osfmk/vm/vm_map.h
typedef struct vm_map_version {
  unsigned int main_timestamp;
} vm_map_version_t;

// From the xnu kernel's osfmk/i386/locks.h.  This struct is the same size
// as struct _IOLock, with which it seems interchangeable.
struct __lck_mtx_t__ {
  unsigned long opaque[2];
};

// Defined in osfmk/i386/pmap_internal.h
typedef struct pv_rooted_entry {
  queue_head_t    qlink;
  vm_map_offset_t va_and_flags; /* virtual address for mapping */
  pmap_t          pmap;         /* pmap where mapping lies */
} *pv_rooted_entry_t;

// Kernel private globals (begin)

pv_rooted_entry_t *g_pv_head_table = NULL;

// Only used on Sierra (and up).
vm_page_t *g_vm_pages = NULL;
vm_page_t *g_vm_page_array_beginning_addr = NULL;
vm_page_t *g_vm_page_array_ending_addr = NULL;

// Kernel private globals (end)

// From the xnu kernel's osfmk/mach/vm_types.h
typedef uint16_t vm_tag_t;

// From the xnu kernel's osfmk/mach/vm_statistics.h
#define VM_KERN_MEMORY_NONE 0

// From the xnu kernel's osfmk/mach/thread_status.h
typedef natural_t *thread_state_t; /* Variable-length array */

// From the xnu kernel's osfmk/mach/thread_info.h
typedef natural_t thread_flavor_t;

// Kernel private functions needed by code below

typedef vm_map_t (*current_map_t)();
typedef vm_map_t (*get_task_map_reference_t)(task_t task);
typedef kern_return_t (*vm_map_copyin_t)(vm_map_t src_map,
                                         vm_map_address_t src_addr,
                                         vm_map_size_t len,
                                         boolean_t src_destroy,
                                         vm_map_copy_t *copy_result);
typedef kern_return_t (*vm_map_copy_overwrite_t)(vm_map_t dst_map,
                                                 vm_map_address_t dst_addr,
                                                 vm_map_copy_t copy,
                                                 boolean_t interruptible);
typedef kern_return_t (*vm_map_copyout_t)(vm_map_t dst_map,
                                          vm_map_address_t *dst_addr,
                                          vm_map_copy_t copy);
typedef void (*vm_map_copy_discard_t)(vm_map_copy_t copy);
// As of macOS 15.4, vm_map_switch_to and vm_map_switch_back are used instead
// of vm_map_switch.
typedef vm_map_t (*vm_map_switch_t)(vm_map_t map);
typedef struct vm_map_task {
  vm_map_t map;
  task_t task;
} vm_map_task_t;
typedef vm_map_task_t (*vm_map_switch_to_t)(vm_map_t map);
typedef void (*vm_map_switch_back_t)(vm_map_task_t map_task);
typedef uint16_t (*thread_get_tag_t)(thread_t);
typedef void (*task_act_iterate_wth_args_t)(task_t task,
                                            void (*func_callback)(thread_t, void *),
                                            void *func_arg);
typedef uthread_t (*get_bsdthread_info_t)(thread_t th);
typedef kern_return_t (*vm_map_region_recurse_64_t)(vm_map_t map,
                                                    vm_map_offset_t *address,        /* IN/OUT */
                                                    vm_map_size_t *size,             /* OUT */
                                                    natural_t *depth,                /* IN/OUT */
                                                    vm_region_submap_info_64_t info, /* IN/OUT */
                                                    mach_msg_type_number_t *count);  /* IN/OUT */
typedef kern_return_t (*task_hold_t)(task_t task);
typedef kern_return_t (*task_wait_t)(task_t task, boolean_t until_not_runnable);
typedef kern_return_t (*task_hold_and_wait_t)(task_t task);
typedef kern_return_t (*task_release_t)(task_t task);
typedef uint64_t (*cpuid_features_t)();
typedef uint64_t (*cpuid_leaf7_features_t)();
typedef kern_return_t (*vm_fault_t)(vm_map_t map,
                                    vm_map_offset_t vaddr,
                                    vm_prot_t fault_type,
                                    boolean_t change_wiring,
                                    vm_tag_t wire_tag,
                                    int interruptible,
                                    pmap_t pmap,
                                    vm_map_offset_t pmap_addr);
typedef vm_map_offset_t (*vm_map_page_mask_t)(vm_map_t map);
typedef int (*vm_map_page_size_t)(vm_map_t map);
typedef boolean_t (*vm_map_lookup_entry_t)(vm_map_t map,
                                           vm_map_address_t address,
                                           vm_map_entry_t *entry);
typedef kern_return_t (*vm_map_lookup_locked_t)(vm_map_t *var_map,
                                                vm_map_offset_t vaddr,
                                                vm_prot_t fault_type,
                                                int object_lock_type,
                                                vm_map_version_t *out_version,
                                                vm_object_t *object,
                                                vm_object_offset_t *offset,
                                                vm_prot_t *out_prot,
                                                boolean_t *wired,
                                                vm_object_fault_info_t fault_info,
                                                vm_map_t *real_map);
typedef kern_return_t (*vm_map_protect_t)(vm_map_t map,
                                          vm_map_offset_t start,
                                          vm_map_offset_t end,
                                          vm_prot_t new_prot,
                                          boolean_t set_max);
typedef void (*pmap_protect_t)(pmap_t map,
                               vm_map_offset_t sva,
                               vm_map_offset_t eva,
                               vm_prot_t prot);
typedef kern_return_t (*pmap_enter_t)(pmap_t pmap,
                                      vm_map_offset_t v,
                                      ppnum_t pn,
                                      vm_prot_t prot,
                                      vm_prot_t fault_type,
                                      unsigned int flags,
                                      boolean_t wired);
typedef unsigned int (*pmap_disconnect_t)(ppnum_t phys);
typedef vm_page_t (*vm_page_lookup_t)(vm_object_t object,
                                      vm_object_offset_t offset);
typedef void (*vm_object_lock_t)(vm_object_t object);
typedef void (*pmap_sync_page_attributes_phys_t)(ppnum_t pa);
typedef task_t (*get_threadtask_t)(thread_t th);
typedef mach_port_name_t (*ipc_port_copyout_send_t)(ipc_port_t sright,
                                                    ipc_space_t space);
typedef ipc_space_t (*get_task_ipcspace_t)(task_t task);
typedef ipc_port_t (*convert_thread_to_port_t)(thread_t thread);
typedef proc_t (*proc_parent_t)(proc_t);
typedef task_t (*proc_task_t)(proc_t proc);
typedef int (*vnode_istty_t)(vnode_t vp);
typedef vnode_t (*proc_getexecutablevnode_t)(proc_t p);
typedef void (*task_coalition_ids_t)(task_t task,
                                     uint64_t ids[2 /* COALITION_NUM_TYPES */]);
typedef coalition_t (*coalition_find_by_id_t)(uint64_t coal_id);
typedef void (*coalition_release_t)(coalition_t coal);
typedef int (*coalition_get_pid_list_t)(coalition_t coal, uint32_t rolemask,
                                        int sort_order, int *pid_list, int list_sz);
typedef void (*vm_object_unlock_t)(vm_object_t object);
typedef uint64_t (*proc_uniqueid_t)(proc_t p);

static current_map_t current_map = NULL;
static get_task_map_reference_t get_task_map_reference = NULL;
static vm_map_copyin_t vm_map_copyin = NULL;
static vm_map_copy_overwrite_t vm_map_copy_overwrite = NULL;
static vm_map_copyout_t vm_map_copyout = NULL;
static vm_map_copy_discard_t vm_map_copy_discard = NULL;
// As of macOS 15.4, vm_map_switch_to and vm_map_switch_back are used instead
// of vm_map_switch.
static vm_map_switch_t vm_map_switch = NULL;
static vm_map_switch_to_t vm_map_switch_to = NULL;
static vm_map_switch_back_t vm_map_switch_back = NULL;
static thread_get_tag_t thread_get_tag = NULL;
static task_act_iterate_wth_args_t task_act_iterate_wth_args = NULL;
static get_bsdthread_info_t get_bsdthread_info = NULL;
static vm_map_region_recurse_64_t vm_map_region_recurse_64 = NULL;
static task_hold_t task_hold = NULL;
static task_wait_t task_wait = NULL;
static task_hold_and_wait_t task_hold_and_wait = NULL;
static task_release_t task_release = NULL;
static cpuid_features_t cpuid_features_ptr = NULL;
static cpuid_leaf7_features_t cpuid_leaf7_features_ptr = NULL;
static vm_fault_t vm_fault = NULL;
static vm_map_page_mask_t vm_map_page_mask = NULL;
static vm_map_page_size_t vm_map_page_size = NULL;
static vm_map_lookup_entry_t vm_map_lookup_entry = NULL;
static vm_map_protect_t vm_map_protect_ptr = NULL;
static pmap_protect_t pmap_protect = NULL;
static pmap_enter_t pmap_enter = NULL;
static pmap_disconnect_t pmap_disconnect = NULL;
static vm_page_lookup_t vm_page_lookup = NULL;
static vm_object_lock_t vm_object_lock = NULL;
static pmap_sync_page_attributes_phys_t pmap_sync_page_attributes_phys = NULL;
static get_threadtask_t get_threadtask = NULL;
static ipc_port_copyout_send_t ipc_port_copyout_send = NULL;
static get_task_ipcspace_t get_task_ipcspace = NULL;
static convert_thread_to_port_t convert_thread_to_port = NULL;
static proc_parent_t proc_parent = NULL;
static proc_task_t proc_task_ptr = NULL;
static vnode_istty_t vnode_istty = NULL;
// Only on Yosemite and up (begin)
static proc_getexecutablevnode_t proc_getexecutablevnode = NULL;
// Only on Yosemite and up (end)
// Only on ElCapitan and up (begin)
static task_coalition_ids_t task_coalition_ids = NULL;
static coalition_find_by_id_t coalition_find_by_id = NULL;
static coalition_release_t coalition_release = NULL;
static coalition_get_pid_list_t coalition_get_pid_list = NULL;
// Only on ElCapitan and up (end)
// Only on Sierra and up (begin)
static vm_object_unlock_t vm_object_unlock_ptr = NULL;
// Only on Sierra and up (end)
// Only on Monterey and up (begin)
static proc_uniqueid_t proc_uniqueid_ptr;
// Only on Monterey and up (end)

bool s_kernel_private_functions_found = false;

bool find_kernel_private_functions()
{
  if (s_kernel_private_functions_found) {
    return true;
  }

  if (!g_pv_head_table) {
    g_pv_head_table = (pv_rooted_entry_t *)
      kernel_dlsym("_pv_head_table");
    if (!g_pv_head_table) {
      return false;
    }
  }

  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    if (!g_vm_pages) {
      g_vm_pages = (vm_page_t *)
        kernel_dlsym("_vm_pages");
      if (!g_vm_pages) {
        return false;
      }
    }
    // As of MacOS 15.4, vm_page_array_beginning_addr changes to vm_pages and
    // vm_page_array_ending_addr changes to vm_pages_end.
    if (!g_vm_page_array_beginning_addr) {
      if (macOS_Sequoia_4_or_greater()) {
        g_vm_page_array_beginning_addr = (vm_page_t *)
          kernel_dlsym("_vm_pages");
      } else {
        g_vm_page_array_beginning_addr = (vm_page_t *)
          kernel_dlsym("_vm_page_array_beginning_addr");
      }
      if (!g_vm_page_array_beginning_addr) {
        return false;
      }
    }
    if (!g_vm_page_array_ending_addr) {
      if (macOS_Sequoia_4_or_greater()) {
        g_vm_page_array_ending_addr = (vm_page_t *)
          kernel_dlsym("_vm_pages_end");
      } else {
        g_vm_page_array_ending_addr = (vm_page_t *)
          kernel_dlsym("_vm_page_array_ending_addr");
      }
      if (!g_vm_page_array_ending_addr) {
        return false;
      }
    }
  }

  if (!current_map) {
    current_map = (current_map_t)
      kernel_dlsym("_current_map");
    if (!current_map) {
      return false;
    }
  }
  if (!get_task_map_reference) {
    get_task_map_reference = (get_task_map_reference_t)
      kernel_dlsym("_get_task_map_reference");
    if (!get_task_map_reference) {
      return false;
    }
  }
  if (!vm_map_copyin) {
    vm_map_copyin = (vm_map_copyin_t) kernel_dlsym("_vm_map_copyin");
    if (!vm_map_copyin) {
      return false;
    }
  }
  if (!vm_map_copy_overwrite) {
    vm_map_copy_overwrite = (vm_map_copy_overwrite_t)
      kernel_dlsym("_vm_map_copy_overwrite");
    if (!vm_map_copy_overwrite) {
      return false;
    }
  }
  if (!vm_map_copyout) {
    vm_map_copyout = (vm_map_copyout_t)
      kernel_dlsym("_vm_map_copyout");
    if (!vm_map_copyout) {
      return false;
    }
  }
  if (!vm_map_copy_discard) {
    vm_map_copy_discard = (vm_map_copy_discard_t)
      kernel_dlsym("_vm_map_copy_discard");
    if (!vm_map_copy_discard) {
      return false;
    }
  }
  // As of macOS 15.4, vm_map_switch_to and vm_map_switch_back are used
  // instead of vm_map_switch.
  if (macOS_Sequoia_4_or_greater()) {
    if (!vm_map_switch_to) {
      vm_map_switch_to = (vm_map_switch_to_t)
        kernel_dlsym("_vm_map_switch_to");
      if (!vm_map_switch_to) {
        return false;
      }
    }
    if (!vm_map_switch_back) {
      vm_map_switch_back = (vm_map_switch_back_t)
        kernel_dlsym("_vm_map_switch_back");
      if (!vm_map_switch_back) {
        return false;
      }
    }
  } else {
    if (!vm_map_switch) {
      vm_map_switch = (vm_map_switch_t)
        kernel_dlsym("_vm_map_switch");
      if (!vm_map_switch) {
        return false;
      }
    }
  }
  if (!strnstr_ptr) {
    strnstr_ptr = (strnstr_t)
      kernel_dlsym("_strnstr");
    if (!strnstr_ptr) {
      return false;
    }
  }
  if (!thread_get_tag) {
    thread_get_tag = (thread_get_tag_t)
      kernel_dlsym("_thread_get_tag");
    if (!thread_get_tag) {
      return false;
    }
  }
  if (!task_act_iterate_wth_args) {
    task_act_iterate_wth_args = (task_act_iterate_wth_args_t)
      kernel_dlsym("_task_act_iterate_wth_args");
    if (!task_act_iterate_wth_args) {
      return false;
    }
  }
  if (!get_bsdthread_info) {
    get_bsdthread_info = (get_bsdthread_info_t)
      kernel_dlsym("_get_bsdthread_info");
    if (!get_bsdthread_info) {
      return false;
    }
  }
  if (!vm_map_region_recurse_64) {
    vm_map_region_recurse_64 = (vm_map_region_recurse_64_t)
      kernel_dlsym("_vm_map_region_recurse_64");
    if (!vm_map_region_recurse_64) {
      return false;
    }
  }
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (!task_hold_and_wait) {
      task_hold_and_wait = (task_hold_and_wait_t)
        kernel_dlsym("_task_hold_and_wait");
      if (!task_hold_and_wait) {
        return false;
      }
    }
  } else {
    if (!task_hold) {
      task_hold = (task_hold_t)
        kernel_dlsym("_task_hold");
      if (!task_hold) {
        return false;
      }
    }
    if (!task_wait) {
      task_wait = (task_wait_t)
        kernel_dlsym("_task_wait");
      if (!task_wait) {
        return false;
      }
    }
  }
  if (!task_release) {
    task_release = (task_release_t)
      kernel_dlsym("_task_release");
    if (!task_release) {
      return false;
    }
  }
  if (!cpuid_features_ptr) {
    cpuid_features_ptr = (cpuid_features_t)
      kernel_dlsym("_cpuid_features");
    if (!cpuid_features_ptr) {
      return false;
    }
  }
  if (!cpuid_leaf7_features_ptr) {
    cpuid_leaf7_features_ptr = (cpuid_leaf7_features_t)
      kernel_dlsym("_cpuid_leaf7_features");
    if (!cpuid_leaf7_features_ptr) {
      return false;
    }
  }
  if (!vm_fault) {
    vm_fault = (vm_fault_t)
      kernel_dlsym("_vm_fault");
    if (!vm_fault) {
      return false;
    }
  }
  if (!vm_map_page_mask) {
    vm_map_page_mask = (vm_map_page_mask_t)
      kernel_dlsym("_vm_map_page_mask");
    if (!vm_map_page_mask) {
      return false;
    }
  }
  if (!vm_map_page_size) {
    vm_map_page_size = (vm_map_page_size_t)
      kernel_dlsym("_vm_map_page_size");
    if (!vm_map_page_size) {
      return false;
    }
  }
  if (!vm_map_lookup_entry) {
    vm_map_lookup_entry = (vm_map_lookup_entry_t)
      kernel_dlsym("_vm_map_lookup_entry");
    if (!vm_map_lookup_entry) {
      return false;
    }
  }
  if (!vm_map_protect_ptr) {
    // As of macOS 15.2 the symbol for vm_map_protect() is hidden. We get
    // around this below.
    vm_map_protect_ptr = (vm_map_protect_t)
      kernel_dlsym("_vm_map_protect");
  }
  if (!pmap_protect) {
    pmap_protect = (pmap_protect_t)
      kernel_dlsym("_pmap_protect");
    if (!pmap_protect) {
      return false;
    }
  }
  if (!pmap_enter) {
    pmap_enter = (pmap_enter_t)
      kernel_dlsym("_pmap_enter");
    if (!pmap_enter) {
      return false;
    }
  }
  if (!pmap_disconnect) {
    pmap_disconnect = (pmap_disconnect_t)
      kernel_dlsym("_pmap_disconnect");
    if (!pmap_disconnect) {
      return false;
    }
  }
  if (!vm_page_lookup) {
    vm_page_lookup = (vm_page_lookup_t)
      kernel_dlsym("_vm_page_lookup");
    if (!vm_page_lookup) {
      return false;
    }
  }
  if (!vm_object_lock) {
    vm_object_lock = (vm_object_lock_t)
      kernel_dlsym("_vm_object_lock");
    if (!vm_object_lock) {
      return false;
    }
  }
  if (!pmap_sync_page_attributes_phys) {
    pmap_sync_page_attributes_phys = (pmap_sync_page_attributes_phys_t)
      kernel_dlsym("_pmap_sync_page_attributes_phys");
    if (!pmap_sync_page_attributes_phys) {
      return false;
    }
  }
  if (!get_threadtask) {
    get_threadtask = (get_threadtask_t)
      kernel_dlsym("_get_threadtask");
    if (!get_threadtask) {
      return false;
    }
  }
  if (!ipc_port_copyout_send) {
    ipc_port_copyout_send = (ipc_port_copyout_send_t)
      kernel_dlsym("_ipc_port_copyout_send");
    if (!ipc_port_copyout_send) {
      return false;
    }
  }
  if (!get_task_ipcspace) {
    get_task_ipcspace = (get_task_ipcspace_t)
      kernel_dlsym("_get_task_ipcspace");
    if (!get_task_ipcspace) {
      return false;
    }
  }
  if (!convert_thread_to_port) {
    convert_thread_to_port = (convert_thread_to_port_t)
      kernel_dlsym("_convert_thread_to_port");
    if (!convert_thread_to_port) {
      return false;
    }
  }
  if (!proc_parent) {
    proc_parent = (proc_parent_t)
      kernel_dlsym("_proc_parent");
    if (!proc_parent) {
      return false;
    }
  }
  if (!proc_task_ptr) {
    proc_task_ptr = (proc_task_t)
      kernel_dlsym("_proc_task");
    if (!proc_task_ptr) {
      return false;
    }
  }
  if (!vnode_istty) {
    vnode_istty = (vnode_istty_t)
      kernel_dlsym("_vnode_istty");
    if (!vnode_istty) {
      return false;
    }
  }
  if (!disable_preemption) {
    disable_preemption = (disable_preemption_t)
      kernel_dlsym("__disable_preemption");
    if (!disable_preemption) {
      return false;
    }
  }
  if (!enable_preemption) {
    enable_preemption = (enable_preemption_t)
      kernel_dlsym("__enable_preemption");
    if (!enable_preemption) {
      return false;
    }
  }
  if (OSX_Yosemite() || OSX_ElCapitan() || macOS_Sierra() ||
      macOS_HighSierra() || macOS_Mojave() || macOS_Catalina() ||
      macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    if (!proc_getexecutablevnode) {
      proc_getexecutablevnode = (proc_getexecutablevnode_t)
        kernel_dlsym("_proc_getexecutablevnode");
      if (!proc_getexecutablevnode) {
        return false;
      }
    }
  }
  if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() ||
      macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    if (!task_coalition_ids) {
      task_coalition_ids = (task_coalition_ids_t)
        kernel_dlsym("_task_coalition_ids");
      if (!task_coalition_ids) {
        return false;
      }
    }
    if (!coalition_find_by_id) {
      coalition_find_by_id = (coalition_find_by_id_t)
        kernel_dlsym("_coalition_find_by_id");
      if (!coalition_find_by_id) {
        return false;
      }
    }
    if (!coalition_release) {
      coalition_release = (coalition_release_t)
        kernel_dlsym("_coalition_release");
      if (!coalition_release) {
        return false;
      }
    }
    if (!coalition_get_pid_list) {
      coalition_get_pid_list = (coalition_get_pid_list_t)
        kernel_dlsym("_coalition_get_pid_list");
      if (!coalition_get_pid_list) {
        return false;
      }
    }
  }
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    if (!vm_object_unlock_ptr) {
      vm_object_unlock_ptr = (vm_object_unlock_t)
        kernel_dlsym("_vm_object_unlock");
      if (!vm_object_unlock_ptr) {
        return false;
      }
    }
  }
  if (macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    if (!proc_uniqueid_ptr) {
      proc_uniqueid_ptr = (proc_uniqueid_t)
        kernel_dlsym("_proc_uniqueid");
      if (!proc_uniqueid_ptr) {
        return false;
      }
    }
  }
  s_kernel_private_functions_found = true;
  return true;
}

// As of macOS 15.2 the symbol for vm_map_protect() is hidden. We use this
// function to get around the problem. Aside from a few parameter differences,
// vm_protect() just does safety checks on the parameters it's called with,
// then calls vm_map_protect(). I suppose the lack of these safety checks in
// vm_map_protect() is why it got hidden.
static kern_return_t vm_map_protect(vm_map_t map,
                                    vm_map_offset_t start,
                                    vm_map_offset_t end,
                                    vm_prot_t new_prot,
                                    boolean_t set_max)
{
  if (vm_map_protect_ptr) {
    return vm_map_protect_ptr(map, start, end, new_prot, set_max);
  }

  return vm_protect(map, start, end - start, set_max, new_prot);
}

// From the xnu kernel's osfmk/i386/mp.h
#define MAX_CPUS 64

// From the xnu kernel's osfmk/mach/i386/vm_param.h
#define VM_MAX_KERNEL_ADDRESS ((vm_offset_t) 0xFFFFFFFFFFFFEFFFUL)
#define atop_64(x) ((uint64_t)(x) >> PAGE_SHIFT)
#define ptoa_64(x) ((uint64_t)(x) << PAGE_SHIFT)

// From the xnu kernel's osfmk/vm/vm_map.h
#define vm_map_trunc_page(x,pgmask) ((vm_map_offset_t)(x) & ~((signed)(pgmask)))
#define vm_map_round_page(x,pgmask) (((vm_map_offset_t)(x) + (pgmask)) & ~((signed)(pgmask)))

// Kernel map tags, from osfmk/mach/vm_statistics.h
#define VM_KERN_MEMORY_NONE  0
#define VM_KERN_MEMORY_OSFMK 1
#define VM_KERN_MEMORY_BSD   2

// From the xnu kernel's osfmk/mach/vm_prot.h
#define VM_PROT_MEMORY_TAG_SHIFT 24
#define VM_PROT_MEMORY_TAG(x) (((x) >> VM_PROT_MEMORY_TAG_SHIFT) & 0xFF)

// From the xnu kernel's osfmk/kern/thread.h
#define THREAD_TAG_MAINTHREAD 0x1

bool is_main_thread(thread_t thread)
{
  return ((thread_get_tag(thread) & THREAD_TAG_MAINTHREAD) > 0);
}

typedef struct _task_thread_info {
  uint32_t num_threads;
  thread_t main_thread;
} task_thread_info, *task_thread_info_t;

static void thread_info_iterator(thread_t thread, void *task_thread_info)
{
  if (!thread || !task_thread_info) {
    return;
  }
  task_thread_info_t info = (task_thread_info_t) task_thread_info;
  if (is_main_thread(thread)) {
    info->main_thread = thread;
  }
  ++info->num_threads;
}

bool get_task_thread_info(task_t task, task_thread_info_t info)
{
  if (!task || !info) {
    return false;
  }
  bzero(info, sizeof(task_thread_info));
  task_act_iterate_wth_args(task, thread_info_iterator, info);
  return true;
}

// Returns the virtual address corresponding to a physical page number
// (ppnum_t).
uintptr_t ppnum_to_vaddr(ppnum_t phys)
{
  pv_rooted_entry_t pv_entry = &(*g_pv_head_table)[phys];
  uintptr_t retval = ((pv_entry->va_and_flags) & ~PAGE_MASK);
  return retval;
}

// From the xnu kernel's osfmk/i386/locks.h
#pragma pack(1)
struct __lck_rw_t__ {
  uint32_t opaque[3];
  uint32_t opaque4;
};
#pragma pack()

// From the xnu kernel's osfmk/vm/vm_map.h
struct vm_map_links {
  vm_map_entry_t prev;   /* previous entry */
  vm_map_entry_t next;   /* next entry */
  vm_map_offset_t start; /* start address */
  vm_map_offset_t end;   /* end address */
};

// From the xnu kernel's osfmk/vm/vm_map.h
typedef union vm_map_object {
  vm_object_t vmo_object; /* object object */
  vm_map_t vmo_submap;    /* belongs to another map */
} vm_map_object_t;

// "struct _vm_map" is defined in the xnu kernel's osfmk/vm/vm_map.h
typedef struct _vm_map_fake {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[4];
  pmap_t pmap;            // Offset 0x50
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[29];
  unsigned int timestamp; // Offset 0xe4
} *vm_map_fake_t;

typedef struct _vm_map_fake_elcapitan {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[4];
  pmap_t pmap;            // Offset 0x50
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[31];
  unsigned int timestamp; // Offset 0xec
} *vm_map_fake_elcapitan_t;

typedef struct _vm_map_fake_sierra {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[33];
  unsigned int timestamp; // Offset 0xec
} *vm_map_fake_sierra_t;

typedef struct _vm_map_fake_highsierra {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[35];
  unsigned int timestamp; // Offset 0xf4
} *vm_map_fake_highsierra_t;

typedef struct _vm_map_fake_mojave {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[34];
  unsigned int timestamp; // Offset 0xf0
} *vm_map_fake_mojave_t;

typedef struct _vm_map_fake_catalina {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[34];
  unsigned int timestamp; // Offset 0xf0
} *vm_map_fake_catalina_t;

typedef struct _vm_map_fake_catalina_dev_debug {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;
  vm_map_size_t user_wire_limit;
  vm_map_size_t user_wire_size;
  uint32_t pad2[37];
  unsigned int timestamp; // Offset 0xfc
} *vm_map_fake_catalina_dev_debug_t;

typedef struct _vm_map_fake_monterey {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;     // Offset 0x50
  uint64_t pad2[2];
  vm_map_size_t user_wire_limit; // Offset 0x68
  vm_map_size_t user_wire_size;  // Offset 0x70
  uint32_t pad3[34];
  unsigned int timestamp; // Offset 0x100
} *vm_map_fake_monterey_t;

typedef struct _vm_map_fake_monterey_dev {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[3];
  pmap_t pmap;            // Offset 0x48
  vm_map_size_t size;     // Offset 0x50
  uint64_t pad2[2];
  vm_map_size_t user_wire_limit; // Offset 0x68
  vm_map_size_t user_wire_size;  // Offset 0x70
  uint32_t pad3[37];
  unsigned int timestamp; // Offset 0x10c
} *vm_map_fake_monterey_dev_t;

typedef struct _vm_map_fake_monterey_3 {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[2];
  pmap_t pmap;            // Offset 0x40
  vm_map_size_t size;     // Offset 0x48
  uint64_t pad2[2];
  vm_map_size_t user_wire_limit; // Offset 0x60
  vm_map_size_t user_wire_size;  // Offset 0x68
  uint32_t pad3[12];
  unsigned int timestamp; // Offset 0xa0
} *vm_map_fake_monterey_3_t;

typedef struct _vm_map_fake_sonoma {
  lck_rw_t lock;
  struct vm_map_links links; // Actually 1st member of "struct vm_map_header hdr"
#define hdr links
  uint64_t pad1[2];
  pmap_t pmap;            // Offset 0x40
  vm_map_size_t size;     // Offset 0x48
  uint64_t pad2[2];
  vm_map_size_t user_wire_limit; // Offset 0x60
  vm_map_size_t user_wire_size;  // Offset 0x68
  uint32_t pad3[13];
  unsigned int timestamp; // Offset 0xa4
} *vm_map_fake_sonoma_t;

pmap_t vm_map_pmap(vm_map_t map)
{
  if (!map) {
    return NULL;
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey_3_or_greater())
  {
    vm_map_fake_monterey_3_t m = (vm_map_fake_monterey_3_t) map;
    return m->pmap;
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
             macOS_Catalina() || macOS_BigSur() || macOS_Monterey())
  {
    vm_map_fake_sierra_t m = (vm_map_fake_sierra_t) map;
    return m->pmap;
  } else {
    vm_map_fake_t m = (vm_map_fake_t) map;
    return m->pmap;
  }
}

unsigned int vm_map_timestamp(vm_map_t map)
{
  if (!map) {
    return 0;
  }
  unsigned int retval = 0;
  if (macOS_Sequoia() || macOS_Sonoma()) {
    vm_map_fake_sonoma_t map_local = (vm_map_fake_sonoma_t) map;
    retval = map_local->timestamp;
  } else if (macOS_Ventura() || macOS_Monterey_3_or_greater()) {
    vm_map_fake_monterey_3_t map_local = (vm_map_fake_monterey_3_t) map;
    retval = map_local->timestamp;
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      vm_map_fake_monterey_t map_local = (vm_map_fake_monterey_t) map;
      retval = map_local->timestamp;
    } else if (kernel_type_is_development()) {
      vm_map_fake_monterey_dev_t map_local =
        (vm_map_fake_monterey_dev_t) map;
      retval = map_local->timestamp;
    }
  } else if (macOS_Catalina() || macOS_BigSur()) {
    if (kernel_type_is_release()) {
      vm_map_fake_catalina_t map_local = (vm_map_fake_catalina_t) map;
      retval = map_local->timestamp;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_map_fake_catalina_dev_debug_t map_local =
        (vm_map_fake_catalina_dev_debug_t) map;
      retval = map_local->timestamp;
    }
  } else if (macOS_Mojave()) {
    vm_map_fake_mojave_t map_local = (vm_map_fake_mojave_t) map;
    retval = map_local->timestamp;
  } else if (macOS_HighSierra()) {
    vm_map_fake_highsierra_t map_local = (vm_map_fake_highsierra_t) map;
    retval = map_local->timestamp;
  } else if (OSX_ElCapitan() || macOS_Sierra()) {
    vm_map_fake_elcapitan_t map_local = (vm_map_fake_elcapitan_t) map;
    retval = map_local->timestamp;
  } else {
    vm_map_fake_t map_local = (vm_map_fake_t) map;
    retval = map_local->timestamp;
  }
  return retval;
}

vm_map_offset_t vm_map_min(vm_map_t map)
{
  if (!map) {
    return 0;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return map_local->hdr.start;
}

vm_map_offset_t vm_map_max(vm_map_t map)
{
  if (!map) {
    return 0;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return map_local->hdr.end;
}

vm_map_size_t vm_map_user_wire_limit(vm_map_t map)
{
  if (!map) {
    return 0;
  }
  vm_map_size_t retval;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey_3_or_greater())
  {
    vm_map_fake_monterey_3_t m = (vm_map_fake_monterey_3_t) map;
    retval = m->user_wire_limit;
  } else if (macOS_Monterey()) {
    vm_map_fake_monterey_t m = (vm_map_fake_monterey_t) map;
    retval = m->user_wire_limit;
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur())
  {
    vm_map_fake_sierra_t m = (vm_map_fake_sierra_t) map;
    retval = m->user_wire_limit;
  } else {
    vm_map_fake_t m = (vm_map_fake_t) map;
    retval = m->user_wire_limit;
  }
  return retval;
}

vm_map_size_t vm_map_user_wire_size(vm_map_t map)
{
  if (!map) {
    return 0;
  }
  vm_map_size_t retval;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey_3_or_greater())
  {
    vm_map_fake_monterey_3_t m = (vm_map_fake_monterey_3_t) map;
    retval = m->user_wire_size;
  } else if (macOS_Monterey()) {
    vm_map_fake_monterey_t m = (vm_map_fake_monterey_t) map;
    retval = m->user_wire_size;
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur())
  {
    vm_map_fake_sierra_t m = (vm_map_fake_sierra_t) map;
    retval = m->user_wire_size;
  } else {
    vm_map_fake_t m = (vm_map_fake_t) map;
    retval = m->user_wire_size;
  }
  return retval;
}

void vm_map_set_user_wire_size(vm_map_t map, vm_map_size_t new_size)
{
  if (!map) {
    return;
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey_3_or_greater())
  {
    vm_map_fake_monterey_3_t m = (vm_map_fake_monterey_3_t) map;
    m->user_wire_size = new_size;
  } else if (macOS_Monterey()) {
    vm_map_fake_monterey_t m = (vm_map_fake_monterey_t) map;
    m->user_wire_size = new_size;
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur())
  {
    vm_map_fake_sierra_t m = (vm_map_fake_sierra_t) map;
    m->user_wire_size = new_size;
  } else {
    vm_map_fake_t m = (vm_map_fake_t) map;
    m->user_wire_size = new_size;
  }
}

// "struct vm_map_entry" is defined in the xnu kernel's osfmk/vm/vm_map.h.
typedef struct _vm_map_entry_fake {
  struct vm_map_links links;
#define vme_prev  links.prev
#define vme_next  links.next
#define vme_start links.start
#define vme_end   links.end
  uint64_t pad1[3];
  union vm_map_object vme_object;   /* object I point to, offset 0x38 */
  vm_object_offset_t vme_offset;    /* offset into object */
  unsigned int                      // Offset 0x48
  /* boolean_t */ is_shared:1,      /* region is shared */
  /* boolean_t */ is_sub_map:1,     /* Is "object" a submap? */
  /* boolean_t */ in_transition:1,  /* Entry being changed */
  /* boolean_t */ needs_wakeup:1,   /* Waiters on in_transition */
  /* vm_behavior_t */ behavior:2,   /* user paging behavior hint */
  /* behavior is not defined for submap type */
  /* boolean_t */ needs_copy:1,     /* object need to be copied? */
  /* Only in task maps: */
  /* vm_prot_t */ protection:3,     /* protection code */
  /* vm_prot_t */ max_protection:3, /* maximum protection */
  /* vm_inherit_t */ inheritance:2, /* inheritance */
  /* boolean_t */ use_pmap:1,       /* nested pmaps */
  /*
   * IMPORTANT:
   * The "alias" field can be updated while holding the VM map lock
   * "shared".  It's OK as along as it's the only field that can be
   * updated without the VM map "exclusive" lock.
   */
  /* unsigned char */ alias:8,      /* user alias */
  /* boolean_t */ no_cache:1,       /* should new pages be cached? */
  /* boolean_t */ permanent:1,      /* mapping can not be removed */
  /* boolean_t */ superpage_size:1, /* use superpages of a certain size */
  /* boolean_t */ map_aligned:1,    /* align to map's page size */
  /* boolean_t */ zero_wired_pages:1, /* zero out the wired pages of
                                       * this entry it is being deleted
                                       * without unwiring them */
  /* boolean_t */ used_for_jit:1,
  /* boolean_t */ from_reserved_zone:1, /* Allocated from
                                         * kernel reserved zone */
  __pad:1;
  unsigned short wired_count;
  unsigned short user_wired_count;
  //uint64_t pad2[33];                // Only present in debug versions
} *vm_map_entry_fake_t;

typedef struct _vm_map_entry_fake_elcapitan {
  struct vm_map_links links;
#define vme_prev  links.prev
#define vme_next  links.next
#define vme_start links.start
#define vme_end   links.end
  uint64_t pad1[3];
  union vm_map_object vme_object;   /* object I point to, offset 0x38 */
  vm_object_offset_t vme_offset;    /* offset into object */
  unsigned int                      // Offset 0x48
  /* boolean_t */ is_shared:1,      /* region is shared */
  /* boolean_t */ is_sub_map:1,     /* Is "object" a submap? */
  /* boolean_t */ in_transition:1,  /* Entry being changed */
  /* boolean_t */ needs_wakeup:1,   /* Waiters on in_transition */
  /* vm_behavior_t */ behavior:2,   /* user paging behavior hint */
  /* behavior is not defined for submap type */
  /* boolean_t */ needs_copy:1,     /* object need to be copied? */
  /* Only in task maps: */
  /* vm_prot_t */ protection:3,     /* protection code */
  /* vm_prot_t */ max_protection:3, /* maximum protection */
  /* vm_inherit_t */ inheritance:2, /* inheritance */
  /* boolean_t */ use_pmap:1,       /* use_pmap is overloaded:
                                     * if "is_sub_map":
                                     *  use a nested pmap?
                                     * else (i.e. if object):
                                     *  use pmap accounting
                                     *  for footprint?
                                     */
  /* boolean_t */ no_cache:1,       /* should new pages be cached? */
  /* boolean_t */ permanent:1,      /* mapping can not be removed */
  /* boolean_t */ superpage_size:1, /* use superpages of a certain size */
  /* boolean_t */ map_aligned:1,    /* align to map's page size */
  /* boolean_t */ zero_wired_pages:1, /* zero out the wired pages of
                                       * this entry it is being deleted
                                       * without unwiring them */
  /* boolean_t */ used_for_jit:1,
  /* boolean_t */ from_reserved_zone:1, /* Allocated from
                                         * kernel reserved zone */
  __pad:9;
  unsigned short wired_count;
  unsigned short user_wired_count;
  //uint64_t pad2[33];                // Only present in debug versions
} *vm_map_entry_fake_elcapitan_t;

typedef struct _vm_map_entry_fake_monterey {
  struct vm_map_links links;
#define vme_prev  links.prev
#define vme_next  links.next
#define vme_start links.start
#define vme_end   links.end
  uint64_t pad1[3];
  union vm_map_object vme_object;   /* object I point to, offset 0x38 */
  vm_object_offset_t vme_offset;    /* offset into object */
  unsigned int                      // Offset 0x48
  /* boolean_t */ is_shared:1,      /* region is shared */
  /* boolean_t */ is_sub_map:1,     /* Is "object" a submap? */
  /* boolean_t */ in_transition:1,  /* Entry being changed */
  /* boolean_t */ needs_wakeup:1,   /* Waiters on in_transition */
  /* vm_behavior_t */ behavior:2,   /* user paging behavior hint */
  /* behavior is not defined for submap type */
  /* boolean_t */ needs_copy:1,     /* object need to be copied? */
  /* Only in task maps: */
  /* vm_prot_t */ protection:4,     /* protection code */
  /* vm_prot_t */ max_protection:4, /* maximum protection */
  /* vm_inherit_t */ inheritance:2, /* inheritance */
  /* boolean_t */ use_pmap:1,       /* use_pmap is overloaded:
                                     * if "is_sub_map":
                                     *  use a nested pmap?
                                     * else (i.e. if object):
                                     *  use pmap accounting
                                     *  for footprint?
                                     */
  /* boolean_t */ no_cache:1,       /* should new pages be cached? */
  /* boolean_t */ permanent:1,      /* mapping can not be removed */
  /* boolean_t */ superpage_size:1, /* use superpages of a certain size */
  /* boolean_t */ map_aligned:1,    /* align to map's page size */
  /* boolean_t */ zero_wired_pages:1, /* zero out the wired pages of
                                       * this entry it is being deleted
                                       * without unwiring them */
  /* boolean_t */ used_for_jit:1,
  __pad:8;
  unsigned short wired_count;       // Offset 0x4c
  unsigned short user_wired_count;  // Offset 0x4e
} *vm_map_entry_fake_monterey_t;

bool vm_map_entry_get_superpage_size(vm_map_entry_t entry)
{
  if (!entry) {
    return false;
  }
  bool retval = false;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey())
  {
    vm_map_entry_fake_monterey_t entry_local =
      (vm_map_entry_fake_monterey_t) entry;
    retval = entry_local->superpage_size;
  } else if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() ||
      macOS_Mojave() || macOS_Catalina() || macOS_BigSur())
  {
    vm_map_entry_fake_elcapitan_t entry_local =
      (vm_map_entry_fake_elcapitan_t) entry;
    retval = entry_local->superpage_size;
  } else {
    vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
    retval = entry_local->superpage_size;
  }
  return retval;
}

vm_map_entry_t vm_map_first_entry(vm_map_t map)
{
  if (!map) {
    return NULL;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return (map_local->links.next);
}

vm_map_entry_t vm_map_to_entry(vm_map_t map)
{
  if (!map) {
    return NULL;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return (vm_map_entry_t) &(map_local->links);
}

void vm_map_lock(vm_map_t map)
{
  if (!map) {
    return;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  lck_rw_lock_exclusive(&(map_local->lock));
}

bool vm_map_trylock(vm_map_t map)
{
  if (!map) {
    return false;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return lck_rw_try_lock(&(map_local->lock), 2);
}

void vm_map_lock_read(vm_map_t map)
{
  if (!map) {
    return;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  lck_rw_lock_shared(&(map_local->lock));
}

bool vm_map_trylock_read(vm_map_t map)
{
  if (!map) {
    return false;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  return lck_rw_try_lock(&(map_local->lock), 1);
}

void vm_map_lock_write_to_read(vm_map_t map)
{
  if (!map) {
    return;
  }
  if (macOS_Sequoia() || macOS_Sonoma()) {
    vm_map_fake_sonoma_t map_local = (vm_map_fake_sonoma_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  } else if (macOS_Ventura() || macOS_Monterey_3_or_greater()) {
    vm_map_fake_monterey_3_t map_local = (vm_map_fake_monterey_3_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      vm_map_fake_monterey_t map_local = (vm_map_fake_monterey_t) map;
      ++map_local->timestamp;
      lck_rw_lock_exclusive_to_shared(&(map_local->lock));
    } else if (kernel_type_is_development()) {
      vm_map_fake_monterey_dev_t map_local =
        (vm_map_fake_monterey_dev_t) map;
      ++map_local->timestamp;
      lck_rw_lock_exclusive_to_shared(&(map_local->lock));
    }
  } else if (macOS_Catalina() || macOS_BigSur()) {
    if (kernel_type_is_release()) {
      vm_map_fake_catalina_t map_local = (vm_map_fake_catalina_t) map;
      ++map_local->timestamp;
      lck_rw_lock_exclusive_to_shared(&(map_local->lock));
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_map_fake_catalina_dev_debug_t map_local =
        (vm_map_fake_catalina_dev_debug_t) map;
      ++map_local->timestamp;
      lck_rw_lock_exclusive_to_shared(&(map_local->lock));
    }
  } else if (macOS_Mojave()) {
    vm_map_fake_mojave_t map_local = (vm_map_fake_mojave_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  } else if (macOS_HighSierra()) {
    vm_map_fake_highsierra_t map_local = (vm_map_fake_highsierra_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  } else if (OSX_ElCapitan() || macOS_Sierra()) {
    vm_map_fake_elcapitan_t map_local = (vm_map_fake_elcapitan_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  } else {
    vm_map_fake_t map_local = (vm_map_fake_t) map;
    ++map_local->timestamp;
    lck_rw_lock_exclusive_to_shared(&(map_local->lock));
  }
}

void vm_map_unlock(vm_map_t map)
{
  if (!map) {
    return;
  }
  if (macOS_Sequoia() || macOS_Sonoma()) {
    vm_map_fake_sonoma_t map_local = (vm_map_fake_sonoma_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  } else if (macOS_Ventura() || macOS_Monterey_3_or_greater()) {
    vm_map_fake_monterey_3_t map_local = (vm_map_fake_monterey_3_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      vm_map_fake_monterey_t map_local = (vm_map_fake_monterey_t) map;
      ++map_local->timestamp;
      lck_rw_done(&(map_local->lock));
    } else if (kernel_type_is_development()) {
      vm_map_fake_monterey_dev_t map_local =
        (vm_map_fake_monterey_dev_t) map;
      ++map_local->timestamp;
      lck_rw_done(&(map_local->lock));
    }
  } else if (macOS_Catalina() || macOS_BigSur()) {
    if (kernel_type_is_release()) {
      vm_map_fake_catalina_t map_local = (vm_map_fake_catalina_t) map;
      ++map_local->timestamp;
      lck_rw_done(&(map_local->lock));
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_map_fake_catalina_dev_debug_t map_local =
        (vm_map_fake_catalina_dev_debug_t) map;
      ++map_local->timestamp;
      lck_rw_done(&(map_local->lock));
    }
  } else if (macOS_Mojave()) {
    vm_map_fake_mojave_t map_local = (vm_map_fake_mojave_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  } else if (macOS_HighSierra()) {
    vm_map_fake_highsierra_t map_local = (vm_map_fake_highsierra_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  } else if (OSX_ElCapitan() || macOS_Sierra()) {
    vm_map_fake_elcapitan_t map_local = (vm_map_fake_elcapitan_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  } else {
    vm_map_fake_t map_local = (vm_map_fake_t) map;
    ++map_local->timestamp;
    lck_rw_done(&(map_local->lock));
  }
}

void vm_map_unlock_read(vm_map_t map)
{
  if (!map) {
    return;
  }
  vm_map_fake_t map_local = (vm_map_fake_t) map;
  lck_rw_done(&(map_local->lock));
}

vm_map_entry_t map_entry_next(vm_map_entry_t entry)
{
  if (!entry) {
    return NULL;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  return entry_local->vme_next;
}

vm_map_offset_t map_entry_start(vm_map_entry_t entry)
{
  if (!entry) {
    return 0;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  return entry_local->vme_start;
}

vm_map_offset_t map_entry_end(vm_map_entry_t entry)
{
  if (!entry) {
    return 0;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  return entry_local->vme_end;
}

// As of macOS 12.5, a flag in the 'vm_map_entry' structure's
// 'vme_object' member is used to determine whether or not the
// map entry is for a submap.
bool map_entry_is_submap(vm_map_entry_t entry)
{
  if (!entry) {
    return false;
  }

  bool retval = false;
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey_5_or_greater())
  {
    uintptr_t value = (uintptr_t) entry_local->vme_object.vmo_object;
    uintptr_t flag = (value & 0xffff);
    retval = ((flag & 2) != 0);
  } else {
    retval = entry_local->is_sub_map;
  }
  return retval;
}

// What's returned may be either an "object" or a "submap". As of macOS 12.5,
// the 'vm_map_entry' structure's 'vme_object' member is "packed". I don't
// know why -- no space seems to have been saved.
union vm_map_object map_entry_object_unpack_ptr(vm_object_t p)
{
  uintptr_t value = (uintptr_t) p;

  union vm_map_object retval;
  retval.vmo_object = p;

  if (!macOS_Sequoia() && !macOS_Sonoma() && !macOS_Ventura() &&
      !macOS_Monterey_5_or_greater())
  {
    return retval;
  }

  uintptr_t flag = (value & 0xffff);
  bool is_sub_map = ((flag & 2) != 0);

  if (is_sub_map) {
    value &= 0xfffffffffffffffc;
  } else {
    uintptr_t raw = (value >> 32);
    if (raw != 0) {
      value = ((value >> 26) & 0xffffffffffffffc0);
      value += 0xffffff7f80000000;
    } else {
      value = 0;
    }
  }

  retval.vmo_object = (vm_object_t) value;
  return retval;
}

// What's returned may be either an "object" or a "submap".
union vm_map_object map_entry_object(vm_map_entry_t entry)
{
  if (!entry) {
    union vm_map_object retval;
    retval.vmo_object = NULL;
    return retval;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  return map_entry_object_unpack_ptr(entry_local->vme_object.vmo_object);
}

vm_object_offset_t map_entry_offset(vm_map_entry_t entry)
{
  if (!entry) {
    return 0;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  // We need to truncate the result the same way the kernel's
  // VME_OFFSET() macro does.  Sometimes Apple leaves garbage in
  // the 12 least significant bits.
  return (entry_local->vme_offset & ~PAGE_MASK);
}

// Assumes the entire region we're interested in (from 'start' to 'end') has
// the same protection as does the entry at 'start'.
kern_return_t vm_region_get_info(vm_map_t map, user_addr_t start,
                                 vm_region_submap_info_64_t info)
{
  kern_return_t retval = KERN_FAILURE;
  if (!find_kernel_private_functions() || !map || !start || !info) {
    return retval;
  }

  vm_map_offset_t start_local = start;
  vm_map_size_t size = 0;
  // This is a saner value than the '0' we used in previous versions of
  // HookCase.  The kernel uses it in a number of places when calling
  // vm_map_region_recurse_64() on user memory regions.  Setting depth
  // to '0' probably often caused us to get incorrect values for
  // info->protection.
  natural_t depth = 999999;
  bzero(info, sizeof(vm_region_submap_info_data_64_t));
  mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
  retval =
    vm_map_region_recurse_64(map, &start_local, &size, &depth, info, &count);

  return retval;
}

// Assumes the entire region we're interested in (from 'start' to 'end') has
// the same protection as does the entry at 'start'.
vm_prot_t vm_region_get_protection(vm_map_t map, user_addr_t start)
{
  vm_prot_t retval = VM_PROT_DEFAULT;

  vm_region_submap_info_data_64_t info;
  bzero(&info, sizeof(info));
  kern_return_t rv = vm_region_get_info(map, start, &info);
  if (rv == KERN_SUCCESS) {
    retval = info.protection;
  }

  return retval;
}

// "struct vm_page" is defined in the xnu kernel's osfmk/vm/vm_page.h.
typedef struct vm_page_fake_mavericks {
  uint64_t pad1[2];
  queue_chain_t listq;  /* all pages in same object (O) */
  uint64_t pad2[1];
  vm_object_t object;  /* which object am I in (O&P) */ // Offset 0x28
  vm_object_offset_t offset; /* offset into that object (O,P) */
  uint32_t pad3;
  ppnum_t  phys_page; /* Offset 0x3c */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
  /*
   * The following word of flags is protected
   * by the "VM object" lock.
   */
  unsigned int // Offset 0x40
    busy:1,  /* page is in transit (O) */
    wanted:1, /* someone is waiting for page (O) */
    tabled:1, /* page is in VP table (O) */
    hashed:1, /* page is in vm_page_buckets[]
              (O) + the bucket lock */
    fictitious:1, /* Physical page doesn't exist (O) */
  /*
   * IMPORTANT: the "pmapped" bit can be turned on while holding the
   * VM object "shared" lock.  See vm_fault_enter().
   * This is OK as long as it's the only bit in this bit field that
   * can be updated without holding the VM object "exclusive" lock.
   */
    pmapped:1,      /* page has been entered at some
                     * point into a pmap (O **shared**) */
    wpmapped:1,     /* page has been entered at some
                     * point into a pmap for write (O) */
    pageout:1, /* page wired & busy for pageout (O) */
    absent:1, /* Data has been requested, but is
               *  not yet available (O) */
    error:1, /* Data manager was unable to provide
              *  data due to error (O) */
    dirty:1, /* Page must be cleaned (O) */
    cleaning:1, /* Page clean has begun (O) */
    precious:1, /* Page is precious; data must be
                 *  returned even if clean (O) */
    clustered:1, /* page is not the faulted page (O) */
    overwriting:1,  /* Request to unlock has been made
                     * without having data. (O)
                     * [See vm_fault_page_overwrite] */
    restart:1, /* Page was pushed higher in shadow
                  chain by copy_call-related pagers;
                  start again at top of chain */
    unusual:1, /* Page is absent, error, restart or
                  page locked */
    encrypted:1, /* encrypted for secure swap (O) */
    encrypted_cleaning:1, /* encrypting page */
    cs_validated:1,    /* code-signing: page was checked */ 
    cs_tainted:1,    /* code-signing: page is tainted */
    reusable:1,
    lopage:1,
    slid:1,
    was_dirty:1, /* was this page previously dirty? */
    compressor:1, /* page owned by compressor pool */
    written_by_kernel:1, /* page was written by kernel (i.e. decompressed) */
    __unused_object_bits:5; /* 5 bits available here */
} *vm_page_fake_mavericks_t;

typedef struct vm_page_fake_yosemite {
  uint64_t pad1[2];
  queue_chain_t listq;  /* all pages in same object (O) */
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_object_t object;  /* which object am I in (O&P) */ // Offset 0x28
  uint64_t pad2;
  ppnum_t  phys_page; /* Offset 0x38 */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
  /*
   * The following word of flags is protected
   * by the "VM object" lock.
   */
  unsigned int // Offset 0x3c
    busy:1,  /* page is in transit (O) */
    wanted:1, /* someone is waiting for page (O) */
    tabled:1, /* page is in VP table (O) */
    hashed:1, /* page is in vm_page_buckets[]
                 (O) + the bucket lock */
    fictitious:1, /* Physical page doesn't exist (O) */
  /*
   * IMPORTANT: the "pmapped", "xpmapped" and "clustered" bits can be modified while holding the
   * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
   * This is done in vm_fault_enter and the CONSUME_CLUSTERED macro.
   * It's also ok to modify them behind just the VM object "exclusive" lock.
   */
    clustered:1, /* page is not the faulted page (O) or (O-shared AND pmap_page) */
    pmapped:1,      /* page has been entered at some
                     * point into a pmap (O) or (O-shared AND pmap_page) */
    xpmapped:1, /* page has been entered with execute permission (O)
                   or (O-shared AND pmap_page) */

    wpmapped:1,     /* page has been entered at some
                     * point into a pmap for write (O) */
    pageout:1, /* page wired & busy for pageout (O) */
    absent:1, /* Data has been requested, but is
               *  not yet available (O) */
    error:1, /* Data manager was unable to provide
              *  data due to error (O) */
    dirty:1, /* Page must be cleaned (O) */
    cleaning:1, /* Page clean has begun (O) */
    precious:1, /* Page is precious; data must be
                 *  returned even if clean (O) */
    overwriting:1,  /* Request to unlock has been made
                     * without having data. (O)
                     * [See vm_fault_page_overwrite] */
    restart:1, /* Page was pushed higher in shadow
                  chain by copy_call-related pagers;
                  start again at top of chain */
    unusual:1, /* Page is absent, error, restart or
                  page locked */
    encrypted:1, /* encrypted for secure swap (O) */
    encrypted_cleaning:1, /* encrypting page */
    cs_validated:1,    /* code-signing: page was checked */ 
    cs_tainted:1,    /* code-signing: page is tainted */
    cs_nx:1,    /* code-signing: page is nx */
    reusable:1,
    lopage:1,
    slid:1,
    compressor:1, /* page owned by compressor pool */
    written_by_kernel:1, /* page was written by kernel (i.e. decompressed) */
    __unused_object_bits:4;  /* 5 bits available here */
} *vm_page_fake_yosemite_t;

typedef struct vm_page_fake_elcapitan {
  uint64_t pad1[2];
  queue_chain_t listq;  /* all pages in same object (O) */
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_object_t object;  /* which object am I in (O&P) */ // Offset 0x28
  uint64_t pad2;
  ppnum_t  phys_page; /* Offset 0x38 */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
  /*
   * The following word of flags is protected
   * by the "VM object" lock.
   */
  unsigned int // Offset 0x3c
    busy:1,  /* page is in transit (O) */
    wanted:1, /* someone is waiting for page (O) */
    tabled:1, /* page is in VP table (O) */
    hashed:1, /* page is in vm_page_buckets[]
                 (O) + the bucket lock */
    fictitious:1, /* Physical page doesn't exist (O) */
  /*
   * IMPORTANT: the "pmapped", "xpmapped" and "clustered" bits can be modified while holding the
   * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
   * This is done in vm_fault_enter and the CONSUME_CLUSTERED macro.
   * It's also ok to modify them behind just the VM object "exclusive" lock.
   */
    clustered:1, /* page is not the faulted page (O) or (O-shared AND pmap_page) */
    pmapped:1,      /* page has been entered at some
                     * point into a pmap (O) or (O-shared AND pmap_page) */
    xpmapped:1, /* page has been entered with execute permission (O)
                   or (O-shared AND pmap_page) */

    wpmapped:1,     /* page has been entered at some
                     * point into a pmap for write (O) */
    pageout:1, /* page wired & busy for pageout (O) */
    absent:1, /* Data has been requested, but is
               *  not yet available (O) */
    error:1, /* Data manager was unable to provide
              *  data due to error (O) */
    dirty:1, /* Page must be cleaned (O) */
    cleaning:1, /* Page clean has begun (O) */
    precious:1, /* Page is precious; data must be
                 *  returned even if clean (O) */
    overwriting:1,  /* Request to unlock has been made
                     * without having data. (O)
                     * [See vm_fault_page_overwrite] */
    restart:1, /* Page was pushed higher in shadow
                  chain by copy_call-related pagers;
                  start again at top of chain */
    unusual:1, /* Page is absent, error, restart or
                  page locked */
    encrypted:1, /* encrypted for secure swap (O) */
    encrypted_cleaning:1, /* encrypting page */
    cs_validated:1,    /* code-signing: page was checked */ 
    cs_tainted:1,    /* code-signing: page is tainted */
    cs_nx:1,    /* code-signing: page is nx */
    reusable:1,
    lopage:1,
    slid:1,
    compressor:1, /* page owned by compressor pool */
    written_by_kernel:1, /* page was written by kernel (i.e. decompressed) */
    __unused_object_bits:4;  /* 5 bits available here */
} *vm_page_fake_elcapitan_t;

typedef uint32_t vm_page_packed_t;

struct vm_page_packed_queue_entry {
  vm_page_packed_t next;   /* next element */
  vm_page_packed_t prev;   /* previous element */
};

typedef struct vm_page_packed_queue_entry *vm_page_queue_t;
typedef struct vm_page_packed_queue_entry vm_page_queue_head_t;
typedef struct vm_page_packed_queue_entry vm_page_queue_chain_t;
typedef struct vm_page_packed_queue_entry *vm_page_queue_entry_t;

typedef vm_page_packed_t vm_page_object_t;

typedef struct vm_page_fake_sierra {
  uint64_t pad1[1];
  vm_page_queue_chain_t listq;
  uint64_t pad2[1];
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_page_object_t vm_page_object;  /* which object am I in (O&P) */ // Offset 0x20
  uint32_t pad3[2];
 /*
  * The following word of flags is protected
  * by the "VM object" lock.
  */
 unsigned int // Offset 0x2c
   busy:1,  /* page is in transit (O) */
   wanted:1, /* someone is waiting for page (O) */
   tabled:1, /* page is in VP table (O) */
   hashed:1, /* page is in vm_page_buckets[]
               (O) + the bucket lock */
   fictitious:1, /* Physical page doesn't exist (O) */
 /*
  * IMPORTANT: the "pmapped", "xpmapped" and "clustered" bits can be modified while holding the
  * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
  * This is done in vm_fault_enter and the CONSUME_CLUSTERED macro.
  * It's also ok to modify them behind just the VM object "exclusive" lock.
  */
   clustered:1, /* page is not the faulted page (O) or (O-shared AND pmap_page) */
   pmapped:1,   /* page has been entered at some
                 * point into a pmap (O) or (O-shared AND pmap_page) */
   xpmapped:1,  /* page has been entered with execute permission (O)
                   or (O-shared AND pmap_page) */

   wpmapped:1,  /* page has been entered at some
                 * point into a pmap for write (O) */
   free_when_done:1, /* page is to be freed once cleaning is completed (O) */
   absent:1, /* Data has been requested, but is
              *  not yet available (O) */
   error:1, /* Data manager was unable to provide
             *  data due to error (O) */
   dirty:1, /* Page must be cleaned (O) */
   cleaning:1, /* Page clean has begun (O) */
   precious:1, /* Page is precious; data must be
                *  returned even if clean (O) */
   overwriting:1,  /* Request to unlock has been made
                    * without having data. (O)
                    * [See vm_fault_page_overwrite] */
   restart:1, /* Page was pushed higher in shadow
                 chain by copy_call-related pagers;
                 start again at top of chain */
   unusual:1, /* Page is absent, error, restart or
                 page locked */
   encrypted:1, /* encrypted for secure swap (O) */
   encrypted_cleaning:1, /* encrypting page */
   cs_validated:1,    /* code-signing: page was checked */ 
   cs_tainted:1,    /* code-signing: page is tainted */
   cs_nx:1,    /* code-signing: page is nx */
   reusable:1,
   lopage:1,
   slid:1,
   written_by_kernel:1, /* page was written by kernel (i.e. decompressed) */
   __unused_object_bits:5;  /* 5 bits available here */

  ppnum_t  phys_page; /* Offset 0x30 */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
} *vm_page_fake_sierra_t;

typedef struct vm_page_fake_highsierra {
  uint64_t pad1[1];
  vm_page_queue_chain_t listq;
  uint64_t pad2[1];
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_page_object_t vm_page_object;  /* which object am I in (O&P) */ // Offset 0x20
  uint32_t pad3[2];
 /*
  * The following word of flags is protected
  * by the "VM object" lock.
  */
 unsigned int // Offset 0x2c
   busy:1,  /* page is in transit (O) */
   wanted:1, /* someone is waiting for page (O) */
   tabled:1, /* page is in VP table (O) */
   hashed:1, /* page is in vm_page_buckets[]
               (O) + the bucket lock */
   fictitious:1, /* Physical page doesn't exist (O) */
 /*
  * IMPORTANT: the "pmapped", "xpmapped" and "clustered" bits can be modified while holding the
  * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
  * This is done in vm_fault_enter and the CONSUME_CLUSTERED macro.
  * It's also ok to modify them behind just the VM object "exclusive" lock.
  */
   clustered:1, /* page is not the faulted page (O) or (O-shared AND pmap_page) */
   pmapped:1,   /* page has been entered at some
                 * point into a pmap (O) or (O-shared AND pmap_page) */
   xpmapped:1,  /* page has been entered with execute permission (O)
                   or (O-shared AND pmap_page) */

   wpmapped:1,  /* page has been entered at some
                 * point into a pmap for write (O) */
   free_when_done:1, /* page is to be freed once cleaning is completed (O) */
   absent:1, /* Data has been requested, but is
              *  not yet available (O) */
   error:1, /* Data manager was unable to provide
             *  data due to error (O) */
   dirty:1, /* Page must be cleaned (O) */
   cleaning:1, /* Page clean has begun (O) */
   precious:1, /* Page is precious; data must be
                *  returned even if clean (O) */
   overwriting:1,  /* Request to unlock has been made
                    * without having data. (O)
                    * [See vm_fault_page_overwrite] */
   restart:1, /* Page was pushed higher in shadow
                 chain by copy_call-related pagers;
                 start again at top of chain */
   unusual:1, /* Page is absent, error, restart or
                 page locked */
   cs_validated:1,    /* code-signing: page was checked */
   cs_tainted:1,    /* code-signing: page is tainted */
   cs_nx:1,    /* code-signing: page is nx */
   reusable:1,
   lopage:1,
   slid:1,
   written_by_kernel:1, /* page was written by kernel (i.e. decompressed) */
   __unused_object_bits:7;  /* 7 bits available here */

  ppnum_t  phys_page; /* Offset 0x30 */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
} *vm_page_fake_highsierra_t;

typedef struct vm_page_fake_bigsur {
  uint64_t pad1[1];
  vm_page_queue_chain_t listq;
  uint64_t pad2[1];
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_page_object_t vm_page_object;  /* which object am I in (O&P) */ // Offset 0x20
  uint32_t pad3[2];
 /*
  * The following word of flags is protected
  * by the "VM object" lock.
  */
 unsigned int // Offset 0x2c
   busy:1,  /* page is in transit (O) */
   wanted:1, /* someone is waiting for page (O) */
   tabled:1, /* page is in VP table (O) */
   hashed:1, /* page is in vm_page_buckets[]
               (O) + the bucket lock */
   fictitious:1, /* Physical page doesn't exist (O) */
 /*
  * IMPORTANT: the "pmapped", "xpmapped" and "clustered" bits can be modified while holding the
  * VM object "shared" lock + the page lock provided through the pmap_lock_phys_page function.
  * This is done in vm_fault_enter and the CONSUME_CLUSTERED macro.
  * It's also ok to modify them behind just the VM object "exclusive" lock.
  */
   clustered:1, /* page is not the faulted page (O) or (O-shared AND pmap_page) */
   pmapped:1,   /* page has been entered at some
                 * point into a pmap (O) or (O-shared AND pmap_page) */
   xpmapped:1,  /* page has been entered with execute permission (O)
                   or (O-shared AND pmap_page) */

   wpmapped:1,  /* page has been entered at some
                 * point into a pmap for write (O) */
   free_when_done:1, /* page is to be freed once cleaning is completed (O) */
   absent:1, /* Data has been requested, but is
              *  not yet available (O) */
   error:1, /* Data manager was unable to provide
             *  data due to error (O) */
   dirty:1, /* Page must be cleaned (O) */
   cleaning:1, /* Page clean has begun (O) */
   precious:1, /* Page is precious; data must be
                *  returned even if clean (O) */
   overwriting:1,  /* Request to unlock has been made
                    * without having data. (O)
                    * [See vm_fault_page_overwrite] */
   restart:1, /* Page was pushed higher in shadow
                 chain by copy_call-related pagers;
                 start again at top of chain */
   unusual:1, /* Page is absent, error, restart or
                 page locked */
   cs_validated:4,
   cs_tainted:4,
   cs_nx:4,
   __unused_object_bits:2;  /* 2 bits available here */

  ppnum_t  phys_page; /* Offset 0x30 */ /* Physical address of page, passed
                                         *  to pmap_enter (read-only) */
} *vm_page_fake_bigsur_t;

// Modified from the Sierra xnu kernel's osfmk/vm/vm_page.h (begin)

#define VM_PACKED_POINTER_ALIGNMENT 64  /* must be a power of 2 */
#define VM_PACKED_POINTER_SHIFT  6

#define VM_PACKED_FROM_VM_PAGES_ARRAY 0x80000000

uintptr_t vm_page_pack_ptr(uintptr_t p)
{
  if (!p || OSX_Mavericks() || OSX_Yosemite() || OSX_ElCapitan()) {
    return p;
  }

  vm_page_fake_sierra_t vm_page_array_beginning_addr = (vm_page_fake_sierra_t)
    *g_vm_page_array_beginning_addr;
  vm_page_fake_sierra_t vm_page_array_ending_addr = (vm_page_fake_sierra_t)
    *g_vm_page_array_ending_addr;

#if (0)
  // Sanity check
  if (((uint64_t) vm_page_array_ending_addr - (uint64_t) vm_page_array_beginning_addr) %
      sizeof(struct vm_page_fake_sierra))
  {
    return 0;
  }
#endif

  vm_page_packed_t packed_ptr;

  if ((p >= (uintptr_t) vm_page_array_beginning_addr) &&
      (p < (uintptr_t) vm_page_array_ending_addr))
  {
    packed_ptr = (vm_page_packed_t)
      ((vm_page_fake_sierra_t) p - vm_page_array_beginning_addr);
    packed_ptr |= VM_PACKED_FROM_VM_PAGES_ARRAY;
    return packed_ptr;
  }

  if ((p & (VM_PACKED_POINTER_ALIGNMENT - 1)) != 0) {
    return 0;
  }

  packed_ptr = (vm_page_packed_t)
    ((p - (uintptr_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS) >> VM_PACKED_POINTER_SHIFT);

  return packed_ptr;
}

uintptr_t vm_page_unpack_ptr(uintptr_t p)
{
  if (!p || OSX_Mavericks() || OSX_Yosemite() || OSX_ElCapitan()) {
    return p;
  }

#if (0)
  vm_map_offset_t vm_page_array_beginning_addr = (vm_map_offset_t)
    *g_vm_page_array_beginning_addr;
  vm_map_offset_t vm_page_array_ending_addr = (vm_map_offset_t)
    *g_vm_page_array_ending_addr;

  // Sanity check
  if ((vm_page_array_ending_addr - vm_page_array_beginning_addr) %
      sizeof(struct vm_page_fake_sierra))
  {
    return 0;
  }
#endif

  vm_page_fake_sierra_t vm_pages = (vm_page_fake_sierra_t) *g_vm_pages;

  if (p & VM_PACKED_FROM_VM_PAGES_ARRAY) {
    return (uintptr_t) &vm_pages[(uint32_t) (p & ~VM_PACKED_FROM_VM_PAGES_ARRAY)];
  }

  return (p << VM_PACKED_POINTER_SHIFT) + (uintptr_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS;
}

// Modified from the Sierra xnu kernel's osfmk/vm/vm_page.h (end)

uintptr_t page_listq(vm_page_t page)
{
  if (!page) {
    return 0;
  }

  uintptr_t retval = 0;

  if (OSX_Mavericks()) {
    retval = (uintptr_t) &((vm_page_fake_mavericks_t) page)->listq;
  } else if (OSX_Yosemite() || OSX_ElCapitan()) {
    retval = (uintptr_t) &((vm_page_fake_yosemite_t) page)->listq;
  } else {
    retval = (uintptr_t) &((vm_page_fake_sierra_t) page)->listq;
  }

  return retval;
}

vm_page_t page_queue_next(uintptr_t queue_entry)
{
  if (!queue_entry) {
    return NULL;
  }

  vm_page_t retval = NULL;

  if (OSX_Mavericks() || OSX_Yosemite() || OSX_ElCapitan()) {
    queue_entry_t entry_local = (queue_entry_t) queue_entry;
    retval = (vm_page_t) entry_local->next;
  } else {
    vm_page_queue_entry_t entry_local = (vm_page_queue_entry_t) queue_entry;
    retval = (vm_page_t) vm_page_unpack_ptr(entry_local->next);
  }

  return retval;
}

#define vm_page_queue_end(q, qe) ((q) == (qe))
#define vm_page_queue_first(q) (page_queue_next(q))
#define vm_page_queue_next(qc) (page_queue_next(qc))

// 'head' is always a vm_object_t object. The actual target is its 'memq'
// field. But this is always its first member, so just using a pointer to
// the object is fine.
#define vm_page_queue_iterate(head, elt)                       \
  for ((elt) = vm_page_queue_first((uintptr_t)head);           \
      !vm_page_queue_end((uintptr_t)(head), (uintptr_t)(elt)); \
      (elt) = vm_page_queue_next(page_listq(elt)))             \

ppnum_t page_phys_page(vm_page_t page)
{
  if (!page) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
        macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
        macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
    {
      offset_in_struct = offsetof(struct vm_page_fake_sierra, phys_page);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct vm_page_fake_elcapitan, phys_page);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct vm_page_fake_yosemite, phys_page);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct vm_page_fake_mavericks, phys_page);
    }
  }

  ppnum_t retval = 0;
  if (offset_in_struct != -1) {
    retval = *((ppnum_t *)((vm_map_offset_t)page + offset_in_struct));
  }

  return retval;
}

// What a pain that you can't take the address of a bit-mapped field!  (Or use
// offsetof() on bit-mapped fields.)  Apparently they're specified very
// badly in all current C/C++ standards -- the actual offset of a bit-mapped
// field is undefined (implementation-dependent)!

bool page_is_wpmapped(vm_page_t page)
{
  if (!page) {
    return false;
  }
  bool retval = false;
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->wpmapped;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->wpmapped;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->wpmapped;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    retval = page_local->wpmapped;
  }
  return retval;
}

bool page_is_pmapped(vm_page_t page)
{
  if (!page) {
    return false;
  }
  bool retval = false;
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->pmapped;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->pmapped;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->pmapped;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    retval = page_local->pmapped;
  }
  return retval;
}

void page_set_wpmapped(vm_page_t page, bool flag)
{
  if (!page) {
    return;
  }
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->wpmapped = flag;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->wpmapped = flag;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->wpmapped = flag;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->wpmapped = flag;
  }
}

unsigned char page_is_cs_validated(vm_page_t page)
{
  if (!page) {
    return false;
  }
  unsigned char retval = 0;
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    retval = page_local->cs_validated;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    retval = page_local->cs_validated;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->cs_validated;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->cs_validated;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->cs_validated;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    retval = page_local->cs_validated;
  }
  return retval;
}

void page_set_cs_validated(vm_page_t page, unsigned char value)
{
  if (!page) {
    return;
  }
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    page_local->cs_validated = value;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_validated = (bool) value;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_validated = (bool) value;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_validated = (bool) value;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_validated = (bool) value;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->cs_validated = (bool) value;
  }
}

unsigned char page_is_cs_tainted(vm_page_t page)
{
  if (!page) {
    return false;
  }
  unsigned char retval = 0;
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    retval = page_local->cs_tainted;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    retval = page_local->cs_tainted;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->cs_tainted;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->cs_tainted;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->cs_tainted;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    retval = page_local->cs_tainted;
  }
  return retval;
}

void page_set_cs_tainted(vm_page_t page, unsigned char value)
{
  if (!page) {
    return;
  }
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    page_local->cs_tainted = value;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_tainted = (bool) value;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_tainted = (bool) value;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_tainted = (bool) value;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_tainted = (bool) value;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->cs_tainted = (bool) value;
  }
}

unsigned char page_is_cs_nx(vm_page_t page)
{
  if (!page) {
    return false;
  }
  unsigned char retval = 0;
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    retval = page_local->cs_nx;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    retval = page_local->cs_nx;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->cs_nx;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->cs_nx;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->cs_nx;
  }
  return retval;
}

void page_set_cs_nx(vm_page_t page, unsigned char value)
{
  if (!page) {
    return;
  }
  if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
      macOS_Sonoma() || macOS_Sequoia())
  {
    vm_page_fake_bigsur_t page_local = (vm_page_fake_bigsur_t) page;
    page_local->cs_nx = value;
  } else if (macOS_HighSierra() || macOS_Mojave() || macOS_Catalina()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_nx = (bool) value;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_nx = (bool) value;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_nx = (bool) value;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_nx = (bool) value;
  }
}

bool page_is_slid(vm_page_t page)
{
  // As best I can tell, the notion of slid pages is absent in macOS Mojave
  // and above.
  if (!page || macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    return false;
  }
  bool retval = false;
  if (macOS_HighSierra()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    retval = page_local->slid;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    retval = page_local->slid;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    retval = page_local->slid;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    retval = page_local->slid;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    retval = page_local->slid;
  }
  return retval;
}

void page_set_slid(vm_page_t page, bool flag)
{
  // As best I can tell, the notion of slid pages is absent in macOS Mojave
  // and above.
  if (!page || macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    return;
  }
  if (macOS_HighSierra()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->slid = flag;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->slid = flag;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->slid = flag;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->slid = flag;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->slid = flag;
  }
}

vm_object_t page_object(vm_page_t page)
{
  if (!page) {
    return NULL;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
        macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
        macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
    {
      offset_in_struct = offsetof(struct vm_page_fake_sierra, vm_page_object);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct vm_page_fake_elcapitan, object);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct vm_page_fake_yosemite, object);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct vm_page_fake_mavericks, object);
    }
  }

  vm_object_t retval = NULL;
  if (offset_in_struct != -1) {
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
        macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
        macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
    {
      vm_page_object_t packed =
        *((vm_page_object_t *)((vm_map_offset_t)page + offset_in_struct));
      retval = (vm_object_t) vm_page_unpack_ptr(packed);
    } else {
      retval = *((vm_object_t *)((vm_map_offset_t)page + offset_in_struct));
    }
  }

  return retval;
}

vm_object_offset_t page_object_offset(vm_page_t page)
{
  if (!page) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
        macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
        macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
    {
      offset_in_struct = offsetof(struct vm_page_fake_sierra, offset);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct vm_page_fake_elcapitan, offset);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct vm_page_fake_yosemite, offset);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct vm_page_fake_mavericks, offset);
    }
  }

  vm_object_offset_t retval = 0;
  if (offset_in_struct != -1) {
    retval = *((vm_object_offset_t *)((vm_map_offset_t)page + offset_in_struct));
  }

  return retval;
}

// 'struct vm_object' is defined in the xnu kernel's osfmk/vm/vm_object.h
typedef struct _vm_object_fake_mavericks {
  uint64_t pad1[2];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[14];
  /* hold object lock when altering */
  unsigned int // Offset 0xc8
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    __object2_unused_bits:9; /* for expansion */
} *vm_object_fake_mavericks_t;

typedef struct _vm_object_fake_mavericks_debug {
  uint64_t pad1[2];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[15];
  /* hold object lock when altering */
  unsigned int // Offset 0xd0
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    __object2_unused_bits:9; /* for expansion */
} *vm_object_fake_mavericks_debug_t;

typedef struct _vm_object_fake_yosemite {
  uint64_t pad1[2];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[13];
  /* hold object lock when altering */
  unsigned int // Offset 0xc0
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_yosemite_t;

typedef struct _vm_object_fake_yosemite_dev_debug {
  uint64_t pad1[2];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[14];
  /* hold object lock when altering */
  unsigned int // Offset 0xc8
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_yosemite_dev_debug_t;

typedef struct _vm_object_fake_sierra {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x40
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[13];
  /* hold object lock when altering */
  unsigned int // Offset 0xb8
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_sierra_t;

typedef struct _vm_object_fake_sierra_dev_debug {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[6];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set 
                                 * to volatile/emtpy, this is the task 
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[14];
  /* hold object lock when altering */
  unsigned int // Offset 0xc8
    wimg_bits:8,    /* cache WIMG bits         */  
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    hashed:1,       /* object/pager entered in hash */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_sierra_dev_debug_t;

typedef struct _vm_object_fake_highsierra {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x40
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set
                                 * to volatile/emtpy, this is the task
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[11];
  /* hold object lock when altering */
  unsigned int // Offset 0xa8
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_highsierra_t;

typedef struct _vm_object_fake_highsierra_dev_debug {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[6];
  vm_object_t shadow; // Offset 0x48
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_purgeable_owner; /* If the purg'a'ble bits below are set
                                 * to volatile/emtpy, this is the task
                                 * that owns this purgeable object.
                                 */
    struct vm_shared_region_slide_info *vou_slide_info;
  } vo_un2;
  uint64_t pad3[11];
  /* hold object lock when altering */
  unsigned int // Offset 0xb0
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_slid:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_highsierra_dev_debug_t;

typedef struct _vm_object_fake_catalina {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x40
  uint64_t pad3[1];
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow (offset 0x50) */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_owner; /* If the object is purgeable
                       * or has a "ledger_tag", this
                       * is the task that owns it.
                       */
  } vo_un2;
  uint32_t pad4[19];
  /* hold object lock when altering */
  unsigned int // Offset 0xa4
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_is_shared_cache:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_catalina_t;

typedef struct _vm_object_fake_catalina_dev_debug {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[6];
  vm_object_t shadow; // Offset 0x48
  uint64_t pad3[1];
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow (offset 0x58) */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_owner; /* If the object is purgeable
                       * or has a "ledger_tag", this
                       * is the task that owns it.
                       */
  } vo_un2;
  uint32_t pad4[19];
  /* hold object lock when altering */
  unsigned int // Offset 0xac
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_is_shared_cache:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_catalina_dev_debug_t;

typedef struct _vm_object_fake_monterey_4 {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[5];
  vm_object_t shadow; // Offset 0x40
  uint64_t pad3[1];
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow (offset 0x50) */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_owner; /* If the object is purgeable
                       * or has a "ledger_tag", this
                       * is the task that owns it.
                       */
  } vo_un2;
  uint32_t pad4[19];
  /* hold object lock when altering */
  unsigned int // Offset 0xa4
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_is_shared_cache:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_monterey_4_t;

typedef struct _vm_object_fake_sonoma_1 {
  uint64_t pad1[1];
  lck_rw_t Lock;
  uint64_t pad2[6];
  vm_object_t shadow; // Offset 0x48
  uint64_t pad3[1];
  union {
    vm_object_offset_t vou_shadow_offset; /* Offset into shadow (offset 0x58) */
    clock_sec_t vou_cache_ts; /* age of an external object
                               * present in cache
                               */
    task_t vou_owner; /* If the object is purgeable
                       * or has a "ledger_tag", this
                       * is the task that owns it.
                       */
  } vo_un2;
  uint32_t pad4[19];
  /* hold object lock when altering */
  unsigned int // Offset 0xac
    wimg_bits:8,    /* cache WIMG bits         */
    code_signed:1,  /* pages are signed and should be
                       validated; the signatures are stored
                       with the pager */
    transposed:1,   /* object was transposed with another */
    mapping_in_progress:1, /* pager being mapped/unmapped */
    phantom_isssd:1,
    volatile_empty:1,
    volatile_fault:1,
    all_reusable:1,
    blocked_access:1,
    set_cache_attr:1,
    object_is_shared_cache:1,
    purgeable_queue_type:2,
    purgeable_queue_group:3,
    io_tracking:1,
    no_tag_update:1,
    __object2_unused_bits:7; /* for expansion */
} *vm_object_fake_sonoma_1_t;

bool object_is_code_signed(vm_object_t object)
{
  if (!object) {
    return false;
  }
  bool retval = false;
  if (OSX_Mavericks()) {
    if (kernel_type_is_release()) {
      vm_object_fake_mavericks_t object_local =
        (vm_object_fake_mavericks_t) object;
      retval = object_local->code_signed;
    } else if (kernel_type_is_debug()) {
      vm_object_fake_mavericks_debug_t object_local =
        (vm_object_fake_mavericks_debug_t) object;
      retval = object_local->code_signed;
    }
  } else if (macOS_Sierra()) {
    if (kernel_type_is_release()) {
      vm_object_fake_sierra_t object_local =
        (vm_object_fake_sierra_t) object;
      retval = object_local->code_signed;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_sierra_dev_debug_t object_local =
        (vm_object_fake_sierra_dev_debug_t) object;
      retval = object_local->code_signed;
    }
  } else if (macOS_HighSierra() || macOS_Mojave()) {
    if (kernel_type_is_release()) {
      vm_object_fake_highsierra_t object_local =
        (vm_object_fake_highsierra_t) object;
      retval = object_local->code_signed;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_highsierra_dev_debug_t object_local =
        (vm_object_fake_highsierra_dev_debug_t) object;
      retval = object_local->code_signed;
    }
  } else if (macOS_Catalina() || macOS_BigSur() ||
             macOS_Monterey_less_than_4())
  {
    if (kernel_type_is_release()) {
      vm_object_fake_catalina_t object_local =
        (vm_object_fake_catalina_t) object;
      retval = object_local->code_signed;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_catalina_dev_debug_t object_local =
        (vm_object_fake_catalina_dev_debug_t) object;
      retval = object_local->code_signed;
    }
  } else if (macOS_Monterey_less_than_7_1() ||
             macOS_Ventura_less_than_6_1() ||
             macOS_Sonoma_less_than_1())
  {
    vm_object_fake_monterey_4_t object_local =
      (vm_object_fake_monterey_4_t) object;
    retval = object_local->code_signed;
  } else if (macOS_Monterey_7_1_or_greater() ||
             macOS_Ventura_6_1_or_greater() ||
             macOS_Sonoma_1_or_greater() ||
             macOS_Sequoia())
  {
    vm_object_fake_sonoma_1_t object_local =
      (vm_object_fake_sonoma_1_t) object;
    retval = object_local->code_signed;
  } else {
    if (kernel_type_is_release()) {
      vm_object_fake_yosemite_t object_local =
        (vm_object_fake_yosemite_t) object;
      retval = object_local->code_signed;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_yosemite_dev_debug_t object_local =
        (vm_object_fake_yosemite_dev_debug_t) object;
      retval = object_local->code_signed;
    }
  }
  return retval;
}

void object_set_code_signed(vm_object_t object, bool flag)
{
  if (!object) {
    return;
  }
  if (OSX_Mavericks()) {
    if (kernel_type_is_release()) {
      vm_object_fake_mavericks_t object_local =
        (vm_object_fake_mavericks_t) object;
      object_local->code_signed = flag;
    } else if (kernel_type_is_debug()) {
      vm_object_fake_mavericks_debug_t object_local =
        (vm_object_fake_mavericks_debug_t) object;
      object_local->code_signed = flag;
    }
  } else if (macOS_Sierra()) {
    if (kernel_type_is_release()) {
      vm_object_fake_sierra_t object_local =
        (vm_object_fake_sierra_t) object;
      object_local->code_signed = flag;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_sierra_dev_debug_t object_local =
        (vm_object_fake_sierra_dev_debug_t) object;
      object_local->code_signed = flag;
    }
  } else if (macOS_HighSierra() || macOS_Mojave()) {
    if (kernel_type_is_release()) {
      vm_object_fake_highsierra_t object_local =
        (vm_object_fake_highsierra_t) object;
      object_local->code_signed = flag;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_highsierra_dev_debug_t object_local =
        (vm_object_fake_highsierra_dev_debug_t) object;
      object_local->code_signed = flag;
    }
  } else if (macOS_Catalina() || macOS_BigSur() ||
             macOS_Monterey_less_than_4())
  {
    if (kernel_type_is_release()) {
      vm_object_fake_catalina_t object_local =
        (vm_object_fake_catalina_t) object;
      object_local->code_signed = flag;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_catalina_dev_debug_t object_local =
        (vm_object_fake_catalina_dev_debug_t) object;
      object_local->code_signed = flag;
    }
  } else if (macOS_Monterey_less_than_7_1() ||
             macOS_Ventura_less_than_6_1() ||
             macOS_Sonoma_less_than_1())
  {
    vm_object_fake_monterey_4_t object_local =
      (vm_object_fake_monterey_4_t) object;
    object_local->code_signed = flag;
  } else if (macOS_Monterey_7_1_or_greater() ||
             macOS_Ventura_6_1_or_greater() ||
             macOS_Sonoma_1_or_greater() ||
             macOS_Sequoia())
  {
    vm_object_fake_sonoma_1_t object_local =
      (vm_object_fake_sonoma_1_t) object;
    object_local->code_signed = flag;
  } else {
    if (kernel_type_is_release()) {
      vm_object_fake_yosemite_t object_local =
        (vm_object_fake_yosemite_t) object;
      object_local->code_signed = flag;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_yosemite_dev_debug_t object_local =
        (vm_object_fake_yosemite_dev_debug_t) object;
      object_local->code_signed = flag;
    }
  }
}

bool object_is_slid(vm_object_t object)
{
  // As best I can tell, the notion of slid objects is absent in macOS Mojave
  // and above.
  if (!object || macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    return false;
  }
  bool retval = false;
  if (OSX_Mavericks()) {
    if (kernel_type_is_release()) {
      vm_object_fake_mavericks_t object_local =
        (vm_object_fake_mavericks_t) object;
      retval = object_local->object_slid;
    } else if (kernel_type_is_debug()) {
      vm_object_fake_mavericks_debug_t object_local =
        (vm_object_fake_mavericks_debug_t) object;
      retval = object_local->object_slid;
    }
  } else if (macOS_Sierra()) {
    if (kernel_type_is_release()) {
      vm_object_fake_sierra_t object_local =
        (vm_object_fake_sierra_t) object;
      retval = object_local->object_slid;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_sierra_dev_debug_t object_local =
        (vm_object_fake_sierra_dev_debug_t) object;
      retval = object_local->object_slid;
    }
  } else if (macOS_HighSierra()) {
    if (kernel_type_is_release()) {
      vm_object_fake_highsierra_t object_local =
        (vm_object_fake_highsierra_t) object;
      retval = object_local->object_slid;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_highsierra_dev_debug_t object_local =
        (vm_object_fake_highsierra_dev_debug_t) object;
      retval = object_local->object_slid;
    }
  } else {
    if (kernel_type_is_release()) {
      vm_object_fake_yosemite_t object_local =
        (vm_object_fake_yosemite_t) object;
      retval = object_local->object_slid;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_yosemite_dev_debug_t object_local =
        (vm_object_fake_yosemite_dev_debug_t) object;
      retval = object_local->object_slid;
    }
  }
  return retval;
}

vm_object_t object_get_shadow(vm_object_t object)
{
  if (!object) {
    return NULL;
  }
  vm_object_t retval = NULL;
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey_less_than_4())
  {
    if (kernel_type_is_release()) {
      vm_object_fake_sierra_t object_local =
        (vm_object_fake_sierra_t) object;
      retval = object_local->shadow;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_sierra_dev_debug_t object_local =
        (vm_object_fake_sierra_dev_debug_t) object;
      retval = object_local->shadow;
    }
  } else if (macOS_Monterey_less_than_7_1() ||
             macOS_Ventura_less_than_6_1() ||
             macOS_Sonoma_less_than_1())
  {
    vm_object_fake_monterey_4_t object_local =
      (vm_object_fake_monterey_4_t) object;
    retval = object_local->shadow;
  } else if (macOS_Monterey_7_1_or_greater() ||
             macOS_Ventura_6_1_or_greater() ||
             macOS_Sonoma_1_or_greater() ||
             macOS_Sequoia())
  {
    vm_object_fake_sonoma_1_t object_local =
      (vm_object_fake_sonoma_1_t) object;
    retval = object_local->shadow;
  } else {
    vm_object_fake_yosemite_t object_local =
      (vm_object_fake_yosemite_t) object;
    retval = object_local->shadow;
  }
  return retval;
}

vm_object_offset_t object_get_shadow_offset(vm_object_t object)
{
  if (!object) {
    return 0;
  }
  vm_object_offset_t retval = 0;
  if (macOS_Monterey_7_1_or_greater() ||
      macOS_Ventura_6_1_or_greater() ||
      macOS_Sonoma_1_or_greater() ||
      macOS_Sequoia())
  {
    vm_object_fake_sonoma_1_t object_local =
      (vm_object_fake_sonoma_1_t) object;
    retval = object_local->vo_un2.vou_shadow_offset;
  } else if (macOS_Monterey_4_or_greater() ||
             macOS_Ventura_less_than_6_1() ||
             macOS_Sonoma_less_than_1())
  {
    vm_object_fake_monterey_4_t object_local =
      (vm_object_fake_monterey_4_t) object;
    retval = object_local->vo_un2.vou_shadow_offset;
  } else if (macOS_Catalina() || macOS_BigSur() ||
             macOS_Monterey_less_than_4())
  {
    if (kernel_type_is_release()) {
      vm_object_fake_catalina_t object_local =
        (vm_object_fake_catalina_t) object;
      retval = object_local->vo_un2.vou_shadow_offset;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_catalina_dev_debug_t object_local =
        (vm_object_fake_catalina_dev_debug_t) object;
      retval = object_local->vo_un2.vou_shadow_offset;
    }
  } else if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    if (kernel_type_is_release()) {
      vm_object_fake_sierra_t object_local =
        (vm_object_fake_sierra_t) object;
      retval = object_local->vo_un2.vou_shadow_offset;
    } else if (kernel_type_is_development() ||
               kernel_type_is_debug())
    {
      vm_object_fake_sierra_dev_debug_t object_local =
        (vm_object_fake_sierra_dev_debug_t) object;
      retval = object_local->vo_un2.vou_shadow_offset;
    }
  } else {
    vm_object_fake_yosemite_t object_local =
      (vm_object_fake_yosemite_t) object;
    retval = object_local->vo_un2.vou_shadow_offset;
  }
  return retval;
}

// From the xnu kernel's osfmk/vm/vm_object.h
#define OBJECT_LOCK_SHARED    0
#define OBJECT_LOCK_EXCLUSIVE 1

void vm_object_unlock(vm_object_t object)
{
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave() ||
      macOS_Catalina() || macOS_BigSur() || macOS_Monterey() ||
      macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia())
  {
    vm_object_unlock_ptr(object);
    return;
  }
  if (!object) {
    return;
  }
  vm_object_fake_yosemite_t object_local = (vm_object_fake_yosemite_t) object;
  lck_rw_done(&object_local->Lock);
}

// Possible value for p_flag, from the xnu kernel's bsd/sys/proc.h
#define P_LP64      0x00000004  /* Process is LP64 */

// Possible values for p_lflag, from the xnu kernel's bsd/sys/proc_internal.h
#define P_LVFORK    0x00000100  /* parent proc of a vfork */
#define P_LINVFORK  0x00000200  /* child proc of a vfork */
#define P_LREGISTER 0x00800000  /* thread start fns registered  */

// Values for p_acflag, from the xnu kernel's bsd/sys/acct.h
#define AFORK   0x01  /* fork'd but not exec'd */
#define ASU     0x02  /* used super-user permissions */
#define ACOMPAT 0x04  /* used compatibility mode */
#define ACORE   0x08  /* dumped core */
#define AXSIG   0x10  /* killed by a signal */

// "struct proc" is defined in the xnu kernel's bsd/sys/proc_internal.h.
typedef struct _proc_fake_mavericks {
  uint32_t pad1[4];
  pid_t p_pid;            // Offset 0x10
  task_t task;            // Offset 0x18
  uint32_t pad2[10];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[68];
  unsigned int p_flag;    // P_* flags (offset 0x160)
  unsigned int p_lflag;
  uint32_t pad4[78];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack
  int32_t p_argc;
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2a8)
  uint32_t pad5[50];
  u_short p_acflag;       // Offset 0x378
} *proc_fake_mavericks_t;

typedef struct _proc_fake_yosemite {
  uint32_t pad1[4];
  pid_t p_pid;            // Offset 0x10
  task_t task;            // Offset 0x18
  uint32_t pad2[10];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[68];
  unsigned int p_flag;    // P_* flags (offset 0x160)
  unsigned int p_lflag;
  uint32_t pad4[78];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack
  int32_t p_argc;
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2a8)
  uint32_t pad5[52];
  u_short p_acflag;       // Offset 0x380
} *proc_fake_yosemite_t;

typedef struct _proc_fake_elcapitan {
  uint32_t pad1[4];
  pid_t p_pid;            // Offset 0x10
  task_t task;            // Offset 0x18
  uint32_t pad2[10];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[72];
  unsigned int p_flag;    // P_* flags (offset 0x170)
  unsigned int p_lflag;
  uint32_t pad4[78];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack
  int32_t p_argc;
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2b8)
  uint32_t pad5[52];
  u_short p_acflag;       // Offset 0x390
} *proc_fake_elcapitan_t;

typedef struct _proc_fake_mojave {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[10];
  uint64_t p_uniqueid;    // Offset 0x40
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[64];
  unsigned int p_flag;    // P_* flags (offset 0x164)
  unsigned int p_lflag;
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x298)
  int32_t p_argc;         // Offset 0x29c
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2a0)
  uint32_t pad6[51];
  u_short p_acflag;       // Offset 0x374
} *proc_fake_mojave_t;

typedef struct _proc_fake_catalina {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[70];
  unsigned int p_flag;    // P_* flags (offset 0x184)
  unsigned int p_lflag;
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x2b8)
  int32_t p_argc;         // Offset 0x2bc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2c0)
  uint32_t pad6[55];
  u_short p_acflag;       // Offset 0x3a4
} *proc_fake_catalina_t;

typedef struct _proc_fake_bigsur {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[64];
  unsigned int p_flag;    // P_* flags (offset 0x16c)
  unsigned int p_lflag;
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x2a0)
  int32_t p_argc;         // Offset 0x2a4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x2a8)
  uint32_t pad6[55];
  u_short p_acflag;       // Offset 0x38c
} *proc_fake_bigsur_t;

typedef struct _proc_fake_monterey {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[100];
  unsigned int p_flag;    // P_* flags (offset 0x1fc)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x328)
  int32_t p_argc;         // Offset 0x32c
  user_addr_t user_stack; // Where user stack was allocated (offset 0x330)
  uint32_t pad6[53];
  u_short p_acflag;       // Offset 0x40c
} *proc_fake_monterey_t;

typedef struct _proc_fake_monterey_dev {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[104];
  unsigned int p_flag;    // P_* flags (offset 0x20c)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x338)
  int32_t p_argc;         // Offset 0x33c
  user_addr_t user_stack; // Where user stack was allocated (offset 0x340)
  uint32_t pad6[53];
  u_short p_acflag;       // Offset 0x41c
} *proc_fake_monterey_dev_t;

typedef struct _proc_fake_monterey_1 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[144];
  unsigned int p_flag;    // P_* flags (offset 0x2ac)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3d8)
  int32_t p_argc;         // Offset 0x3dc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3e0)
  uint32_t pad6[49];
  u_short p_acflag;       // Offset 0x4ac
} *proc_fake_monterey_1_t;

typedef struct _proc_fake_monterey_dev_1 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[148];
  unsigned int p_flag;    // P_* flags (offset 0x2bc)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3e8)
  int32_t p_argc;         // Offset 0x3ec
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3f0)
  uint32_t pad6[49];
  u_short p_acflag;       // Offset 0x4bc
} *proc_fake_monterey_dev_1_t;

typedef struct _proc_fake_monterey_3 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[142];
  unsigned int p_flag;    // P_* flags (offset 0x2a4)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3d0)
  int32_t p_argc;         // Offset 0x3d4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3d8)
  uint32_t pad6[49];
  u_short p_acflag;       // Offset 0x4a4
} *proc_fake_monterey_3_t;

typedef struct _proc_fake_monterey_dev_3 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[6];
  pid_t p_pid;            // Offset 0x68
  uint32_t pad4[146];
  unsigned int p_flag;    // P_* flags (offset 0x2b4)
  unsigned int p_lflag;
  uint32_t pad5[73];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3e0)
  int32_t p_argc;         // Offset 0x3e4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3e8)
  uint32_t pad6[49];
  u_short p_acflag;       // Offset 0x4b4
} *proc_fake_monterey_dev_3_t;

typedef struct _proc_fake_ventura {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[142];
  unsigned int p_flag;    // P_* flags (offset 0x29c)
  unsigned int p_lflag;   // Offset 0x2a0
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3d0)
  int32_t p_argc;         // Offset 0x3d4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3d8)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x49c
} *proc_fake_ventura_t;

typedef struct _proc_fake_ventura_dev {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[146];
  unsigned int p_flag;    // P_* flags (offset 0x2a4)
  unsigned int p_lflag;   // Offset 0x2a8
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x3d8)
  int32_t p_argc;         // Offset 0x3dc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x3e0)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x4a4
} *proc_fake_ventura_dev_t;

typedef struct _proc_fake_ventura_3 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[268];
  unsigned int p_flag;    // P_* flags (offset 0x494)
  unsigned int p_lflag;   // Offset 0x498
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5c8)
  int32_t p_argc;         // Offset 0x5cc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5d0)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x694
} *proc_fake_ventura_3_t;

typedef struct _proc_fake_ventura_dev_3 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[270];
  unsigned int p_flag;    // P_* flags (offset 0x49c)
  unsigned int p_lflag;   // Offset 0x4a0
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5d0)
  int32_t p_argc;         // Offset 0x5d4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5d8)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x69c
} *proc_fake_ventura_dev_3_t;

typedef struct _proc_fake_sonoma {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[272];
  unsigned int p_flag;    // P_* flags (offset 0x4a4)
  unsigned int p_lflag;   // Offset 0x4a8
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5d8)
  int32_t p_argc;         // Offset 0x5dc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5e0)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x6a4
} *proc_fake_sonoma_t;

typedef struct _proc_fake_sonoma_dev {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[274];
  unsigned int p_flag;    // P_* flags (offset 0x4ac)
  unsigned int p_lflag;   // Offset 0x4b0
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5e0)
  int32_t p_argc;         // Offset 0x5e4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5e8)
  uint32_t pad6[47];
  u_short p_acflag;       // Offset 0x6ac
} *proc_fake_sonoma_dev_t;

typedef struct _proc_fake_sonoma_4 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[272];
  unsigned int p_flag;    // P_* flags (offset 0x4a4)
  unsigned int p_lflag;   // Offset 0x4a8
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5d8)
  int32_t p_argc;         // Offset 0x5dc
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5e0)
  uint32_t pad6[51];
  u_short p_acflag;       // Offset 0x6b4
} *proc_fake_sonoma_4_t;

typedef struct _proc_fake_sonoma_dev_4 {
  uint32_t pad1[4];
  task_t task;            // Offset 0x10 (Not valid on Ventura and up?)
  uint32_t pad2[12];
  uint64_t p_uniqueid;    // Offset 0x48 (Not valid on 12.1 and up?)
  uint32_t pad3[4];
  pid_t p_pid;            // Offset 0x60
  uint32_t pad4[278];
  unsigned int p_flag;    // P_* flags (offset 0x4bc)
  unsigned int p_lflag;   // Offset 0x4c0
  uint32_t pad5[75];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack (offset 0x5f0)
  int32_t p_argc;         // Offset 0x5f4
  user_addr_t user_stack; // Where user stack was allocated (offset 0x5f8)
  uint32_t pad6[51];
  u_short p_acflag;       // Offset 0x6cc
} *proc_fake_sonoma_dev_4_t;

static uint64_t proc_uniqueid(proc_t proc)
{
  if (!proc) {
    return 0;
  }
  // As of macOS 12.1, finding a process's uniquepid became much more
  // complicated, to the point that we're forced to use the system call. It's
  // also available on 12.0.1, so we can also use it there.
  if (macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    return proc_uniqueid_ptr(proc);
  }
  if (macOS_Catalina() || macOS_BigSur()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) proc;
    return p->p_uniqueid;
  }
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->p_uniqueid;
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return p->p_uniqueid;
}

static task_t proc_task(proc_t proc)
{
  if (!proc) {
    return NULL;
  }
  // As of macOS 13, finding a process's task became much more complicated.
  // So just use the (private) system call.
  if (macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia()) {
    return proc_task_ptr(proc);
  }
  if (macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey())
  {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->task;
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return p->task;
}

bool is_64bit_task(task_t task);

static bool IS_64BIT_PROCESS(proc_t proc)
{
  if (!proc) {
    return false;
  }
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_4_t p = (proc_fake_sonoma_4_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_4_t p = (proc_fake_sonoma_dev_4_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Sonoma()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_t p = (proc_fake_sonoma_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_t p = (proc_fake_sonoma_dev_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Ventura_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_3_t p = (proc_fake_ventura_3_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_3_t p = (proc_fake_ventura_dev_3_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Ventura()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_t p = (proc_fake_ventura_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_t p = (proc_fake_ventura_dev_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Monterey_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_3_t p = (proc_fake_monterey_3_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_3_t p = (proc_fake_monterey_dev_3_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Monterey_1_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_1_t p = (proc_fake_monterey_1_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_1_t p = (proc_fake_monterey_dev_1_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_t p = (proc_fake_monterey_t) proc;
      return (p && (p->p_flag & P_LP64));
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_t p = (proc_fake_monterey_dev_t) proc;
      return (p && (p->p_flag & P_LP64));
    }
  } else if (macOS_BigSur()) {
    proc_fake_bigsur_t p = (proc_fake_bigsur_t) proc;
    return (p && (p->p_flag & P_LP64));
  } else if (macOS_Catalina()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) proc;
    return (p && (p->p_flag & P_LP64));
  }
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return (p && (p->p_flag & P_LP64));
  }
  if (macOS_HighSierra() || macOS_Sierra() || OSX_ElCapitan()) {
    proc_fake_elcapitan_t p = (proc_fake_elcapitan_t) proc;
    return (p && (p->p_flag & P_LP64));
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return (p && (p->p_flag & P_LP64));
}

u_short get_acflag(proc_t proc)
{
  if (!proc) {
    return 0;
  }
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_4_t p = (proc_fake_sonoma_4_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_4_t p = (proc_fake_sonoma_dev_4_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Sonoma()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_t p = (proc_fake_sonoma_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_t p = (proc_fake_sonoma_dev_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Ventura_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_3_t p = (proc_fake_ventura_3_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_3_t p = (proc_fake_ventura_dev_3_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Ventura()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_t p = (proc_fake_ventura_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_t p = (proc_fake_ventura_dev_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Monterey_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_3_t p = (proc_fake_monterey_3_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_3_t p = (proc_fake_monterey_dev_3_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Monterey_1_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_1_t p = (proc_fake_monterey_1_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_1_t p = (proc_fake_monterey_dev_1_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_t p = (proc_fake_monterey_t) proc;
      return p->p_acflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_t p = (proc_fake_monterey_dev_t) proc;
      return p->p_acflag;
    }
  } else if (macOS_BigSur()) {
    proc_fake_bigsur_t p = (proc_fake_bigsur_t) proc;
    return p->p_acflag;
  } else if (macOS_Catalina()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) proc;
    return p->p_acflag;
  }
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->p_acflag;
  }
  if (OSX_Mavericks()) {
    proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
    return p->p_acflag;
  }
  if (OSX_Yosemite()) {
    proc_fake_yosemite_t p = (proc_fake_yosemite_t) proc;
    return p->p_acflag;
  }
  // ElCapitan or Sierra or HighSierra
  proc_fake_elcapitan_t p = (proc_fake_elcapitan_t) proc;
  return p->p_acflag;
}

unsigned int get_lflag(proc_t proc)
{
  if (!proc) {
    return 0;
  }
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_4_t p = (proc_fake_sonoma_4_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_4_t p = (proc_fake_sonoma_dev_4_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Sonoma()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_t p = (proc_fake_sonoma_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_t p = (proc_fake_sonoma_dev_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Ventura_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_3_t p = (proc_fake_ventura_3_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_3_t p = (proc_fake_ventura_dev_3_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Ventura()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_t p = (proc_fake_ventura_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_t p = (proc_fake_ventura_dev_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Monterey_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_3_t p = (proc_fake_monterey_3_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_3_t p = (proc_fake_monterey_dev_3_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Monterey_1_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_1_t p = (proc_fake_monterey_1_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_1_t p = (proc_fake_monterey_dev_1_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_t p = (proc_fake_monterey_t) proc;
      return p->p_lflag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_t p = (proc_fake_monterey_dev_t) proc;
      return p->p_lflag;
    }
  } else if (macOS_BigSur()) {
    proc_fake_bigsur_t p = (proc_fake_bigsur_t) proc;
    return p->p_lflag;
  } else if (macOS_Catalina()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) proc;
    return p->p_lflag;
  }
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->p_lflag;
  }
  if (macOS_HighSierra() || macOS_Sierra() || OSX_ElCapitan()) {
    proc_fake_elcapitan_t p = (proc_fake_elcapitan_t) proc;
    return p->p_lflag;
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return p->p_lflag;
}

unsigned int get_flag(proc_t proc)
{
  if (!proc) {
    return 0;
  }
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_4_t p = (proc_fake_sonoma_4_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_4_t p = (proc_fake_sonoma_dev_4_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Sonoma()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_t p = (proc_fake_sonoma_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_t p = (proc_fake_sonoma_dev_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Ventura_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_3_t p = (proc_fake_ventura_3_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_3_t p = (proc_fake_ventura_dev_3_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Ventura()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_t p = (proc_fake_ventura_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_t p = (proc_fake_ventura_dev_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Monterey_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_3_t p = (proc_fake_monterey_3_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_3_t p = (proc_fake_monterey_dev_3_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Monterey_1_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_1_t p = (proc_fake_monterey_1_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_1_t p = (proc_fake_monterey_dev_1_t) proc;
      return p->p_flag;
    }
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_t p = (proc_fake_monterey_t) proc;
      return p->p_flag;
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_t p = (proc_fake_monterey_dev_t) proc;
      return p->p_flag;
    }
  } else if (macOS_BigSur()) {
    proc_fake_bigsur_t p = (proc_fake_bigsur_t) proc;
    return p->p_flag;
  } else if (macOS_Catalina()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) proc;
    return p->p_flag;
  }
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->p_flag;
  }
  if (macOS_HighSierra() || macOS_Sierra() || OSX_ElCapitan()) {
    proc_fake_elcapitan_t p = (proc_fake_elcapitan_t) proc;
    return p->p_flag;
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return p->p_flag;
}

bool forked_but_not_execd(proc_t proc)
{
  return ((get_acflag(proc) & AFORK) != 0);
}

// From the xnu kernel's osfmk/task/kern.h
#define THROTTLE_LEVEL_NONE     -1

// From the xnu kernel's osfmk/i386/fpu.h
typedef enum {
  FXSAVE32  = 1,
  FXSAVE64  = 2,
  XSAVE32   = 3,
  XSAVE64   = 4,
  FP_UNUSED = 5
} fp_save_layout_t;

// "struct thread" is defined in osfmk/kern/thread.h.  "struct machine_thread"
// is defined in osfmk/i386/thread.h.  For the offset of iotier_override, look
// at the machine code for set_thread_iotier_override().

// Only "map"'s offset has changed in Sequoia, and then only in the release
// kernel. We don't currently use "map".
typedef struct thread_fake_sequoia
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[118];
  vm_map_t map;         // Offset 0x620
} thread_fake_sequoia_t;

// thread_fake_sequoia_dev is exactly the same as
// thread_fake_sonoma_dev_1.
typedef struct thread_fake_sequoia_dev
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[134];
  vm_map_t map;         // Offset 0x6b0
} thread_fake_sequoia_dev_t;

// Only "map"'s offset has changed in Sequoia 15.4. We don't currently use
// "map".
typedef struct thread_fake_sequoia_4
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[120];
  vm_map_t map;         // Offset 0x628
} thread_fake_sequoia_4_t;

typedef struct thread_fake_sequoia_dev_4
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[136];
  vm_map_t map;         // Offset 0x6b8
} thread_fake_sequoia_dev_4_t;

typedef struct thread_fake_sonoma
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[116];
  vm_map_t map;         // Offset 0x618
} thread_fake_sonoma_t;

typedef struct thread_fake_sonoma_dev
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[130];
  vm_map_t map;         // Offset 0x6a0
} thread_fake_sonoma_dev_t;

typedef struct thread_fake_sonoma_1
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[120];
  vm_map_t map;         // Offset 0x628
} thread_fake_sonoma_1_t;

typedef struct thread_fake_sonoma_dev_1
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[134];
  vm_map_t map;         // Offset 0x6b0
} thread_fake_sonoma_dev_1_t;

typedef struct thread_fake_ventura
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[118];
  vm_map_t map;         // Offset 0x620
} thread_fake_ventura_t;

typedef struct thread_fake_ventura_dev
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[132];
  vm_map_t map;         // Offset 0x6a8
} thread_fake_ventura_dev_t;

typedef struct thread_fake_monterey
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[154];
  vm_map_t map;         // Offset 0x6b0
} thread_fake_monterey_t;

typedef struct thread_fake_monterey_dev
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[172];
  vm_map_t map;         // Offset 0x748
} thread_fake_monterey_dev_t;

typedef struct thread_fake_monterey_1
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[128];
  vm_map_t map;         // Offset 0x648
} thread_fake_monterey_1_t;

typedef struct thread_fake_monterey_dev_1
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[142];
  vm_map_t map;         // Offset 0x6d0
} thread_fake_monterey_dev_1_t;

typedef struct thread_fake_monterey_4
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[231];
  int iotier_override;  // Offset 0x444
  uint32_t pad4[126];
  vm_map_t map;         // Offset 0x640
} thread_fake_monterey_4_t;

typedef struct thread_fake_monterey_dev_4
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[249];
  int iotier_override;  // Offset 0x494
  uint32_t pad4[140];
  vm_map_t map;         // Offset 0x6c8
} thread_fake_monterey_dev_4_t;

typedef struct thread_fake_bigsur
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[23];
  int iotier_override;  // Offset 0xc0
  uint32_t pad3[155];
  vm_map_t map;         // Offset 0x330
  uint32_t pad4[74];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x460
} thread_fake_bigsur_t;

typedef struct thread_fake_bigsur_3
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[228];
  int iotier_override;  // Offset 0x438
  uint32_t pad4[155];
  vm_map_t map;         // Offset 0x6a8
} thread_fake_bigsur_3_t;

typedef struct thread_fake_bigsur_4
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa0
  uint32_t pad3[230];
  int iotier_override;  // Offset 0x440
  uint32_t pad4[155];
  vm_map_t map;         // Offset 0x6b0
} thread_fake_bigsur_4_t;

typedef struct thread_fake_bigsur_development
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[23];
  int iotier_override;  // Offset 0xc8
  uint32_t pad3[163];
  vm_map_t map;         // Offset 0x358
  uint32_t pad4[80];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x4a0
} thread_fake_bigsur_development_t;

typedef struct thread_fake_bigsur_development_3
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[246];
  int iotier_override;  // Offset 0x488
  uint32_t pad4[163];
  vm_map_t map;         // Offset 0x718
} thread_fake_bigsur_development_3_t;

typedef struct thread_fake_bigsur_development_4
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[15];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0xa8
  uint32_t pad3[248];
  int iotier_override;  // Offset 0x490
  uint32_t pad4[163];
  vm_map_t map;         // Offset 0x720
} thread_fake_bigsur_development_4_t;

typedef struct thread_fake_catalina
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[21];
  int iotier_override;  // Offset 0xb8
  uint32_t pad3[147];
  vm_map_t map;         // Offset 0x308
  uint32_t pad4[84];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x460
} thread_fake_catalina_t;

typedef struct thread_fake_catalina_development
{
  uint32_t pad1[26];
  integer_t options;    // Offset 0x68
  uint32_t pad2[21];
  int iotier_override;  // Offset 0xc0
  uint32_t pad3[151];
  vm_map_t map;         // Offset 0x320
  uint32_t pad4[90];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x490
} thread_fake_catalina_development_t;

typedef struct thread_fake_catalina_debug
{
  uint32_t pad1[58];
  integer_t options;    // Offset 0xe8
  uint32_t pad2[21];
  int iotier_override;  // Offset 0x140
  uint32_t pad3[169];
  vm_map_t map;         // Offset 0x3e8
  uint32_t pad4[106];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x598
} thread_fake_catalina_debug_t;

typedef struct thread_fake_mojave
{
  uint32_t pad1[22];
  integer_t options;    // Offset 0x58
  uint32_t pad2[23];
  int iotier_override;  // Offset 0xb8
  uint32_t pad3[171];
  vm_map_t map;         // Offset 0x368
  uint32_t pad4[58];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x458
} thread_fake_mojave_t;

typedef struct thread_fake_mojave_development
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[23];
  int iotier_override;  // Offset 0xc0
  uint32_t pad3[171];
  vm_map_t map;         // Offset 0x370
  uint32_t pad4[64];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x478
} thread_fake_mojave_development_t;

// Apple changed some values in the macOS 10.14.2 minor release :-(
typedef struct thread_fake_mojave_development_2
{
  uint32_t pad1[24];
  integer_t options;    // Offset 0x60
  uint32_t pad2[23];
  int iotier_override;  // Offset 0xc0
  uint32_t pad3[175];
  vm_map_t map;         // Offset 0x380
  uint32_t pad4[64];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x488
} thread_fake_mojave_development_2_t;

typedef struct thread_fake_mojave_debug
{
  uint32_t pad1[56];
  integer_t options;    // Offset 0xe0
  uint32_t pad2[23];
  int iotier_override;  // Offset 0x140
  uint32_t pad3[205];
  vm_map_t map;         // Offset 0x478
  uint32_t pad4[64];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x580
} thread_fake_mojave_debug_t;

// Apple changed some values in the macOS 10.14.2 minor release :-(
typedef struct thread_fake_mojave_debug_2
{
  uint32_t pad1[56];
  integer_t options;    // Offset 0xe0
  uint32_t pad2[23];
  int iotier_override;  // Offset 0x140
  uint32_t pad3[209];
  vm_map_t map;         // Offset 0x488
  uint32_t pad4[64];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x590
} thread_fake_mojave_debug_2_t;

typedef struct thread_fake_highsierra
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[193];
  vm_map_t map;         // Offset 0x340
  uint32_t pad3[58];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x430
  uint32_t pad4[30];
  int iotier_override;  // Offset 0x4b0
} thread_fake_highsierra_t;

// As of build 17G7020 the size of the 'machine' struct increased by one byte.
// So the offset of 'iotier_override' was pushed down by one byte.
typedef struct thread_fake_highsierra_17G7020
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[193];
  vm_map_t map;         // Offset 0x340
  uint32_t pad3[58];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x430
  uint32_t pad4[32];
  int iotier_override;  // Offset 0x4b8
} thread_fake_highsierra_17G7020_t;

typedef struct thread_fake_highsierra_development
{
  uint32_t pad1[16];
  integer_t options;    // Offset 0x40
  uint32_t pad2[193];
  vm_map_t map;         // Offset 0x348
  uint32_t pad3[62];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x448
  uint32_t pad4[30];
  int iotier_override;  // Offset 0x4c8
} thread_fake_highsierra_development_t;

// As of build 17G7020 the size of the 'machine' struct increased by one byte.
// So the offset of 'iotier_override' was pushed down by eight bytes.
typedef struct thread_fake_highsierra_development_17G7020
{
  uint32_t pad1[16];
  integer_t options;    // Offset 0x40
  uint32_t pad2[193];
  vm_map_t map;         // Offset 0x348
  uint32_t pad3[62];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x448
  uint32_t pad4[32];
  int iotier_override;  // Offset 0x4d0
} thread_fake_highsierra_development_17G7020_t;

typedef struct thread_fake_highsierra_debug
{
  uint32_t pad1[48];
  integer_t options;    // Offset 0xc0
  uint32_t pad2[227];
  vm_map_t map;         // Offset 0x450
  uint32_t pad3[62];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x550
  uint32_t pad4[46];
  int iotier_override;  // Offset 0x610
} thread_fake_highsierra_debug_t;

// As of build 17G7020 the size of the 'machine' struct increased by one byte.
// So the offset of 'iotier_override' was pushed down by eight bytes.
typedef struct thread_fake_highsierra_debug_17G7020
{
  uint32_t pad1[48];
  integer_t options;    // Offset 0xc0
  uint32_t pad2[227];
  vm_map_t map;         // Offset 0x450
  uint32_t pad3[62];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x550
  uint32_t pad4[48];
  int iotier_override;  // Offset 0x618
} thread_fake_highsierra_debug_17G7020_t;

typedef struct thread_fake_sierra
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[185];
  vm_map_t map;         // Offset 0x320
  uint32_t pad3[53];
  int iotier_override;  // Offset 0x3fc
  uint32_t pad4[16];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x440
} thread_fake_sierra_t;

typedef struct thread_fake_sierra_development
{
  uint32_t pad1[16];
  integer_t options;    // Offset 0x40
  uint32_t pad2[185];
  vm_map_t map;         // Offset 0x328
  uint32_t pad3[57];
  int iotier_override;  // Offset 0x414
  uint32_t pad4[16];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x458
} thread_fake_sierra_development_t;

typedef struct thread_fake_sierra_debug
{
  uint32_t pad1[48];
  integer_t options;    // Offset 0xc0
  uint32_t pad2[219];
  vm_map_t map;         // Offset 0x430
  uint32_t pad3[57];
  int iotier_override;  // Offset 0x51c
  uint32_t pad4[16];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x560
} thread_fake_sierra_debug_t;

typedef struct thread_fake_elcapitan
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[181];
  vm_map_t map;         // Offset 0x310
  uint32_t pad3[54];
  int iotier_override;  // Offset 0x3f0
  uint32_t pad4[17];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x438
} thread_fake_elcapitan_t;

typedef struct thread_fake_elcapitan_development
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[183];
  vm_map_t map;         // Offset 0x318
  uint32_t pad3[58];
  int iotier_override;  // Offset 0x408
  uint32_t pad4[17];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x450
} thread_fake_elcapitan_development_t;

typedef struct thread_fake_elcapitan_debug
{
  uint32_t pad1[46];
  integer_t options;    // Offset 0xb8
  uint32_t pad2[217];
  vm_map_t map;         // Offset 0x420
  uint32_t pad3[58];
  int iotier_override;  // Offset 0x510
  uint32_t pad4[17];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x558
} thread_fake_elcapitan_debug_t;

typedef struct thread_fake_yosemite
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[183];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x318
  uint32_t pad3[22];
  vm_map_t map;         // Offset 0x378
  uint32_t pad4[62];
  int iotier_override;  // Offset 0x478
} thread_fake_yosemite_t;

typedef struct thread_fake_yosemite_development
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[185];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x320
  uint32_t pad3[22];
  vm_map_t map;         // Offset 0x380
  uint32_t pad4[66];
  int iotier_override;  // Offset 0x490
} thread_fake_yosemite_development_t;

typedef struct thread_fake_yosemite_debug
{
  uint32_t pad1[46];
  integer_t options;    // Offset 0xb8
  uint32_t pad2[217];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x420
  uint32_t pad3[38];
  vm_map_t map;         // Offset 0x4c0
  uint32_t pad4[66];
  int iotier_override;  // Offset 0x5d0
} thread_fake_yosemite_debug_t;

typedef struct thread_fake_mavericks
{
  uint32_t pad1[14];
  integer_t options;    // Offset 0x38
  uint32_t pad2[179];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x308
  uint32_t pad3[20];
  vm_map_t map;         // Offset 0x360
  uint32_t pad4[50];
  int iotier_override;  // Offset 0x430
} thread_fake_mavericks_t;

typedef struct thread_fake_mavericks_debug
{
  uint32_t pad1[46];
  integer_t options;    // Offset 0xb8
  uint32_t pad2[211];
  // Actually a member of thread_t's 'machine' member.
  void *ifps;           // Offset 0x408
  uint32_t pad3[36];
  vm_map_t map;         // Offset 0x4a0
  uint32_t pad4[50];
  int iotier_override;  // Offset 0x570
} thread_fake_mavericks_debug_t;

typedef void (*fp_load_t)(thread_t active_thread);
extern "C" fp_load_t fp_load = NULL;

uint64_t g_iotier_override_offset = -1L;

bool initialize_thread_offsets()
{
  if (!fp_load) {
    fp_load = (fp_load_t)
      kernel_dlsym("_fp_load");
    if (!fp_load) {
      return false;
    }
  }

  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey())
  {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_monterey, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_monterey_dev, iotier_override);
    }
  } else if (macOS_BigSur_4_or_greater()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur_4, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur_development_4, iotier_override);
    }
  } else if (macOS_BigSur_less_than_3()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur_development, iotier_override);
    }
  } else if (macOS_BigSur()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur_3, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_bigsur_development_3, iotier_override);
    }
  } else if (macOS_Catalina()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_catalina, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_catalina_development, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_catalina_debug, iotier_override);
    }
  } else if (macOS_Mojave()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_mojave, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_mojave_development, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_mojave_debug, iotier_override);
    }
  } else if (macOS_HighSierra()) {
    if (macOS_HighSierra_less_than_17G7020()) {
      if (kernel_type_is_release()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra, iotier_override);
      } else if (kernel_type_is_development()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra_debug, iotier_override);
      }
    } else {
      if (kernel_type_is_release()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra_17G7020, iotier_override);
      } else if (kernel_type_is_development()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra_development_17G7020, iotier_override);
      } else if (kernel_type_is_debug()) {
        g_iotier_override_offset =
          offsetof(struct thread_fake_highsierra_debug_17G7020, iotier_override);
      }
    }
  } else if (macOS_Sierra()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_sierra, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_sierra_development, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_sierra_debug, iotier_override);
    }
  } else if (OSX_ElCapitan()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_elcapitan, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_elcapitan_development, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_elcapitan_debug, iotier_override);
    }
  } else if (OSX_Yosemite()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_yosemite, iotier_override);
    } else if (kernel_type_is_development()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_yosemite_development, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_yosemite_debug, iotier_override);
    }
  } else if (OSX_Mavericks()) {
    if (kernel_type_is_release()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_mavericks, iotier_override);
    } else if (kernel_type_is_debug()) {
      g_iotier_override_offset =
        offsetof(struct thread_fake_mavericks_debug, iotier_override);
    }
  }
  if (g_iotier_override_offset == -1L) {
    return false;
  }

  return true;
}

// From the xnu kernel's osfmk/kern/thread.h
#define TH_OPT_INTMASK  0x0003  /* interrupt / abort level */

// Modified from the private external function in the xnu kernel's
// osfmk/kern/sched_prim.c
wait_interrupt_t thread_interrupt_level(wait_interrupt_t new_level)
{
  wait_interrupt_t oldval = THREAD_ABORTSAFE;

  thread_t current = current_thread();
  if (!current) {
    return oldval;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
        macOS_Sonoma() || macOS_Sequoia())
    {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_bigsur, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_bigsur_development, options);
      }
    } else if (macOS_Catalina()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_catalina, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_catalina_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_catalina_debug, options);
      }
    } else if (macOS_Mojave()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mojave, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_debug, options);
      }
    } else if (macOS_HighSierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_highsierra, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_debug, options);
      }
    } else if (macOS_Sierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_sierra, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_debug, options);
      }
    } else if (OSX_ElCapitan()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_elcapitan, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_debug, options);
      }
    } else if (OSX_Yosemite()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_yosemite, options);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_development, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_debug, options);
      }
    } else if (OSX_Mavericks()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mavericks, options);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mavericks_debug, options);
      }
    }
  }

  integer_t *options_addr = NULL;
  if (offset_in_struct != -1) {
    options_addr = (integer_t *) ((vm_map_offset_t) current + offset_in_struct);
  }

  if (!options_addr) {
    return oldval;
  }

  oldval = (*options_addr & TH_OPT_INTMASK);
  *options_addr =
    ((*options_addr & ~TH_OPT_INTMASK) | (new_level & TH_OPT_INTMASK));

  return oldval;
}

// Possible value for uu_flag.
#define UT_NOTCANCELPT 0x00000004  /* not a cancelation point */

typedef struct uthread_fake_monterey
{
  uint64_t pad[32];
  int uu_flag;        // Offset 0x100
} *uthread_fake_monterey_t;

typedef struct uthread_fake_monterey_1
{
  uint64_t pad[31];
  int uu_flag;        // Offset 0xf8
} *uthread_fake_monterey_1_t;

typedef struct uthread_fake_monterey_3
{
  uint64_t pad[30];
  int uu_flag;        // Offset 0xf0
} *uthread_fake_monterey_3_t;

typedef struct uthread_fake_catalina
{
  uint64_t pad[33];
  int uu_flag;        // Offset 0x108
} *uthread_fake_catalina_t;

typedef struct uthread_fake_mojave
{
  uint64_t pad[42];
  int uu_flag;        // Offset 0x150
} *uthread_fake_mojave_t;

typedef struct uthread_fake_highsierra
{
  uint64_t pad[40];
  int uu_flag;        // Offset 0x140
} *uthread_fake_highsierra_t;

typedef struct uthread_fake_sierra
{
  uint64_t pad[41];
  int uu_flag;        // Offset 0x148
} *uthread_fake_sierra_t;

typedef struct uthread_fake_elcapitan
{
  uint64_t pad[34];
  int uu_flag;        // Offset 0x110
} *uthread_fake_elcapitan_t;

typedef struct uthread_fake_yosemite
{
  uint64_t pad[35];
  int uu_flag;        // Offset 0x118
} *uthread_fake_yosemite_t;

typedef struct uthread_fake_mavericks
{
  uint64_t pad[36];
  int uu_flag;        // Offset 0x120
} *uthread_fake_mavericks_t;

int get_uu_flag(uthread_t uthread)
{
  if (!uthread) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
        macOS_Monterey_3_or_greater())
    {
      offset_in_struct = offsetof(struct uthread_fake_monterey_3, uu_flag);
    } else if (macOS_Monterey_1_or_greater()) {
      offset_in_struct = offsetof(struct uthread_fake_monterey_1, uu_flag);
    } else if (macOS_Monterey()) {
      offset_in_struct = offsetof(struct uthread_fake_monterey, uu_flag);
    } else if (macOS_Catalina() || macOS_BigSur()) {
      offset_in_struct = offsetof(struct uthread_fake_catalina, uu_flag);
    } else if (macOS_Mojave()) {
      offset_in_struct = offsetof(struct uthread_fake_mojave, uu_flag);
    } else if (macOS_HighSierra()) {
      offset_in_struct = offsetof(struct uthread_fake_highsierra, uu_flag);
    } else if (macOS_Sierra()) {
      offset_in_struct = offsetof(struct uthread_fake_sierra, uu_flag);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct uthread_fake_elcapitan, uu_flag);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct uthread_fake_yosemite, uu_flag);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct uthread_fake_mavericks, uu_flag);
    }
  }

  int retval = 0;
  if (offset_in_struct != -1) {
    retval = *((int *)((vm_map_offset_t) uthread + offset_in_struct));
  }

  return retval;
}

void report_proc_thread_state(const char *header, thread_t thread)
{
  if (!header) {
    return;
  }
  if (!thread) {
    printf("%s: report_proc_thread_state(): 'thread' is NULL!\n", header);
    return;
  }
  uthread_t uthread = get_bsdthread_info(thread);
  task_t task = get_threadtask(thread);
  proc_t proc = NULL;
  if (task) {
    proc = (proc_t) get_bsdtask_info(task);
  }
  if (!proc) {
    proc = current_proc();
  }

  pid_t pid = -1;
  uint64_t uniqueid = -1;
  u_short acflag = -1;
  unsigned int lflag = -1;
  unsigned int flag = -1;
  char procname[PATH_MAX];
  if (proc) {
    pid = proc_pid(proc);
    uniqueid = proc_uniqueid(proc);
    acflag = get_acflag(proc);
    lflag = get_lflag(proc);
    flag = get_flag(proc);
    proc_name(pid, procname, sizeof(procname));
  } else {
    strncpy(procname, "null", sizeof(procname));
  }

  uint16_t tag = thread_get_tag(thread);

  int uu_flag = -1;
  if (uthread) {
    uu_flag = get_uu_flag(uthread);
  }

  printf("%s: report_proc_thread_state(): proc %s[%d:%lld], 64bit %i, acflag \'0x%x\', lflag \'0x%x\', flag \'0x%x\', tag \'0x%x\', uu_flag \'0x%x\'\n",
         header, procname, pid, uniqueid, IS_64BIT_PROCESS(proc),
         acflag, lflag, flag, tag, uu_flag);
}

// Change memory permissions, but only at the lowest level -- that of
// kernel_pmap and of pmap_t structures, not that of kernel_map and of
// vm_map_t and vm_map_entry_t structures.  In version 1 we worked at a higher
// level, but as best I can tell that isn't necessary, and may even have been
// harmful.  In any case, many of the relevant vm_map_entry_t variables (for
// example 'protection') are kept blank for the parts of kernel memory that we
// deal with.  In effect, that structure isn't used to manage permissions in
// standard kernel memory (or in the double-mapped HIB segment that's used to
// implement KPTI in recent versions of macOS and OS X).
//
// This method no longer works properly on macOS Mojave (10.14) and above for
// most of our purposes -- neither pmap_protect() nor pmap_enter().
// pmap_enter() returns no error (when you use it), but attempting to write
// the target memory still triggers a write-protect page fault (error code 3,
// T_PF_PROT | T_PF_WRITE).  This only happens when VM_PROT_WRITE is newly
// added (not when it was already present).  It doesn't happen when
// VM_PROT_EXECUTE is newly added.  I don't know what tricks Apple has played,
// though I may learn more when they release the source code for Mojave's xnu
// kernel.  In the meantime we'll use use brute force where necessary -- by
// changing CR0's write protect bit.
bool set_kernel_physmap_protection(vm_map_offset_t start, vm_map_offset_t end,
                                   vm_prot_t new_prot, bool use_pmap_protect)
{
  vm_map_offset_t start_fixed =
    vm_map_trunc_page(start, vm_map_page_mask(kernel_map));
  vm_map_offset_t end_fixed =
    vm_map_round_page(end, vm_map_page_mask(kernel_map));

  if (start_fixed >= end_fixed) {
    return false;
  }

  // Though we don't access kernel_map here, holding a lock on it seems to
  // help prevent weirdness.  But on Mojave we hang, even if we use
  // vm_map_trylock() instead.
  if (!macOS_Mojave() && !macOS_Catalina() && !macOS_BigSur() &&
      !macOS_Monterey() && !macOS_Ventura() && !macOS_Sonoma() &&
      !macOS_Sequoia())
  {
    vm_map_lock(kernel_map);
  }

  // Apple's comments in their xnu kernel source code claim that
  // pmap_protect() can't be used to increase permissions, and that one should
  // use pmap_enter() for that purpose.  This isn't true.  But there do seem
  // to be some limitations on pmap_protect().  For example, it sometimes
  // fails to add execute permissions where they previously weren't granted.
  // In those cases we need to use pmap_enter().  However, pmap_protect() is
  // much less "invasive" that pmap_enter(), so we should use pmap_protect()
  // where we can.
  bool retval = true;
  if (use_pmap_protect) {
    pmap_protect(kernel_pmap, start_fixed, end_fixed, new_prot);
  } else {
    vm_map_offset_t page_offset = start_fixed;
    while (page_offset < end_fixed) {
      ppnum_t page_num = pmap_find_phys(kernel_pmap, page_offset);
      if (!page_num) {
        retval = false;
        break;
      }
      kern_return_t rv = pmap_enter(kernel_pmap, page_offset, page_num,
                                    new_prot, VM_PROT_NONE, 0, false);
      if (rv != KERN_SUCCESS) {
        retval = false;
        break;
      }
      page_offset += vm_map_page_size(kernel_map);
    }
  }

  if (!macOS_Mojave() && !macOS_Catalina() && !macOS_BigSur() &&
      !macOS_Monterey() && !macOS_Ventura() && !macOS_Sonoma() &&
      !macOS_Sequoia())
  {
    vm_map_unlock(kernel_map);
  }

  return retval;
}

typedef void (*vm_map_iterator_t)(vm_map_t map, vm_map_entry_t entry,
                                  uint32_t submap_level, void *info);

void vm_submap_iterate_entries(vm_map_t submap, vm_map_offset_t start,
                               vm_map_offset_t end, uint32_t submap_level,
                               vm_map_iterator_t iterator, void *info)
{
  if (!submap || !iterator) {
    return;
  }

  if (end >= VM_MAX_KERNEL_ADDRESS) {
    end = vm_map_trunc_page(VM_MAX_KERNEL_ADDRESS, vm_map_page_mask(submap));
  }

  vm_map_offset_t start_fixed =
    vm_map_trunc_page(start, vm_map_page_mask(submap));
  vm_map_offset_t end_fixed =
    vm_map_round_page(end, vm_map_page_mask(submap));

  if (start_fixed > end_fixed) {
    return;
  }

  if (end_fixed == start_fixed) {
    end_fixed += vm_map_page_size(submap);
  }

  vm_map_lock(submap);

  vm_map_entry_t entry;
  vm_map_offset_t entry_start;
  if (!vm_map_lookup_entry(submap, start_fixed, &entry)) {
    entry = vm_map_first_entry(submap);
    entry_start = map_entry_start(entry);
    if (start_fixed > entry_start) {
      while ((entry != vm_map_to_entry(submap)) && (entry_start < start_fixed)) {
        entry = map_entry_next(entry);
        entry_start = map_entry_start(entry);
      }
    }
  } else {
    entry_start = map_entry_start(entry);
  }

  while ((entry != vm_map_to_entry(submap)) && (entry_start < end_fixed)) {
    if (map_entry_is_submap(entry)) {
      vm_map_offset_t submap_start = map_entry_offset(entry);
      vm_map_offset_t submap_end =
        map_entry_offset(entry) + end_fixed - entry_start;
      vm_submap_iterate_entries(map_entry_object(entry).vmo_submap,
                                submap_start, submap_end, submap_level + 1,
                                iterator, info);
    } else {
      iterator(submap, entry, submap_level, info);
    }

    entry = map_entry_next(entry);
    entry_start = map_entry_start(entry);
  }

  vm_map_unlock(submap);
}

void vm_map_iterate_entries(vm_map_t map, vm_map_offset_t start,
                            vm_map_offset_t end, vm_map_iterator_t iterator,
                            void *info)
{
  if (!map || !iterator) {
    return;
  }

  if (end >= VM_MAX_KERNEL_ADDRESS) {
    end = vm_map_trunc_page(VM_MAX_KERNEL_ADDRESS, vm_map_page_mask(map));
  }

  vm_map_offset_t start_fixed =
    vm_map_trunc_page(start, vm_map_page_mask(map));
  vm_map_offset_t end_fixed =
    vm_map_round_page(end, vm_map_page_mask(map));

  if (start_fixed > end_fixed) {
    return;
  }

  if (end_fixed == start_fixed) {
    end_fixed += vm_map_page_size(map);
  }

  vm_map_lock(map);

  vm_map_entry_t entry;
  vm_map_offset_t entry_start;
  if (!vm_map_lookup_entry(map, start_fixed, &entry)) {
    entry = vm_map_first_entry(map);
    entry_start = map_entry_start(entry);
    if (start_fixed > entry_start) {
      while ((entry != vm_map_to_entry(map)) && (entry_start < start_fixed)) {
        entry = map_entry_next(entry);
        entry_start = map_entry_start(entry);
      }
    }
  } else {
    entry_start = map_entry_start(entry);
  }

  while ((entry != vm_map_to_entry(map)) && (entry_start < end_fixed)) {
    if (map_entry_is_submap(entry)) {
      vm_map_offset_t submap_start = map_entry_offset(entry);
      vm_map_offset_t submap_end = 
        map_entry_offset(entry) + end_fixed - entry_start;
      vm_submap_iterate_entries(map_entry_object(entry).vmo_submap,
                                submap_start, submap_end, 1, iterator, info);
    } else {
      iterator(map, entry, 0, info);
    }

    entry = map_entry_next(entry);
    entry_start = map_entry_start(entry);
  }

  vm_map_unlock(map);
}

#if (0)
// Must call vm_map_deallocate() on what this method returns.
vm_map_t task_map_for_pid(pid_t pid)
{
  proc_t our_proc = proc_find(pid);
  if (!our_proc) {
    return NULL;
  }
  task_t our_task = proc_task(our_proc);
  proc_rele(our_proc);
  if (!our_task) {
    return NULL;
  }
  task_reference(our_task);
  vm_map_t proc_map = get_task_map_reference(our_task);
  task_deallocate(our_task);
  return proc_map;
}
#endif

// Must call vm_map_deallocate() on what this method returns.
vm_map_t task_map_for_proc(proc_t proc)
{
  if (!proc) {
    return NULL;
  }
  task_t our_task = proc_task(proc);
  if (!our_task) {
    return NULL;
  }
  task_reference(our_task);
  vm_map_t proc_map = get_task_map_reference(our_task);
  task_deallocate(our_task);
  return proc_map;
}

bool proc_copyin(vm_map_t proc_map, const user_addr_t source,
                 void *dest, size_t len)
{
  if (!proc_map || !source || !dest || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }

  vm_map_copy_t copy;
  // vm_map_copyin() can fail with KERN_INVALID_ADDRESS if our_proc/our_task
  // is quitting.
  kern_return_t rv = vm_map_copyin(proc_map, source, len, false, &copy);
  if (rv != KERN_SUCCESS) {
    return false;
  }
  vm_map_offset_t out;
  rv = vm_map_copyout(kernel_map, &out, copy);
  if (rv != KERN_SUCCESS) {
    vm_map_copy_discard(copy);
    return false;
  }
  bcopy((void *) out, dest, len);
  vm_deallocate(kernel_map, out, len);

  return true;
}

bool proc_mapin(vm_map_t proc_map, const user_addr_t source,
                vm_map_offset_t *target, size_t len)
{
  if (!proc_map || !source || !target || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }
  *target = 0;

  vm_map_copy_t copy;
  // vm_map_copyin() can fail with KERN_INVALID_ADDRESS if our_proc/our_task
  // is quitting.
  kern_return_t rv = vm_map_copyin(proc_map, source, len, false, &copy);
  if (rv != KERN_SUCCESS) {
    return false;
  }
  vm_map_offset_t out;
  rv = vm_map_copyout(kernel_map, &out, copy);
  if (rv != KERN_SUCCESS) {
    vm_map_copy_discard(copy);
    return false;
  }
  *target = out;

  return true;
}

//#define DEBUG_LAZY_POINTERS 1

#ifdef DEBUG_LAZY_POINTERS

kthread_key_t s_set_interpose_hooks_for_module_proc;
int64_t s_set_interpose_hooks_for_module_proc_initialized = 0;

proc_t get_set_interpose_hooks_for_module_proc()
{
  if (!s_set_interpose_hooks_for_module_proc_initialized) {
    OSIncrementAtomic64(&s_set_interpose_hooks_for_module_proc_initialized);
    kthread_key_init(&s_set_interpose_hooks_for_module_proc);
  }
  return (proc_t)
    kthread_getspecific(&s_set_interpose_hooks_for_module_proc);
}

void set_set_interpose_hooks_for_module_proc(proc_t proc)
{
  if (!s_set_interpose_hooks_for_module_proc_initialized) {
    OSIncrementAtomic64(&s_set_interpose_hooks_for_module_proc_initialized);
    kthread_key_init(&s_set_interpose_hooks_for_module_proc);
  }
  kthread_setspecific(&s_set_interpose_hooks_for_module_proc,
                      (void *) proc);
}

#endif

bool user_region_codesigned(vm_map_t map, vm_map_offset_t start,
                            vm_map_offset_t end);
void sign_user_pages(vm_map_t map, vm_map_offset_t start,
                     vm_map_offset_t end);
void unsign_user_pages(vm_map_t map, vm_map_offset_t start,
                       vm_map_offset_t end);

bool proc_copyout(vm_map_t proc_map, const void *source,
                  user_addr_t dest, size_t len)
{
  if (!proc_map || !source || !dest || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }

  int page_size = vm_map_page_size(proc_map);
  user_addr_t dest_rounded = (dest & ~((signed)(vm_map_page_mask(proc_map))));
  size_t len_rounded = page_size;
  while (dest_rounded + len_rounded < dest + len) {
    len_rounded += page_size;
  }

  kern_return_t rv1 = KERN_SUCCESS;
  kern_return_t rv2 = KERN_SUCCESS;

  // It's possible to write to kernel memory without altering existing write
  // permissions -- just temporarily unset the "write protect" bit of the CR0
  // register (CR0_WP).  Doing that here, though, has very bad side effects.
  // The "DYLD shared cache" gets altered permanently, for all processes.
  // These changes even survive a reboot!  (Though they can be cleared by
  // running update_dyld_shared_cache.)  Even changes to dyld happen to a
  // global copy in RAM, shared by all processes.  Using vm_protect() and
  // vm_fault() somehow avoids all this trouble.
  vm_region_submap_info_data_64_t info;
  bzero(&info, sizeof(info));
  if (vm_region_get_info(proc_map, dest, &info) != KERN_SUCCESS) {
    return false;
  }
  bool codesigned = user_region_codesigned(proc_map, dest, dest + len);
  bool prot_needs_restore = false;
  vm_prot_t old_prot = info.protection;
  vm_prot_t new_prot = old_prot;
  if (!(old_prot & VM_PROT_WRITE)) {
    prot_needs_restore = true;
    // Don't include 'old_prot' in 'new_prot'.  We want to avoid ever
    // simultaneously setting VM_PROT_WRITE and VM_PROT_EXECUTE, even
    // temporarily.  Doing so can upset macOS 10.14 (Mojave), if SIP is
    // only disabled for kernel extensions (and not for anything else).
    new_prot = VM_PROT_READ | VM_PROT_WRITE;
    if (macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
        macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
        macOS_Sequoia())
    {
      // Though shared libraries are all "copy on write", Mojave and above
      // somehow need us to request this specifically, if SIP is only disabled
      // for kernel extensions.
      if (info.share_mode == SM_COW) {
        new_prot |= VM_PROT_COPY;
      }
    }
    // If 'dest' is in the "DYLD shared cache", the first time vm_protect() is
    // called on it, it triggers a call to vm_map_clip_unnest() (via
    // vm_map_clip_start() or vm_map_clip_end()), which "unnests" a part of
    // the shared cache, creating a private copy of it for the current process.
    // This is exactly what we want -- we *don't* want to alter the shared
    // cache itself, even temporarily.  The whole business is something like a
    // copy-on-write.  In 64-bit mode it triggers a warning message from the
    // kernel about a "triggered unnest of range ... of DYLD shared region".
    // On macOS 10.14 (Mojave), some settings for the shared cache
    // (before the unnesting) are:
    //  'protection'     == VM_PROT_EXECUTE
    //  'max_protection' == VM_PROT_EXECUTE
    //  'inheritance'    == VM_INHERIT_COPY
    //  'user_tag'       == 0
    //  'share_mode'     == SM_COW
    //  'is_submap'      == false
    //  'depth'          == 1
    // In the unnested part (after vm_protect() and vm_fault()) they become:
    //  'protection'     == VM_PROT_READ | VM_PROT_WRITE
    //  'max_protection' == VM_PROT_ALL
    //  'inheritance'    == VM_INHERIT_COPY
    //  'user_tag'       == VM_MEMORY_SHARED_PMAP
    //  'share_mode'     == SM_PRIVATE
    //  'is_submap'      == false
    //  'depth'          == 0
    vm_protect(proc_map, dest_rounded, len_rounded, false, new_prot);
    // user_region_codesigned() and unsign_user_pages() need to be called
    // after vm_protect(), which can move things around in memory.
    codesigned = user_region_codesigned(proc_map, dest, dest + len);
    // If we're writing to a "private" region that's codesigned, we should
    // first "unsign" it -- otherwise the OS may give us trouble for setting
    // write permission on a region that should remain unchanged. We don't
    // need to worry about this for a shared region, because the region we
    // write to will be a private copy of it (generated via COW). On Mojave
    // and above we need to do this for all private regions. Starting on
    // Monterey 12.4, "private" regions have the share_mode SM_PRIVATE or
    // SM_PRIVATE_ALIASED.
    if ((info.share_mode == SM_PRIVATE) ||
        (info.share_mode == SM_PRIVATE_ALIASED))
    {
      if (macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
          macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
          macOS_Sequoia() || codesigned)
      {
        unsign_user_pages(proc_map, dest, dest + len);
      }
    }
  }

  // This call to vm_fault() finishes the job of preparing the region that
  // contains 'dest' for writing.  It maps in an unnested region (created
  // above by the call to vm_protect()), or unnests part of a shared region
  // that already had write permission.  This call to vm_fault() also helps
  // to remedy some kind of race condition -- without it we sometimes panic
  // with a write-protect GPF.
  if (prot_needs_restore) {
    rv1 = vm_fault(proc_map, dest_rounded, new_prot, false,
                   VM_KERN_MEMORY_NONE, THREAD_UNINT, NULL, 0);
  }
  if (rv1 == KERN_SUCCESS) {
    if (macOS_Sequoia_4_or_greater()) {
      vm_map_task_t oldmap = vm_map_switch_to(proc_map);
      rv2 = copyout(source, dest, len);
      vm_map_switch_back(oldmap);
    } else {
      vm_map_t oldmap = vm_map_switch(proc_map);
      rv2 = copyout(source, dest, len);
      vm_map_switch(oldmap);
    }
  }

  // If we've altered a write-protected codesigned region, we need to "sign"
  // it ourselves to prevent later rechecks from finding the signature no
  // longer matches.  On macOS 10.14 (Mojave) and above we need to "sign"
  // every write-protected page we change, whether or not it's codesigned.
  if ((rv1 == KERN_SUCCESS) &&
      (rv2 == KERN_SUCCESS) &&
      prot_needs_restore)
  {
    if (macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
        macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
        macOS_Sequoia() || codesigned)
    {
      sign_user_pages(proc_map, dest, dest + len);
    }
  }

  //pmap_t proc_pmap = vm_map_pmap(proc_map);
  //if (proc_pmap) {
  //  ppnum_t page_num = pmap_find_phys(proc_pmap, dest);
  //  if (page_num) {
  //    pmap_sync_page_attributes_phys(page_num);
  //  }
  //}

  if (prot_needs_restore) {
    vm_protect(proc_map, dest_rounded, len_rounded, false, old_prot);
  }

#ifdef DEBUG_LAZY_POINTERS
  proc_t proc = get_set_interpose_hooks_for_module_proc();
  if (proc) {
    pid_t pid = proc_pid(proc);
    char procname[PATH_MAX];
    proc_name(pid, procname, sizeof(procname));
    kprintf("HookCase(%s[%d]): proc_copyout(): codesigned %d, old_prot 0x%x, new_prot 0x%x, share mode 0x%x, depth %d, user wired count %d, submap %d, dest 0x%llx, cpu number %d, rv1 0x%x, rv2 0x%x\n",
            procname, pid, codesigned, old_prot, new_prot, info.share_mode,
            info.shadow_depth, info.user_wired_count, info.is_submap,
            dest, get_cpu_number(), rv1, rv2);
  }
#endif

  return ((rv1 == KERN_SUCCESS) && (rv2 == KERN_SUCCESS));
}

bool proc_mapout(vm_map_t proc_map, const void *source,
                 vm_map_offset_t *target, size_t len)
{
  if (!proc_map || !source || !target || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }
  *target = 0;

  vm_map_copy_t copy;
  // On Monterey 12.4 and above, setting 'src_destroy' to 'true' triggers
  // a kernel panic with an error message about "attempting to remove
  // permanent VM map entry". This error presumably also happened on earlier
  // versions of macOS, but was non-fatal. We should probably never trigger
  // it. So set 'src_destroy' to 'false' here and release 'source' in the
  // caller.
  kern_return_t rv = vm_map_copyin(kernel_map, (vm_map_address_t) source,
                                   len, false, &copy);
  if (rv != KERN_SUCCESS) {
    return false;
  }
  vm_map_offset_t out;
  rv = vm_map_copyout(proc_map, &out, copy);
  if (rv != KERN_SUCCESS) {
    vm_map_copy_discard(copy);
    return false;
  }
  // On macOS 10.14 (Mojave) and above we need to "sign" every page we add
  // to proc_map.
  if (macOS_Mojave() || macOS_Catalina() || macOS_BigSur() ||
      macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
      macOS_Sequoia())
  {
    sign_user_pages(proc_map, out, out + len);
  }
  *target = out;

  return true;
}

bool proc_copyinstr(vm_map_t proc_map, const user_addr_t source,
                    void *dest, size_t len)
{
  if (!proc_map || !source || !dest || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }

  kern_return_t rv = KERN_SUCCESS;
  if (macOS_Sequoia_4_or_greater()) {
    vm_map_task_t oldmap = vm_map_switch_to(proc_map);
    size_t size;
    rv = copyinstr(source, dest, len, &size);
    vm_map_switch_back(oldmap);
  } else {
    vm_map_t oldmap = vm_map_switch(proc_map);
    size_t size;
    rv = copyinstr(source, dest, len, &size);
    vm_map_switch(oldmap);
  }

  return (rv == KERN_SUCCESS);
}

typedef char name_out_t[PATH_MAX];

char *basename(const char *path, name_out_t basename_out)
{
  if (!path || !path[0]) {
    strncpy(basename_out, ".", PATH_MAX);
    return basename_out;
  }

  char holder[PATH_MAX];
  strncpy(holder, path, sizeof(holder));
  char *retval = NULL;
  char *remaining = holder;
  while (remaining) {
    char *token = strsep(&remaining, "/");
    if (token) {
      retval = token;
    }
  }

  if (retval) {
    strncpy(basename_out, retval, PATH_MAX);
  } else {
    strncpy(basename_out, path, PATH_MAX);
  }
  return basename_out;
}

char *dirname(const char *path, name_out_t dirname_out)
{
  if (!path || !path[0]) {
    strncpy(dirname_out, ".", PATH_MAX);
    return dirname_out;
  }

  char holder[PATH_MAX];
  strncpy(holder, path, sizeof(holder));
  char *basename = NULL;
  char *remaining = holder;
  while (remaining) {
    char *token = strsep(&remaining, "/");
    if (token) {
      basename = token;
    }
  }

  strncpy(dirname_out, path, PATH_MAX);
  if (basename && (basename != holder)) {
    dirname_out[basename - holder] = 0;
  }

  return dirname_out;
}


// From ElCapitan's xnu kernel's osfmk/mach/coalition.h [begin]

#define COALITION_TYPE_RESOURCE  (0)
#define COALITION_TYPE_JETSAM    (1)
#define COALITION_TYPE_MAX       (1)

#define COALITION_NUM_TYPES      (COALITION_TYPE_MAX + 1)

#define COALITION_TASKROLE_UNDEF  (0)
#define COALITION_TASKROLE_LEADER (1)
#define COALITION_TASKROLE_XPC    (2)
#define COALITION_TASKROLE_EXT    (3)

#define COALITION_NUM_TASKROLES   (4)

#define COALITION_ROLEMASK_ALLROLES ((1 << COALITION_NUM_TASKROLES) - 1)
#define COALITION_ROLEMASK_UNDEF    (1 << COALITION_TASKROLE_UNDEF)
#define COALITION_ROLEMASK_LEADER   (1 << COALITION_TASKROLE_LEADER)
#define COALITION_ROLEMASK_XPC      (1 << COALITION_TASKROLE_XPC)
#define COALITION_ROLEMASK_EXT      (1 << COALITION_TASKROLE_EXT)

#define COALITION_SORT_NOSORT     (0)
#define COALITION_SORT_DEFAULT    (1)
#define COALITION_SORT_MEM_ASC    (2)
#define COALITION_SORT_MEM_DEC    (3)
#define COALITION_SORT_USER_ASC   (4)
#define COALITION_SORT_USER_DEC   (5)

#define COALITION_NUM_SORT        (6)

// From ElCapitan's xnu kernel's osfmk/mach/coalition.h [end]

// Many Apple applications (like Safari) now use XPC to launch child
// processes.  But unlike ordinary child processes, these don't inherit their
// parents' environment (with its HC_... trigger variables).  That would make
// it difficult to use HookCase.kext with Apple applications.  As it happens,
// though, an XPC child (like an ordinary child process) does become a member
// of its parent process's "coalition".  The coalition infrastructure's
// intended use is to deal with memory pressure
// (http://apple.stackexchange.com/questions/155458/strange-message-in-console-about-dirtyjetsammemorylimit-key,
// http://newosxbook.com/articles/MemoryPressure.html).  But we can lean on it
// to find a given child process's "XPC parent" (if it has one).  Coalitions
// are supported on Yosemite and above.  But the following would be much more
// difficult on Yosemite, and isn't possible at all on Mavericks.  So it's
// probably best just to implement this method on ElCapitan (and above).
pid_t get_xpc_parent(pid_t possible_child)
{
  if (!possible_child ||
      (!OSX_ElCapitan() && !macOS_Sierra() && !macOS_HighSierra() &&
       !macOS_Mojave() && !macOS_Catalina() && !macOS_BigSur() &&
       !macOS_Monterey() && !macOS_Ventura() && !macOS_Sonoma() &&
       !macOS_Sequoia()))
  {
    return 0;
  }

  proc_t child_process = proc_find(possible_child);
  if (!child_process) {
    return 0;
  }
  task_t child_task = proc_task(child_process);
  proc_rele(child_process);
  if (!child_task) {
    return 0;
  }
  uint64_t coal_ids[COALITION_NUM_TYPES];
  task_coalition_ids(child_task, coal_ids);
  coalition_t coal = NULL;
  int i;
  for (i = 0; i < COALITION_NUM_TYPES; ++i) {
    coal = coalition_find_by_id(coal_ids[i]);
    if (coal) {
      break;
    }
  }
  if (!coal) {
    return 0;
  }

  // Get a list of the pids of all the processes in 'possible_child's
  // coalition.  This will be ordered from the topmost parent to its most
  // recently created descendant (maybe newer than 'possible_child').
  pid_t coal_pid_list[50];
  int npids = coalition_get_pid_list(coal, COALITION_ROLEMASK_ALLROLES,
                                     COALITION_SORT_NOSORT, coal_pid_list,
                                     sizeof(coal_pid_list)/sizeof(pid_t));
  coalition_release(coal);
  // Given a list of two or more items:  Starting from its end, look first for
  // 'possible_child'.  Then look for the first child process whose parent
  // isn't launchd (whose 'parent_pid' isn't '1') -- in other words for the
  // first "ordinary" child (which isn't an XPC child).  Break without setting
  // 'xpc_parent' if this is 'possible_child' itself.  If no such process is
  // found before the top, choose the top process.  (The XPC parent may have
  // been launched from the command line -- in which case Terminal will be at
  // the top of the list, and be the XPC parent's ancestor.  Otherwise the XPC
  // parent will be at the top of the list.)
  pid_t xpc_parent = 0;
  bool found_possible_child = false;
  for (i = npids - 1; i > 0; --i) {
    if (!found_possible_child && (coal_pid_list[i] != possible_child)) {
      continue;
    }
    found_possible_child = true;
    proc_t a_process = proc_find(coal_pid_list[i]);
    if (!a_process) {
      continue;
    }
    pid_t parent_pid = proc_ppid(a_process);
    proc_rele(a_process);
    if ((parent_pid != coal_pid_list[i]) && (parent_pid > 0) &&
        (parent_pid != 1))
    {
      if (coal_pid_list[i] != possible_child) {
        xpc_parent = coal_pid_list[i];
      }
      break;
    }
    if (i == 1) {
      xpc_parent = coal_pid_list[i - 1];
    }
  }

  return xpc_parent;
}

// See source for exec_copyout_strings() in bsd/kern/kern_exec.c for layout of
// beginning of user stack.

// The caller must call IOFree() on *envp and *buffer.  '*buffer' is workspace
// that holds the strings pointed to by *path and *envp.  Every process's full
// path, arguments and environment are stored (in user space) just before its
// "user stack".  p_argslen includes all of these.  p_argc includes argv[0]
// (the process name) but not the process path.
//
// The environment we examine here is the one with which the process 'pid' was
// created (and which may have been inherited from a parent process).  It
// doesn't contain any changes the process may have made to its own environment
// (for example using setenv()).  We may find use cases that require a change
// to this behavior.
bool get_proc_info(int32_t pid, char **path,
                   char ***envp, vm_size_t *envp_size,
                   void **buffer, vm_size_t *buf_size)
{
  if (!pid || !path || !envp || !envp_size || !buffer || !buf_size) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }

  proc_t our_proc = proc_find(pid);
  if (!our_proc) {
    return false;
  }
  task_t our_task = proc_task(our_proc);
  if (!our_task) {
    proc_rele(our_proc);
    return false;
  }
  task_reference(our_task);

  uint32_t p_argslen = 0;
  int32_t p_argc = 0;
  user_addr_t user_stack = 0;
  if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_4_t p = (proc_fake_sonoma_4_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_4_t p = (proc_fake_sonoma_dev_4_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Sonoma()) {
    if (kernel_type_is_release()) {
      proc_fake_sonoma_t p = (proc_fake_sonoma_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_sonoma_dev_t p = (proc_fake_sonoma_dev_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Ventura_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_3_t p = (proc_fake_ventura_3_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_3_t p = (proc_fake_ventura_dev_3_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Ventura()) {
    if (kernel_type_is_release()) {
      proc_fake_ventura_t p = (proc_fake_ventura_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_ventura_dev_t p = (proc_fake_ventura_dev_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Monterey_3_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_3_t p = (proc_fake_monterey_3_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_3_t p = (proc_fake_monterey_dev_3_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Monterey_1_or_greater()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_1_t p = (proc_fake_monterey_1_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_1_t p = (proc_fake_monterey_dev_1_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_Monterey()) {
    if (kernel_type_is_release()) {
      proc_fake_monterey_t p = (proc_fake_monterey_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    } else if (kernel_type_is_development()) {
      proc_fake_monterey_dev_t p = (proc_fake_monterey_dev_t) our_proc;
      if (p) {
        p_argslen = p->p_argslen;
        p_argc = p->p_argc;
        user_stack = p->user_stack;
      }
    }
  } else if (macOS_BigSur()) {
    proc_fake_bigsur_t p = (proc_fake_bigsur_t) our_proc;
    if (p) {
      p_argslen = p->p_argslen;
      p_argc = p->p_argc;
      user_stack = p->user_stack;
    }
  } else if (macOS_Catalina()) {
    proc_fake_catalina_t p = (proc_fake_catalina_t) our_proc;
    if (p) {
      p_argslen = p->p_argslen;
      p_argc = p->p_argc;
      user_stack = p->user_stack;
    }
  } else if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) our_proc;
    if (p) {
      p_argslen = p->p_argslen;
      p_argc = p->p_argc;
      user_stack = p->user_stack;
    }
  } else if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra()) {
    proc_fake_elcapitan_t p = (proc_fake_elcapitan_t) our_proc;
    if (p) {
      p_argslen = p->p_argslen;
      p_argc = p->p_argc;
      user_stack = p->user_stack;
    }
  } else {
    proc_fake_mavericks_t p = (proc_fake_mavericks_t) our_proc;
    if (p) {
      p_argslen = p->p_argslen;
      p_argc = p->p_argc;
      user_stack = p->user_stack;
    }
  }
  proc_rele(our_proc);
  if (!p_argslen || !user_stack) {
    task_deallocate(our_task);
    return false;
  }
  *path = NULL;
  *envp = NULL;
  *envp_size = 0;
  *buffer = NULL;
  *buf_size = 0;

  vm_map_t proc_map = get_task_map_reference(our_task);
  task_deallocate(our_task);
  if (!proc_map) {
    return false;
  }

  vm_size_t desired_buf_size = p_argslen;
  char *holder = (char *) IOMalloc(desired_buf_size);
  if (!holder) {
    return false;
  }
  user_addr_t source = user_stack - desired_buf_size;
  bool rv = proc_copyin(proc_map, source, holder, desired_buf_size);
  vm_map_deallocate(proc_map);
  if (!rv) {
    IOFree(holder, desired_buf_size);
    return false;
  }

  char *holder_past_end = holder + desired_buf_size;
  holder_past_end[-1] = 0;
  holder_past_end[-2] = 0;

  int args_env_count = 0;
  int i; char *item;
  for (i = 0, item = holder; item < holder_past_end; ++i) {
    if (!item[0]) {
      args_env_count = i;
      break;
    }
    if (i == 0) {
      const char *path_header = "executable_path=";
      size_t path_header_len = strlen(path_header);
      if (!strncmp(item, path_header, path_header_len)) {
        item += path_header_len;
      }
      *path = item;
    }
    item += strlen(item) + 1;
    // The process path (the first 'item') is padded (at the end) with
    // multiple NULLs.  Presumably a fixed amount of storage has been set
    // aside for it.
    if (i == 0) {
      while (!item[0]) {
        ++item;
      }
    }
  }
  int args_count = p_argc + 1; // Including the process path
  int env_count = args_env_count - args_count;
  // Though it's very unlikely, we might have a process path and no environment.
  if (env_count <= 0) {
    return true;
  }

  vm_size_t desired_envp_size = (env_count + 1) * sizeof(char *);
  char **envp_holder = (char **) IOMalloc(desired_envp_size);
  // Do an error return if we're out of memory -- even if we already have the
  // process path.
  if (!envp_holder) {
    *path = NULL;
    IOFree(holder, desired_buf_size);
    return false;
  }

  for (i = 0, item = holder; i < args_env_count; ++i) {
    if (i >= args_count) {
      envp_holder[i - args_count] = item;
    }
    item += strlen(item) + 1;
    if (i == 0) {
      while (!item[0]) {
        ++item;
      }
    }
  }
  envp_holder[env_count] = NULL;

  *envp = envp_holder;
  *envp_size = desired_envp_size;
  *buffer = holder;
  *buf_size = desired_buf_size;
  return true;
}

// Masks defining possible values for a tasks's t_flags.
// From the xnu kernel's osfmk/kern/task.h
#define TF_64B_ADDR         0x00000001    /* task has 64-bit addressing */
#define TF_64B_DATA         0x00000002    /* task has 64-bit data registers */
#define TF_CPUMON_WARNING   0x00000004    /* task has at least one thread in CPU usage warning zone */
#define TF_WAKEMON_WARNING  0x00000008    /* task is in wakeups monitor warning zone */
#define TF_TELEMETRY        (TF_CPUMON_WARNING | TF_WAKEMON_WARNING) /* task is a telemetry participant */
#define TF_GPU_DENIED       0x00000010    /* task is not allowed to access the GPU */
#define TF_CORPSE           0x00000020    /* task is a corpse */
#define TF_PENDING_CORPSE   0x00000040    /* task corpse has not been reported yet */

typedef struct _task_fake_mavericks {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[6];
  queue_head_t threads; // Size 0x10, offset 0x40
  uint64_t pad2[84];
  void *bsd_info;       // Offset 0x2f0
  uint64_t pad3[1];
  volatile uint32_t t_flags; /* Offset 0x300, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x308
  mach_vm_size_t all_image_info_size;    // Offset 0x310
} *task_fake_mavericks_t;

typedef struct _task_fake_yosemite {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[85];
  void *bsd_info;       // Offset 0x300
  uint64_t pad3[1];
  volatile uint32_t t_flags; /* Offset 0x310, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x318
  mach_vm_size_t all_image_info_size;    // Offset 0x320
} *task_fake_yosemite_t;

typedef struct _task_fake_elcapitan {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[88];
  void *bsd_info;       // Offset 0x318
  uint64_t pad3[2];
  volatile uint32_t t_flags; /* Offset 0x330, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x338
  mach_vm_size_t all_image_info_size;    // Offset 0x340
} *task_fake_elcapitan_t;

typedef struct _task_fake_sierra {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[101];
  void *bsd_info;       // Offset 0x380
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3b8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3c0
  mach_vm_size_t all_image_info_size;    // Offset 0x3c8
} *task_fake_sierra_t;

typedef struct _task_fake_highsierra {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[103];
  void *bsd_info;       // Offset 0x390
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_highsierra_t;

// Apple messed with the development and debug versions of this structure in
// the macOS 10.14.2 release :-(
typedef struct _task_fake_mojave {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[6];
  queue_head_t threads; // Size 0x10, offset 0x40
  uint64_t pad2[102];
  void *bsd_info;       // Offset 0x380
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3b8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3c0
  mach_vm_size_t all_image_info_size;    // Offset 0x3c8
} *task_fake_mojave_t;

// Only valid on macOS 10.14.2 and up
typedef struct _task_fake_mojave_dev_debug {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[8];
  queue_head_t threads; // Size 0x10, offset 0x50
  uint64_t pad2[102];
  void *bsd_info;       // Offset 0x390
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_mojave_dev_debug_t;

typedef struct _task_fake_catalina {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad2[103];
  void *bsd_info;       // Offset 0x3a0
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3d8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x3e8
  mach_vm_size_t all_image_info_size;    // Offset 0x3f0
} *task_fake_catalina_t;

typedef struct _task_fake_catalina_dev_debug {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[10];
  queue_head_t threads; // Size 0x10, offset 0x60
  uint64_t pad2[103];
  void *bsd_info;       // Offset 0x3a8
  uint64_t pad3[6];
  volatile uint32_t t_flags; /* Offset 0x3e0, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x3f0
  mach_vm_size_t all_image_info_size;    // Offset 0x3f8
} *task_fake_catalina_dev_debug_t;

typedef struct _task_fake_bigsur {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad2[105];
  void *bsd_info;       // Offset 0x3b0
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x3f8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x408
  mach_vm_size_t all_image_info_size;    // Offset 0x410
} *task_fake_bigsur_t;

typedef struct _task_fake_bigsur_3 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[8];
  queue_head_t threads; // Size 0x10, offset 0x50
  uint64_t pad2[108];
  void *bsd_info;       // Offset 0x3c0
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x408, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x418
  mach_vm_size_t all_image_info_size;    // Offset 0x420
} *task_fake_bigsur_3_t;

typedef struct _task_fake_bigsur_development {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[10];
  queue_head_t threads; // Size 0x10, offset 0x60
  uint64_t pad2[105];
  void *bsd_info;       // Offset 0x3b8
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x400, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x410
  mach_vm_size_t all_image_info_size;    // Offset 0x418
} *task_fake_bigsur_development_t;

typedef struct _task_fake_bigsur_development_3 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad2[108];
  void *bsd_info;       // Offset 0x3c8
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x410, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x420
  mach_vm_size_t all_image_info_size;    // Offset 0x428
} *task_fake_bigsur_development_3_t;

typedef struct _task_fake_monterey {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad2[108];
  void *bsd_info;       // Offset 0x3c8
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x410, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x420
  mach_vm_size_t all_image_info_size;    // Offset 0x428
} *task_fake_monterey_t;

typedef struct _task_fake_monterey_dev {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[12];
  queue_head_t threads; // Size 0x10, offset 0x70
  uint64_t pad2[109];
  void *bsd_info;       // Offset 0x3e8
  uint64_t pad3[8];
  volatile uint32_t t_flags; /* Offset 0x430, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x440
  mach_vm_size_t all_image_info_size;    // Offset 0x448
} *task_fake_monterey_dev_t;

typedef struct _task_fake_monterey_1 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad2[103];
  void *bsd_info;       // Offset 0x3a0
  uint64_t pad3[7];
  volatile uint32_t t_flags; /* Offset 0x3e0, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x3f0
  mach_vm_size_t all_image_info_size;    // Offset 0x3f8
} *task_fake_monterey_1_t;

typedef struct _task_fake_monterey_dev_1 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[12];
  queue_head_t threads; // Size 0x10, offset 0x70
  uint64_t pad2[104];
  void *bsd_info;       // Offset 0x3c0
  uint64_t pad3[7];
  volatile uint32_t t_flags; /* Offset 0x400, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[3];
  mach_vm_address_t all_image_info_addr; // Offset 0x410
  mach_vm_size_t all_image_info_size;    // Offset 0x418
} *task_fake_monterey_dev_1_t;

typedef struct _task_fake_ventura {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad3[108];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_ventura_t;

typedef struct _task_fake_ventura_dev {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[13];
  queue_head_t threads; // Size 0x10, offset 0x78
  uint64_t pad3[109];
  volatile uint32_t t_flags; /* Offset 0x3f0, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3f8
  mach_vm_size_t all_image_info_size;    // Offset 0x400
} *task_fake_ventura_dev_t;

typedef struct _task_fake_sonoma {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[9];
  queue_head_t threads; // Size 0x10, offset 0x58
  uint64_t pad3[108];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_sonoma_t;

typedef struct _task_fake_sonoma_dev {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[13];
  queue_head_t threads; // Size 0x10, offset 0x78
  uint64_t pad3[157];
  volatile uint32_t t_flags; /* Offset 0x570, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x578
  mach_vm_size_t all_image_info_size;    // Offset 0x580
} *task_fake_sonoma_dev_t;

typedef struct _task_fake_sequoia {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[8];
  queue_head_t threads; // Size 0x10, offset 0x50
  uint64_t pad3[113];
  volatile uint32_t t_flags; /* Offset 0x3e8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3f0
  mach_vm_size_t all_image_info_size;    // Offset 0x3f8
} *task_fake_sequoia_t;

typedef struct _task_fake_sequoia_dev {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[12];
  queue_head_t threads; // Size 0x10, offset 0x70
  uint64_t pad3[162];
  volatile uint32_t t_flags; /* Offset 0x590, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x598
  mach_vm_size_t all_image_info_size;    // Offset 0x5a0
} *task_fake_sequoia_dev_t;

typedef struct _task_fake_sequoia_4 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[8];
  queue_head_t threads; // Size 0x10, offset 0x50
  uint64_t pad3[117];
  volatile uint32_t t_flags; /* Offset 0x408, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x410
  mach_vm_size_t all_image_info_size;    // Offset 0x418
} *task_fake_sequoia_4_t;

typedef struct _task_fake_sequoia_dev_4 {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[12];
  queue_head_t threads; // Size 0x10, offset 0x70
  uint64_t pad3[166];
  volatile uint32_t t_flags; /* Offset 0x5b0, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad4[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x5b8
  mach_vm_size_t all_image_info_size;    // Offset 0x5c0
} *task_fake_sequoia_dev_4_t;

void task_lock(task_t task)
{
  if (!task) {
    return;
  }
  task_fake_mavericks_t task_local = (task_fake_mavericks_t) task;
  lck_mtx_lock(&task_local->lock);
}

void task_unlock(task_t task)
{
  if (!task) {
    return;
  }
  task_fake_mavericks_t task_local = (task_fake_mavericks_t) task;
  lck_mtx_unlock(&task_local->lock);
}

mach_vm_address_t task_all_image_info_addr(task_t task)
{
  if (!task) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sequoia_4_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_4, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev_4, all_image_info_addr);
      }
    } else if (macOS_Sequoia()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev, all_image_info_addr);
      }
    } else if (macOS_Sonoma()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sonoma, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sonoma_dev, all_image_info_addr);
      }
    } else if (macOS_Ventura()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_ventura, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_ventura_dev, all_image_info_addr);
      }
    } else if (macOS_Monterey_1_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_1, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev_1, all_image_info_addr);
      }
    } else if (macOS_Monterey()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev, all_image_info_addr);
      }
    } else if (macOS_BigSur_less_than_3()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development, all_image_info_addr);
      }
    } else if (macOS_BigSur()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_3, all_image_info_addr);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development_3, all_image_info_addr);
      }
    } else if (macOS_Catalina()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_catalina, all_image_info_addr);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_catalina_dev_debug, all_image_info_addr);
      }
    } else if (macOS_Mojave()) {
      if (macOS_Mojave_less_than_2() || kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_mojave, all_image_info_addr);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_mojave_dev_debug, all_image_info_addr);
      }
    } else if (macOS_HighSierra()) {
      offset_in_struct =
        offsetof(struct _task_fake_highsierra, all_image_info_addr);
    } else if (macOS_Sierra()) {
      offset_in_struct =
        offsetof(struct _task_fake_sierra, all_image_info_addr);
    } else if (OSX_ElCapitan()) {
      offset_in_struct =
        offsetof(struct _task_fake_elcapitan, all_image_info_addr);
    } else if (OSX_Yosemite()) {
      offset_in_struct =
        offsetof(struct _task_fake_yosemite, all_image_info_addr);
    } else if (OSX_Mavericks()) {
      offset_in_struct =
        offsetof(struct _task_fake_mavericks, all_image_info_addr);
    }
  }

  mach_vm_address_t retval = 0;
  if (offset_in_struct != -1) {
    retval = *((mach_vm_address_t *)
               ((vm_map_offset_t) task + offset_in_struct));
  }

  return retval;
}

mach_vm_size_t task_all_image_info_size(task_t task)
{
  if (!task) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sequoia_4_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_4, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev_4, all_image_info_size);
      }
    } else if (macOS_Sequoia()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev, all_image_info_size);
      }
    } else if (macOS_Sonoma()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_sonoma, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sonoma_dev, all_image_info_size);
      }
    } else if (macOS_Ventura()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_ventura, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_ventura_dev, all_image_info_size);
      }
    } else if (macOS_Monterey_1_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_1, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev_1, all_image_info_size);
      }
    } else if (macOS_Monterey()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev, all_image_info_size);
      }
    } else if (macOS_BigSur_less_than_3()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development, all_image_info_size);
      }
    } else if (macOS_BigSur()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_3, all_image_info_size);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development_3, all_image_info_size);
      }
    } else if (macOS_Catalina()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_catalina, all_image_info_size);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_catalina_dev_debug, all_image_info_size);
      }
    } else if (macOS_Mojave()) {
      if (macOS_Mojave_less_than_2() || kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct _task_fake_mojave, all_image_info_size);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_mojave_dev_debug, all_image_info_size);
      }
    } else if (macOS_HighSierra()) {
      offset_in_struct =
        offsetof(struct _task_fake_highsierra, all_image_info_size);
    } else if (macOS_Sierra()) {
      offset_in_struct =
        offsetof(struct _task_fake_sierra, all_image_info_size);
    } else if (OSX_ElCapitan()) {
      offset_in_struct =
        offsetof(struct _task_fake_elcapitan, all_image_info_size);
    } else if (OSX_Yosemite()) {
      offset_in_struct =
        offsetof(struct _task_fake_yosemite, all_image_info_size);
    } else if (OSX_Mavericks()) {
      offset_in_struct =
        offsetof(struct _task_fake_mavericks, all_image_info_size);
    }
  }

  mach_vm_size_t retval = 0;
  if (offset_in_struct != -1) {
    retval = *((mach_vm_size_t *)
               ((vm_map_offset_t) task + offset_in_struct));
  }

  return retval;
}

uint32_t task_flags(task_t task)
{
  if (!task) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sequoia_4_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_sequoia_4, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev_4, t_flags);
      }
    } else if (macOS_Sequoia()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_sequoia, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sequoia_dev, t_flags);
      }
    } else if (macOS_Sonoma()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_sonoma, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_sonoma_dev, t_flags);
      }
    } else if (macOS_Ventura()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_ventura, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_ventura_dev, t_flags);
      }
    } else if (macOS_Monterey_1_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_monterey_1, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev_1, t_flags);
      }
    } else if (macOS_Monterey()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_monterey, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev, t_flags);
      }
    } else if (macOS_BigSur_less_than_3()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_bigsur, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development, t_flags);
      }
    } else if (macOS_BigSur()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_bigsur_3, t_flags);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development_3, t_flags);
      }
    } else if (macOS_Catalina()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_catalina, t_flags);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_catalina_dev_debug, t_flags);
      }
    } else if (macOS_Mojave()) {
      if (macOS_Mojave_less_than_2() || kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_mojave, t_flags);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_mojave_dev_debug, t_flags);
      }
    } else if (macOS_HighSierra()) {
      offset_in_struct = offsetof(struct _task_fake_highsierra, t_flags);
    } else if (macOS_Sierra()) {
      offset_in_struct = offsetof(struct _task_fake_sierra, t_flags);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct _task_fake_elcapitan, t_flags);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct _task_fake_yosemite, t_flags);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct _task_fake_mavericks, t_flags);
    }
  }

  uint32_t retval = 0;
  if (offset_in_struct != -1) {
    retval = *((uint32_t *)((vm_map_offset_t) task + offset_in_struct));
  }

  return retval;
}

bool is_64bit_thread(thread_t thread)
{
  if (!thread) {
    return false;
  }
  task_t task = get_threadtask(thread);
  if (!task) {
    return false;
  }
  return ((task_flags(task) & TF_64B_ADDR) != 0);
}

bool is_64bit_task(task_t task)
{
  if (!task) {
    return false;
  }
  return ((task_flags(task) & TF_64B_ADDR) != 0);
}

proc_t task_proc(task_t task)
{
  if (!task) {
    return NULL;
  }

  // Getting bsd_info has gotten very complicated as of macOS 13. Just use
  // the system call.
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura()) {
    return (proc_t) get_bsdtask_info(task);
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Monterey_1_or_greater()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_monterey_1, bsd_info);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev_1, bsd_info);
      }
    } else if (macOS_Monterey()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_monterey, bsd_info);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_monterey_dev, bsd_info);
      }
    } else if (macOS_BigSur_less_than_3()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_bigsur, bsd_info);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development, bsd_info);
      }
    } else if (macOS_BigSur()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_bigsur_3, bsd_info);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct _task_fake_bigsur_development_3, bsd_info);
      }
    } else if (macOS_Catalina()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_catalina, bsd_info);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_catalina_dev_debug, bsd_info);
      }
    } else if (macOS_Mojave()) {
      if (macOS_Mojave_less_than_2() || kernel_type_is_release()) {
        offset_in_struct = offsetof(struct _task_fake_mojave, bsd_info);
      } else if (kernel_type_is_development() ||
                 kernel_type_is_debug())
      {
        offset_in_struct =
          offsetof(struct _task_fake_mojave_dev_debug, bsd_info);
      }
    } else if (macOS_HighSierra()) {
      offset_in_struct = offsetof(struct _task_fake_highsierra, bsd_info);
    } else if (macOS_Sierra()) {
      offset_in_struct = offsetof(struct _task_fake_sierra, bsd_info);
    } else if (OSX_ElCapitan()) {
      offset_in_struct = offsetof(struct _task_fake_elcapitan, bsd_info);
    } else if (OSX_Yosemite()) {
      offset_in_struct = offsetof(struct _task_fake_yosemite, bsd_info);
    } else if (OSX_Mavericks()) {
      offset_in_struct = offsetof(struct _task_fake_mavericks, bsd_info);
    }
  }

  proc_t retval = NULL;
  if (offset_in_struct != -1) {
    retval = *((proc_t *)((vm_map_offset_t) task + offset_in_struct));
  }

  return retval;
}

proc_t current_proc_alt()
{
  return task_proc(current_task());
}

// From mach-o/dyld_images.h (begin)

enum dyld_image_mode {
  dyld_image_adding=0,
  dyld_image_removing=1,
  dyld_image_info_change=2
};

struct dyld_image_info {
 const struct mach_header* imageLoadAddress; /* base address image is mapped into */
 const char*               imageFilePath;    /* path dyld used to load the image */
 uintptr_t                 imageFileModDate; /* time_t of image file */
         /* if stat().st_mtime of imageFilePath does not match imageFileModDate, */
         /* then file has been modified since dyld loaded it */
};

struct dyld_uuid_info {
 const struct mach_header* imageLoadAddress; /* base address image is mapped into */
 uuid_t                    imageUUID;        /* UUID of image */
};

typedef void (*dyld_image_notifier)(enum dyld_image_mode mode, uint32_t infoCount,
                                    const struct dyld_image_info info[]);

/* for use in dyld_all_image_infos.errorKind field */
enum {
  dyld_error_kind_none=0,
  dyld_error_kind_dylib_missing=1,
  dyld_error_kind_dylib_wrong_arch=2,
  dyld_error_kind_dylib_version=3,
  dyld_error_kind_symbol_missing=4
};

struct dyld_all_image_infos {
  uint32_t                      version;  /* 1 in Mac OS X 10.4 and 10.5 */
  uint32_t                      infoArrayCount;
  const struct dyld_image_info* infoArray;
  dyld_image_notifier           notification;
  bool                          processDetachedFromSharedRegion;
  /* the following fields are only in version 2 (Mac OS X 10.6, iPhoneOS 2.0) and later */
  bool                          libSystemInitialized;
  const struct mach_header*     dyldImageLoadAddress;
  /* the following field is only in version 3 (Mac OS X 10.6, iPhoneOS 3.0) and later */
  void*                         jitInfo;
  /* the following fields are only in version 5 (Mac OS X 10.6, iPhoneOS 3.0) and later */
  const char*                   dyldVersion;
  const char*                   errorMessage;
  uintptr_t                     terminationFlags;
  /* the following field is only in version 6 (Mac OS X 10.6, iPhoneOS 3.1) and later */
  void*                         coreSymbolicationShmPage;
  /* the following field is only in version 7 (Mac OS X 10.6, iPhoneOS 3.1) and later */
  uintptr_t                     systemOrderFlag;
  /* the following field is only in version 8 (Mac OS X 10.7, iPhoneOS 3.1) and later */
  uintptr_t                     uuidArrayCount;
  const struct dyld_uuid_info*  uuidArray;  /* only images not in dyld shared cache */
  /* the following field is only in version 9 (Mac OS X 10.7, iOS 4.0) and later */
  struct dyld_all_image_infos*  dyldAllImageInfosAddress;
  /* the following field is only in version 10 (Mac OS X 10.7, iOS 4.2) and later */
  uintptr_t                     initialImageCount;
  /* the following field is only in version 11 (Mac OS X 10.7, iOS 4.2) and later */
  uintptr_t                     errorKind;
  const char*                   errorClientOfDylibPath;
  const char*                   errorTargetDylibPath;
  const char*                   errorSymbol;
  /* the following field is only in version 12 (Mac OS X 10.7, iOS 4.3) and later */
  uintptr_t                     sharedCacheSlide;
  /* the following field is only in version 13 (Mac OS X 10.9, iOS 7.0) and later */
  uint8_t                       sharedCacheUUID[16];
  /* the following field is only in version 14 (Mac OS X 10.9, iOS 7.0) and later */
  uintptr_t                     reserved[16];
};

// From mach-o/dyld_images.h (end)

// Modified from the xnu kernel's osfmk/kdp/kdp_dyld.h (begin)

struct user32_dyld_all_image_infos {
  uint32_t      version;
  uint32_t      infoArrayCount;
  user32_addr_t infoArray;
  user32_addr_t notification;
  uint8_t       processDetachedFromSharedRegion;
  uint8_t       libSystemInitialized;
  user32_addr_t dyldImageLoadAddress;
  user32_addr_t jitInfo;
  user32_addr_t dyldVersion;
  user32_addr_t errorMessage;
  user32_addr_t terminationFlags;
  user32_addr_t coreSymbolicationShmPage;
  user32_addr_t systemOrderFlag;
  user32_size_t uuidArrayCount;    // dyld defines this as a uintptr_t despite it being a count
  user32_addr_t uuidArray;
  user32_addr_t dyldAllImageInfosAddress;
  user32_addr_t initialImageCount; // dyld defines this as a uintptr_t despite it being a count
  user32_addr_t errorKind;
  user32_addr_t errorClientOfDylibPath;
  user32_addr_t errorTargetDylibPath;
  user32_addr_t errorSymbol;
  user32_addr_t sharedCacheSlide;
  uint8_t       sharedCacheUUID[16];
  user32_addr_t reserved[16];
};

struct user64_dyld_all_image_infos {
  uint32_t      version;
  uint32_t      infoArrayCount;
  user64_addr_t infoArray;
  user64_addr_t notification;
  uint8_t       processDetachedFromSharedRegion;
  uint8_t       libSystemInitialized;
  user64_addr_t dyldImageLoadAddress;
  user64_addr_t jitInfo;
  user64_addr_t dyldVersion;
  user64_addr_t errorMessage;
  user64_addr_t terminationFlags;
  user64_addr_t coreSymbolicationShmPage;
  user64_addr_t systemOrderFlag;
  user64_size_t uuidArrayCount;    // dyld defines this as a uintptr_t despite it being a count
  user64_addr_t uuidArray;
  user64_addr_t dyldAllImageInfosAddress;
  user64_addr_t initialImageCount; // dyld defines this as a uintptr_t despite it being a count
  user64_addr_t errorKind;
  user64_addr_t errorClientOfDylibPath;
  user64_addr_t errorTargetDylibPath;
  user64_addr_t errorSymbol;
  user64_addr_t sharedCacheSlide;
  uint8_t       sharedCacheUUID[16];
  user64_addr_t reserved[16];
};

// Modified from the xnu kernel's osfmk/kdp/kdp_dyld.h (end)

struct user32_dyld_image_info {
 user32_addr_t imageLoadAddress; // Slid
 user32_addr_t imageFilePath;
 user32_addr_t imageFileModDate;
};

struct user64_dyld_image_info {
 user64_addr_t imageLoadAddress; // Slid
 user64_addr_t imageFilePath;
 user64_addr_t imageFileModDate;
};

// Bit in mach_header.flags that indicates whether or not the (dylib) module
// is in the shared cache.
#define MH_SHAREDCACHE 0x80000000

typedef enum {
  symbol_type_defined = 0, // For locally defined symbols
  symbol_type_undef   = 1, // For symbols imported from other modules
} symbol_type_t;

typedef struct _symbol_table {
  vm_address_t symbol_table;
  vm_size_t symbol_table_size;
  vm_address_t indirect_symbol_table;
  vm_size_t indirect_symbol_table_size;
  vm_address_t string_table;
  vm_size_t string_table_size;
  vm_address_t lazy_ptr_table;
  vm_size_t lazy_ptr_table_size;
  user_addr_t lazy_ptr_table_addr;
  uint64_t lazy_ptr_table_count; // Number of items in table
  vm_address_t stubs_table;
  user_addr_t stubs_table_addr;
  vm_size_t stubs_table_size;
  uint64_t stubs_table_count;    // Number of items in table
  vm_offset_t slide;
  vm_offset_t module_size;
  vm_offset_t pagezero_size;
  // If symbol_type == symbol_type_defined, symbol_index and symbol_count
  // refer to the symbol table itself.  But for symbol_type_undef, they
  // refer to the indirect symbol table.
  uint32_t symbol_index; // Index to "interesting" symbols
  uint32_t symbol_count; // Number of "interesting" symbols
  uint32_t total_symbol_count; // Total # of items in symbol table
  symbol_type_t symbol_type;
  bool is_64bit;
  bool is_in_shared_cache;
  // If false, browse the lazy pointer table directly when searching for
  // interpose hooking targets. If true, browse it indirectly via the stubs
  // table. Only meaningful if symbol_type == symbol_type_undefined.
  bool use_stubs_table_proxy;
} symbol_table_t;

typedef struct _module_info {
  char path[PATH_MAX];
  user_addr_t load_address; // Slid
  vm_offset_t shared_cache_slide;
  bool libSystem_initialized;
  proc_t proc;
} module_info_t;

// As of macOS 13 (Ventura), some mach-o modules in the dyld shared cache
// no longer have their own lazy (or non-lazy) pointer table. In such cases
// it's been "optimized" away, and replaced by one that's not described in the
// module's load commands, and which may be shared with other modules. In this
// case our only access to it is via the "__stubs" section of the "__TEXT"
// segment -- the stubs table. Each entry in the stubs table is a 'jmpq
// *address(%rip)' instruction, where 'address' is an entry in the (otherwise
// invisible) lazy pointer table. As this happens on Ventura (and up), we only
// need to worry about it in 64-bit mode.

// {0xFF, 0x25}
#define STUBS_TABLE_ENTRY_OPCODE 0x25FF

// Format of each entry in the stubs table, which is always a
// 'jmpq *address(%rip)' instruction.
#pragma pack(2)
typedef struct _stubs_table_entry {
  uint16_t opcode; // Should always be STUBS_TABLE_ENTRY_OPCODE
  int32_t offset;  // Offset from address after end of instruction
} stubs_table_entry;
#pragma pack()

// If some of our modules' lazy pointer tables have been optimized away (and
// replaced by ones that are shared with other modules), they may not have
// been fully initialized by the time we would normally call
// set_interpose_hooks(). Uncomment this to delay our call until after the
// hooked process has finished calling its initializers. Note that this
// prevents interpose hooks from working in code called from these
// initializers.
//#define DELAY_SET_INTERPOSE_HOOKS 1

// Copy the "interesting" part of a module's symbol table into kernel space.
// We need to call free_symbol_table(symbol_table) after we're done.
bool copyin_symbol_table(module_info_t *module_info,
                         symbol_table_t *symbol_table,
                         symbol_type_t symbol_type)
{
  if (!module_info || !symbol_table) {
    return false;
  }
  if ((symbol_type != symbol_type_defined) &&
      (symbol_type != symbol_type_undef))
  {
    return false;
  }
  bzero(symbol_table, sizeof(symbol_table_t));
  if (!find_kernel_private_functions()) {
    return false;
  }

  bool is_64bit = IS_64BIT_PROCESS(module_info->proc);
  vm_map_t proc_map = task_map_for_proc(module_info->proc);
  if (!proc_map) {
    return false;
  }

  struct mach_header_64 mh_local;
  mach_vm_size_t mh_size;
  if (is_64bit) {
    mh_size = sizeof(mach_header_64);
  } else {
    mh_size = sizeof(mach_header);
  }
  if (!proc_copyin(proc_map, module_info->load_address, &mh_local, mh_size)) {
    vm_map_deallocate(proc_map);
    return false;
  }
  if ((mh_local.magic != MH_MAGIC) && (mh_local.magic != MH_MAGIC_64)) {
    vm_map_deallocate(proc_map);
    return false;
  }

  bool is_in_shared_cache = ((mh_local.flags & MH_SHAREDCACHE) != 0);

  vm_size_t cmds_size = mh_local.sizeofcmds;
  user_addr_t cmds_offset = module_info->load_address + mh_size;
  void *cmds_local;
  if (!proc_mapin(proc_map, cmds_offset,
                  (vm_map_offset_t *) &cmds_local, cmds_size))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  vm_offset_t slide = 0;
  if (is_in_shared_cache) {
    slide = module_info->shared_cache_slide;
  }
  vm_offset_t symbol_table_offset = 0;
  vm_size_t symbol_table_size = 0;
  uint32_t total_symbol_count = 0;
  uint32_t interesting_symbol_index = 0;
  uint32_t interesting_symbol_count = 0;
  vm_offset_t indirect_symbol_table_offset = 0;
  vm_size_t indirect_symbol_table_size = 0;
  vm_offset_t string_table_offset = 0;
  vm_size_t string_table_size = 0;

  vm_offset_t text_sections_offset = 0;
  uint32_t num_text_sections = 0;
  vm_offset_t data_sections_offset = 0;
  uint32_t num_data_sections = 0;
  vm_offset_t data_const_sections_offset = 0;
  uint32_t num_data_const_sections = 0;
  vm_offset_t lazy_ptr_table_offset = 0;
  vm_size_t lazy_ptr_table_size = 0;
  uint64_t lazy_ptr_table_count = 0;
  uint32_t lazy_ptr_indirect_symbol_index = 0;
  vm_offset_t stubs_table_offset = 0;
  vm_size_t stubs_table_size = 0;
  uint64_t stubs_table_count = 0;
  uint32_t stubs_indirect_symbol_index = 0;
  bool use_stubs_table_proxy = false;

  bool found_symbol_table = false;
  bool found_indirect_symbol_table = false;
  bool found_linkedit_segment = false;
  bool found_symtab_segment = false;
  bool found_dysymtab_segment = false;

  bool found_text_segment = false;
  bool found_data_segment = false;
  bool found_data_const_segment = false;
  bool found_lazy_ptr_table = false;
  bool found_stubs_table = false;

  vm_offset_t module_size = mh_size + cmds_size;
  vm_offset_t pagezero_size = 0;
  uint32_t num_commands = mh_local.ncmds;
  const struct load_command *load_command =
    (struct load_command *) cmds_local;
  vm_offset_t linkedit_fileoff_increment = 0;
  uint32_t i, j, k;
  for (i = 1; i <= num_commands; ++i) {
    uint32_t cmd = load_command->cmd;
    switch (cmd) {
      case LC_SEGMENT:
      case LC_SEGMENT_64: {
        char *segname;
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
        uint64_t sections_offset;
        uint32_t nsects;
        if (is_64bit) {
          struct segment_command_64 *command =
            (struct segment_command_64 *) load_command;
          segname = command->segname;
          vmaddr = command->vmaddr;
          vmsize = command->vmsize;
          fileoff = command->fileoff;
          filesize = command->filesize;
          sections_offset =
            (vm_offset_t) load_command + sizeof(struct segment_command_64);
          nsects = command->nsects;
        } else {
          struct segment_command *command =
            (struct segment_command *) load_command;
          segname = command->segname;
          vmaddr = command->vmaddr;
          vmsize = command->vmsize;
          fileoff = command->fileoff;
          filesize = command->filesize;
          sections_offset =
            (vm_offset_t) load_command + sizeof(struct segment_command);
          nsects = command->nsects;
        }
        if (!is_in_shared_cache && !fileoff && filesize) {
          slide = module_info->load_address - vmaddr;
        }
        const char *pagezero_segname = "__PAGEZERO";
        if (!strncmp(segname, pagezero_segname,
            strlen(pagezero_segname) + 1))
        {
          pagezero_size = vmsize;
        } else {
          vm_offset_t segment_end = vmaddr + slide + vmsize;
          vm_offset_t size_to_segment_end =
            segment_end - module_info->load_address;
          if (size_to_segment_end > module_size) {
            module_size = size_to_segment_end;
          }
        }
        const char *text_segname = "__TEXT";
        const char *data_segname = "__DATA";
        // As of macOS Big Sur, the lazy pointers table is at least sometimes
        // in the __DATA_CONST segment.
        const char *data_const_segname = "__DATA_CONST";
        const char *linkedit_segname = "__LINKEDIT";
        if (!strncmp(segname, text_segname, strlen(text_segname) + 1)) {
          text_sections_offset = sections_offset;
          num_text_sections = nsects;
          found_text_segment = true;
        } else if (!strncmp(segname, data_segname, strlen(data_segname) + 1)) {
          data_sections_offset = sections_offset;
          num_data_sections = nsects;
          found_data_segment = true;
        } else if (!strncmp(segname, data_const_segname,
                            strlen(data_const_segname) + 1))
        {
          data_const_sections_offset = sections_offset;
          num_data_const_sections = nsects;
          found_data_const_segment = true;
        } else if (!strncmp(segname, linkedit_segname,
                   strlen(linkedit_segname) + 1))
        {
          linkedit_fileoff_increment = vmaddr - fileoff;
          found_linkedit_segment = true;
        }
        break;
      }
      case LC_SYMTAB: {
        struct symtab_command *command =
          (struct symtab_command *) load_command;
        symbol_table_offset =
          command->symoff + linkedit_fileoff_increment + slide;
        total_symbol_count = command->nsyms;
        string_table_offset =
          command->stroff + linkedit_fileoff_increment + slide;
        string_table_size = command->strsize;
        found_symtab_segment = true;
        break;
      }
      case LC_DYSYMTAB: {
        struct dysymtab_command *command =
          (struct dysymtab_command *) load_command;
        if (symbol_type == symbol_type_defined) {
          interesting_symbol_index = command->ilocalsym;
          interesting_symbol_count = command->nlocalsym + command->nextdefsym;
        } else {        // symbol_type_undef
          interesting_symbol_index = 0;                      // provisional
          interesting_symbol_count = command->nindirectsyms; // provisional
        }
        indirect_symbol_table_offset =
          command->indirectsymoff + linkedit_fileoff_increment + slide;
        indirect_symbol_table_size = command->nindirectsyms * sizeof(uint32_t);
        if (indirect_symbol_table_offset && indirect_symbol_table_size) {
          found_indirect_symbol_table = true;
        }
        found_dysymtab_segment = true;
        break;
      }
    }
    if (found_linkedit_segment && found_symtab_segment &&
        found_dysymtab_segment && total_symbol_count && string_table_size)
    {
      found_symbol_table = true;
    }
    load_command = (struct load_command *)
      ((vm_offset_t)load_command + load_command->cmdsize);
  }

  if (is_64bit && found_text_segment && found_indirect_symbol_table &&
      (symbol_type == symbol_type_undef))
  {
    vm_offset_t section_offset = text_sections_offset;
    for (i = 1; i <= num_text_sections; ++i) {
      struct section_64 *section = (struct section_64 *) section_offset;
      uint64_t addr = section->addr;
      uint64_t size = section->size;
      bool expected_stubs_align = (section->align == 1);
      uint8_t type = (section->flags & SECTION_TYPE);
      uint32_t indirect_symbol_index = section->reserved1;
      uint32_t entry_size = section->reserved2;

      if ((type == S_SYMBOL_STUBS) && size && expected_stubs_align &&
          (entry_size == sizeof(stubs_table_entry)))
      {
        stubs_table_offset = addr + slide;
        stubs_table_size = size;
        stubs_indirect_symbol_index = indirect_symbol_index;
        stubs_table_count = size / entry_size;
        found_stubs_table = true;
        break;
      }

      section_offset += sizeof(struct section_64);
    }
  }

  if ((found_data_segment || found_data_const_segment) &&
      found_indirect_symbol_table && (symbol_type == symbol_type_undef))
  {
    // Look first in the __DATA segment for the lazy pointers table. Then if
    // it's not found, look in the __DATA_CONST segment.
    for (i = 1; i <= 2; ++i) {
      vm_offset_t section_begin;
      uint32_t num_sections;
      if (i == 1) {
        if (!found_data_segment) {
          continue;
        }
        section_begin = data_sections_offset;
        num_sections = num_data_sections;
      } else {
        if (!found_data_const_segment) {
          continue;
        }
        section_begin = data_const_sections_offset;
        num_sections = num_data_const_sections;
      }

      // On macOS Monterey and above, most dylibs no longer have a "lazy"
      // pointer table. When this happens, its place is taken by a single
      // "non-lazy" pointer table (usually/always in a "__got" section). So
      // first look for a lazy pointer table, then look for a non-lazy one. Do
      // this even on earlier versions of macOS. It's likely that dylibs
      // compiled on Monterey without a lazy pointer table will end up running
      // there. A non-lazy pointer table's contents are already initialized,
      // which supposedly speeds up an application's loading.
      for (j = 1; j <= 2; ++j) {
        vm_offset_t section_offset = section_begin;
        uint8_t expected_section_type = S_LAZY_SYMBOL_POINTERS;
        if (j == 2) {
          expected_section_type = S_NON_LAZY_SYMBOL_POINTERS;
        }

        for (k = 1; k <= num_sections; ++k) {
          uint64_t addr;
          uint64_t size;
          uint64_t count;
          bool expected_lazy_align;
          uint8_t type;
          uint32_t indirect_symbol_index;
          if (is_64bit) {
            struct section_64 *section = (struct section_64 *) section_offset;
            addr = section->addr;
            size = section->size;
            count = size / sizeof(uint64_t);
            expected_lazy_align = (section->align == 3);
            type = (section->flags & SECTION_TYPE);
            indirect_symbol_index = section->reserved1;
          } else {
            struct section *section = (struct section *) section_offset;
            addr = section->addr;
            size = section->size;
            count = size / sizeof(uint32_t);
            expected_lazy_align = (section->align == 2);
            type = (section->flags & SECTION_TYPE);
            indirect_symbol_index = section->reserved1;
          }

          if ((type == expected_section_type) && size && expected_lazy_align) {
            // If there's more than one of the sections we're looking for, we
            // want the last one, which should always be the right one.
            if (count + indirect_symbol_index == interesting_symbol_count) {
              lazy_ptr_table_offset = addr + slide;
              lazy_ptr_table_size = size;
              lazy_ptr_indirect_symbol_index = indirect_symbol_index;
              lazy_ptr_table_count = count;
              found_lazy_ptr_table = true;
              break;
            }
          }

          if (is_64bit) {
            section_offset += sizeof(struct section_64);
          } else {
            section_offset += sizeof(struct section);
          }
        }

        if (found_lazy_ptr_table) {
          break;
        }
      }
    }
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) cmds_local, cmds_size);

  if (!found_symbol_table) {
    vm_map_deallocate(proc_map);
    return false;
  }

  vm_map_offset_t stubs_table_local = 0;
  if (symbol_type == symbol_type_undef) {
    // If we're in 64-bit mode and haven't found our module's lazy pointer
    // table, we've got to browse the stubs table when we're looking for
    // interpose hooking targets.
    if (is_64bit && !found_lazy_ptr_table) {
      if (!found_stubs_table) {
        vm_map_deallocate(proc_map);
        return false;
      }
      if (!proc_mapin(proc_map, stubs_table_offset, &stubs_table_local,
                      stubs_table_size))
      {
        vm_map_deallocate(proc_map);
        return false;
      }
      use_stubs_table_proxy = true;
    }
    if (!use_stubs_table_proxy && !found_lazy_ptr_table) {
      if (stubs_table_local) {
        vm_deallocate(kernel_map, stubs_table_local, stubs_table_size);
      }
      vm_map_deallocate(proc_map);
      return false;
    }

    if (use_stubs_table_proxy) {
      interesting_symbol_index += stubs_indirect_symbol_index;
      interesting_symbol_count -= stubs_indirect_symbol_index;
    } else {
      interesting_symbol_index += lazy_ptr_indirect_symbol_index;
      interesting_symbol_count -= lazy_ptr_indirect_symbol_index;
    }
  }

  vm_size_t nlist_size;
  if (is_64bit) {
    nlist_size = sizeof(struct nlist_64);
  } else {
    nlist_size = sizeof(struct nlist);
  }
  symbol_table_size = nlist_size * total_symbol_count;

  vm_map_offset_t symbol_table_local;
  if (!proc_mapin(proc_map, symbol_table_offset, &symbol_table_local,
                  symbol_table_size))
  {
    if (stubs_table_local) {
      vm_deallocate(kernel_map, stubs_table_local, stubs_table_size);
    }
    vm_map_deallocate(proc_map);
    return false;
  }
  vm_map_offset_t string_table_local;
  if (!proc_mapin(proc_map, string_table_offset, &string_table_local,
                  string_table_size))
  {
    if (stubs_table_local) {
      vm_deallocate(kernel_map, stubs_table_local, stubs_table_size);
    }
    vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
    vm_map_deallocate(proc_map);
    return false;
  }
  vm_map_offset_t indirect_symbol_table_local = 0;
  vm_map_offset_t lazy_ptr_table_local = 0;
  if (symbol_type == symbol_type_undef) {
    if (!proc_mapin(proc_map, indirect_symbol_table_offset,
                    &indirect_symbol_table_local, indirect_symbol_table_size))
    {
      if (stubs_table_local) {
        vm_deallocate(kernel_map, stubs_table_local, stubs_table_size);
      }
      vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
      vm_deallocate(kernel_map, string_table_local, string_table_size);
      vm_map_deallocate(proc_map);
      return false;
    }
    if (found_lazy_ptr_table) {
      if (!proc_mapin(proc_map, lazy_ptr_table_offset, &lazy_ptr_table_local,
                      lazy_ptr_table_size))
      {
        if (stubs_table_local) {
          vm_deallocate(kernel_map, stubs_table_local, stubs_table_size);
        }
        vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
        vm_deallocate(kernel_map, string_table_local, string_table_size);
        vm_deallocate(kernel_map, indirect_symbol_table_local,
                      indirect_symbol_table_size);
        vm_map_deallocate(proc_map);
        return false;
      }
    }
  }

  vm_map_deallocate(proc_map);

  symbol_table->symbol_table = (vm_address_t) symbol_table_local;
  symbol_table->symbol_table_size = symbol_table_size;
  symbol_table->indirect_symbol_table =
    (vm_address_t) indirect_symbol_table_local;
  symbol_table->indirect_symbol_table_size = indirect_symbol_table_size;
  symbol_table->string_table = (vm_address_t) string_table_local;
  symbol_table->string_table_size = string_table_size;
  symbol_table->lazy_ptr_table = (vm_address_t) lazy_ptr_table_local;
  symbol_table->lazy_ptr_table_size = lazy_ptr_table_size;
  symbol_table->lazy_ptr_table_addr = lazy_ptr_table_offset;
  symbol_table->lazy_ptr_table_count = lazy_ptr_table_count;
  symbol_table->stubs_table = (vm_address_t) stubs_table_local;
  symbol_table->stubs_table_size = stubs_table_size;
  symbol_table->stubs_table_addr = stubs_table_offset;
  symbol_table->stubs_table_count = stubs_table_count;
  symbol_table->slide = slide;
  symbol_table->module_size = module_size;
  symbol_table->pagezero_size = pagezero_size;
  symbol_table->symbol_index = interesting_symbol_index;
  symbol_table->symbol_count = interesting_symbol_count;
  symbol_table->total_symbol_count = total_symbol_count;
  symbol_table->symbol_type = symbol_type;
  symbol_table->is_64bit = is_64bit;
  symbol_table->is_in_shared_cache = is_in_shared_cache;
  symbol_table->use_stubs_table_proxy = use_stubs_table_proxy;
  return true;
}

void free_symbol_table(symbol_table_t *symbol_table)
{
  if (!symbol_table) {
    return;
  }
  if (symbol_table->symbol_table) {
    vm_deallocate(kernel_map, symbol_table->symbol_table,
                  symbol_table->symbol_table_size);
  }
  if (symbol_table->indirect_symbol_table) {
    vm_deallocate(kernel_map, symbol_table->indirect_symbol_table,
                  symbol_table->indirect_symbol_table_size);
  }
  if (symbol_table->string_table) {
    vm_deallocate(kernel_map, symbol_table->string_table,
                  symbol_table->string_table_size);
  }
  if (symbol_table->lazy_ptr_table) {
    vm_deallocate(kernel_map, symbol_table->lazy_ptr_table,
                  symbol_table->lazy_ptr_table_size);
  }
  if (symbol_table->stubs_table) {
    vm_deallocate(kernel_map, symbol_table->stubs_table,
                  symbol_table->stubs_table_size);
  }
}

// Don't let DYLD_SLIDE_SEARCH_INCREMENT be greater than PAGE_SIZE
#define DYLD_SLIDE_SEARCH_INCREMENT   PAGE_SIZE
#define DYLD_SLIDE_SEARCH_LIMIT       0x200000
#define DYLD_SLIDE_SEARCH_COPYIN_SIZE (0x10 * PAGE_SIZE)

// 'module_mh' is already 'slid'.  This method supports partial matches.  So
// 'module_name' might be a substring of the module's full name.
bool get_module_info(proc_t proc, const char *module_name,
                     user_addr_t module_mh, module_info_t *module_info)
{
  if (!proc || !module_info) {
    return false;
  }
  if ((!module_name || !module_name[0]) && !module_mh) {
    return false;
  }
  if (module_name && module_name[0] && module_mh) {
    return false;
  }
  bzero(module_info, sizeof(module_info_t));
  if (!find_kernel_private_functions()) {
    return false;
  }

  bool is_64bit = IS_64BIT_PROCESS(proc);
  task_t our_task = proc_task(proc);
  if (!our_task) {
    return false;
  }

  vm_address_t all_image_info_addr = task_all_image_info_addr(our_task);
  vm_size_t all_image_info_size = task_all_image_info_size(our_task);

  if (!all_image_info_addr || !all_image_info_size) {
    return false;
  }

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return false;
  }

  char *holder;
  if (!proc_mapin(proc_map, all_image_info_addr,
                  (vm_map_offset_t *) &holder, all_image_info_size))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  uint32_t info_array_count = 0;
  user_addr_t info_array_addr = 0;
  vm_size_t info_array_size = 0;
  bool libSystem_initialized = false;
  user_addr_t dyld_image_load_address = 0;
  vm_offset_t shared_cache_slide = 0;
  if (is_64bit) {
    struct user64_dyld_all_image_infos *info =
      (struct user64_dyld_all_image_infos *) holder;
    info_array_count = info->infoArrayCount;
    info_array_size =
      info_array_count * sizeof(struct user64_dyld_image_info);
    info_array_addr = info->infoArray;
    libSystem_initialized = info->libSystemInitialized;
    dyld_image_load_address = info->dyldImageLoadAddress;
    shared_cache_slide = info->sharedCacheSlide;
  } else {
    struct user32_dyld_all_image_infos *info =
      (struct user32_dyld_all_image_infos *) holder;
    info_array_count = info->infoArrayCount;
    info_array_size =
      info_array_count * sizeof(struct user32_dyld_image_info);
    info_array_addr = info->infoArray;
    libSystem_initialized = info->libSystemInitialized;
    dyld_image_load_address = info->dyldImageLoadAddress;
    shared_cache_slide = info->sharedCacheSlide;
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) holder, all_image_info_size);

  name_out_t basename_out;
  const char *dyld_basename = "dyld";
  if (module_name && module_name[0] &&
      !strncmp(basename(module_name, basename_out), dyld_basename,
               strlen(dyld_basename) + 1))
  {
    bool dyld_image_load_address_good = true;
    // dyld_image_load_address is inaccurate (zero or unslid, or on Catalina
    // some impossibly large value) if the process's executable image hasn't
    // yet been initialized (if _dyld_start hasn't yet been called).  So we
    // need to look for the header (and compute its slide) ourselves.
    if (!libSystem_initialized) {
      dyld_image_load_address_good = false;
      // On Catalina and up dyld_image_load_address is initialized to
      // 0x0020000000000000!
      if (dyld_image_load_address > VM_MAX_USER_PAGE_ADDRESS) {
        dyld_image_load_address = 0;
      }
      // all_image_info_addr is always in dyld, and dyld's size is 1-3 MB.
      // The dyld_all_image_infos are in their own section in dyld's DATA
      // segment (__all_image_info), which seems always to be within the first
      // MB. But decrement search_start by another MB, just to be sure.
      uint64_t search_start = (all_image_info_addr & 0xfffffffffff00000);
      if (search_start > 0x100000) {
        search_start -= 0x100000;
      }
      if (search_start > dyld_image_load_address) {
        dyld_image_load_address = search_start;
      }

      vm_map_offset_t buffer = 0;
      vm_offset_t dyld_slide = 0;
      vm_size_t copyin_size = DYLD_SLIDE_SEARCH_COPYIN_SIZE;
      vm_size_t buffer_size = DYLD_SLIDE_SEARCH_COPYIN_SIZE;
      for (; dyld_slide < DYLD_SLIDE_SEARCH_LIMIT;
           dyld_slide += DYLD_SLIDE_SEARCH_INCREMENT)
      {
        if ((dyld_slide % DYLD_SLIDE_SEARCH_COPYIN_SIZE) == 0) {
          copyin_size = DYLD_SLIDE_SEARCH_COPYIN_SIZE;
        }

        vm_offset_t buffer_offset = (dyld_slide % copyin_size);
        bool needs_new_buffer = (!buffer || !buffer_offset);
        // Skip the rest of 'buffer' if the space remaining might not contain
        // a whole header structure.
        if (buffer && !needs_new_buffer) {
          vm_size_t space_remaining = copyin_size - buffer_offset;
          vm_size_t mach_header_size;
          if (is_64bit) {
            mach_header_size = sizeof(struct mach_header_64);
          } else {
            mach_header_size = sizeof(struct mach_header);
          }
          if ((space_remaining <= mach_header_size) &&
              ((space_remaining / DYLD_SLIDE_SEARCH_INCREMENT) ==
                (mach_header_size / DYLD_SLIDE_SEARCH_INCREMENT)))
          {
            dyld_slide += space_remaining;
            buffer_offset = 0;
            needs_new_buffer = true;
          }
        }

        if (needs_new_buffer) {
          if (buffer) {
            vm_deallocate(kernel_map, buffer, buffer_size);
            buffer = 0;
          }
          vm_map_copy_t copy;
          kern_return_t rv =
            vm_map_copyin(proc_map, dyld_image_load_address + dyld_slide,
                          copyin_size, false, &copy);
          if (rv != KERN_SUCCESS) {
            vm_size_t old_copyin_size = copyin_size;
            copyin_size = PAGE_SIZE;
            if (copyin_size != old_copyin_size) {
              rv = vm_map_copyin(proc_map, dyld_image_load_address + dyld_slide,
                                 copyin_size, false, &copy);
            }
            if (rv != KERN_SUCCESS) {
              dyld_slide += (copyin_size - DYLD_SLIDE_SEARCH_INCREMENT);
              continue;
            }
          }
          rv = vm_map_copyout(kernel_map, &buffer, copy);
          if (rv != KERN_SUCCESS) {
            buffer = 0;
            vm_map_copy_discard(copy);
            dyld_slide += (copyin_size - DYLD_SLIDE_SEARCH_INCREMENT);
            continue;
          }
          buffer_size = copyin_size;
        }

        vm_offset_t addr = buffer + buffer_offset;
        if (is_64bit) {
          struct mach_header_64 *header = (struct mach_header_64 *) addr;
          if ((header->magic != MH_MAGIC_64) ||
              (header->cputype != CPU_TYPE_X86_64) ||
              (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
              (header->filetype != MH_DYLINKER))
          {
            continue;
          }
        } else {
          struct mach_header *header = (struct mach_header *) addr;
          if ((header->magic != MH_MAGIC) ||
              (header->cputype != CPU_TYPE_X86) ||
              (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
              (header->filetype != MH_DYLINKER))
          {
            continue;
          }
        }
        vm_deallocate(kernel_map, buffer, buffer_size);
        dyld_image_load_address += dyld_slide;
        dyld_image_load_address_good = true;
        break;
      }
    }

    vm_map_deallocate(proc_map);
    if (!dyld_image_load_address_good) {
      return false;
    }
    strncpy(module_info->path, module_name, sizeof(module_info->path));
    module_info->load_address = dyld_image_load_address;
    module_info->shared_cache_slide = shared_cache_slide;
    module_info->libSystem_initialized = libSystem_initialized;
    module_info->proc = proc;
    return true;
  }

  if (!info_array_count || !info_array_size || !info_array_addr) {
    vm_map_deallocate(proc_map);
    return false;
  }

  if (!proc_mapin(proc_map, info_array_addr,
                  (vm_map_offset_t *) &holder, info_array_size))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  bool module_name_is_basename = false;
  if (module_name && module_name[0]) {
    name_out_t basename_out;
    module_name_is_basename =
      (strncmp(basename(module_name, basename_out),
               module_name, strlen(module_name) + 1) == 0);
  }

  uint32_t i;
  bool matched = false;
  char path_local[PATH_MAX];
  for (i = 0; i < info_array_count; ++i) {
    user_addr_t load_addr = 0;
    user_addr_t path_addr = 0;
    if (is_64bit) {
      struct user64_dyld_image_info *info_array =
        (struct user64_dyld_image_info *) holder;
      load_addr = info_array[i].imageLoadAddress;
      path_addr = info_array[i].imageFilePath;
    } else {
      struct user32_dyld_image_info *info_array =
        (struct user32_dyld_image_info *) holder;
      load_addr = info_array[i].imageLoadAddress;
      path_addr = info_array[i].imageFilePath;
    }
    if (!path_addr) {
      continue;
    }
    if (!proc_copyinstr(proc_map, path_addr, path_local, sizeof(path_local))) {
      continue;
    }
    // If possible, canonicalize path_local.
    char fixed_path_local[PATH_MAX];
    fixed_path_local[0] = 0;
    vfs_context_t context = vfs_context_create(NULL);
    if (context) {
      vnode_t module_vnode;
      if (!vnode_lookup(path_local, 0, &module_vnode, context)) {
        int len = sizeof(fixed_path_local);
        vn_getpath(module_vnode, fixed_path_local, &len);
        vnode_put(module_vnode);
      }
      vfs_context_rele(context);
    }
    if (fixed_path_local[0]) {
      strncpy(path_local, fixed_path_local, sizeof(path_local));
    }
    if (module_name && module_name[0]) {
      if (module_name_is_basename) {
        name_out_t basename_out;
        matched = 
          (strnstr_ptr(basename(path_local, basename_out), module_name,
                                sizeof(path_local)) != NULL);
      } else {
        matched = (strnstr_ptr(path_local, module_name, sizeof(path_local)) != NULL);
      }
    } else {
      matched = (load_addr == module_mh);
    }
    if (matched) {
      strncpy(module_info->path, path_local, sizeof(module_info->path));
      module_info->load_address = load_addr;
      module_info->shared_cache_slide = shared_cache_slide;
      module_info->libSystem_initialized = libSystem_initialized;
      module_info->proc = proc;
      break;
    }
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) holder, info_array_size);
  vm_map_deallocate(proc_map);
  return matched;
}

// Look for a symbol that's defined in 'symbol_table'.
user_addr_t find_symbol(const char *symbol_name, symbol_table_t *symbol_table)
{
  if (!symbol_name || !symbol_name[0] || !symbol_table) {
    return 0;
  }

  user_addr_t retval = 0;
  int32_t i;
  for (i = symbol_table->symbol_index;
       i < symbol_table->symbol_index + symbol_table->symbol_count; ++i)
  {
    uint8_t type;
    uint8_t sect;
    char *string_table_item;
    uint64_t value;
    if (symbol_table->is_64bit) {
      struct nlist_64 *symbol_table_item = (struct nlist_64 *)
        (symbol_table->symbol_table + i * sizeof(struct nlist_64));
      type = symbol_table_item->n_type;
      sect = symbol_table_item->n_sect;
      string_table_item = (char *)
        (symbol_table->string_table + symbol_table_item->n_un.n_strx);
      value = symbol_table_item->n_value;
    } else {
      struct nlist *symbol_table_item = (struct nlist *)
        (symbol_table->symbol_table + i * sizeof(struct nlist));
      type = symbol_table_item->n_type;
      sect = symbol_table_item->n_sect;
      string_table_item = (char *)
        (symbol_table->string_table + symbol_table_item->n_un.n_strx);
      value = symbol_table_item->n_value;
    }
    if ((type & N_STAB) || ((type & N_TYPE) != N_SECT)) {
      continue;
    }
    if (!sect) {
      continue;
    }
    if (strncmp(symbol_name, string_table_item, strlen(symbol_name) + 1)) {
      continue;
    }
    retval = value + symbol_table->slide;
    break;
  }

  return retval;
}

#if (0)
typedef struct report_region_info {
  uint32_t entry_count;
} *report_region_info_t;

void report_region_iterator(vm_map_t map, vm_map_entry_t entry,
                            uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }
  report_region_info_t info_local = (report_region_info_t) info;
  ++info_local->entry_count;

  vm_prot_t entry_protection = 0;
  vm_prot_t entry_max_protection = 0;
  vm_inherit_t entry_inheritance = 0;
  unsigned short entry_wired_count = 0;
  unsigned short entry_user_wired_count = 0;
  bool entry_shared = false;
  bool entry_superpage_size = false;
  vm_map_offset_t entry_start = 0;
  vm_map_offset_t entry_end = 0;
  vm_map_size_t entry_size = 0;
  vm_object_t object = NULL;
  vm_object_offset_t offset = 0;
  bool object_code_signed = false;
  bool object_slid = false;
  vm_page_t page = NULL;
  ppnum_t phys_page = 0;
  bool page_wpmapped = false;
  unsigned char page_cs_validated = 0;
  unsigned char page_cs_tainted = 0;
  bool page_slid = false;

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

  entry_protection = an_entry->protection;
  entry_max_protection = an_entry->max_protection;
  entry_inheritance = an_entry->inheritance;
  entry_wired_count = an_entry->wired_count;
  entry_user_wired_count = an_entry->user_wired_count;
  entry_shared = an_entry->is_shared;
  entry_superpage_size = vm_map_entry_get_superpage_size(entry);
  entry_start = an_entry->vme_start;
  entry_end = an_entry->vme_end;
  entry_size = entry_end - entry_start;
  object = map_entry_object(entry).vmo_object;
  offset = map_entry_offset(entry);

  if (object) {
    vm_object_t orig_object = object;

    vm_object_lock(object);
    page = vm_page_lookup(object, offset);
    while (!page) {
      vm_object_t shadow = object_get_shadow(object);
      if (!shadow) {
        break;
      }
      vm_object_lock(shadow);
      vm_object_unlock(object);
      offset += object_get_shadow_offset(object);
      object = shadow;
      page = vm_page_lookup(object, offset);
    }
    vm_object_unlock(object);

    if (page) {
      phys_page = page_phys_page(page);
      page_wpmapped = page_is_wpmapped(page);
      page_cs_validated = page_is_cs_validated(page);
      page_cs_tainted = page_is_cs_tainted(page);
      page_slid = page_is_slid(page);
    } else {
      object = orig_object;
    }

    object_code_signed = object_is_code_signed(object);
    object_slid = object_is_slid(object);
  }

  printf("HookCase: report_region(%d): submap_level \'%d\', entry_start \'0x%llx\', entry_end \'0x%llx\', entry_size \'0x%llx\', prot \'%d\', max_prot \'%d\', inheritance \'%d\', wired_count \'%d\', shared \'%d\', superpage_size \'%d\', object \'0x%08llx%08llx\', offset \'0x%llx\', code_signed \'%d\', slid \'%d\', page \'0x%08llx%08llx\', phys_page \'0x%x\', wpmapped \'%d\', slid \'%d\', cs_validated \'%d\', cs_tainted \'%d\'\n",
         info_local->entry_count, submap_level, entry_start, entry_end, entry_size,
         entry_protection, entry_max_protection, entry_inheritance,
         entry_wired_count, entry_shared, entry_superpage_size,
         (uint64_t) object >> 32, (uint64_t) object & 0xffffffff, offset,
         object_code_signed, object_slid, (uint64_t) page >> 32, (uint64_t) page & 0xffffffff,
         phys_page, page_wpmapped, page_slid, page_cs_validated, page_cs_tainted);
}

void report_region(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return;
  }

  struct report_region_info info;
  bzero(&info, sizeof(info));

  vm_map_iterate_entries(map, start, end, report_region_iterator, &info);
}
#endif

typedef struct user_region_codesigned_info {
  bool is_signed;
} *user_region_codesigned_info_t;

void user_region_codesigned_iterator(vm_map_t map, vm_map_entry_t entry,
                                     uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }
  user_region_codesigned_info_t info_local =
    (user_region_codesigned_info_t) info;

  bool is_signed = false;

  vm_object_t object = map_entry_object(entry).vmo_object;
  vm_object_offset_t offset = map_entry_offset(entry);

  if (object) {
    vm_object_t orig_object = object;

    vm_object_lock(object);
    vm_page_t page = vm_page_lookup(object, offset);
    while (!page) {
      vm_object_t shadow = object_get_shadow(object);
      if (!shadow) {
        break;
      }
      vm_object_lock(shadow);
      vm_object_unlock(object);
      offset += object_get_shadow_offset(object);
      object = shadow;
      page = vm_page_lookup(object, offset);
    }
    vm_object_unlock(object);

    if (!page) {
      object = orig_object;
    }

    is_signed = object_is_code_signed(object);

#ifdef DEBUG_LAZY_POINTERS
    proc_t proc = get_set_interpose_hooks_for_module_proc();
    if (proc) {
      pid_t pid = proc_pid(proc);
      char procname[PATH_MAX];
      proc_name(pid, procname, sizeof(procname));
      kprintf("HookCase(%s[%d]): user_region_codesigned_iterator(): is_signed %d, offset 0x%llx, submap_level %d\n",
              procname, pid, is_signed, offset, submap_level);
    }
#endif
  }

  info_local->is_signed |= is_signed;
}

bool user_region_codesigned(vm_map_t map, vm_map_offset_t start,
                            vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return false;
  }

  struct user_region_codesigned_info info;
  bzero(&info, sizeof(info));

  vm_map_iterate_entries(map, start, end,
                         user_region_codesigned_iterator, &info);

  return info.is_signed;
}

void sign_user_pages_iterator(vm_map_t map, vm_map_entry_t entry,
                              uint32_t submap_level, void *info)
{
  if (!map || !entry) {
    return;
  }

  bool sign = (bool) info;

  vm_object_t object = map_entry_object(entry).vmo_object;
  vm_object_offset_t offset = map_entry_offset(entry);

  if (!object) {
    return;
  }

  vm_object_t shadow = NULL;
  vm_page_t page = NULL;

  while (1) {
    vm_object_lock(object);

    page = vm_page_lookup(object, offset);
    while (!page) {
      vm_object_t shadow = object_get_shadow(object);
      if (!shadow) {
        break;
      }
      vm_object_lock(shadow);
      vm_object_unlock(object);
      offset += object_get_shadow_offset(object);
      object = shadow;
      page = vm_page_lookup(object, offset);
    }

    if (!page) {
      vm_object_unlock(object);
      break;
    }

    // Emulate vm_map_sign() from the xnu kernel's osfmk/vm/vm_map.c
    if (sign) {
      if (macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
          macOS_Sonoma() || macOS_Sequoia())
      {
        page_set_cs_validated(page, 0xf);
      } else {
        page_set_cs_validated(page, 1);
      }
      page_set_wpmapped(page, false);
    } else {
      page_set_cs_validated(page, 0);
    }

    vm_object_unlock(object);

#ifdef DEBUG_LAZY_POINTERS
    proc_t proc = get_set_interpose_hooks_for_module_proc();
    if (proc) {
      pid_t pid = proc_pid(proc);
      char procname[PATH_MAX];
      proc_name(pid, procname, sizeof(procname));
      kprintf("HookCase(%s[%d]): sign_user_pages_iterator(): sign %d, offset 0x%llx, submap_level %d\n",
              procname, pid, sign, offset, submap_level);
    }
#endif

    shadow = object_get_shadow(object);
    if (!shadow) {
      break;
    }
    offset += object_get_shadow_offset(object);
    object = shadow;
  }
}

// Make sure the contents of this region are considered to be validated as
// codesigned -- so they won't subsequently be rechecked.
void sign_user_pages(vm_map_t map, vm_map_offset_t start,
                     vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return;
  }

  vm_map_iterate_entries(map, start, end, sign_user_pages_iterator, (void *) true);
}

// Make sure the contents of this region aren't considered to be validated.
// On macOS 10.14 (Mojave) and up, writing to a "validated" region can cause
// problems.
void unsign_user_pages(vm_map_t map, vm_map_offset_t start,
                       vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return;
  }

  vm_map_iterate_entries(map, start, end, sign_user_pages_iterator, (void *) false);
}

typedef struct user_region_prot_info {
  uint32_t prot_none_count;
  uint32_t prot_read_count;
  uint32_t prot_write_count;
  uint32_t prot_exec_count;
  uint32_t entry_count;
} *user_region_prot_info_t;

void user_region_prot_iterator(vm_map_t map, vm_map_entry_t entry,
                               uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }
  user_region_prot_info_t info_local = (user_region_prot_info_t) info;
  ++info_local->entry_count;

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;
  vm_prot_t protection = an_entry->protection;

  if (protection == VM_PROT_NONE) {
    ++info_local->prot_none_count;
  } else {
    if (protection & VM_PROT_READ) {
      ++info_local->prot_read_count;
    }
    if (protection & VM_PROT_WRITE) {
      ++info_local->prot_write_count;
    }
    if (protection & VM_PROT_EXECUTE) {
      ++info_local->prot_exec_count;
    }
  }
}

// retval == -1 indicates an invalid value. Either vm_map_iterate_entries()
// failed or the region has multiple pages with different permissions.
vm_prot_t user_region_protection(vm_map_t map, vm_map_offset_t start,
                                 vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return -1;
  }

  struct user_region_prot_info info;
  bzero(&info, sizeof(info));

  vm_map_iterate_entries(map, start, end,
                         user_region_prot_iterator, &info);

  vm_prot_t retval = -1;
  if (info.entry_count) {
    for (;;) {
      if (info.prot_none_count == info.entry_count) {
        retval = VM_PROT_NONE;
        break;
      } else if (info.prot_none_count != 0) {
        break;
      }
      retval = VM_PROT_NONE;
      if (info.prot_read_count == info.entry_count) {
        retval |= VM_PROT_READ;
      } else if (info.prot_read_count != 0) {
        retval = -1;
        break;
      }
      if (info.prot_write_count == info.entry_count) {
        retval |= VM_PROT_WRITE;
      } else if (info.prot_write_count != 0) {
        retval = -1;
        break;
      }
      if (info.prot_exec_count == info.entry_count) {
        retval |= VM_PROT_EXECUTE;
      } else if (info.prot_exec_count != 0) {
        retval = -1;
        break;
      }
      break;
    }
  }
  return retval;
}

typedef struct user_region_wired_info {
  uint32_t wired_count;
  uint32_t not_wired_count;
  uint32_t entry_count;
} *user_region_wired_info_t;

void user_region_wired_iterator(vm_map_t map, vm_map_entry_t entry,
                                uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }
  user_region_wired_info_t info_local = (user_region_wired_info_t) info;
  ++info_local->entry_count;

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;
  unsigned short wired_count = an_entry->wired_count;
  unsigned short user_wired_count = an_entry->user_wired_count;

  if (wired_count || user_wired_count) {
    ++info_local->wired_count;
  } else {
    ++info_local->not_wired_count;
  }
}

// retval == -1 indicates an invalid value. Either vm_map_iterate_entries()
// failed or the region has some pages that are wired and some that aren't.
int32_t user_region_wired(vm_map_t map, vm_map_offset_t start,
                          vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return -1;
  }

  struct user_region_wired_info info;
  bzero(&info, sizeof(info));

  vm_map_iterate_entries(map, start, end,
                         user_region_wired_iterator, &info);

  vm_prot_t retval = -1;
  if (info.entry_count) {
    if (info.wired_count == info.entry_count) {
      retval = 1;
    } else if (info.not_wired_count == info.entry_count) {
      retval = 0;
    }
  }
  return retval;
}

typedef struct  pageout_user_region_info {
  vm_map_offset_t start;
  vm_map_offset_t end;
} *pageout_user_region_info_t;

void pageout_user_region_iterator(vm_map_t map, vm_map_entry_t entry,
                                  uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }

  pageout_user_region_info_t info_local = (pageout_user_region_info_t) info;

  vm_object_t object = map_entry_object(entry).vmo_object;

  if (!object) {
    return;
  }

  while (object) {
    vm_object_lock(object);

    vm_page_t page;
    vm_page_queue_iterate(object, page) {
      if (!page_is_pmapped(page)) {
        continue;
      }
      ppnum_t phys_page = page_phys_page(page);
      uintptr_t page_vmaddr = ppnum_to_vaddr(phys_page);
      if ((page_vmaddr < info_local->start) ||
          (page_vmaddr >= info_local->end))
      {
        continue;
      }
      pmap_disconnect(phys_page);
    }

    vm_object_unlock(object);
    object = object_get_shadow(object);
  }
}

void pageout_user_region(vm_map_t map, vm_map_offset_t start,
                         vm_map_offset_t end)
{
  struct pageout_user_region_info info;
  info.start = start;
  info.end = end;

  vm_map_iterate_entries(map, start, end,
                         pageout_user_region_iterator, &info);
}

// At the heart of HookCase.kext's infrastructure is a lock-protected linked
// list of hook_t structures.  Think of these as something like fish hooks.
// There are "cast hooks" and "user hooks".  There are also two different
// kinds of "user hook":  "patch hooks" and "interpose hooks".  Each is only
// valid for a particular process (identified by its 64-bit "unique id").
//
// Exactly one hook_t structure is created (and added to the linked list) as a
// cast hook for a process in which we want to set hooks.  It lives as long as
// the process itself.  It's used to keep track of the work needed to create
// user hooks.
//
// A user hook is one that we wish to "set" in a given process.
//
// Patch hooks are user hooks that work by patching the original method with
// an "int 0x30" instruction as a breakpoint.  One hook_t structure is created
// (and added to the linked list) for every patch hook that was set
// successfully.  It lives as long as the process to which it corresponds.
//
// Interpose hooks are user hooks that work by changing pointers in tables
// that are used to dynamically link to methods called from other modules.
// Interpose hooks don't get their own hook_t structures, and aren't added
// individually to the linked list.  Instead the cast hook has a list of
// them in its 'interpose_hooks' member.  (Since interpose hooks require no
// intervention after they've been "set", they don't need individual entries
// in the linked list.)

// All hooks (if any) that existed before a process is "exec"-ed get deleted
// when that happens.

// Every cast hook has four "legal" states it may be in at any given time.
// These correspond to where we are in the work needed to create user hooks
// for a given process.
//
// hook_state_cast
//
// We've set a breakpoint in the process's embedded copy of dyld (in
// maybe_cast_hook()), and are waiting for it to be hit for the first time.
//
// hook_state_flying
//
// We've hit the breakpoint once, and (in process_hook_cast()) have set up a
// call to dlopen() to load our hook library.  We've also set another hook to
// prevent the call to dlopen() from triggering any calls to C++ initializers.
// (Otherwise some of those initializers would run before we had a chance to
// hook methods they call.)  Now we're waiting for the call to dlopen() to
// finish, and for the breakpoint to be hit a second time.
//
// hook_state_landed
//
// We've hit the breakpoint again, and the call to dlopen() has succeeded or
// failed. If it succeeded we've looked (in process_hook_flying()) for hook
// descriptions in the hook library and have tried to set user hooks
// accordingly. We've also unset the hook that prevents calls to C++
// initializers. If there was no more work to do, we've unset our breakpoint.
// In that case we won't have reached this point, though our cast hook is
// being kept alive for future reference. But if there might be more
// breakpoints to set in modules that haven't yet been loaded, we've set up a
// call to _dyld_register_func_for_add_image(), and are waiting for our
// breakpoint to be hit again (indicating the call has happened). If it
// succeeds, on_add_image() will be called every time a new module is loaded.
//
// On macOS Monterey and up we might also have shifted our breakpoint to just
// after the initializers have finished running, and be waiting for it to be
// hit. On these newer versions of macOS we need to alter dyld to allow our
// hook library's C++ initializers to run, and to undo our alteration as soon
// as possible afterwards. So this state can be used multiple times on
// Monterey and up.
//
// hook_state_floating
//
// We've hit the breakpoint one last time, and the call to
// _dyld_register_func_for_add_image() has happened. If it succeeded,
// on_add_image() will be called every time a new module is loaded. In
// process_hook_landed() we've unset our breakpoint (whether or not we
// shifted it to allow our hook library's C++ initializers to run). Our cast
// hook is being kept alive for future reference.

// Every patch hook has two legal states it may be in at any given time
//
// hook_state_set
//
// The "int 0x30" breakpoint is set.  process_hook_set() is called every time
// this breakpoint is hit.  If the original method doesn't have a standard
// prologue, we'll need to unset it in process_hook_set().
//
// hook_state_unset
//
// The "int 0x30" breakpoint is unset.  The hook will need to call
// reset_hook() in the hook library to reset it.  (reset_hook() in the hook
// library invokes "int 0x32" and triggers a call to reset_hook() here).

// In order to set hooks in a process, we need to find a method that runs at
// an appropriate time as the process is being initialized, and hook that
// method itself. A process's binary is loaded by the parent process, via a
// call (indirectly) to parse_machfile() in the xnu kernel's
// bsd/kern/mach_loader.c. Among other things, this loads a (shared) copy of
// the /usr/lib/dyld module into the image of every new process (via a call to
// load_dylinker()). dyld's man page calls it the "dynamic link editor", and
// it's what runs first (starting from _dyld_start in dyld's
// src/dyldStartup.s) as a new process starts up. Not coincidentally, dyld is
// what implements Apple's support for the DYLD_INSERT_LIBRARIES environment
// variable. dyld::initializeMainExecutable() (or on macOS Monterey and above,
// dyld4::APIs::runAllInitializersForMain()) is called (from _main()) after
// all the automatically linked shared libraries (including those specified by
// DYLD_INSERT_LIBRARIES) are loaded, but before any of those libraries' C++
// initializers have run (which happens in dyld::initializeMainExecutable()
// itself). This seems an ideal place to intervene.
//
// On macOS 10.13 through macOS 11, dyld has an alternate way of launching
// 64-bit executables that bypasses dyld::initializeMainExecutable() --
// dyld::launchWithClosure(). But dyld::launchWithClosure() fails over to
// dyld's "traditional" code path, which does use
// dyld::initializeMainExecutable(). So, in a 64-bit process where we might
// want to set hooks on these versions of macOS, we patch
// dyld::launchWithClosure() to "return false" unconditionally. As of macOS
// 12 (Monterey), closure support happens differently, and never bypasses the
// method used to initialize the main executable
// (dyld4::APIs::runAllInitializersForMain()).
//
// maybe_cast_hook() is called just before the new process's execution begins
// at _dyld_start. There, if appropriate, we write an "int 0x30" breakpoint to
// the beginning of the method that initializes the main executable, and wait
// for the breakpoint to be hit. When dealing with a 64-bit process on macOS
// 10.13 through macOS 11, we also patch dyld::launchWithClosure() to always
// "return false".
//
// Hitting the breakpoint (for the first time) triggers a call to
// process_hook_cast().  There we set up a call to dlopen() to load our
// hook library.  We can't actually call dlopen() in the user process from
// kernel code.  Instead we use a technique modeled on what Apple does to make
// signal handlers run in user processes (see sendsig() in the xnu kernel's
// dev/i386/unix_signal.c).  First we find the address of dlopen() in
// /usr/lib/system/libdyld.dylib.  Then, in the thread state that will be
// "restored" when we return from process_hook_cast(), we
//   1) Change RSP/ESP to make room on the user stack
//   2) Copy the value of HC_INSERT_LIBRARY to the user stack
//   3) Set registers or stack locations to dlopen's 'path' and 'mode' args
//   4) Set the stack's "return address" to the breakpoint
//   5) Set RIP/EIP to dlopen()
//
// Later, in process_hook_landed(), we may set up another call, to
// _dyld_register_func_for_add_image(). This time we need user mode code for
// this method's 'func' argument. We allocate a page of kernel memory and copy
// to it the appropriate machine code (which contains an "int 0x31"
// instruction). Then we remap that page into the user process and set the
// 'func' argument accordingly. We also set RIP/EIP to
// _dyld_register_func_for_add_image() and the "return address" to our
// breakpoint (at the beginning of the method used to initialize the main
// executable). Our int 0x31 handler calls on_add_image().
//
// When we're all done, we return the thread state to what it was before the
// first call to the method that initializes the main executable, remove our
// breakpoint, set RIP/EIP to the start of that method, and allow that call to
// happen as originally intended.

// HookCase.kext is compatible with DYLD_INSERT_LIBRARIES, and doesn't stomp
// on any of the changes it may have been used to make.  HookCase.kext always
// makes its own changes to a module after any changes that might have been
// made using DYLD_INSERT_LIBRARIES.  This is true for both the automatically
// linked shared libraries and those loaded "manually" using dlopen().  So
// HookCase.kext can look for previously installed interpose hooks and refuse
// to change them.  See set_interpose_hooks_for_module().

// From the xnu kernel's bsd/dev/i386/unix_signal.c
#define C_64_REDZONE_LEN  128

// From /usr/include/dlfcn.h
#define RTLD_LAZY       0x1
#define RTLD_NOW        0x2
#define RTLD_LOCAL      0x4
#define RTLD_GLOBAL     0x8

typedef struct _user_hook_desc_64bit {
  user_addr_t hook_function;         // const void *
  union {
    // For interpose hooks
    user_addr_t orig_function;       // const void *
    // For patch hooks
    user_addr_t func_caller_ptr;     // const void *
  };
  user_addr_t orig_function_name;    // const char *
  user_addr_t orig_module_name;      // const char *, only for patch hooks
} user_hook_desc_64bit;

typedef struct _user_hook_desc_32bit {
  user32_addr_t hook_function;       // const void *
  union {
    // For interpose hooks
    user32_addr_t orig_function;     // const void *
    // For patch hooks
    user32_addr_t func_caller_ptr;   // const void *
  };
  user32_addr_t orig_function_name;  // const char *
  user32_addr_t orig_module_name;    // const char *, only for patch hooks
} user_hook_desc_32bit;

typedef struct _hook_desc {
  user_addr_t hook_function;
  union {
    // For interpose hooks
    user_addr_t orig_function;
    // For patch hooks
    user_addr_t func_caller_ptr;
  };
  char orig_function_name[PATH_MAX];
  char orig_module_name[PATH_MAX];   // Only for patch hooks
} hook_desc;

typedef enum {
  hook_state_broken   = 0,
  hook_state_cast     = 1, // Only for cast hooks
  hook_state_flying   = 2, // Only for cast hooks
  hook_state_landed   = 3, // Only for cast hooks
  hook_state_floating = 4, // Only for cast hooks
  hook_state_set      = 5, // Only for patch hooks
  hook_state_unset    = 6, // Only for patch hooks
} hook_state;

typedef struct _hook {
  LIST_ENTRY(_hook) list_entry;
  hook_state state;
  pid_t pid;
  uint64_t unique_pid;
  hc_path_t proc_path;
  hc_path_t inserted_dylib_path;
  hc_path_t add_kids_path;              // Only used in cast hook
                                        // Not passed to children
  user_addr_t orig_addr;
  user_addr_t hook_addr;
  user_addr_t inserted_dylib_textseg;
  vm_size_t inserted_dylib_textseg_len;
  user_addr_t call_orig_func_addr;      // Only used in patch hook
  IORecursiveLock *patch_hook_lock;     // Only used in patch hook
  x86_saved_state_t orig_intr_state;    // Only used in cast hook
  user_addr_t dyld_initMain;            // Only used in cast hook
  user_addr_t dyld_afterInitMain;       // Only used in cast hook
  user_addr_t dyld_runInitializers;     // Only used in cast hook
  user_addr_t dyld_runInitializers2;    // Only used in cast hook
  user_addr_t dyld_isMainExecutable;    // Only used in cast hook
  user_addr_t add_image_func_addr;      // Only used in cast hook
  user_addr_t call_orig_func_block;     // Only used in cast hook
  hook_desc *patch_hooks;               // Only used in cast hook
  hook_desc *interpose_hooks;           // Only used in cast hook
  pid_t hooked_ancestor;                // Only used in cast hook
  uint16_t orig_dyld_initMain;          // Only used in cast hook
  uint16_t orig_dyld_afterInitMain;     // Only used in cast hook
  uint32_t orig_dyld_runInitializers;   // Only used in cast hook
  uint32_t orig_dyld_runInitializers2;  // Only used in cast hook
  uint32_t orig_dyld_isMainExecutable;  // Only used in cast hook
  uint32_t num_call_orig_funcs;         // Only used in cast hook
  uint32_t num_patch_hooks;             // Only used in cast hook
  uint32_t num_interpose_hooks;         // Only used in cast hook
  bool no_numerical_addrs;              // Only used in cast hook
  bool set_interpose_hooks_delayed;     // Only used in cast hook
  bool is_dynamic_hook;                 // Only used in patch hook
  bool is_cast_hook;
  uint16_t orig_code;
} hook_t;

// We use this linked list to ensure that the "current" patch hook can always
// be found when we need it (in methods that have been "called", indirectly,
// from the hook function, like reset_hook() and get_dynamic_caller() below).
// Now that we support dynamically added patch hooks, we can no longer depend
// on being able to look up a patch hook using its hook address. There's no
// reasonable way we can prevent a hook function from being used by more than
// one dynamically added patch hook. When hooking event handlers we're often
// forced to do this. So the linked list (above) of hook_t objects may contain
// more than one with the same hook_addr.
typedef struct _hook_thread_info {
  LIST_ENTRY(_hook_thread_info) list_entry;
  // A thread on which patch_hook->hook_addr recently executed. The same
  // hook_thread may appear more than once in this list per process, if two or
  // more patch hooks can run on it. But each combination of hook_thread and
  // patch_hook->hook_addr is kept unique per process.
  thread_t hook_thread;
  // The patch hook that has executed most recently on hook_thread. The same
  // patch_hook may appear more than once in this list, per process. This will
  // happen if patch_hook->hook_addr runs on different threads. The value of
  // patch_hook in a single list_entry may also need to change periodically,
  // if multiple dynamic patch hooks with the same hook_addr (though with
  // different orig_addr) run on the same thread.
  hook_t *patch_hook;
  uint64_t unique_pid;
} hook_thread_info_t;

typedef struct _kern_hook {
  LIST_ENTRY(_kern_hook) list_entry;
  vm_offset_t orig_addr;
  vm_offset_t hook_addr;
  vm_offset_t caller_addr;
  uint32_t orig_begin;
} kern_hook_t;

#define STACK_MAX 256
typedef uint64_t callstack_t[STACK_MAX];

typedef struct _watcher_info {
  // Stack trace of the code running when the watchpoint is hit.
  callstack_t callstack;
  // Exact address hit (inside the watchpoint's address range).
  uint64_t hit;
  // User-land equivalent of the thread (kernel-mode thread_t object) running
  // when the watchpoint is hit. Use pthread_from_mach_thread_np() to convert
  // it to a pthread object.
  uint32_t mach_thread;
  // Trap code for page fault that happens when the watchpoint is hit.
  uint32_t page_fault_code;
} watcher_info_t;

typedef enum {
  watcher_state_unset                  = 0,
  // Set a watchpoint without changing memory access permissions or paging
  // anything out -- for pageable memory blocks, has no effect on wired blocks.
  watcher_state_set_plain              = 1,
  // Set a watchpoint and make its memory range read-only -- for wired memory
  // blocks, though it can also be used (cautiously) with pageable blocks.
  watcher_state_set_write_protect      = 2,
  // Set a watchpoint without changing memory access permissions, but page out
  // its memory range -- for pageable memory blocks, forbidden for wired blocks.
  watcher_state_set_pageout            = 3,
  watcher_state_set_max                = 3,
  // Old usage
  watcher_state_set_no_write_protect   = watcher_state_set_plain,
  watcher_state_set_with_write_protect = watcher_state_set_write_protect,
} watcher_state;

typedef struct _watcher {
  LIST_ENTRY(_watcher) list_entry;
  vm_offset_t range_start;
  vm_offset_t range_end;
  vm_prot_t orig_prot;
  uint64_t unique_pid;
  watcher_info_t info;
  user_addr_t info_addr;
  watcher_state status;
  pid_t pid;
} watcher_t;

#define CALL_ORIG_FUNC_SIZE 0x20
#define MAX_CALL_ORIG_FUNCS 128 // PAGE_SIZE / CALL_ORIG_FUNC_SIZE

// The first two bytes of a "standard" C/C++ function in 64-bit mode --
// one whose prologue begins as follows:
//   push %rbp
//   mov  %rsp, %rbp
// unsigned char[] = {0x55, 0x48} when stored in little endian format
#define PROLOGUE_BEGIN_64BIT_SHORT 0x4855

// The first two bytes of a "standard" C/C++ function in 32-bit mode --
// one whose prologue begins as follows:
//   push %ebp
//   mov  %esp, %ebp
// unsigned char[] = {0x55, 0x89} when stored in little endian format
#define PROLOGUE_BEGIN_32BIT_SHORT 0x8955

// Prologue of a "standard" C/C++ function in 64-bit mode:
//   push %rbp
//   mov  %rsp, %rbp
// unsigned char[] = {0x55, 0x48, 0x89, 0xe5} when stored in little
// endian format
#define PROLOGUE_BEGIN_64BIT 0xe5894855

// Prologue of a "standard" C/C++ function in 32-bit mode:
//   push %ebp
//   mov  %esp, %ebp
// unsigned char[] = {0x55, 0x89, 0xe5} when stored in little endian
// format
#define PROLOGUE_BEGIN_32BIT 0xe58955

// unsigned char[] = {0xcd, HC_INT1} when stored in little endian format
#define HC_INT1_OPCODE_SHORT ((HC_INT1 << 8) + 0xcd)

// unsigned char[] = {0xcd, HC_INT2} when stored in little endian format
#define HC_INT2_OPCODE_SHORT ((HC_INT2 << 8) + 0xcd)

// unsigned char[] = {0xcd, HC_INT3} when stored in little endian format
#define HC_INT3_OPCODE_SHORT ((HC_INT3 << 8) + 0xcd)

// unsigned char[] = {0xcd, HC_INT4} when stored in little endian format
#define HC_INT4_OPCODE_SHORT ((HC_INT4 << 8) + 0xcd)

// unsigned char[] = {0xcd, HC_INT5} when stored in little endian format
#define HC_INT5_OPCODE_SHORT ((HC_INT5 << 8) + 0xcd)

// unsigned char[] = {0xcd, HC_INT6} when stored in little endian format
#define HC_INT6_OPCODE_SHORT ((HC_INT6 << 8) + 0xcd)

#define HC_INT_OPCODE_BYTE 0xcd

// xor   %rax, %rax
// ret

// 48 31 C0 C3

#define RETURN_FALSE_64BIT_INT 0xC3C03148
#define RETURN_NULL_64BIT_INT RETURN_FALSE_64BIT_INT

// xor   %eax, %eax
// ret

// 31 C0 C3

#define RETURN_FALSE_32BIT_INT 0x00C3C031
#define RETURN_NULL_32BIT_INT RETURN_FALSE_32BIT_INT

// mov   0x1, %eax
// ret

// B8 01 00 00 00 C3

#define RETURN_TRUE_32BIT_LONG 0x0000C300000001B8

//push   %rbp
//mov    %rsp, %rbp
//pop    %rbp
//ret

// 55 48 89 E5 5D C3

#define EMPTY_FUNC_64BIT_LONG 0x0000C35DE5894855

//push    %rbp
//mov     %rsp, %rbp
//int     $(HC_INT2)
//pop     %rbp
//ret

// 55 48 89 E5 CD HC_INT2 5D C3

#define HC_INT2_FUNC_64BIT_LONG (0xC35D00CDE5894855 + (HC_INT2 << 40))

//push   %ebp
//mov    %esp, %ebp
//pop    %ebp
//ret

// 55 89 E5 5D C3

#define EMPTY_FUNC_32BIT_LONG 0x000000C35DE58955

//push    %ebp
//mov     %esp, %ebp
//int     $(HC_INT2)
//pop     %ebp
//ret

// 55 89 E5 CD HC_INT2 5D C3

#define HC_INT2_FUNC_32BIT_LONG (0x00C35D00CDE58955 + (HC_INT2 << 32))

// See call_orig.s for more information about how the machine code in
// g_call_orig_func_64bit and g_call_orig_func_32bit is generated.
// Both strings need to end in a space.  Also see get_call_orig_func()
// below.

const char *g_call_orig_func_64bit =
  "55 48 89 E5 4C 8D 15 F5 0F 00 00 4D 8B 12 49 83 C2 04 41 FF E2 ";

const char *g_call_orig_func_32bit =
  "55 89 E5 E8 00 00 00 00 58 8D 80 F8 0F 00 00 8B 00 83 C0 03 FF E0 ";

bool hook_kern_method(vm_offset_t method, uint32_t *method_begin,
                      uint16_t intr_opcode)
{
  if (!method || !method_begin) {
    return false;
  }
  if ((intr_opcode & 0xff) != HC_INT_OPCODE_BYTE) {
    return false;
  }

  *method_begin = 0;

  uint32_t *target = (uint32_t *) method;
  *method_begin = target[0];

  bool retval = true;

  uint32_t new_begin = *method_begin;
  new_begin &= 0xffff0000;
  new_begin |= intr_opcode;

  boolean_t org_int_level = ml_set_interrupts_enabled(false);
  disable_preemption();
  uintptr_t org_cr0 = get_cr0();
  set_cr0(org_cr0 & ~CR0_WP);

  if (!OSCompareAndSwap(*method_begin, new_begin, target)) {
    *method_begin = 0;
    retval = false;
  }

  set_cr0(org_cr0);
  enable_preemption();
  ml_set_interrupts_enabled(org_int_level);

  return retval;
}

bool unhook_kern_method(vm_offset_t method, uint32_t method_begin)
{
  if (!method || !method_begin) {
    return false;
  }

  // If method is/was in a kernel extension, it might have been unloaded.
  if (!pmap_find_phys(kernel_pmap, method)) {
    return false;
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) method;
  uint32_t current_value = target[0];
  if ((current_value & 0xff) != HC_INT_OPCODE_BYTE) {
    return false;
  }

  boolean_t org_int_level = ml_set_interrupts_enabled(false);
  disable_preemption();
  uintptr_t org_cr0 = get_cr0();
  set_cr0(org_cr0 & ~CR0_WP);

  if (!OSCompareAndSwap(current_value, method_begin, target)) {
    retval = false;
  }

  set_cr0(org_cr0);
  enable_preemption();
  ml_set_interrupts_enabled(org_int_level);

  return retval;
}

void get_callstack(vm_map_t proc_map, x86_saved_state_t *intr_state,
                   callstack_t callstack)
{
  if (!proc_map || !intr_state || !callstack) {
    return;
  }
  bzero(callstack, sizeof(callstack_t));

  user_addr_t frame;
  user_addr_t caller;
  size_t item_size;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    frame = (user_addr_t) intr_state->ss_64.rbp;
    caller = (user_addr_t) intr_state->ss_64.isf.rip;
    item_size = sizeof(uint64_t);
  } else { // flavor == x86_SAVED_STATE32
    frame = (user_addr_t) intr_state->ss_32.ebp;
    caller = (user_addr_t) intr_state->ss_32.eip;
    item_size = sizeof(uint32_t);
  }

  int i;
  for (i = 0; i < STACK_MAX; ++i) {
    callstack[i] = caller;

    if (!proc_copyin(proc_map, frame + item_size, &caller, item_size)) {
      break;
    }
    user_addr_t caller_code;
    if (!proc_copyin(proc_map, caller, &caller_code, sizeof(user_addr_t))) {
      break;
    }

    if (!proc_copyin(proc_map, frame, &frame, item_size)) {
      callstack[i] = caller;
      break;
    }
    if (intr_state->flavor == x86_SAVED_STATE64) {
      if (frame & 0xf) {        // 'frame' is unaligned
        callstack[i] = caller;
        break;
      }
    } else { // flavor == x86_SAVED_STATE32
      if ((frame & 0xf) != 8) { // 'frame' is unaligned
        callstack[i] = caller;
        break;
      }
    }
  }
}

bool g_locks_inited = false;
bool g_locks_destroyed = false;

lck_grp_attr_t *all_hooks_grp_attr = NULL;
lck_grp_t *all_hooks_grp = NULL;
lck_attr_t *all_hooks_attr = NULL;
lck_rw_t *all_hooks_mlock = NULL;
LIST_HEAD(hook_list, _hook);
struct hook_list g_all_hooks;
LIST_HEAD(hook_thread_info_list, _hook_thread_info);
struct hook_thread_info_list g_all_hook_thread_infos;

LIST_HEAD(kern_hook_list, _kern_hook);
struct kern_hook_list g_all_kern_hooks;
lck_rw_t *all_kern_hooks_mlock = NULL;

lck_grp_attr_t *all_watchers_grp_attr = NULL;
lck_grp_t *all_watchers_grp = NULL;
lck_attr_t *all_watchers_attr = NULL;
lck_rw_t *all_watchers_mlock = NULL;
LIST_HEAD(watcher_list, _watcher);
struct watcher_list g_all_watchers;

bool check_init_locks()
{
  if (g_locks_destroyed) {
    return false;
  } else if (g_locks_inited) {
    return true;
  }

  LIST_INIT(&g_all_hooks);
  LIST_INIT(&g_all_hook_thread_infos);
  all_hooks_grp_attr = lck_grp_attr_alloc_init();
  if (!all_hooks_grp_attr) {
    return false;
  }
  all_hooks_grp = lck_grp_alloc_init("hook", all_hooks_grp_attr);
  if (!all_hooks_grp) {
    return false;
  }
  all_hooks_attr = lck_attr_alloc_init();
  if (!all_hooks_attr) {
    return false;
  }
  all_hooks_mlock = lck_rw_alloc_init(all_hooks_grp, all_hooks_attr);
  if (!all_hooks_mlock) {
    return false;
  }

  LIST_INIT(&g_all_kern_hooks);
  all_kern_hooks_mlock = lck_rw_alloc_init(all_hooks_grp, all_hooks_attr);
  if (!all_kern_hooks_mlock) {
    return false;
  }

  LIST_INIT(&g_all_watchers);
  all_watchers_grp_attr = lck_grp_attr_alloc_init();
  if (!all_watchers_grp_attr) {
    return false;
  }
  all_watchers_grp = lck_grp_alloc_init("watcher", all_watchers_grp_attr);
  if (!all_watchers_grp) {
    return false;
  }
  all_watchers_attr = lck_attr_alloc_init();
  if (!all_watchers_attr) {
    return false;
  }
  all_watchers_mlock = lck_rw_alloc_init(all_watchers_grp, all_watchers_attr);
  if (!all_watchers_mlock) {
    return false;
  }

  g_locks_inited = true;
  return true;
}

void all_hooks_lock_write()
{
  if (check_init_locks()) {
    lck_rw_lock_exclusive(all_hooks_mlock);
  }
}

void all_hooks_unlock_write()
{
  if (check_init_locks()) {
    lck_rw_unlock_exclusive(all_hooks_mlock);
  }
}

void all_hooks_lock_read()
{
  if (check_init_locks()) {
    lck_rw_lock_shared(all_hooks_mlock);
  }
}

void all_hooks_unlock_read()
{
  if (check_init_locks()) {
    lck_rw_unlock_shared(all_hooks_mlock);
  }
}

void all_kern_hooks_lock_write()
{
  if (check_init_locks()) {
    lck_rw_lock_exclusive(all_kern_hooks_mlock);
  }
}

void all_kern_hooks_unlock_write()
{
  if (check_init_locks()) {
    lck_rw_unlock_exclusive(all_kern_hooks_mlock);
  }
}

void all_kern_hooks_lock_read()
{
  if (check_init_locks()) {
    lck_rw_lock_shared(all_kern_hooks_mlock);
  }
}

void all_kern_hooks_unlock_read()
{
  if (check_init_locks()) {
    lck_rw_unlock_shared(all_kern_hooks_mlock);
  }
}

void all_watchers_lock_write()
{
  if (check_init_locks()) {
    lck_rw_lock_exclusive(all_watchers_mlock);
  }
}

void all_watchers_unlock_write()
{
  if (check_init_locks()) {
    lck_rw_unlock_exclusive(all_watchers_mlock);
  }
}

void all_watchers_lock_read()
{
  if (check_init_locks()) {
    lck_rw_lock_shared(all_watchers_mlock);
  }
}

void all_watchers_unlock_read()
{
  if (check_init_locks()) {
    lck_rw_unlock_shared(all_watchers_mlock);
  }
}

hook_t *create_hook()
{
  hook_t *retval = (hook_t *) IOMalloc(sizeof(hook_t));
  if (retval) {
    bzero(retval, sizeof(hook_t));
  }
  return retval;
}

hook_thread_info_t *create_hook_thread_info()
{
  hook_thread_info_t *retval = (hook_thread_info_t *)
    IOMalloc(sizeof(hook_thread_info_t));
  if (retval) {
    bzero(retval, sizeof(hook_thread_info_t));
  }
  return retval;
}

void add_hook(hook_t *hookp)
{
  if (!hookp || !check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  LIST_INSERT_HEAD(&g_all_hooks, hookp, list_entry);
  all_hooks_unlock_write();
}

void add_hook_thread_info(hook_thread_info_t *infop)
{
  if (!infop || !check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  LIST_INSERT_HEAD(&g_all_hook_thread_infos, infop, list_entry);
  all_hooks_unlock_write();
}

void free_hook(hook_t *hookp)
{
  if (!hookp) {
    return;
  }
  hookp->state = hook_state_broken;
  if (hookp->patch_hook_lock) {
    IORecursiveLockFree(hookp->patch_hook_lock);
  }
  if (hookp->patch_hooks) {
    IOFree(hookp->patch_hooks,
           hookp->num_patch_hooks * sizeof(hook_desc));
  }
  if (hookp->interpose_hooks) {
    IOFree(hookp->interpose_hooks,
           hookp->num_interpose_hooks * sizeof(hook_desc));
  }
  IOFree(hookp, sizeof(hook_t));
}

void free_hook_thread_info(hook_thread_info_t *infop)
{
  if (!infop) {
    return;
  }
  IOFree(infop, sizeof(hook_thread_info_t));
}

void remove_hook(hook_t *hookp)
{
  if (!hookp || !check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  LIST_REMOVE(hookp, list_entry);
  free_hook(hookp);
  all_hooks_unlock_write();
}

void remove_hook_thread_info(hook_thread_info_t *infop)
{
  if (!infop || !check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  LIST_REMOVE(infop, list_entry);
  free_hook_thread_info(infop);
  all_hooks_unlock_write();
}

hook_t *find_hook(user_addr_t orig_addr, uint64_t unique_pid)
{
  if (!check_init_locks() || !orig_addr || !unique_pid) {
    return NULL;
  }
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->orig_addr == orig_addr) &&
        (hookp->unique_pid == unique_pid))
    {
      break;
    }
  }
  all_hooks_unlock_read();
  return hookp;
}

hook_thread_info_t *find_hook_thread_info(thread_t thread, uint64_t unique_pid,
                                          user_addr_t hook_addr)
{
  if (!check_init_locks() || !thread || !unique_pid || !hook_addr) {
    return NULL;
  }
  all_hooks_lock_read();
  hook_thread_info_t *infop = NULL;
  LIST_FOREACH(infop, &g_all_hook_thread_infos, list_entry) {
    if ((infop->hook_thread == thread) && (infop->unique_pid == unique_pid) &&
        infop->patch_hook && (infop->patch_hook->hook_addr == hook_addr))
    {
      break;
    }
  }
  all_hooks_unlock_read();
  return infop;
}

hook_t *find_hook_by_thread_and_hook_addr(thread_t thread, uint64_t unique_pid,
                                          user_addr_t hook_addr)
{
  if (!check_init_locks() || !thread || !unique_pid || !hook_addr) {
    return NULL;
  }
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  hook_thread_info_t *infop = NULL;
  LIST_FOREACH(infop, &g_all_hook_thread_infos, list_entry) {
    if ((infop->hook_thread == thread) && (infop->unique_pid == unique_pid) &&
        infop->patch_hook && (infop->patch_hook->hook_addr == hook_addr))
    {
      hookp = infop->patch_hook;
      break;
    }
  }
  all_hooks_unlock_read();
  return hookp;
}

// There's no reasonable way to prevent a hook function from being used by
// more than one dynamically added patch hook.  So we've now got to live with
// the possibility that a given hook function will have been used more than
// once.
bool hook_exists_with_hook_addr(user_addr_t hook_addr, uint64_t unique_pid)
{
  if (!check_init_locks() || !hook_addr || !unique_pid) {
    return false;
  }
  all_hooks_lock_read();
  bool retval = false;
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->hook_addr == hook_addr) &&
        (hookp->unique_pid == unique_pid))
    {
      retval = true;
      break;
    }
  }
  all_hooks_unlock_read();
  return retval;
}

hook_t *find_hook_with_add_image_func(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return NULL;
  }
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->unique_pid == unique_pid) && hookp->add_image_func_addr) {
      break;
    }
  }
  all_hooks_unlock_read();
  return hookp;
}

hook_t *find_cast_hook(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return NULL;
  }
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->unique_pid == unique_pid) && hookp->is_cast_hook) {
      break;
    }
  }
  all_hooks_unlock_read();
  return hookp;
}

void free_watcher(watcher_t *watcherp);
bool unset_watcher(vm_map_t proc_map, watcher_t *watcherp);

void remove_process_watchers(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return;
  }

  vm_map_t proc_map = NULL;
  proc_t cur_proc = current_proc();
  if (proc_uniqueid(cur_proc) == unique_pid) {
    proc_map = task_map_for_proc(cur_proc);
  }

  all_watchers_lock_write();
  watcher_t *watcherp = NULL;
  watcher_t *tmp_watcherp = NULL;
  LIST_FOREACH_SAFE(watcherp, &g_all_watchers, list_entry, tmp_watcherp) {
    if (watcherp->unique_pid == unique_pid) {
      LIST_REMOVE(watcherp, list_entry);
      if (proc_map) {
        unset_watcher(proc_map, watcherp);
      }
      free_watcher(watcherp);
    }
  }
  all_watchers_unlock_write();

  if (proc_map) {
    vm_map_deallocate(proc_map);
  }
}

void remove_process_hooks(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return;
  }

  all_hooks_lock_write();
  hook_thread_info_t *infop = NULL;
  hook_thread_info_t *tmp_infop = NULL;
  LIST_FOREACH_SAFE(infop, &g_all_hook_thread_infos, list_entry, tmp_infop) {
    if (infop->unique_pid == unique_pid) {
      LIST_REMOVE(infop, list_entry);
      free_hook_thread_info(infop);
    }
  }
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    if (hookp->unique_pid == unique_pid) {
      LIST_REMOVE(hookp, list_entry);
      free_hook(hookp);
    }
  }
  all_hooks_unlock_write();

  remove_process_watchers(unique_pid);
}

// Make copies of src_proc's hook list entries and add them to g_all_hooks.
// Later, in assign_copied_hooks(), we'll finish assigning them to the forked
// child process whose pid is dest_pid. Each entry gets copied, and also every
// resource it contains that's subject to deallocation when the entry is
// destroyed.
void copy_process_hooks(proc_t src_proc, pid_t dest_pid)
{
  if (!check_init_locks() || !src_proc || !dest_pid) {
    return;
  }

  uint64_t src_unique_pid = proc_uniqueid(src_proc);
  if (src_unique_pid == 0) {
    return;
  }

  all_hooks_lock_write();
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    if (hookp->unique_pid == src_unique_pid) {
      hook_t *new_hookp = create_hook();
      if (new_hookp) {
        memcpy(new_hookp, hookp, sizeof(hook_t));
        bzero(&new_hookp->list_entry, sizeof(new_hookp->list_entry));
        new_hookp->pid = dest_pid;
        // Provisional. Will get fixed in assign_copied_hooks() below.
        new_hookp->unique_pid = 0;
        if (hookp->patch_hook_lock) {
          new_hookp->patch_hook_lock = IORecursiveLockAlloc();
        }
        if (hookp->patch_hooks) {
          hook_desc *patch_hooks = NULL;
          uint32_t num_patch_hooks = hookp->num_patch_hooks;
          if (num_patch_hooks) {
            size_t size = num_patch_hooks * sizeof(hook_desc);
            patch_hooks = (hook_desc *) IOMalloc(size);
            if (patch_hooks) {
              memcpy(patch_hooks, hookp->patch_hooks, size);
            } else {
              num_patch_hooks = 0;
            }
          }
          new_hookp->patch_hooks = patch_hooks;
          new_hookp->num_patch_hooks = num_patch_hooks;
        }
        if (hookp->interpose_hooks) {
          hook_desc *interpose_hooks = NULL;
          uint32_t num_interpose_hooks = hookp->num_interpose_hooks;
          if (num_interpose_hooks) {
            size_t size = num_interpose_hooks * sizeof(hook_desc);
            interpose_hooks = (hook_desc *) IOMalloc(size);
            if (interpose_hooks) {
              memcpy(interpose_hooks, hookp->interpose_hooks, size);
            } else {
              num_interpose_hooks = 0;
            }
          }
          new_hookp->interpose_hooks = interpose_hooks;
          new_hookp->num_interpose_hooks = num_interpose_hooks;
        }
        LIST_INSERT_HEAD(&g_all_hooks, new_hookp, list_entry);
      }
    }
  }
  all_hooks_unlock_write();
}

// dest_proc is a forked child process. copy_process_hooks() has already been
// called to copy its parent's hook list entries and add them to g_all_hooks.
// Here we set each copied entry's unique_pid to that of the forked child
// process. This is needed for hooks and the hooking infrastructure to work
// properly. In effect it finishes assigning each copied hook to dest_proc.
void assign_copied_hooks(proc_t dest_proc)
{
  if (!check_init_locks() || !dest_proc) {
    return;
  }

  pid_t dest_pid = proc_pid(dest_proc);
  uint64_t dest_unique_pid = proc_uniqueid(dest_proc);
  if ((dest_pid == 0) || (dest_unique_pid == 0)) {
    return;
  }

  all_hooks_lock_write();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->pid == dest_pid) && (hookp->unique_pid == 0)) {
      hookp->unique_pid = dest_unique_pid;
    }
  }
  all_hooks_unlock_write();
}

bool process_has_hooks(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return false;
  }
  bool retval = false;
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if (hookp->unique_pid == unique_pid) {
      retval = true;
      break;
    }
  }
  all_hooks_unlock_read();
  return retval;
}

// This won't work properly unless zombie process hooks are actively being
// removed using remove_zombie_hooks().
bool any_process_has_hooks()
{
  if (!check_init_locks()) {
    return false;
  }
  all_hooks_lock_read();
  bool retval = !LIST_EMPTY(&g_all_hooks);
  all_hooks_unlock_read();
  return retval;
}

// Look for proc_path in the add_kids_path of every running hooked process.
bool is_added_kid(hc_path_t proc_path, hc_path_t dylib_path,
                  pid_t *hooked_ancestor, bool *no_numerical_addrs)
{
  if (!check_init_locks() || !proc_path || !proc_path[0] ||
      !dylib_path || !hooked_ancestor || !no_numerical_addrs)
  {
    return false;
  }
  bool retval = false;
  all_hooks_lock_read();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    char *match = strnstr_ptr(hookp->add_kids_path, proc_path,
                              sizeof(hc_path_t));
    if (match) {
      strncpy(dylib_path, hookp->inserted_dylib_path, HC_PATH_SIZE);
      *hooked_ancestor = hookp->pid;
      *no_numerical_addrs = hookp->no_numerical_addrs;
      retval = true;
      break;
    }
  }
  all_hooks_unlock_read();
  return retval;
}

void remove_zombie_watchers()
{
  if (!check_init_locks()) {
    return;
  }
  all_watchers_lock_write();
  watcher_t *watcherp = NULL;
  watcher_t *tmp_watcherp = NULL;
  LIST_FOREACH_SAFE(watcherp, &g_all_watchers, list_entry, tmp_watcherp) {
    proc_t proc = NULL;
    if (watcherp->pid != 0) {
      proc = proc_find(watcherp->pid);
    }
    if (!proc || (watcherp->unique_pid != proc_uniqueid(proc))) {
      LIST_REMOVE(watcherp, list_entry);
      free_watcher(watcherp);
    }
    if (proc) {
      proc_rele(proc);
    }
  }
  all_watchers_unlock_write();
}

// This is unsafe when called at process exit -- proc_find() sometimes hangs,
// possibly when its pid_t parameter is itself a zombie process. But it works
// fine when loading a process. Now that HookCase supports HC_ADDKIDS, it's
// important that is_added_kid() (above) not be able to find the add_kids_path
// of crashed or zombie hooked processes.
void remove_zombie_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    proc_t proc = NULL;
    if (hookp->pid != 0) {
      proc = proc_find(hookp->pid);
    }
    if (!proc || (hookp->unique_pid != proc_uniqueid(proc))) {
      LIST_REMOVE(hookp, list_entry);
      free_hook(hookp);
    }
    if (proc) {
      proc_rele(proc);
    }
  }
  all_hooks_unlock_write();
  remove_zombie_watchers();
}

kern_hook_t *create_kern_hook()
{
  kern_hook_t *retval = (kern_hook_t *)
    IOMalloc(sizeof(kern_hook_t));
  if (retval) {
    bzero(retval, sizeof(kern_hook_t));
  }
  return retval;
}

void add_kern_hook(kern_hook_t *kern_hookp)
{
  if (!kern_hookp || !check_init_locks()) {
    return;
  }
  all_kern_hooks_lock_write();
  LIST_INSERT_HEAD(&g_all_kern_hooks, kern_hookp, list_entry);
  all_kern_hooks_unlock_write();
}

void free_kern_hook(kern_hook_t *kern_hookp)
{
  if (!kern_hookp) {
    return;
  }
  IOFree(kern_hookp, sizeof(kern_hook_t));
}

kern_hook_t *find_kern_hook(vm_offset_t orig_addr)
{
  if (!check_init_locks() || !orig_addr) {
    return NULL;
  }
  all_kern_hooks_lock_read();
  kern_hook_t *kern_hookp = NULL;
  LIST_FOREACH(kern_hookp, &g_all_kern_hooks, list_entry) {
    if (kern_hookp->orig_addr == orig_addr) {
      break;
    }
  }
  all_kern_hooks_unlock_read();
  return kern_hookp;
}

bool set_kern_hook(vm_offset_t orig_addr, vm_offset_t hook_addr,
                   vm_offset_t caller_addr, kern_hook_t **kern_hookpp)
{
  if (!orig_addr || !hook_addr || !caller_addr) {
    return false;
  }
  if (kern_hookpp) {
    *kern_hookpp = NULL;
  }

  if (find_kern_hook(orig_addr)) {
    return false;
  }

  kern_hook_t *kern_hookp = create_kern_hook();
  if (!kern_hookp) {
    return false;
  }

  uint32_t orig_begin = 0;
  if (!hook_kern_method(orig_addr, &orig_begin, HC_INT1_OPCODE_SHORT)) {
    free_kern_hook(kern_hookp);
    return false;
  }

  kern_hookp->orig_addr = orig_addr;
  kern_hookp->hook_addr = hook_addr;
  kern_hookp->caller_addr = caller_addr;
  kern_hookp->orig_begin = orig_begin;
  add_kern_hook(kern_hookp);
  if (kern_hookpp) {
    *kern_hookpp = kern_hookp;
  }

  return true;
}

void unset_kern_hook(kern_hook_t *kern_hookp)
{
  if (!kern_hookp) {
    return;
  }
  unhook_kern_method(kern_hookp->orig_addr, kern_hookp->orig_begin);
}

watcher_t *create_watcher()
{
  watcher_t *retval = (watcher_t *) IOMalloc(sizeof(watcher_t));
  if (retval) {
    bzero(retval, sizeof(watcher_t));
  }
  return retval;
}

void add_watcher(watcher_t *watcherp)
{
  if (!watcherp || !check_init_locks()) {
    return;
  }
  all_watchers_lock_write();
  LIST_INSERT_HEAD(&g_all_watchers, watcherp, list_entry);
  all_watchers_unlock_write();
}

void free_watcher(watcher_t *watcherp)
{
  if (!watcherp) {
    return;
  }
  IOFree(watcherp, sizeof(watcher_t));
}

void remove_watcher(watcher_t *watcherp)
{
  if (!watcherp || !check_init_locks()) {
    return;
  }
  all_watchers_lock_write();
  LIST_REMOVE(watcherp, list_entry);
  free_watcher(watcherp);
  all_watchers_unlock_write();
}

watcher_t *find_watcher_by_addr(user_addr_t addr, uint64_t unique_pid)
{
  if (!check_init_locks() || !addr || !unique_pid) {
    return NULL;
  }
  all_watchers_lock_read();
  watcher_t *watcherp = NULL;
  LIST_FOREACH(watcherp, &g_all_watchers, list_entry) {
    if ((unique_pid == watcherp->unique_pid) &&
        (addr >= watcherp->range_start) &&
        (addr < watcherp->range_end))
    {
      break;
    }
  }
  all_watchers_unlock_read();
  return watcherp;
}

typedef enum {
  would_overlap_state_not =   0,
  would_overlap_state_unset = 1,
  would_overlap_state_set =   2,
} would_overlap_state;

watcher_t *find_watcher_by_range(user_addr_t range_start,
                                 user_addr_t range_end,
                                 would_overlap_state *would_overlap,
                                 uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid || (range_start >= range_end)) {
    return NULL;
  }

  would_overlap_state would_overlap_local = would_overlap_state_not;
  watcher_t *retval = NULL;

  all_watchers_lock_read();
  watcher_t *watcherp = NULL;
  LIST_FOREACH(watcherp, &g_all_watchers, list_entry) {
    if (unique_pid != watcherp->unique_pid) {
      continue;
    }
    if ((range_start == watcherp->range_start) &&
        (range_end == watcherp->range_end))
    {
      retval = watcherp;
      continue;
    }
    if (((range_start >= watcherp->range_start) &&
          (range_start < watcherp->range_end)) ||
        ((range_end > watcherp->range_start) &&
          (range_end <= watcherp->range_end)))
    {
      if (would_overlap_local != would_overlap_state_set) {
        if (watcherp->status == watcher_state_unset) {
          would_overlap_local = would_overlap_state_unset;
        } else {
          would_overlap_local = would_overlap_state_set;
        }
      }
    }
  }
  all_watchers_unlock_read();

  if (would_overlap) {
    *would_overlap = would_overlap_local;
  }
  return retval;
}

void remove_would_overlap(user_addr_t range_start,
                          user_addr_t range_end,
                          uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid || (range_start >= range_end)) {
    return;
  }

  proc_t proc = current_proc();
  pid_t pid = proc_pid(proc);
  char procname[PATH_MAX];
  proc_name(pid, procname, sizeof(procname));

  all_watchers_lock_write();
  watcher_t *watcherp = NULL;
  watcher_t *tmp_watcherp = NULL;
  LIST_FOREACH_SAFE(watcherp, &g_all_watchers, list_entry, tmp_watcherp) {
    if (watcherp->unique_pid != unique_pid) {
     continue;
    }
    if (((range_start >= watcherp->range_start) &&
          (range_start < watcherp->range_end)) ||
        ((range_end > watcherp->range_start) &&
          (range_end <= watcherp->range_end)))
    {
      if (watcherp->status != watcher_state_unset) {
        printf("HookCase(%s[%d]): remove_would_overlap(): removing active watchpoint with range \'0x%lx\' to \'0x%lx\'\n",
               procname, pid, watcherp->range_start, watcherp->range_end);
      }
      LIST_REMOVE(watcherp, list_entry);
      free_watcher(watcherp);
    }
  }
  all_watchers_unlock_write();
}

bool set_watcher(vm_map_t proc_map, user_addr_t watchpoint,
                 size_t watchpoint_length, user_addr_t info_addr,
                 watcher_state status, watcher_t **watcher_result)
{
  if (!proc_map || !watchpoint || !watchpoint_length ||
      !status || (status > watcher_state_set_max))
  {
    return false;
  }
  if (watcher_result) {
    *watcher_result = NULL;
  }

  proc_t proc = current_proc();
  uint64_t unique_pid = proc_uniqueid(proc);
  pid_t pid = proc_pid(proc);
  char procname[PATH_MAX];
  proc_name(pid, procname, sizeof(procname));

  user_addr_t range_start =
    vm_map_trunc_page(watchpoint, vm_map_page_mask(proc_map));
  user_addr_t range_end =
    vm_map_round_page(watchpoint + watchpoint_length,
                      vm_map_page_mask(proc_map));

  vm_prot_t prev_prot = 0;
  if (status == watcher_state_set_write_protect) {
    prev_prot = user_region_protection(proc_map, range_start, range_end);
    if (prev_prot == -1) {
      printf("HookCase(%s[%d]): set_watcher(): watchpoint \'0x%llx\' with length \'0x%lx\' is invalid for \"watcher_state_set_write_protect\"\n",
             procname, pid, watchpoint, watchpoint_length);
      return false;
    } else if (prev_prot == VM_PROT_NONE) {
      printf("HookCase(%s[%d]): set_watcher(): Unexpected VM_PROT_NONE permission at watchpoint \'0x%llx\' with length \'0x%lx\'\n",
             procname, pid, watchpoint, watchpoint_length);
      return false;
    }
  } else if (status == watcher_state_set_pageout) {
    int32_t wired = user_region_wired(proc_map, range_start, range_end);
    if (wired == -1) {
      printf("HookCase(%s[%d]): set_watcher(): watchpoint \'0x%llx\' with length \'0x%lx\' is invalid for \"watcher_state_set_pageout\"\n",
             procname, pid, watchpoint, watchpoint_length);
      return false;
    } else if (wired) {
      printf("HookCase(%s[%d]): set_watcher(): watchpoint \'0x%llx\' with length \'0x%lx\' would page out wired pages\n",
             procname, pid, watchpoint, watchpoint_length);
      return false;
    }
  }

  bool have_old_watcher = true;
  would_overlap_state would_overlap = would_overlap_state_not;
  watcher_t *watcherp =
    find_watcher_by_range(range_start, range_end,
                          &would_overlap, unique_pid);
  if (!watcherp) {
    have_old_watcher = false;
    if (would_overlap == would_overlap_state_unset) {
      remove_would_overlap(range_start, range_end, unique_pid);
    } else if (would_overlap == would_overlap_state_set) {
      printf("HookCase(%s[%d]): set_watcher(): watchpoint \'0x%llx\' with length \'0x%lx\' would overlap existing active watchpoint(s)\n",
             procname, pid, watchpoint, watchpoint_length);
      return false;
    }
    watcherp = create_watcher();
    if (!watcherp) {
      return false;
    }
  // Don't do anything if the watchpoint's status is already what we want.
  // The watchpoint hasn't yet been hit, so we don't need to do anything
  // more. If it had been hit, unset_watcher() would have been called from
  // user_trap_hook() and the status would be 'watcher_state_unset'.
  } else if (watcherp->status == status) {
    if (watcher_result) {
      *watcher_result = watcherp;
    }
    return true;
  }

  if ((status == watcher_state_set_write_protect) &&
      (prev_prot & VM_PROT_WRITE))
  {
    vm_prot_t new_prot = (prev_prot & ~VM_PROT_WRITE);
    kern_return_t rv =
      vm_map_protect(proc_map, range_start, range_end, new_prot, false);

    if (rv != KERN_SUCCESS) {
      printf("HookCase(%s[%d]): set_watcher(): vm_map_protect() failed at watchpoint \'0x%llx\' with length \'0x%lx\' and returned 0x%x\n",
             procname, pid, watchpoint, watchpoint_length, rv);
      if (have_old_watcher) {
        remove_watcher(watcherp);
      } else {
        free_watcher(watcherp);
      }
      return false;
    }
  }

  if (status == watcher_state_set_pageout) {
    pageout_user_region(proc_map, range_start, range_end);
  }

  if (have_old_watcher) {
    all_watchers_lock_write();
  }
  watcherp->range_start = range_start;
  watcherp->range_end = range_end;
  // prev_prot will be 0 if status is watcher_state_set_plain or
  // watcher_state_set_pageout
  watcherp->orig_prot = prev_prot;
  watcherp->unique_pid = unique_pid;
  watcherp->pid = pid;
  watcherp->info_addr = info_addr; // May be 0
  OSCompareAndSwap(watcherp->status, status, (UInt32 *) &watcherp->status);
  if (have_old_watcher) {
    all_watchers_unlock_write();
  } else {
    add_watcher(watcherp);
  }

  if (watcher_result) {
    *watcher_result = watcherp;
  }
  return true;
}

bool unset_watcher(vm_map_t proc_map, watcher_t *watcherp)
{
  if (!proc_map || !watcherp) {
    return false;
  }

  // Don't do anything if the watchpoint is already unset
  if (!watcherp->status) {
    return true;
  }

  pid_t pid = proc_pid(current_proc());
  char procname[PATH_MAX];
  proc_name(pid, procname, sizeof(procname));

#if (0)
  unsigned int page_size = vm_map_page_size(proc_map);
  vm_size_t copy_size = page_size;
  if (copy_size > PAGE_SIZE) {
    copy_size = PAGE_SIZE;
  }
  user_addr_t page = watcherp->range_start;
  while (page < watcherp->range_end) {
    unsigned char page_holder[PAGE_SIZE];
    if (!proc_copyin(proc_map, page, &page_holder, copy_size)) {
      printf("HookCase(%s[%d]): unset_watcher(): page \'0x%llx\' in watchpoint range is invalid\n",
             procname, pid, page);
      OSCompareAndSwap(watcherp->status, 0, (UInt32 *) &watcherp->status);
      return false;
    }
    page += page_size;
  }
#endif

  kern_return_t rv = KERN_SUCCESS;
  vm_prot_t orig_prot = watcherp->orig_prot;
  if (watcherp->status == watcher_state_set_write_protect) {
    rv = vm_map_protect(proc_map, watcherp->range_start,
                        watcherp->range_end, orig_prot, false);
  }

  if (rv != KERN_SUCCESS) {
    printf("HookCase(%s[%d]): unset_watcher(): vm_map_protect() failed (\'0x%x\') at \'0x%lx\' with protection \'0x%x\'\n",
           procname, pid, rv, watcherp->range_start, orig_prot);
  } else {
    OSCompareAndSwap(watcherp->status, 0, (UInt32 *) &watcherp->status);
  }

  return (rv == KERN_SUCCESS);
}

void destroy_locks()
{
  if (g_locks_destroyed) {
    return;
  }
  g_locks_destroyed = true;

  if (all_hooks_grp) {
    if (all_hooks_mlock) {
      lck_rw_free(all_hooks_mlock, all_hooks_grp);
      all_hooks_mlock = NULL;
    }
    if (all_kern_hooks_mlock) {
      lck_rw_free(all_kern_hooks_mlock, all_hooks_grp);
      all_kern_hooks_mlock = NULL;
    }
  }
  if (all_hooks_attr) {
    lck_attr_free(all_hooks_attr);
    all_hooks_attr = NULL;
  }
  if (all_hooks_grp) {
    lck_grp_free(all_hooks_grp);
    all_hooks_grp = NULL;
  }
  if (all_hooks_grp_attr) {
    lck_grp_attr_free(all_hooks_grp_attr);
    all_hooks_grp_attr = NULL;
  }

  if (all_watchers_mlock && all_watchers_grp) {
    lck_rw_free(all_watchers_mlock, all_watchers_grp);
    all_watchers_mlock = NULL;
  }
  if (all_watchers_attr) {
    lck_attr_free(all_watchers_attr);
    all_watchers_attr = NULL;
  }
  if (all_watchers_grp) {
    lck_grp_free(all_watchers_grp);
    all_watchers_grp = NULL;
  }
  if (all_watchers_grp_attr) {
    lck_grp_attr_free(all_watchers_grp_attr);
    all_watchers_grp_attr = NULL;
  }
}

void destroy_all_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_hooks_lock_write();
  hook_thread_info_t *infop = NULL;
  hook_thread_info_t *tmp_infop = NULL;
  LIST_FOREACH_SAFE(infop, &g_all_hook_thread_infos, list_entry, tmp_infop) {
    LIST_REMOVE(infop, list_entry);
    free_hook_thread_info(infop);
  }
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    LIST_REMOVE(hookp, list_entry);
    free_hook(hookp);
  }
  all_hooks_unlock_write();
}

void unset_all_kern_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_kern_hooks_lock_write();
  kern_hook_t *kern_hookp = NULL;
  LIST_FOREACH(kern_hookp, &g_all_kern_hooks, list_entry) {
    unset_kern_hook(kern_hookp);
  }
  all_kern_hooks_unlock_write();
}

void destroy_all_kern_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_kern_hooks_lock_write();
  kern_hook_t *kern_hookp = NULL;
  kern_hook_t *tmp_kern_hookp = NULL;
  LIST_FOREACH_SAFE(kern_hookp, &g_all_kern_hooks, list_entry, tmp_kern_hookp) {
    LIST_REMOVE(kern_hookp, list_entry);
    unset_kern_hook(kern_hookp);
    free_kern_hook(kern_hookp);
  }
  all_kern_hooks_unlock_write();
}

void destroy_all_watchers()
{
  if (!check_init_locks()) {
    return;
  }
  all_watchers_lock_write();
  watcher_t *watcherp = NULL;
  watcher_t *tmp_watcherp = NULL;
  LIST_FOREACH_SAFE(watcherp, &g_all_watchers, list_entry, tmp_watcherp) {
    LIST_REMOVE(watcherp, list_entry);
    free_watcher(watcherp);
  }
  all_watchers_unlock_write();
}

void destroy_all_lists()
{
  destroy_all_hooks();
  destroy_all_kern_hooks();
  destroy_all_watchers();
  destroy_locks();
}

bool lock_hook(IORecursiveLock *a_lock)
{
  if (a_lock) {
    // If the current process has no hooks, a_lock has been destroyed.
    if (!process_has_hooks(proc_uniqueid(current_proc()))) {
      return false;
    }
    IORecursiveLockLock(a_lock);
    // If the current process has no hooks, a_lock was destroyed while we were
    // waiting on it.
    if (!process_has_hooks(proc_uniqueid(current_proc()))) {
      return false;
    }
    return true;
  }
  return false;
}

void unlock_hook(IORecursiveLock *a_lock)
{
  // If the current process has no hooks, a_lock has been destroyed.
  if (a_lock && process_has_hooks(proc_uniqueid(current_proc()))) {
    IORecursiveLockUnlock(a_lock);
  }
}

typedef void
(*hook_function)(x86_saved_state_t *intr_state, kern_hook_t *kern_hookp);

void do_kern_hook(x86_saved_state_t *intr_state)
{
  vm_offset_t orig_addr = intr_state->ss_64.isf.rip - 2;
  kern_hook_t *kern_hookp = find_kern_hook(orig_addr);
  if (!kern_hookp || !kern_hookp->hook_addr || !kern_hookp->caller_addr) {
    uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
    intr_state->ss_64.isf.rsp += 8;
    intr_state->ss_64.isf.rip = return_address;
    return;
  }

  hook_function hook = (hook_function) kern_hookp->hook_addr;
  hook(intr_state, kern_hookp);
}

// Now that HookCase supports HC_ADDKIDS, it's important that each process's
// path be canonicalized, so that it can be used to search all hooked
// process's add_kids_path (the contents of which are also canonicalized).
void canonicalize_proc_path(proc_t proc, char *path, hc_path_t result)
{
  if (!proc || !result) {
    return;
  }

  // If possible, canonicalize path.
  char result_local[PATH_MAX];
  result_local[0] = 0;
  // proc_getexecutablevnode() is only available on Yosemite and up.
  if (!OSX_Mavericks()) {
    vfs_context_t context = vfs_context_create(NULL);
    if (context) {
      vnode_t prog_vnode = proc_getexecutablevnode(proc);
      if (prog_vnode) {
        int len = sizeof(result_local);
        vn_getpath(prog_vnode, result_local, &len);
        vnode_put(prog_vnode);
      }
      vfs_context_rele(context);
    }
  }
  if (result_local[0]) {
    strncpy(result, result_local, HC_PATH_SIZE);
  } else if (path) {
    strncpy(result, path, HC_PATH_SIZE);
  }
}

// Check if 'proc' (or its parent) has an HC_INSERT_LIBRARY, HC_ADDKIDS,
// HC_NOKIDS or HC_NO_NUMERICAL_ADDRS environment variable that we should pay
// attention to.
bool get_cast_info(proc_t proc, hc_path_t proc_path, hc_path_t dylib_path,
                   hc_path_t add_kids_path, pid_t *hooked_ancestor,
                   bool *no_numerical_addrs)
{
  if (!proc || !proc_path || !dylib_path || !add_kids_path ||
      !hooked_ancestor || !no_numerical_addrs)
  {
    return false;
  }
  proc_path[0] = 0;
  dylib_path[0] = 0;
  add_kids_path[0] = 0;
  *hooked_ancestor = 0;
  *no_numerical_addrs = false;

  char *path_ptr = NULL;
  char **envp = NULL;
  vm_size_t envp_size = 0;
  void *buffer = NULL;
  vm_size_t buf_size = 0;
  pid_t current_pid = proc_pid(proc);
  if (!get_proc_info(current_pid, &path_ptr, &envp, &envp_size,
                     &buffer, &buf_size))
  {
    return false;
  }

  canonicalize_proc_path(proc, path_ptr, proc_path);

  // Though it's very unlikely, we might have a process path and no
  // environment.
  if (!envp) {
    IOFree(buffer, buf_size);
    return false;
  }

  // This is safe to call here, but not at process exit.
  remove_zombie_hooks();

  bool no_kids = false;

  int i;
  bool found_insert_file_variable = false;
  bool found_trigger_variable = false;
  for (i = 0; envp[i]; ++i) {
    //printf("   %s\n", envp[i]);
    char *value = envp[i];
    char *key = strsep(&value, "=");
    //printf("   key %s, value %s\n", key, value ? value : "");
    if (key && value && value[0]) {
      if (!strncmp(key, HC_INSERT_LIBRARY_ENV_VAR,
                   strlen(HC_INSERT_LIBRARY_ENV_VAR) + 1))
      {
        strncpy(dylib_path, value, HC_PATH_SIZE);
        found_insert_file_variable = true;
        found_trigger_variable = true;
      } else if (!strncmp(key, HC_ADDKIDS_ENV_VAR,
                          strlen(HC_ADDKIDS_ENV_VAR) + 1))
      {
        strncpy(add_kids_path, value, HC_PATH_SIZE);
        found_trigger_variable = true;
      } else if (!strncmp(key, HC_NOKIDS_ENV_VAR,
                          strlen(HC_NOKIDS_ENV_VAR) + 1))
      {
        no_kids = true;
        found_trigger_variable = true;
      } else if (!strncmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR,
                          strlen(HC_NO_NUMERICAL_ADDRS_ENV_VAR) + 1))
      {
        *no_numerical_addrs = true;
        found_trigger_variable = true;
      }
    }
  }
  IOFree(envp, envp_size);
  IOFree(buffer, buf_size);
  envp = NULL;
  buffer = NULL;

  // Check our ancestors to see if we're descended from a previously
  // hooked process, and (if so) whether or not we should inherit the values
  // of its HookCase-specific environment variables. We used to check only
  // one level up -- to that of our parent. But that may not be enough.

  bool is_child = false;
  bool done_with_ancestors = false;

  hc_path_t parent_path;
  parent_path[0] = 0;
  proc_t prev_proc = proc;
  proc_t parent_proc = proc_parent(prev_proc);
  pid_t parent_pid = proc_ppid(prev_proc);
  pid_t first_parent_pid = parent_pid;
  if (!parent_proc || !parent_pid) {
    if (parent_proc) {
      proc_rele(parent_proc);
      parent_proc = NULL;
    }
    done_with_ancestors = true;
  }

  int ancestor_level;
  for (ancestor_level = 1; !done_with_ancestors; ++ancestor_level) {
    // "Normal" parents usually pass their environments to their children, but
    // not always. XPC parents never do. So check both for trigger variables,
    // to determine if the current process is the child of a hooked parent,
    // and so if it should also be hooked.
    bool have_parent_info = false;
    bool have_xpc_parent_info = false;
    // launchd has pid 1
    if (parent_pid != 1) {
      have_parent_info =
        get_proc_info(parent_pid, &path_ptr,
                      &envp, &envp_size, &buffer, &buf_size);
      if (have_parent_info) {
        canonicalize_proc_path(parent_proc, path_ptr, parent_path);
      }
    }

    // Look first at info for a "normal" parent (if present), then if
    // necessary at info for an XPC parent (if present).
    int tries;
    bool done_with_parent = false;
    for (tries = 1; (tries <= 2) && !done_with_parent; ++tries) {
      if (found_trigger_variable) {
        if (have_parent_info) {
          if (envp) {
            for (i = 0; envp[i]; ++i) {
              char *value = envp[i];
              char *key = strsep(&value, "=");
              if (key && value && value[0]) {
                if (!strncmp(key, HC_INSERT_LIBRARY_ENV_VAR,
                             strlen(HC_INSERT_LIBRARY_ENV_VAR) + 1) ||
                    !strncmp(key, HC_ADDKIDS_ENV_VAR,
                             strlen(HC_ADDKIDS_ENV_VAR) + 1) ||
                    !strncmp(key, HC_NOKIDS_ENV_VAR,
                             strlen(HC_NOKIDS_ENV_VAR) + 1) ||
                    !strncmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR,
                             strlen(HC_NO_NUMERICAL_ADDRS_ENV_VAR) + 1))
                {
                  is_child = true;
                  *hooked_ancestor = first_parent_pid;
                  // Only return add_kids_path for a main process that sets
                  // HC_ADDKIDS -- not for any of its children.
                  add_kids_path[0] = 0;
                  done_with_parent = true;
                }
              }
            }
            IOFree(envp, envp_size);
            envp = NULL;
          }
          if (buffer) {
            IOFree(buffer, buf_size);
            buffer = NULL;
          }
          have_parent_info = false;
        }
      } else {
        if (have_parent_info) {
          if (envp) {
            for (i = 0; envp[i]; ++i) {
              char *value = envp[i];
              char *key = strsep(&value, "=");
              if (key && value && value[0]) {
                // Since we only return add_kids_path for a main process that
                // sets HC_ADDKIDS, we're not interested in tracking the value
                // of HC_ADDKIDS in the ancestors of a process that doesn't
                // set HC_ADDKIDS.
                if (!strncmp(key, HC_INSERT_LIBRARY_ENV_VAR,
                             strlen(HC_INSERT_LIBRARY_ENV_VAR) + 1))
                {
                  strncpy(dylib_path, value, HC_PATH_SIZE);
                  found_insert_file_variable = true;
                  is_child = true;
                  *hooked_ancestor = first_parent_pid;
                  found_trigger_variable = true;
                  done_with_parent = true;
                } else if (!strncmp(key, HC_NOKIDS_ENV_VAR,
                                    strlen(HC_NOKIDS_ENV_VAR) + 1))
                {
                  no_kids = true;
                  is_child = true;
                  *hooked_ancestor = first_parent_pid;
                  found_trigger_variable = true;
                  done_with_parent = true;
                } else if (!strncmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR,
                                    strlen(HC_NO_NUMERICAL_ADDRS_ENV_VAR) + 1))
                {
                  *no_numerical_addrs = true;
                  is_child = true;
                  *hooked_ancestor = first_parent_pid;
                  found_trigger_variable = true;
                  done_with_parent = true;
                }
              }
            }
            IOFree(envp, envp_size);
            envp = NULL;
          }
          if (buffer) {
            IOFree(buffer, buf_size);
            buffer = NULL;
          }
          have_parent_info = false;
        }
      }

      if (!done_with_parent && !have_xpc_parent_info) {
        pid_t old_parent_pid = parent_pid;
        parent_pid = get_xpc_parent(proc_pid(prev_proc));
        if (parent_pid) {
          have_xpc_parent_info =
            get_proc_info(parent_pid, &path_ptr, &envp, &envp_size,
                          &buffer, &buf_size);
        }
        if (!have_xpc_parent_info) {
          done_with_parent = true;
        }
        have_parent_info = have_xpc_parent_info;
        if (have_parent_info) {
          proc_t old_parent_proc = parent_proc;
          // parent_proc can end up NULL here. I don't know why.
          parent_proc = proc_find(parent_pid);
          if (parent_proc) {
            proc_rele(old_parent_proc);
            canonicalize_proc_path(parent_proc, path_ptr, parent_path);
          } else {
            parent_proc = old_parent_proc;
            parent_pid = old_parent_pid;
            if (envp) {
              IOFree(envp, envp_size);
              envp = NULL;
            }
            if (buffer) {
              IOFree(buffer, buf_size);
              buffer = NULL;
            }
            have_parent_info = false;
            done_with_parent = true;
          }
        }
      }
    }

    if (!found_trigger_variable) {
      found_insert_file_variable =
        is_added_kid(parent_path, dylib_path, hooked_ancestor, no_numerical_addrs);
      if (found_insert_file_variable) {
        found_trigger_variable = true;
        is_child = true;
      }
    }

    if (found_trigger_variable) {
      proc_rele(parent_proc);
      done_with_ancestors = true;
    } else {
      parent_path[0] = 0;
      prev_proc = parent_proc;
      parent_proc = proc_parent(prev_proc);
      parent_pid = proc_ppid(prev_proc);
      proc_rele(prev_proc);
      if (!parent_proc || !parent_pid) {
        done_with_ancestors = true;
      }
    }
  }

  if (!found_insert_file_variable) {
    found_insert_file_variable =
      is_added_kid(proc_path, dylib_path, hooked_ancestor, no_numerical_addrs);
    if (found_insert_file_variable) {
      is_child = true;
      // Override HC_NOKIDS if proc is listed explicitly in some other
      // hooked process's HC_ADDKIDS.
      no_kids = false;
    }
  }

  return (found_insert_file_variable && (!no_kids || !is_child));
}

// Possibly create a cast hook and set its state to hook_state_cast.  This
// should be called as a process starts up (or restarts after it's been
// "exec"-ed) -- ideally before any code has run at all.  With luck, there's
// just a single thread (the main thread) and RIP/EIP points to _dyld_start in
// the process's copy of the dyld module.
bool maybe_cast_hook(proc_t proc)
{
  // maybe_cast_hook() won't work properly if current_proc() is the kernel
  // process (pid 0).
  if (!proc || (proc == kernproc)) {
    return false;
  }

  // maybe_cast_hook() may legitimately be called more than once on a given
  // process -- for example after another binary has been loaded into it
  // using POSIX_SPAWN_SETEXEC.  But in that case remove_process_hooks() must
  // be called beforehand to remove all existing hooks.  If any hooks do
  // still exist in 'proc', maybe_cast_hook() must accidentally have been
  // more than once on it.
  if (process_has_hooks(proc_uniqueid(proc))) {
    return false;
  }

  wait_interrupt_t old_state = thread_interrupt_level(THREAD_UNINT);
  hc_path_t proc_path;
  hc_path_t dylib_path;
  // add_kids_path is only set for a main process that sets HC_ADDKIDS -- not
  // for any of its children.
  hc_path_t add_kids_path;
  pid_t hooked_ancestor;
  bool no_numerical_addrs;
  bool rv = get_cast_info(proc, proc_path, dylib_path, add_kids_path,
                          &hooked_ancestor, &no_numerical_addrs);
  thread_interrupt_level(old_state);
  if (!rv) {
    return false;
  }

  char procname[PATH_MAX];
  proc_name(proc_pid(proc), procname, sizeof(procname));

  if (dylib_path[0] != '/') {
    printf("HookCase(%s[%d]): maybe_cast_hook(): HC_INSERT_LIBRARY (\"%s\") must be a full path\n",
           procname, proc_pid(proc), dylib_path);
    return false;
  }

  // If possible, canonicalize dylib_path.
  hc_path_t fixed_dylib_path;
  fixed_dylib_path[0] = 0;
  vfs_context_t context = vfs_context_create(NULL);
  if (context) {
    vnode_t dylib_vnode;
    if (!vnode_lookup(dylib_path, 0, &dylib_vnode, context)) {
      int len = sizeof(fixed_dylib_path);
      vn_getpath(dylib_vnode, fixed_dylib_path, &len);
      vnode_put(dylib_vnode);
    }
    vfs_context_rele(context);
  }
  if (fixed_dylib_path[0]) {
    strncpy(dylib_path, fixed_dylib_path, sizeof(dylib_path));
  }

  // If possible, canonicalize the elements in add_kids_path

  char fixed_add_kids_path[PATH_MAX];
  fixed_add_kids_path[0] = 0;
  int fixed_to = 0;

  hc_path_t holder;
  strncpy(holder, add_kids_path, sizeof(holder));
  char *remaining = holder;
  while (remaining) {
    char *path_element = strsep(&remaining, ":");
    if (path_element && path_element[0]) {
      if (path_element[0] != '/') {
        printf("HookCase(%s[%d]): maybe_cast_hook(): HC_ADDKIDS (\"%s\") must contain full paths\n",
               procname, proc_pid(proc), add_kids_path);
        return false;
      }

      vfs_context_t context = vfs_context_create(NULL);
      if (context) {
        vnode_t path_element_vnode;
        if (!vnode_lookup(path_element, 0, &path_element_vnode, context)) {
          char fixed_path_element[PATH_MAX];
          fixed_path_element[0] = 0;
          int len = sizeof(fixed_path_element);
          vn_getpath(path_element_vnode, fixed_path_element, &len);
          vnode_put(path_element_vnode);
          // len, as set by vn_getpath(), includes the terminal NULL.
          len = (int) strlen(fixed_path_element);

          if (fixed_path_element[0]) {
            if (len <= sizeof(fixed_path_element) - 2) {
              fixed_path_element[len] = ':';
              ++len;
              fixed_path_element[len] = 0;
            }
            strncat(fixed_add_kids_path, fixed_path_element,
                    sizeof(fixed_add_kids_path) - fixed_to - 1);
            fixed_to += len;
          }
        }
        vfs_context_rele(context);
      }
    }
  }

  if (fixed_add_kids_path[0]) {
    strncpy(add_kids_path, fixed_add_kids_path, sizeof(add_kids_path));
  }

  // We start setting hooks just before dyld::initializeMainExecutable() (or
  // dyld4::APIs::runAllInitializersForMain() on macOS Monterey and up) runs.
  // It's called (from _main()) after all the automatically linked shared
  // libraries are loaded, but before any of those libraries' C++ initializers
  // have run (which happens while the main executable is being initialized).
  // This seems an ideal place to intervene.
  user_addr_t initializeMainExecutable = 0;
  // On macOS Monterey and up, we must fiddle with dyld to ensure our hook
  // library's initializers (and those of its dependents) are run along with
  // the initializers for the main executable and its dependents. Then we need
  // to undo our change immediately afterwards (after all the initializers
  // have run). So we need to find another method to which we can shift our
  // hook at the appropriate time.
  user_addr_t dyld_afterInitMain = 0;
  user_addr_t dyld_runInitializers = 0;
  user_addr_t dyld_runInitializers2 = 0;
  user_addr_t dyld_isMainExecutable = 0;
  user_addr_t hasExistingDyldCache = 0;
  user_addr_t dyld_launchWithClosure = 0;
  user_addr_t DyldSharedCache_findClosure = 0;
  user_addr_t dyld_findCachedLaunchClosure = 0;
  user_addr_t dyld_buildLaunchClosure = 0;
  module_info_t module_info;
  symbol_table_t symbol_table;
  if (get_module_info(proc, "dyld", 0, &module_info)) {
    if (copyin_symbol_table(&module_info, &symbol_table,
                            symbol_type_defined))
    {
      if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
          macOS_Monterey())
      {
        if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura()) {
          if (macOS_Sequoia_4_or_greater()) {
            hasExistingDyldCache =
              find_symbol("__ZNK5dyld415SyscallDelegate20hasExistingDyldCacheERyR11FileIdTuple",
                          &symbol_table);
          } else {
            hasExistingDyldCache =
              find_symbol("__ZNK5dyld415SyscallDelegate20hasExistingDyldCacheERyS1_S1_",
                          &symbol_table);
          }
        }
        initializeMainExecutable =
          find_symbol("__ZN5dyld44APIs25runAllInitializersForMainEv",
                      &symbol_table);
        if (macOS_Sequoia() || macOS_Sonoma()) {
          if (macOS_Sequoia_4_or_greater()) {
            dyld_afterInitMain =
              find_symbol("__ZN5dyld423ExternallyViewableState25notifyMonitorOfMainCalledEv",
                          &symbol_table);
          } else {
            dyld_afterInitMain =
              find_symbol("__ZN5dyld423ExternallyViewableState19notifyMonitorNeededEv",
                          &symbol_table);
          }
          dyld_runInitializers2 =
            find_symbol("__ZNK5dyld46Loader15runInitializersERNS_12RuntimeStateE",
                        &symbol_table);
        } else {
          dyld_afterInitMain =
            find_symbol("__ZN5dyld424notifyMonitoringDyldMainEv",
                        &symbol_table);
        }
        dyld_runInitializers =
          find_symbol("__ZNK5dyld46Loader38runInitializersBottomUpPlusUpwardLinksERNS_12RuntimeStateE",
                      &symbol_table);
        dyld_isMainExecutable =
          find_symbol("__ZNK5dyld39MachOFile16isMainExecutableEv",
                      &symbol_table);
      } else {
        initializeMainExecutable =
          find_symbol("__ZN4dyld24initializeMainExecutableEv",
                      &symbol_table);
        dyld_runInitializers =
          find_symbol("__ZN4dyld15runInitializersEP11ImageLoader",
                      &symbol_table);
      }
      if (IS_64BIT_PROCESS(proc)) {
        if (macOS_BigSur()) {
          DyldSharedCache_findClosure =
            find_symbol("__ZNK15DyldSharedCache11findClosureEPKc",
                        &symbol_table);
          dyld_findCachedLaunchClosure =
            find_symbol("__ZN4dyldL23findCachedLaunchClosureEPKhRKN5dyld37closure14LoadedFileInfoEPPKcRKNS2_5ArrayIhEE",
                        &symbol_table);
          dyld_buildLaunchClosure =
            find_symbol("__ZN4dyldL18buildLaunchClosureEPKhRKN5dyld37closure14LoadedFileInfoEPPKcRKNS2_5ArrayIhEE",
                        &symbol_table);
        } else if (macOS_Mojave() || macOS_Catalina()) {
          dyld_launchWithClosure =
            find_symbol("__ZN4dyldL17launchWithClosureEPKN5dyld37closure13LaunchClosureEPK15DyldSharedCachePKNS0_11MachOLoadedEmiPPKcSD_SD_PmSE_",
                        &symbol_table);
          dyld_buildLaunchClosure =
            find_symbol("__ZN4dyldL18buildLaunchClosureEPKhRKN5dyld37closure14LoadedFileInfoEPPKc",
                        &symbol_table);
        } else if (macOS_HighSierra()) {
          dyld_launchWithClosure =
            find_symbol("__ZN4dyldL17launchWithClosureEPKN5dyld312launch_cache13binary_format7ClosureEPK15DyldSharedCachePK11mach_headermiPPKcSE_SE_PmSF_",
                        &symbol_table);
        }
      }
      free_symbol_table(&symbol_table);
    }
  }
  if (!initializeMainExecutable || !dyld_runInitializers) {
    return false;
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey())
  {
    if (macOS_Sequoia() || macOS_Sonoma()) {
      if (!dyld_runInitializers2) {
        return false;
      }
    }
    if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura()) {
      if (!hasExistingDyldCache) {
        return false;
      }
    }
    if (!dyld_afterInitMain || !dyld_isMainExecutable) {
      return false;
    }
  }

  uint64_t unique_pid = proc_uniqueid(proc);

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return false;
  }

  uint16_t orig_code = 0;
  if (!proc_copyin(proc_map, initializeMainExecutable, &orig_code,
                   sizeof(orig_code)))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  uint16_t orig_dyld_afterInitMain = 0;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey())
  {
    if (!proc_copyin(proc_map, dyld_afterInitMain, &orig_dyld_afterInitMain,
                     sizeof(orig_dyld_afterInitMain)))
    {
      vm_map_deallocate(proc_map);
      return false;
    }
  }

  uint32_t orig_dyld_runInitializers = 0;
  if (!proc_copyin(proc_map, dyld_runInitializers, &orig_dyld_runInitializers,
                   sizeof(orig_dyld_runInitializers)))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  uint32_t orig_dyld_runInitializers2 = 0;
  if (dyld_runInitializers2) {
    if (!proc_copyin(proc_map, dyld_runInitializers2, &orig_dyld_runInitializers2,
                     sizeof(orig_dyld_runInitializers2)))
    {
      vm_map_deallocate(proc_map);
      return false;
    }
  }

  uint32_t orig_dyld_isMainExecutable = 0;
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey())
  {
    if (!proc_copyin(proc_map, dyld_isMainExecutable, &orig_dyld_isMainExecutable,
                     sizeof(orig_dyld_isMainExecutable)))
    {
      vm_map_deallocate(proc_map);
      return false;
    }
  }

  hook_t *hookp = create_hook();
  if (!hookp) {
    vm_map_deallocate(proc_map);
    return false;
  }

  hookp->pid = proc_pid(proc);
  hookp->unique_pid = unique_pid;
  strncpy(hookp->proc_path, proc_path, sizeof(hc_path_t));
  strncpy(hookp->add_kids_path, add_kids_path, sizeof(hc_path_t));
  strncpy(hookp->inserted_dylib_path, dylib_path, sizeof(hc_path_t));
  hookp->orig_addr = initializeMainExecutable;
  hookp->orig_code = orig_code;
  hookp->dyld_initMain = initializeMainExecutable;
  hookp->orig_dyld_initMain = orig_code;
  hookp->dyld_afterInitMain = dyld_afterInitMain;
  hookp->orig_dyld_afterInitMain = orig_dyld_afterInitMain;
  hookp->dyld_runInitializers = dyld_runInitializers;
  hookp->orig_dyld_runInitializers = orig_dyld_runInitializers;
  hookp->dyld_runInitializers2 = dyld_runInitializers2;
  hookp->orig_dyld_runInitializers2 = orig_dyld_runInitializers2;
  hookp->dyld_isMainExecutable = dyld_isMainExecutable;
  hookp->orig_dyld_isMainExecutable = orig_dyld_isMainExecutable;
  hookp->no_numerical_addrs = no_numerical_addrs;
  hookp->is_cast_hook = true;

  if (hooked_ancestor) {
    hookp->hooked_ancestor = hooked_ancestor;
  }

  uint16_t new_code = HC_INT1_OPCODE_SHORT;
  bool rv1 = proc_copyout(proc_map, &new_code, initializeMainExecutable,
                          sizeof(new_code));
  bool rv2 = true, rv3 = true, rv4 = true, rv5 = true, rv6 = true;
  // If a 64-bit process is being launched on macOS 10.13 through 11 (Big Sur),
  // dyld might call dyld::launchWithClosure(), and take a code path that never
  // calls dyld::initializeMainExecutable(). We have two different ways to
  // prevent this. On 10.13 through 10.15 we patch dyld::launchWithClosure()
  // to make it always "return false". This makes dyld fail over to the code
  // path that calls dyld::initializeMainExecutable(). But it can cause crashes
  // on macOS 11. So there we patch DyldSharedCache::findClosure() and
  // dyld::findCachedLaunchClosure() to make them "return NULL". This prevents
  // dyld::launchWithClosure() from being called in the first place, by making
  // it impossible to find existing closures. On 10.14 and up,
  // dyld::buildLaunchClosure() can be called if dyld::launchWithClosure() or
  // dyld::findCachedLaunchClosure() fails. But we don't want to waste time
  // rebuilding closures that already exist, so we also need to make
  // dyld::buildLaunchClosure() "return NULL".
  uint32_t ret_null = RETURN_NULL_64BIT_INT;
  if (macOS_BigSur()) {
    if (DyldSharedCache_findClosure) {
      rv2 = proc_copyout(proc_map, &ret_null, DyldSharedCache_findClosure,
                         sizeof(ret_null));
    }
    if (dyld_findCachedLaunchClosure) {
      rv3 = proc_copyout(proc_map, &ret_null, dyld_findCachedLaunchClosure,
                         sizeof(ret_null));
    }
  } else {
    if (dyld_launchWithClosure) {
      rv4 = proc_copyout(proc_map, &ret_null, dyld_launchWithClosure,
                         sizeof(ret_null));
    }
  }
  if (dyld_buildLaunchClosure) {
    rv5 = proc_copyout(proc_map, &ret_null, dyld_buildLaunchClosure,
                       sizeof(ret_null));
  }
  // On macOS 13 (Ventura) and above, the OS defaults to switching over from
  // the local copy of dyld to the one in the dyld cache, via a call to
  // dyld4::restartWithDyldInCache(). But this means our hooks will never get
  // hit. So we want the local copy to be used for everything. One way to
  // accomplish this is to make dyld4::SyscallDelegate::hasExistingDyldCache()
  // always return 'false'. (Another is to set the DYLD_IN_CACHE environment
  // variable to '0'.)
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura()) {
    if (hasExistingDyldCache) {
      rv6 = proc_copyout(proc_map, &ret_null, hasExistingDyldCache,
                         sizeof(ret_null));
    }
  }
  vm_map_deallocate(proc_map);
  if (!rv1 || !rv2 || !rv3 || !rv4 || !rv5 || !rv6) {
    free_hook(hookp);
    return false;
  }

  hookp->state = hook_state_cast;
  add_hook(hookp);
  return true;
}

// Our breakpoint (at the beginning of the method that initializes the main
// executable) has been hit for the first time. Set up a call to dlopen() our
// hook library and wait for it to be hit again, triggering a call to
// process_hook_flying(). Also hook hookp->dyld_runInitializers to prevent the
// call to dlopen() from triggering any calls to C++ initializers. (Otherwise
// some of those initializers would run before we had a chance to hook methods
// they call.)
void process_hook_cast(hook_t *hookp, x86_saved_state_t *intr_state)
{
  if (!hookp || !intr_state) {
    return;
  }

  hookp->state = hook_state_broken;

  if (!hookp->dyld_runInitializers) {
    return;
  }

  proc_t proc = current_proc();
  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  user_addr_t dlopen = 0;
  module_info_t module_info;
  symbol_table_t symbol_table;
  if (get_module_info(proc, "/usr/lib/system/libdyld.dylib", 0,
                      &module_info))
  {
    if (copyin_symbol_table(&module_info, &symbol_table,
                            symbol_type_defined))
    {
      dlopen = find_symbol("_dlopen", &symbol_table);
      free_symbol_table(&symbol_table);
    }
  }
  if (!dlopen) {
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code)))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
    }
    vm_map_deallocate(proc_map);
    remove_hook(hookp);
    return;
  }

  memcpy(&hookp->orig_intr_state, intr_state, sizeof(x86_saved_state_t));

  if (intr_state->flavor == x86_SAVED_STATE64) {
    size_t path_len = strlen(hookp->inserted_dylib_path) + 1;
    user_addr_t stack_base = intr_state->ss_64.isf.rsp;
    stack_base -= C_64_REDZONE_LEN;
    stack_base -= path_len;
    user_addr_t inserted_dylib_path = stack_base;
    // In 64-bit mode the stack needs to be 16-byte aligned.  We also need to
    // ensure that RBP will get the same alignment, to prevent GPFs when
    // reads/writes are made between stack variables and SSE registers.  As it
    // happens the standard no-argument stack frame does this just fine.
    stack_base &= 0xfffffffffffffff0;
    stack_base -= sizeof(uint64_t);
    user_addr_t return_address = stack_base;
    if (!proc_copyout(proc_map, hookp->inserted_dylib_path,
                      inserted_dylib_path, path_len) ||
        !proc_copyout(proc_map, &hookp->orig_addr,
                      return_address, sizeof(uint64_t)))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      }
      vm_map_deallocate(proc_map);
      remove_hook(hookp);
      return;
    }
    intr_state->ss_64.isf.rsp = stack_base;
    intr_state->ss_64.rdi = inserted_dylib_path;
    intr_state->ss_64.rsi = RTLD_NOW;
    intr_state->ss_64.isf.rip = dlopen;
    // Note for future reference:  In 64-bit mode there's a varargs ABI that
    // requires AL to be set to how many SSE registers contain arguments.
    // dlopen() doesn't use varargs, but we might also want to insert calls to
    // other functions that do.
    //intr_state->ss_64.rax = 0;
  } else {     // flavor == x86_SAVED_STATE32
    size_t path_len = strlen(hookp->inserted_dylib_path) + 1;
    user32_addr_t stack_base = intr_state->ss_32.uesp;
    stack_base -= path_len;
    user32_addr_t inserted_dylib_path = stack_base;
    // As best I can tell, the stack doesn't need to be 16- or 8-byte aligned
    // in 32-bit mode.  But we do need to ensure that EBP will be 8 bytes off
    // of 16-byte aligned.  The machine code written by Apple's compilers to
    // read/write between stack variables and SSE registers assumes this.  So
    // if we break this rule, these instructions will GPF because the memory
    // addresses aren't 16-byte aligned.
    stack_base &= 0xfffffff0;
    stack_base -= 8;
    uint32_t args[3];
    args[2] = RTLD_NOW;
    args[1] = inserted_dylib_path;
    args[0] = (uint32_t) hookp->orig_addr;
    stack_base -= sizeof(args);
    user32_addr_t args_base = stack_base;
    if (!proc_copyout(proc_map, hookp->inserted_dylib_path,
                      inserted_dylib_path, path_len) ||
        !proc_copyout(proc_map, args, args_base, sizeof(args)))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
      vm_map_deallocate(proc_map);
      remove_hook(hookp);
      return;
    }
    intr_state->ss_32.uesp = stack_base;
    intr_state->ss_32.eip = (uint32_t) dlopen;
  }

  // Patch hookp->dyld_runInitializers to always "return 0". This prevents
  // calls to C++ initializers from being triggered by our call to dlopen().
  // Without this, C++ initializers might call methods before we've had a
  // chance to hook them. We'll restore the original method later in
  // process_hook_flying(). On Sonoma and up we also need to patch hookp->
  // dyld_runInitializers2.
  uint32_t new_code;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    new_code = RETURN_NULL_64BIT_INT;
  } else {     // flavor == x86_SAVED_STATE32
    new_code = RETURN_NULL_32BIT_INT;
  }
  proc_copyout(proc_map, &new_code, hookp->dyld_runInitializers,
               sizeof(new_code));
  if (hookp->dyld_runInitializers2) {
    proc_copyout(proc_map, &new_code, hookp->dyld_runInitializers2,
                 sizeof(new_code));
  }

  vm_map_deallocate(proc_map);
  hookp->state = hook_state_flying;
}

// Must call IOFree on whatever this function returns.
bool get_valid_user_hooks(proc_t proc, char *inserted_dylib_path,
                          hook_desc *user_hooks, uint32_t num_user_hooks,
                          hook_desc **patch_hooks, uint32_t *num_patch_hooks,
                          hook_desc **interpose_hooks, uint32_t *num_interpose_hooks)
{
  if (!inserted_dylib_path || !user_hooks || !num_user_hooks ||
      !patch_hooks || !num_patch_hooks ||
      !interpose_hooks || !num_interpose_hooks)
  {
    return false;
  }

  *patch_hooks = NULL;
  *num_patch_hooks = 0;
  *interpose_hooks = NULL;
  *num_interpose_hooks = 0;

  uint32_t num_patch_hooks_local = 0;
  uint32_t num_interpose_hooks_local = 0;
  hook_desc *patch_hooks_local = NULL;
  hook_desc *interpose_hooks_local = NULL;

  char procname[PATH_MAX];
  proc_name(proc_pid(proc), procname, sizeof(procname));

  uint32_t i, j, k;
  for (i = 0; i < num_user_hooks; ++i) {
    if (!user_hooks[i].hook_function || !user_hooks[i].orig_function_name[0]) {
      if (!user_hooks[i].hook_function) {
        if (user_hooks[i].orig_module_name[0]) {
          printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No hook specified for function \"%s\" of module \"%s\"\n",
                 procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].orig_function_name, user_hooks[i].orig_module_name);
        } else {
          printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No hook specified for function \"%s\"\n",
                 procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].orig_function_name);
        }
      }
      if (!user_hooks[i].orig_function_name[0]) {
        if (user_hooks[i].orig_module_name[0]) {
          printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No function specified for hook \'0x%llx\' in module \"%s\"\n",
                 procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].hook_function, user_hooks[i].orig_module_name);
        } else {
          printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No function specified for hook \'0x%llx\'\n",
                 procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].hook_function);
        }
      }
      continue;
    }
    if (user_hooks[i].orig_module_name[0] &&
        (user_hooks[i].orig_module_name[0] != '/'))
    {
      printf("HookCase(%s[%d]): get_valid_user_hooks(%s): Module name (\"%s\") must be a full path\n",
             procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].orig_module_name);
      user_hooks[i].hook_function = 0;
      continue;
    }

    if (user_hooks[i].orig_module_name[0]) {
      if (!user_hooks[i].func_caller_ptr) {
        printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No caller specified for function \"%s\" in module \"%s\"\n",
               procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].orig_function_name, user_hooks[i].orig_module_name);
        user_hooks[i].hook_function = 0;
        continue;
      }

      // If possible, canonicalize orig_module_name. Doing this allows us to
      // use a soft link for orig_module_name (for example 'libobjc.dylib'
      // instead of 'libobjc.A.dylib'), which is much more convenient.
      hc_path_t fixed_module_name;
      fixed_module_name[0] = 0;
      vnode_t module_vnode;
      vfs_context_t context = vfs_context_create(NULL);
      if (context) {
        if (!vnode_lookup(user_hooks[i].orig_module_name, 0,
                          &module_vnode, context))
        {
          int len = sizeof(fixed_module_name);
          vn_getpath(module_vnode, fixed_module_name, &len);
          vnode_put(module_vnode);
        }
        vfs_context_rele(context);
      }

      // On macOS 11 (Big Sur), vnode_lookup() generally doesn't work on
      // orig_module_name, because it generally isn't in the file system (only
      // in the dyld shared cache). As best I can tell, there's no general
      // workaround for this design flaw. But because all (or almost all)
      // frameworks have a 'Resources' soft link in the same directory where
      // there used to be a soft link to the framework binary, we can hack
      // together a workaround for frameworks.
      if ((macOS_BigSur() || macOS_Monterey() || macOS_Ventura() ||
           macOS_Sonoma() || macOS_Sequoia()) &&
          !fixed_module_name[0])
      {
        char holder[PATH_MAX];
        strncpy(holder, user_hooks[i].orig_module_name, sizeof(holder));
        size_t fixed_to = 0;
        bool done = false;

        while (!done) {
          char proxy_path[PATH_MAX];
          strncpy(proxy_path, holder, sizeof(proxy_path));
          const char *subpath_tag = ".framework/";
          char *subpath_ptr =
            strnstr_ptr(proxy_path + fixed_to,
                        subpath_tag, sizeof(proxy_path) - fixed_to);

          if (subpath_ptr) {
            subpath_ptr += strlen(subpath_tag);
            char subpath[PATH_MAX];
            strncpy(subpath, subpath_ptr, sizeof(subpath));
            subpath_ptr[0] = 0;

            const char *proxy_name = "Resources";
            size_t proxy_name_len = strlen(proxy_name);
            strncat(proxy_path, proxy_name,
                    sizeof(proxy_path) - strlen(proxy_path) - 1);

            context = vfs_context_create(NULL);
            if (context) {
              if (!vnode_lookup(proxy_path, 0, &module_vnode, context)) {
                int len = sizeof(holder);
                // 'len' includes terminal NULL.
                vn_getpath(module_vnode, holder, &len);
                vnode_put(module_vnode);
                fixed_to = len - proxy_name_len - 1;
                holder[fixed_to] = 0;
                strncat(holder, subpath, sizeof(holder) - fixed_to);

                // We're looking for a string starting with 'frameworks_tag',
                // not one equal to it.
                const char *frameworks_tag = "Frameworks";
                if (strncmp(holder + fixed_to, frameworks_tag,
                            strlen(frameworks_tag)) != 0)
                {
                  strncpy(fixed_module_name, holder,
                          sizeof(fixed_module_name));
                  done = true;
                }
              } else {
                done = true;
              }
              vfs_context_rele(context);
            } else {
              done = true;
            }
          } else {
            done = true;
          }
        }
      }

      if (fixed_module_name[0]) {
        strncpy(user_hooks[i].orig_module_name, fixed_module_name,
                sizeof(user_hooks[i].orig_module_name));
      }
    }

    if (user_hooks[i].orig_module_name[0]) {
      ++num_patch_hooks_local;
    } else {
      ++num_interpose_hooks_local;
    }
  }

  if (!num_patch_hooks_local && !num_interpose_hooks_local) {
    return false;
  }

  if (num_patch_hooks_local) {
    patch_hooks_local = (hook_desc *)
      IOMalloc(num_patch_hooks_local * sizeof(hook_desc));
    if (!patch_hooks_local) {
      return false;
    }
  }
  if (num_interpose_hooks_local) {
    interpose_hooks_local = (hook_desc *)
      IOMalloc(num_interpose_hooks_local * sizeof(hook_desc));
    if (!interpose_hooks_local) {
      if (patch_hooks_local) {
        IOFree(patch_hooks_local, num_patch_hooks_local * sizeof(hook_desc));
      }
      return false;
    }
  }

  for (i = 0, j = 0, k = 0; i < num_user_hooks; ++i) {
    if (!user_hooks[i].hook_function || !user_hooks[i].orig_function_name[0]) {
      continue;
    }
    if (user_hooks[i].orig_module_name[0]) {
      memcpy(&(patch_hooks_local[j]), &(user_hooks[i]), sizeof(hook_desc));
      ++j;
    } else {
      memcpy(&(interpose_hooks_local[k]), &(user_hooks[i]), sizeof(hook_desc));
      ++k;
    }
  }

  *patch_hooks = patch_hooks_local;
  *num_patch_hooks = num_patch_hooks_local;
  *interpose_hooks = interpose_hooks_local;
  *num_interpose_hooks = num_interpose_hooks_local;

  return true;
}

// Are there any user hooks that haven't yet been fully resolved/processed?
bool check_for_pending_user_hooks(hook_desc *patch_hooks,
                                  uint32_t num_patch_hooks,
                                  hook_desc *interpose_hooks,
                                  uint32_t num_interpose_hooks)
{
  bool retval = false;

  uint32_t i;
  if (patch_hooks) {
    for (i = 0; i < num_patch_hooks; ++i) {
      if (!patch_hooks[i].hook_function ||
          !patch_hooks[i].func_caller_ptr ||
          !patch_hooks[i].orig_function_name[0] ||
          !patch_hooks[i].orig_module_name[0])
      {
        continue;
      }
      retval = true;
      break;
    }
  }
  if (interpose_hooks) {
    for (i = 0; i < num_interpose_hooks; ++i) {
      if (!interpose_hooks[i].hook_function ||
          !interpose_hooks[i].orig_function_name[0])
      {
        continue;
      }
      retval = true;
      break;
    }
  }

  return retval;
}

// Get the user hook information contained in our hook library, plus other
// useful information.
bool get_user_hooks(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp,
                    hook_desc **patch_hooks, uint32_t *num_patch_hooks,
                    hook_desc **interpose_hooks, uint32_t *num_interpose_hooks)
{
  if (!proc || !proc_map || !cast_hookp ||
      !patch_hooks || !num_patch_hooks ||
      !interpose_hooks || !num_interpose_hooks)
  {
    return false;
  }

  *patch_hooks = NULL;
  *num_patch_hooks = 0;
  *interpose_hooks = NULL;
  *num_interpose_hooks = 0;

  module_info_t module_info;
  if (!get_module_info(proc, cast_hookp->inserted_dylib_path, 0,
                       &module_info))
  {
    return false;
  }
  // Make sure inserted_dylib_path contains the entire path --
  // get_module_info() supports partial matches.
  strncpy(cast_hookp->inserted_dylib_path, module_info.path,
          sizeof(cast_hookp->inserted_dylib_path));

  bool is_64bit = IS_64BIT_PROCESS(proc);

  struct mach_header_64 mh_local;
  mach_vm_size_t mh_size;
  if (is_64bit) {
    mh_size = sizeof(mach_header_64);
  } else {
    mh_size = sizeof(mach_header);
  }
  if (!proc_copyin(proc_map, module_info.load_address, &mh_local, mh_size)) {
    return false;
  }
  if ((mh_local.magic != MH_MAGIC) && (mh_local.magic != MH_MAGIC_64)) {
    return false;
  }

  bool is_in_shared_cache = ((mh_local.flags & MH_SHAREDCACHE) != 0);

  vm_size_t cmds_size = mh_local.sizeofcmds;
  user_addr_t cmds_offset = module_info.load_address + mh_size;
  void *cmds_local;
  if (!proc_mapin(proc_map, cmds_offset,
                  (vm_map_offset_t *) &cmds_local, cmds_size))
  {
    return false;
  }

  uint32_t user_hook_desc_size;
  if (is_64bit) {
    user_hook_desc_size = sizeof(user_hook_desc_64bit);
  } else {
    user_hook_desc_size = sizeof(user_hook_desc_32bit);
  }

  vm_offset_t slide = 0;
  if (is_in_shared_cache) {
    slide = module_info.shared_cache_slide;
  }

  vm_offset_t data_sections_offset = 0;
  uint32_t num_data_sections = 0;
  vm_offset_t hook_data_offset = 0;
  vm_size_t hook_data_size = 0;
  bool found_text_segment = false;
  bool found_data_segment = false;
  bool found_hook_section = false;

  uint32_t num_commands = mh_local.ncmds;
  const struct load_command *load_command =
    (struct load_command *) cmds_local;
  uint32_t i;
  for (i = 1; i <= num_commands; ++i) {
    uint32_t cmd = load_command->cmd;
    switch (cmd) {
      case LC_SEGMENT:
      case LC_SEGMENT_64: {
        char *segname;
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
        uint64_t sections_offset;
        uint32_t nsects;
        if (is_64bit) {
          struct segment_command_64 *command =
            (struct segment_command_64 *) load_command;
          segname = command->segname;
          vmaddr = command->vmaddr;
          vmsize = command->vmsize;
          fileoff = command->fileoff;
          filesize = command->filesize;
          sections_offset =
            (vm_offset_t) load_command + sizeof(struct segment_command_64);
          nsects = command->nsects;
        } else {
          struct segment_command *command =
            (struct segment_command *) load_command;
          segname = command->segname;
          vmaddr = command->vmaddr;
          vmsize = command->vmsize;
          fileoff = command->fileoff;
          filesize = command->filesize;
          sections_offset =
            (vm_offset_t) load_command + sizeof(struct segment_command);
          nsects = command->nsects;
        }
        if (!is_in_shared_cache && !fileoff && filesize) {
          slide = module_info.load_address - vmaddr;
        }
        const char *text_segname = "__TEXT";
        if (!strncmp(segname, text_segname, strlen(text_segname) + 1)) {
          cast_hookp->inserted_dylib_textseg = vmaddr + slide;
          cast_hookp->inserted_dylib_textseg_len = vmsize;
          found_text_segment = true;
          if (found_data_segment) {
            i = num_commands + 1;
          }
        }
        const char *data_segname = "__DATA";
        if (!strncmp(segname, data_segname, strlen(data_segname) + 1)) {
          data_sections_offset = sections_offset;
          num_data_sections = nsects;
          found_data_segment = true;
          if (found_text_segment) {
            i = num_commands + 1;
          }
        }
      }
      break;
    }
    load_command = (struct load_command *)
      ((vm_offset_t)load_command + load_command->cmdsize);
  }

  if (!found_data_segment) {
    vm_deallocate(kernel_map, (vm_map_offset_t) cmds_local, cmds_size);
    return false;
  }

  char procname[PATH_MAX];
  proc_name(proc_pid(proc), procname, sizeof(procname));

  // Search for the __hook section in the __DATA segment.
  for (i = 1; i <= num_data_sections; ++i) {
    char *sectname;
    uint64_t addr;
    uint64_t size;
    if (is_64bit) {
      struct section_64 *section = (struct section_64 *) data_sections_offset;
      sectname = section->sectname;
      addr = section->addr;
      size = section->size;
    } else {
      struct section *section = (struct section *) data_sections_offset;
      sectname = section->sectname;
      addr = section->addr;
      size = section->size;
    }

    const char *hook_sectname = "__hook";
    if (!strncmp(sectname, hook_sectname, strlen(hook_sectname) + 1)) {
      if (size && (size % user_hook_desc_size == 0)) {
        found_hook_section = true;
      } else {
        printf("HookCase(%s[%d]): get_user_hooks(): Incorrect size (\'%lld\' bytes) for \"__DATA, __hook\" section of inserted library \"%s\" -- should be a multiple of \'%d\'\n",
               procname, proc_pid(proc), size, cast_hookp->inserted_dylib_path, user_hook_desc_size);
      }
      hook_data_offset = addr + slide;
      hook_data_size = size;
      break;
    }

    if (is_64bit) {
      data_sections_offset += sizeof(struct section_64);
    } else {
      data_sections_offset += sizeof(struct section);
    }
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) cmds_local, cmds_size);
  if (!found_hook_section) {
    if (!hook_data_offset) {
      printf("HookCase(%s[%d]): get_user_hooks(): Inserted library \"%s\" has no \"__DATA, __hook\" section\n",
             procname, proc_pid(proc), cast_hookp->inserted_dylib_path);
    }
    return false;
  }

  void *hook_data;
  if (!proc_mapin(proc_map, hook_data_offset,
                  (vm_map_offset_t *) &hook_data, hook_data_size))
  {
    return false;
  }

  uint32_t num_user_hooks = (uint32_t) (hook_data_size/user_hook_desc_size);
  size_t user_hooks_size = num_user_hooks * sizeof(hook_desc);
  hook_desc *user_hooks_local = (hook_desc *) IOMalloc(user_hooks_size);
  if (!user_hooks_local) {
    vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);
    return false;
  }
  bzero(user_hooks_local, user_hooks_size);

  for (i = 0; i < num_user_hooks; ++i) {
    if (is_64bit) {
      user_hook_desc_64bit *data = (user_hook_desc_64bit *) hook_data;
      user_hooks_local[i].hook_function = data[i].hook_function;
      user_hooks_local[i].orig_function = data[i].orig_function;
      if (data[i].orig_function_name) {
        if (!proc_copyinstr(proc_map, data[i].orig_function_name,
                            user_hooks_local[i].orig_function_name,
                            sizeof(user_hooks_local[i].orig_function_name)))
        {
          IOFree(user_hooks_local, user_hooks_size);
          vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);
          return false;
        }
      }
      if (data[i].orig_module_name) {
        if (!proc_copyinstr(proc_map, data[i].orig_module_name,
                            user_hooks_local[i].orig_module_name,
                            sizeof(user_hooks_local[i].orig_module_name)))
        {
          IOFree(user_hooks_local, user_hooks_size);
          vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);
          return false;
        }
      }
    } else {
      user_hook_desc_32bit *data = (user_hook_desc_32bit *) hook_data;
      user_hooks_local[i].hook_function = data[i].hook_function;
      user_hooks_local[i].orig_function = data[i].orig_function;
      if (data[i].orig_function_name) {
        if (!proc_copyinstr(proc_map, data[i].orig_function_name,
                            user_hooks_local[i].orig_function_name,
                            sizeof(user_hooks_local[i].orig_function_name)))
        {
          IOFree(user_hooks_local, user_hooks_size);
          vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);
          return false;
        }
      }
      if (data[i].orig_module_name) {
        if (!proc_copyinstr(proc_map, data[i].orig_module_name,
                            user_hooks_local[i].orig_module_name,
                            sizeof(user_hooks_local[i].orig_module_name)))
        {
          IOFree(user_hooks_local, user_hooks_size);
          vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);
          return false;
        }
      }
    }
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) hook_data, hook_data_size);

  bool retval =
    get_valid_user_hooks(proc, cast_hookp->inserted_dylib_path,
                         user_hooks_local, num_user_hooks,
                         patch_hooks, num_patch_hooks,
                         interpose_hooks, num_interpose_hooks);
  IOFree(user_hooks_local, user_hooks_size);

  return retval;
}

// Transcribe code_string into actual machine code.  Must call IOFree() on
// '*buffer' when done.
bool get_code_buffer(const char *code_string, unsigned char **buffer,
                     size_t *buf_len)
{
  if (!code_string || !buffer || !buf_len) {
    return false;
  }

  *buffer = NULL;
  *buf_len = 0;

  size_t string_len = strlen(code_string);
  if (!string_len) {
    return false;
  }
  ++string_len;
  char *code_string_local = (char *) IOMalloc(string_len);
  if (!code_string_local) {
    return false;
  }
  strncpy(code_string_local, code_string, string_len);

  size_t buf_len_local = (string_len / 3) + 1;
  unsigned char *buffer_local = (unsigned char *) IOMalloc(buf_len_local);
  if (!buffer_local) {
    IOFree(code_string_local, string_len);
    return false;
  }
  bzero(buffer_local, buf_len_local);

  int i;
  char *code_string_iterator = code_string_local;
  for (i = 0; i < buf_len_local; ++i) {
    char *code_byte = strsep(&code_string_iterator, " ");
    if (!code_byte) {
      break;
    }
    buffer_local[i] = (unsigned char) strtoul(code_byte, NULL, 16);
  }

  IOFree(code_string_local, string_len);

  *buffer = buffer_local;
  *buf_len = buf_len_local;
  return true;
}

// Get the machine code for a function (call_orig_func) that, given the
// address of a method where we've set a breakpoint, call_orig_func will call
// that method without us having to unset the breakpoint.  call_orig_func
// expects a pointer to the address to be PAGE_SIZE bytes after its own
// beginning.  See call_orig.s for more information.  We must call IOFree()
// on '*buffer' when done.
bool get_call_orig_func(proc_t proc, unsigned char **buffer, size_t *buf_len)
{
  if (!proc || !buffer || !buf_len) {
    return false;
  }
  *buffer = NULL;
  *buf_len = 0;

  bool is_64bit = IS_64BIT_PROCESS(proc);
  bool rv;
  if (is_64bit) {
    rv = get_code_buffer(g_call_orig_func_64bit, buffer, buf_len);
  } else {
    rv = get_code_buffer(g_call_orig_func_32bit, buffer, buf_len);
  }
  return rv;
}

bool can_use_call_orig_func(proc_t proc, hook_t *cast_hookp,
                            uint32_t prologue)
{
  if (!proc || !cast_hookp || !prologue) {
    return false;
  }

  if (!cast_hookp->call_orig_func_block ||
      (cast_hookp->num_call_orig_funcs >= MAX_CALL_ORIG_FUNCS))
  {
    return false;
  }

  bool retval;
  bool is_64bit = IS_64BIT_PROCESS(proc);
  if (is_64bit) {
    retval = (prologue == PROLOGUE_BEGIN_64BIT);
  } else {
    retval = ((prologue & 0xffffff) == PROLOGUE_BEGIN_32BIT);
  }

  return retval;
}

bool set_call_orig_func(proc_t proc, vm_map_t proc_map,
                        hook_t *hookp, hook_t *cast_hookp,
                        user_addr_t orig_addr)
{
  if (!proc || !proc_map || !hookp || !cast_hookp || !orig_addr) {
    return false;
  }

  if (!cast_hookp->call_orig_func_block ||
      (cast_hookp->num_call_orig_funcs >= MAX_CALL_ORIG_FUNCS))
  {
    return false;
  }

  unsigned char *code_buffer = NULL;
  size_t code_buffer_len = 0;
  if (!get_call_orig_func(proc, &code_buffer, &code_buffer_len)) {
    return false;
  }

  user_addr_t call_orig_func_addr =
    cast_hookp->call_orig_func_block +
      CALL_ORIG_FUNC_SIZE * cast_hookp->num_call_orig_funcs;
  user_addr_t orig_func_ptr_addr = call_orig_func_addr + PAGE_SIZE;

  bool retval = true;

  if (proc_copyout(proc_map, code_buffer, call_orig_func_addr,
                   code_buffer_len))
  {
    if (!proc_copyout(proc_map, &orig_addr, orig_func_ptr_addr,
                      sizeof(orig_addr)))
    {
      retval = false;
    }
  } else {
    retval = false;
  }

  IOFree(code_buffer, code_buffer_len);

  if (retval) {
    ++cast_hookp->num_call_orig_funcs;
    hookp->call_orig_func_addr = call_orig_func_addr;
  }

  return retval;
}

// Allocate a page-aligned block of PAGE_SIZE * 2 bytes and map it into the
// user process.  The first PAGE_SIZE part will hold callers of breakpointed
// original methods that we've hooked (ones that skip over the breakpoints, so
// we don't have to remove and reset them).  The second PAGE_SIZE part will
// hold the addresses of those original methods -- each exactly PAGE_SIZE
// bytes after its caller function.
bool setup_call_orig_func_block(vm_map_t proc_map, hook_t *cast_hookp)
{
  if (!proc_map || !cast_hookp) {
    return false;
  }

  char *page_buffer = (char *) IOMallocPageable(2 * PAGE_SIZE, PAGE_SIZE);
  if (!page_buffer) {
    return false;
  }
  bzero(page_buffer, 2 * PAGE_SIZE);

  bool rv = true;
  vm_map_offset_t block = 0;
  if (proc_mapout(proc_map, page_buffer, &block, 2 * PAGE_SIZE)) {
    vm_protect(proc_map, block, PAGE_SIZE, false,
               VM_PROT_READ | VM_PROT_EXECUTE);
    vm_protect(proc_map, block + PAGE_SIZE, PAGE_SIZE, false,
               VM_PROT_READ);
    cast_hookp->call_orig_func_block = block;
  } else {
    rv = false;
  }
  IOFreePageable(page_buffer, 2 * PAGE_SIZE);

  return rv;
}

#define NUM_ADDR_HEADER "_sub_"
#define NUM_ADDR_HEADER_LEN 5

// Check if a 'function_name' follows our convention to specify a numerical
// address, and if so return that numerical address.
bool function_name_to_numerical_addr(char *function_name,
                                     user_addr_t *numerical_addr)
{
  if (!function_name || !numerical_addr) {
    return false;
  }

  *numerical_addr = 0;

  if (strlen(function_name) <= NUM_ADDR_HEADER_LEN) {
    return false;
  }
  if (strncasecmp(function_name, NUM_ADDR_HEADER, NUM_ADDR_HEADER_LEN)) {
    return false;
  }

  char *endptr = NULL;
  user_addr_t addr = strtoul(function_name + NUM_ADDR_HEADER_LEN, &endptr, 16);
  if (!endptr || *endptr) {
    return false;
  }

  *numerical_addr = addr;
  return true;
}

hook_t *create_patch_hook(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp,
                          user_addr_t orig_func_addr, user_addr_t hook_addr,
                          user_addr_t func_caller_ptr, uint32_t prologue,
                          bool is_64bit)
{
  if (!proc || !proc_map || !cast_hookp ||
      !orig_func_addr || !hook_addr)
  {
    return NULL;
  }

  hook_t *hookp = create_hook();
  if (!hookp) {
    return NULL;
  }

  hookp->patch_hook_lock = IORecursiveLockAlloc();
  if (!hookp->patch_hook_lock) {
    free_hook(hookp);
    return NULL;
  }

  bool use_call_orig_func =
    can_use_call_orig_func(proc, cast_hookp, prologue);
  if (use_call_orig_func) {
    if (!set_call_orig_func(proc, proc_map, hookp, cast_hookp,
                            orig_func_addr))
    {
      free_hook(hookp);
      return NULL;
    }
  }

  if (func_caller_ptr) {
    user_addr_t caller_addr = orig_func_addr;
    if (use_call_orig_func) {
      caller_addr = hookp->call_orig_func_addr;
    }
    size_t sizeof_caller_addr;
    if (is_64bit) {
      sizeof_caller_addr = sizeof(uint64_t);
    } else {
      sizeof_caller_addr = sizeof(uint32_t);
    }
    if (!proc_copyout(proc_map, &caller_addr, func_caller_ptr,
                      sizeof_caller_addr))
    {
      free_hook(hookp);
      return NULL;
    }
  }

  uint16_t orig_code = (uint16_t) (prologue & 0xffff);

  hookp->pid = cast_hookp->pid;
  hookp->unique_pid = cast_hookp->unique_pid;
  strncpy(hookp->proc_path, cast_hookp->proc_path,
          sizeof(hookp->proc_path));
  strncpy(hookp->inserted_dylib_path, cast_hookp->inserted_dylib_path,
          sizeof(hookp->inserted_dylib_path));
  hookp->inserted_dylib_textseg = cast_hookp->inserted_dylib_textseg;
  hookp->inserted_dylib_textseg_len = cast_hookp->inserted_dylib_textseg_len;
  hookp->orig_addr = orig_func_addr;
  hookp->orig_code = orig_code;
  hookp->hook_addr = hook_addr;
  hookp->state = hook_state_set;
  add_hook(hookp);

  uint16_t new_code = HC_INT1_OPCODE_SHORT;
  if (!proc_copyout(proc_map, &new_code, orig_func_addr,
                    sizeof(new_code)))
  {
    remove_hook(hookp);
    return NULL;
  }

  return hookp;
}

void set_patch_hooks(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp,
                     hook_desc *patch_hooks, uint32_t num_patch_hooks)
{
  if (!proc || !proc_map || !cast_hookp ||
      !patch_hooks || !num_patch_hooks)
  {
    return;
  }

  char procname[PATH_MAX];
  proc_name(proc_pid(proc), procname, sizeof(procname));

  uint64_t unique_pid = proc_uniqueid(proc);
  bool is_64bit = IS_64BIT_PROCESS(proc);

  int i;
  for (i = 0; i < num_patch_hooks; ++i) {
    if (!patch_hooks[i].hook_function ||
        !patch_hooks[i].func_caller_ptr ||
        !patch_hooks[i].orig_function_name[0] ||
        !patch_hooks[i].orig_module_name[0])
    {
      continue;
    }

    if (hook_exists_with_hook_addr(patch_hooks[i].hook_function, unique_pid)) {
      printf("HookCase(%s[%d]): set_patch_hooks(%s): The function at address \'0x%llx\' has already been used as a hook\n",
             procname, proc_pid(proc), cast_hookp->inserted_dylib_path, patch_hooks[i].hook_function);
      patch_hooks[i].hook_function = 0;
      continue;
    }

    user_addr_t orig_addr = 0;
    module_info_t module_info;
    symbol_table_t symbol_table;
    bool is_numerical_addr = false;
    user_addr_t numerical_addr = 0;
    if (get_module_info(proc, patch_hooks[i].orig_module_name, 0,
                        &module_info))
    {
      if (copyin_symbol_table(&module_info, &symbol_table,
                              symbol_type_defined))
      {
        // In a main executable's Mach-O binary, before it's loaded into
        // memory, the symbol-table addresses of all symbols are offsets from
        // the beginning of the PAGEZERO segment (which is only present in the
        // main executable).  So, for example, in a main executable's file on
        // disk, the address of the _mh_execute_header symbol, which points to
        // the Mach-O header, is always the length of the PAGEZERO segment.
        // But once the main executable is loaded into memory, all its symbols
        // become offsets from the beginning of the Mach-O header.  So in
        // effect the addresses of all symbols are decremented by the size of
        // the PAGEZERO segment, and the address of _mh_execute_header is
        // reduced to 0 (relative to the beginning of the loaded image).  If
        // we're dealing with a function name that translates to a numerical
        // address, the user will have gotten the address from a Mach-O binary
        // file (using 'nm' or a disassembler).  So if the address is in the
        // main executable, we need to compensate, by subtracting from it the
        // size of the PAGEZERO segment.
        if (!cast_hookp->no_numerical_addrs &&
            function_name_to_numerical_addr(patch_hooks[i].orig_function_name,
                                            &numerical_addr))
        {
          // symbol_table.pagezero_size will be 0 for a module that lacks a
          // PAGEZERO segment.
          numerical_addr -= symbol_table.pagezero_size;
          orig_addr = numerical_addr + module_info.load_address;
          is_numerical_addr = true;
        } else {
          orig_addr =
            find_symbol(patch_hooks[i].orig_function_name, &symbol_table);
        }
        free_symbol_table(&symbol_table);
      }
    } else {
      printf("HookCase(%s[%d]): set_patch_hooks(%s): Module \"%s\" not (yet) present/loaded in process\n",
             procname, proc_pid(proc), cast_hookp->inserted_dylib_path, patch_hooks[i].orig_module_name);
      continue;
    }
    if (!is_numerical_addr && !orig_addr) {
      printf("HookCase(%s[%d]): set_patch_hooks(%s): Function \"%s\" not found in module \"%s\"\n",
             procname, proc_pid(proc), cast_hookp->inserted_dylib_path, patch_hooks[i].orig_function_name, patch_hooks[i].orig_module_name);
      patch_hooks[i].hook_function = 0;
      continue;
    }
    if (find_hook(orig_addr, unique_pid)) {
      printf("HookCase(%s[%d]): set_patch_hooks(%s): The function \"%s\" in \"%s\" has already been hooked\n",
             procname, proc_pid(proc), cast_hookp->inserted_dylib_path, patch_hooks[i].orig_function_name, patch_hooks[i].orig_module_name);
      patch_hooks[i].hook_function = 0;
      continue;
    }

    uint32_t prologue = 0;
    if (!proc_copyin(proc_map, orig_addr, &prologue, sizeof(prologue))) {
      if (is_numerical_addr) {
        printf("HookCase(%s[%d]): set_patch_hooks(%s): The address \'0x%llx\' of function \"%s\" in \"%s\" (load address \'0x%llx\') is invalid\n",
               procname, proc_pid(proc), cast_hookp->inserted_dylib_path, orig_addr, patch_hooks[i].orig_function_name,
               patch_hooks[i].orig_module_name, module_info.load_address);
        patch_hooks[i].hook_function = 0;
      }
      continue;
    }

    create_patch_hook(proc, proc_map, cast_hookp, orig_addr,
                      patch_hooks[i].hook_function,
                      patch_hooks[i].func_caller_ptr,
                      prologue, is_64bit);

    patch_hooks[i].hook_function = 0;
  }
}

//#define DEBUG_LAZY_POINTER_TYPES 1

void set_interpose_hooks_for_module(proc_t proc, vm_map_t proc_map,
                                    module_info_t *module_info,
                                    hook_desc *interpose_hooks,
                                    uint32_t num_interpose_hooks)
{
  if (!proc || !proc_map || !module_info ||
      !interpose_hooks || !num_interpose_hooks)
  {
    return;
  }

  bool is_64bit = IS_64BIT_PROCESS(proc);

  symbol_table_t symbol_table;
  if (!copyin_symbol_table(module_info, &symbol_table, symbol_type_undef)) {
    return;
  }

  uint32_t i, j;
  for (i = symbol_table.symbol_index;
       i < symbol_table.symbol_index + symbol_table.symbol_count; ++i)
  {
    // As a comment says in mach-o/loader.h, "an indirect symbol table entry
    // is simply a 32bit index into the symbol table to the symbol that the
    // pointer or stub is refering to".  But entries can also be 0x80000000
    // (for a local symbol) and/or 0x40000000 (for an absolute symbol).
    // These we need to skip.
    uint32_t *indirectSymbolTableItem = (uint32_t *)
      (symbol_table.indirect_symbol_table + (i * sizeof(uint32_t)));
    if (0xF0000000 & *indirectSymbolTableItem) {
      continue;
    }
    if (*indirectSymbolTableItem >= symbol_table.total_symbol_count) {
      break;
    }

    char *string_table_item;
#ifdef DEBUG_LAZY_POINTER_TYPES
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
#endif
    if (symbol_table.is_64bit) {
      struct nlist_64 *symbol_table_item = (struct nlist_64 *)
        (symbol_table.symbol_table +
          *indirectSymbolTableItem * sizeof(struct nlist_64));
      string_table_item = (char *)
        (symbol_table.string_table + symbol_table_item->n_un.n_strx);
#ifdef DEBUG_LAZY_POINTER_TYPES
      n_type = symbol_table_item->n_type;
      n_sect = symbol_table_item->n_sect;
      n_desc = symbol_table_item->n_desc;
      n_value = symbol_table_item->n_value;
#endif
    } else {
      struct nlist *symbol_table_item = (struct nlist *)
        (symbol_table.symbol_table +
          *indirectSymbolTableItem * sizeof(struct nlist));
      string_table_item = (char *)
        (symbol_table.string_table + symbol_table_item->n_un.n_strx);
#ifdef DEBUG_LAZY_POINTER_TYPES
      n_type = symbol_table_item->n_type;
      n_sect = symbol_table_item->n_sect;
      n_desc = symbol_table_item->n_desc;
      n_value = symbol_table_item->n_value;
#endif
    }
    if ((vm_offset_t) string_table_item >=
        symbol_table.string_table + symbol_table.string_table_size)
    {
      break;
    }

    uint64_t target_index = i - symbol_table.symbol_index;
#ifdef DEBUG_LAZY_POINTER_TYPES
    pid_t pid = proc_pid(proc);
    char procname[PATH_MAX];
    proc_name(pid, procname, sizeof(procname));
    kprintf("HookCase(%s[%d]): set_interpose_hooks_for_module(0x%x:0x%llx): module %s, string_table_item %s, n_type 0x%x, n_sect 0x%x, n_desc 0x%x, n_value 0x%llx\n",
            procname, pid, i, target_index, module_info->path,
            string_table_item, n_type, n_sect, n_desc, n_value);
#endif

    // If 'symbol_table.use_stubs_table_proxy' == true, we find entries in the
    // lazy pointer table by browsing the stubs table. Otherwise we browse the
    // lazy pointer table directly. If we're browsing the stubs table, we
    // haven't loaded the lazy pointer table into kernel memory -- so each
    // entry we find in the lazy pointer table will need to be copied in
    // individually.

    uint32_t lazy_ptr_size;
    if (is_64bit) {
      lazy_ptr_size = sizeof(uint64_t);
    } else {
      lazy_ptr_size = sizeof(uint32_t);
    }
    uint64_t old_lazy_ptr = 0;
    user_addr_t old_lazy_ptr_addr;
    bool old_lazy_ptr_needs_copyin = false;

    if (symbol_table.use_stubs_table_proxy) {
      if (target_index >= symbol_table.stubs_table_count) {
        break;
      }
      stubs_table_entry instr =
        ((stubs_table_entry *)(symbol_table.stubs_table))
          [target_index];
      // Sanity check
      if ((instr.opcode != STUBS_TABLE_ENTRY_OPCODE) ||
          (instr.offset == 0))
      {
        break;
      }
      user_addr_t entry_offset =
        symbol_table.stubs_table_addr +
          target_index * sizeof(stubs_table_entry);
      user_addr_t next_entry_offset =
        entry_offset + sizeof(stubs_table_entry);
      old_lazy_ptr_addr =
        (int64_t) next_entry_offset + (int64_t) instr.offset;
      old_lazy_ptr_needs_copyin = true;
    } else {
      if (target_index >= symbol_table.lazy_ptr_table_count) {
        break;
      }
      old_lazy_ptr_addr =
        symbol_table.lazy_ptr_table_addr + target_index * lazy_ptr_size;
      if (is_64bit) {
        uint64_t old_lazy_ptr_64 =
          ((uint64_t *)(symbol_table.lazy_ptr_table))[target_index];
        old_lazy_ptr = old_lazy_ptr_64;
      } else {
        uint32_t old_lazy_ptr_32 =
          ((uint32_t *)(symbol_table.lazy_ptr_table))[target_index];
        old_lazy_ptr = old_lazy_ptr_32;
      }
    }

    for (j = 0; j < num_interpose_hooks; ++j) {
      // This loop can take so long that our cast hook gets deleted partway
      // through, leading to kernel panics in strncmp() or strlen() below.
      if (!find_cast_hook(proc_uniqueid(proc))) {
        break;
      }
      if (!interpose_hooks[j].hook_function ||
          !interpose_hooks[j].orig_function_name[0])
      {
        continue;
      }
      if (!strncmp(string_table_item, interpose_hooks[j].orig_function_name,
                   strlen(interpose_hooks[j].orig_function_name) + 1))
      {
        user_addr_t module_begin = module_info->load_address;
        user_addr_t module_end = module_begin + symbol_table.module_size;
        if (is_64bit) {
          if (old_lazy_ptr_needs_copyin) {
            if (!proc_copyin(proc_map, old_lazy_ptr_addr, &old_lazy_ptr,
                lazy_ptr_size))
            {
              continue;
            }
          }
          uint64_t new_lazy_ptr = interpose_hooks[j].hook_function;
          // Don't change 'old_lazy_ptr' if it's already been changed --
          // presumably via DYLD_INSERT_LIBRARIES. But note that it won't
          // be NULL if it's not yet been initialized. It will point to a
          // local method for lazily setting it to the correct (external)
          // value -- a small block in the __stub_helper section of the
          // __TEXT, containing a PUSH instruction and a JMP instruction.
          // We assume that if a module is in the dyld shared cache it
          // doesn't contain any uninitialized lazy pointers.
          bool uninitialized = (!symbol_table.is_in_shared_cache &&
                                (old_lazy_ptr > module_begin) &&
                                (old_lazy_ptr < module_end));
#ifdef DEBUG_LAZY_POINTERS
          bool interesting =
            ((old_lazy_ptr != interpose_hooks[j].orig_function) &&
              !symbol_table.is_in_shared_cache);
          // On macOS Monterey and above, most (if not all) "lazy" pointers
          // are already initialized. Supposedly this makes applications
          // load faster.
          if (macOS_Monterey() || macOS_Ventura() || macOS_Sonoma() ||
              macOS_Sequoia())
          {
            interesting = true;
          }
          if (interesting) {
#ifndef DEBUG_LAZY_POINTER_TYPES
            pid_t pid = proc_pid(proc);
            char procname[PATH_MAX];
            proc_name(pid, procname, sizeof(procname));
#endif
            vm_offset_t slide = symbol_table.slide;
            kprintf("HookCase(%s[%d]): set_interpose_hooks_for_module(0x%x:0x%llx): module %s, string_table_item %s, new_lazy_ptr 0x%llx(0x%llx), old_lazy_ptr 0x%.08llx%.08llx, orig_function 0x%llx, module_begin 0x%llx, module_end 0x%llx, uninitialized %d, cpu number %d\n",
                    procname, pid, i, target_index, module_info->path, string_table_item,
                    new_lazy_ptr, new_lazy_ptr - slide, (old_lazy_ptr - slide) >> 32,
                    (old_lazy_ptr - slide) & 0xffffffff,
                    interpose_hooks[j].orig_function - slide,
                    module_begin - slide, module_end - slide, uninitialized,
                    get_cpu_number());
          }
          set_set_interpose_hooks_for_module_proc(proc);
#endif
          if (!interpose_hooks[j].orig_function || uninitialized ||
              (old_lazy_ptr == interpose_hooks[j].orig_function))
          {
            proc_copyout(proc_map, &new_lazy_ptr, old_lazy_ptr_addr,
                         sizeof(new_lazy_ptr));
          }
#ifdef DEBUG_LAZY_POINTERS
          set_set_interpose_hooks_for_module_proc(NULL);
#endif
        } else {
          uint32_t new_lazy_ptr =
            (uint32_t) interpose_hooks[j].hook_function;
          // Don't change 'old_lazy_ptr' if it's already been changed --
          // presumably via DYLD_INSERT_LIBRARIES.  But note that it won't
          // be NULL if it's not yet been initialized.  It will point to a
          // local method for lazily setting it to the correct (external)
          // value -- a small block in the __stub_helper section of the
          // __TEXT, containing a PUSH instruction and a JMP instruction.
          // We assume that if a module is in the dyld shared cache it
          // doesn't contain any uninitialized lazy pointers.
          bool uninitialized = (!symbol_table.is_in_shared_cache &&
                                (old_lazy_ptr > module_begin) &&
                                (old_lazy_ptr < module_end));
#ifdef DEBUG_LAZY_POINTERS
          if ((old_lazy_ptr != interpose_hooks[j].orig_function) &&
              !symbol_table.is_in_shared_cache)
          {
#ifndef DEBUG_LAZY_POINTER_TYPES
            pid_t pid = proc_pid(proc);
            char procname[PATH_MAX];
            proc_name(pid, procname, sizeof(procname));
#endif
            vm_offset_t slide = symbol_table.slide;
            kprintf("HookCase(%s[%d]): set_interpose_hooks_for_module(): module %s, new_lazy_ptr 0x%x(0x%x), old_lazy_ptr 0x%llx, module_begin 0x%llx, module_end 0x%llx, uninitialized %d\n",
                    procname, pid, module_info->path, new_lazy_ptr, new_lazy_ptr - (uint32_t) slide,
                    old_lazy_ptr - slide, module_begin - slide, module_end - slide, uninitialized);
          }
          set_set_interpose_hooks_for_module_proc(proc);
#endif
          if (!interpose_hooks[j].orig_function || uninitialized ||
              (old_lazy_ptr == (uint32_t) interpose_hooks[j].orig_function))
          {
            proc_copyout(proc_map, &new_lazy_ptr, old_lazy_ptr_addr,
                         sizeof(new_lazy_ptr));
          }
#ifdef DEBUG_LAZY_POINTERS
          set_set_interpose_hooks_for_module_proc(NULL);
#endif
        }
      }
    }
  }

  free_symbol_table(&symbol_table);
}

void set_interpose_hooks(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp,
                         hook_desc *interpose_hooks, uint32_t num_interpose_hooks)
{
  if (!proc || !proc_map || !cast_hookp ||
      !interpose_hooks || !num_interpose_hooks)
  {
    return;
  }

  bool is_64bit = IS_64BIT_PROCESS(proc);
  task_t task = proc_task(proc);
  if (!task) {
    return;
  }

  vm_address_t all_image_info_addr = task_all_image_info_addr(task);
  vm_size_t all_image_info_size = task_all_image_info_size(task);

  if (!all_image_info_addr || !all_image_info_size) {
    return;
  }

  char *holder;
  if (!proc_mapin(proc_map, all_image_info_addr,
                  (vm_map_offset_t *) &holder, all_image_info_size))
  {
    return;
  }

  uint32_t info_array_count = 0;
  user_addr_t info_array_addr = 0;
  vm_size_t info_array_size = 0;
  bool libSystem_initialized = false;
  vm_offset_t shared_cache_slide = 0;
  if (is_64bit) {
    struct user64_dyld_all_image_infos *info =
      (struct user64_dyld_all_image_infos *) holder;
    info_array_count = info->infoArrayCount;
    info_array_size =
      info_array_count * sizeof(struct user64_dyld_image_info);
    info_array_addr = info->infoArray;
    libSystem_initialized = info->libSystemInitialized;
    shared_cache_slide = info->sharedCacheSlide;
  } else {
    struct user32_dyld_all_image_infos *info =
      (struct user32_dyld_all_image_infos *) holder;
    info_array_count = info->infoArrayCount;
    info_array_size =
      info_array_count * sizeof(struct user32_dyld_image_info);
    info_array_addr = info->infoArray;
    libSystem_initialized = info->libSystemInitialized;
    shared_cache_slide = info->sharedCacheSlide;
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) holder, all_image_info_size);

  if (!info_array_count || !info_array_size || !info_array_addr) {
    return;
  }

  if (!proc_mapin(proc_map, info_array_addr,
                  (vm_map_offset_t *) &holder, info_array_size))
  {
    return;
  }

  uint32_t i;
  char path_local[PATH_MAX];
  for (i = 0; i < info_array_count; ++i) {
    user_addr_t load_addr = 0;
    user_addr_t path_addr = 0;
    if (is_64bit) {
      struct user64_dyld_image_info *info_array =
        (struct user64_dyld_image_info *) holder;
      load_addr = info_array[i].imageLoadAddress;
      path_addr = info_array[i].imageFilePath;
    } else {
      struct user32_dyld_image_info *info_array =
        (struct user32_dyld_image_info *) holder;
      load_addr = info_array[i].imageLoadAddress;
      path_addr = info_array[i].imageFilePath;
    }
    if (!path_addr) {
      continue;
    }
    if (!proc_copyinstr(proc_map, path_addr, path_local, sizeof(path_local))) {
      continue;
    }
    // If possible, canonicalize path_local.
    char fixed_path_local[PATH_MAX];
    fixed_path_local[0] = 0;
    vfs_context_t context = vfs_context_create(NULL);
    if (context) {
      vnode_t module_vnode;
      if (!vnode_lookup(path_local, 0, &module_vnode, context)) {
        int len = sizeof(fixed_path_local);
        vn_getpath(module_vnode, fixed_path_local, &len);
        vnode_put(module_vnode);
      }
      vfs_context_rele(context);
    }
    if (fixed_path_local[0]) {
      strncpy(path_local, fixed_path_local, sizeof(path_local));
    }
    // Don't set any interpose hooks in our hook library.  That would prevent
    // calls from hooks to their original functions from working properly.
    if (!strncmp(path_local, cast_hookp->inserted_dylib_path,
                 strlen(cast_hookp->inserted_dylib_path) + 1))
    {
      continue;
    }

    module_info_t module_info;
    bzero(&module_info, sizeof(module_info));
    strncpy(module_info.path, path_local, sizeof(module_info.path));
    module_info.load_address = load_addr;
    module_info.shared_cache_slide = shared_cache_slide;
    module_info.libSystem_initialized = libSystem_initialized;
    module_info.proc = proc;
    set_interpose_hooks_for_module(proc, proc_map, &module_info,
                                   interpose_hooks, num_interpose_hooks);
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) holder, info_array_size);
}

bool set_hooks(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp,
               bool *user_hooks_pending)
{
  if (!proc || !proc_map || !cast_hookp || !user_hooks_pending) {
    return false;
  }
  *user_hooks_pending = false;

  hook_desc *patch_hooks = NULL;
  uint32_t num_patch_hooks = 0;
  hook_desc *interpose_hooks = NULL;
  uint32_t num_interpose_hooks = 0;
  if (!get_user_hooks(proc, proc_map, cast_hookp,
                      &patch_hooks, &num_patch_hooks,
                      &interpose_hooks, &num_interpose_hooks))
  {
    return false;
  }

  if (!setup_call_orig_func_block(proc_map, cast_hookp)) {
    return false;
  }

  wait_interrupt_t old_state = thread_interrupt_level(THREAD_UNINT);

  bool retval = true;

  if (interpose_hooks) {
#ifdef DELAY_SET_INTERPOSE_HOOKS
    // On macOS Ventura we can delay calling set_interpose_hooks() until our
    // shared "__got" sections, if any, have been initialized.
    if (macOS_Ventura() || macOS_Sonoma() || macOS_Sequoia()) {
      cast_hookp->set_interpose_hooks_delayed = true;
    } else {
      set_interpose_hooks(proc, proc_map, cast_hookp,
                          interpose_hooks, num_interpose_hooks);
    }
#else
    set_interpose_hooks(proc, proc_map, cast_hookp,
                        interpose_hooks, num_interpose_hooks);
#endif
    cast_hookp->interpose_hooks = interpose_hooks;
    cast_hookp->num_interpose_hooks = num_interpose_hooks;
  }
  if (patch_hooks) {
    set_patch_hooks(proc, proc_map, cast_hookp,
                    patch_hooks, num_patch_hooks);
    cast_hookp->patch_hooks = patch_hooks;
    cast_hookp->num_patch_hooks = num_patch_hooks;
  }

  if (check_for_pending_user_hooks(patch_hooks, num_patch_hooks,
                                   interpose_hooks, num_interpose_hooks))
  {
    *user_hooks_pending = true;
  }

  thread_interrupt_level(old_state);

  return retval;
}

// Set up a call to _dyld_register_func_for_add_image().
bool setup_register_for_add_image(hook_t *hookp, x86_saved_state_t *intr_state,
                                  vm_map_t proc_map)
{
  if (!hookp || !intr_state || !proc_map) {
    return false;
  }

  user_addr_t dyld_register_func_for_add_image = 0;
  module_info_t module_info;
  symbol_table_t symbol_table;
  if (get_module_info(current_proc(), "/usr/lib/system/libdyld.dylib", 0,
                      &module_info))
  {
    if (copyin_symbol_table(&module_info, &symbol_table,
                            symbol_type_defined))
    {
      dyld_register_func_for_add_image =
        find_symbol("__dyld_register_func_for_add_image", &symbol_table);
      free_symbol_table(&symbol_table);
    }
  }

  // Allocate a block to hold the 'func' we will pass to
  // _dyld_register_func_for_add_image().  Copy to it the appropriate machine
  // code (which contains an "int 0x31" instruction).  Then remap that block
  // into the current user process.
  vm_map_offset_t on_add_image = 0;
  uint64_t *func_buffer = (uint64_t *) IOMallocPageable(PAGE_SIZE, PAGE_SIZE);
  if (func_buffer) {
    bzero(func_buffer, PAGE_SIZE);
    if (intr_state->flavor == x86_SAVED_STATE64) {
      func_buffer[0] = HC_INT2_FUNC_64BIT_LONG;
    } else {     // flavor == x86_SAVED_STATE32
      func_buffer[0] = HC_INT2_FUNC_32BIT_LONG;
    }
    if (proc_mapout(proc_map, func_buffer, &on_add_image, PAGE_SIZE)) {
      vm_protect(proc_map, on_add_image, PAGE_SIZE, false,
                 VM_PROT_READ | VM_PROT_EXECUTE);
      hookp->add_image_func_addr = on_add_image;
    }
    IOFreePageable(func_buffer, PAGE_SIZE);
  }

  if (!dyld_register_func_for_add_image || !on_add_image) {
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code)))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
    }
    remove_hook(hookp);
    return false;
  }

  if (intr_state->flavor == x86_SAVED_STATE64) {
    user_addr_t stack_base = intr_state->ss_64.isf.rsp;
    stack_base -= C_64_REDZONE_LEN;
    // In 64-bit mode the stack needs to be 16-byte aligned.  We also need to
    // ensure that RBP will get the same alignment, to prevent GPFs when
    // reads/writes are made between stack variables and SSE registers.  As it
    // happens the standard no-argument stack frame does this just fine.
    stack_base &= 0xfffffffffffffff0;
    stack_base -= sizeof(uint64_t);
    user_addr_t return_address = stack_base;
    if (!proc_copyout(proc_map, &hookp->orig_addr,
                      return_address, sizeof(uint64_t)))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      }
      remove_hook(hookp);
      return false;
    }
    intr_state->ss_64.isf.rsp = stack_base;
    intr_state->ss_64.rdi = on_add_image;
    intr_state->ss_64.isf.rip = dyld_register_func_for_add_image;
    // Note for future reference:  In 64-bit mode there's a varargs ABI that
    // requires AL to be set to how many SSE registers contain arguments.
    // dyld_register_func_for_add_image() doesn't use varargs, but we might
    // also want to insert calls to other functions that do.
    //intr_state->ss_64.rax = 0;
  } else {     // flavor == x86_SAVED_STATE32
    user32_addr_t stack_base = intr_state->ss_32.uesp;
    // As best I can tell, the stack doesn't need to be 16- or 8-byte aligned
    // in 32-bit mode.  But we do need to ensure that EBP will be 8 bytes off
    // of 16-byte aligned.  The machine code written by Apple's compilers to
    // read/write between stack variables and SSE registers assumes this.  So
    // if we break this rule, these instructions will GPF because the memory
    // addresses aren't 16-byte aligned.
    stack_base &= 0xfffffff0;
    stack_base -= 12;
    uint32_t args[2];
    args[1] = (uint32_t) on_add_image;
    args[0] = (uint32_t) hookp->orig_addr;
    stack_base -= sizeof(args);
    user32_addr_t args_base = stack_base;
    if (!proc_copyout(proc_map, args, args_base, sizeof(args))) {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
      remove_hook(hookp);
      return false;
    }
    intr_state->ss_32.uesp = stack_base;
    intr_state->ss_32.eip = (uint32_t) dyld_register_func_for_add_image;
  }

  return true;
}

// Our breakpoint (on the method that initializes the main executable) has
// been hit for the second time. If dlopen() loaded our hook library, try to
// set the hooks it describes. Then if there's no more to do, unset our
// breakpoint and pay no further attention to the current user process.
// Otherwise set up a call to _dyld_register_func_for_add_image(), which (if
// it succeeds) will trigger calls to on_add_image() (below) whenever a new
// module is loaded. Then wait for our breakpoint to be hit again, triggering
// a call to process_hook_landed() below. On macOS Monterey and above we may
// also need to shift our breakpoint to hookp->dyld_afterInitMain.
void process_hook_flying(hook_t *hookp, x86_saved_state_t *intr_state)
{
  if (!hookp || !intr_state) {
    return;
  }

  hookp->state = hook_state_broken;

  if (!hookp->dyld_runInitializers) {
    return;
  }

  proc_t proc = current_proc();
  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  // Restore the original hookp->dyld_runInitializers method that we disabled
  // above in process_hook_cast(). On macOS 11 (Big Sur) and below, our hook
  // library's C++ initializers (and those of its dependencies) will run along
  // with those from the remaining modules in our host process, when
  // dyld::runInitializers() is called again from the code that initializes
  // our main executable. But on macOS Monterey and above this won't happen
  // unless we make a temporary change to dyld. So we postpone restoring the
  // original hookp->dyld_runInitializers method until just before we need to.
  if (!hookp->dyld_afterInitMain) {
    proc_copyout(proc_map, &hookp->orig_dyld_runInitializers,
                 hookp->dyld_runInitializers,
                 sizeof(hookp->orig_dyld_runInitializers));
  }

  char procname[PATH_MAX];
  proc_name(proc_pid(proc), procname, sizeof(procname));

  uint64_t dlopen_result = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    dlopen_result = intr_state->ss_64.rax;
  } else {     // flavor == x86_SAVED_STATE32
    dlopen_result = intr_state->ss_32.eax;
  }

  // Reset the thread state to what it was just before we hit our
  // dyld::initializeMainExecutable() breakpoint for the first time.
  memcpy(intr_state, &hookp->orig_intr_state, sizeof(x86_saved_state_t));

  bool work_done = true;
  bool user_hooks_pending = false;
  if (dlopen_result) {
    set_hooks(proc, proc_map, hookp, &user_hooks_pending);
  } else {
    printf("HookCase(%s[%d]): process_hook_flying(): Library \"%s\" not found or can't be loaded\n",
           procname, proc_pid(proc), hookp->inserted_dylib_path);
  }

  if (dlopen_result && (user_hooks_pending || hookp->dyld_afterInitMain)) {
    work_done = false;
  }

  if (work_done) {
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code)))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
    }

    vm_map_deallocate(proc_map);
    return;
  }

  if (user_hooks_pending) {
    if (setup_register_for_add_image(hookp, intr_state, proc_map)) {
      hookp->state = hook_state_landed;
    }
  } else if (hookp->dyld_afterInitMain) {
    // Restore the original hookp->dyld_runInitializers method(s) that we
    // disabled above in process_hook_cast().
    proc_copyout(proc_map, &hookp->orig_dyld_runInitializers,
                 hookp->dyld_runInitializers,
                 sizeof(hookp->orig_dyld_runInitializers));
    if (hookp->dyld_runInitializers2) {
      proc_copyout(proc_map, &hookp->orig_dyld_runInitializers2,
                   hookp->dyld_runInitializers2,
                   sizeof(hookp->orig_dyld_runInitializers2));
    }

    // On macOS 12 (Monterey) and up, we need to temporarily alter dyld to
    // ensure that our hook library's initializers (and those of its
    // dependents) run along with all the other initializers. We patch
    // dyld3::MachOFile::isMainExecutable() to always "return false". Then we
    // undo this change as soon as possible below.
    uint32_t new_code;
    if (intr_state->flavor == x86_SAVED_STATE64) {
      new_code = RETURN_NULL_64BIT_INT;
    } else {     // flavor == x86_SAVED_STATE32
      new_code = RETURN_NULL_32BIT_INT;
    }
    proc_copyout(proc_map, &new_code, hookp->dyld_isMainExecutable,
                 sizeof(new_code));

    // Shift our breakpoint and wait for the new breakpoint to be hit -- after
    // which all the currently loaded modules' initializers should have
    // finished running. Then undo the change we just made to
    // dyld3::MachOFile::isMainExecutable(), below.
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code)))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }

      hookp->orig_addr = hookp->dyld_afterInitMain;
      hookp->orig_code = hookp->orig_dyld_afterInitMain;

      uint16_t new_code = HC_INT1_OPCODE_SHORT;
      if (proc_copyout(proc_map, &new_code, hookp->orig_addr,
                       sizeof(new_code)))
      {
        hookp->state = hook_state_landed;
      }
    }
  }

  vm_map_deallocate(proc_map);
}

// Our breakpoint has been hit again. It might still be set to the method that
// initializes our main executable. Or (on macOS Monterey and up) it might
// have been shifted to a method that runs just after the first one has
// returned. On macOS 11 (Big Sur) and below, just unset our breakpoint and
// keep our cast hook alive for future reference. On macOS Monterey and above,
// we may need to set up further calls in the target process, which will
// result in repeated calls to process_hook_landed().
void process_hook_landed(hook_t *hookp, x86_saved_state_t *intr_state)
{
  if (!hookp || !intr_state) {
    return;
  }

  hookp->state = hook_state_broken;

  proc_t proc = current_proc();
  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  hook_state next_hook_state = hook_state_floating;

  if (hookp->dyld_afterInitMain) {
    if (hookp->orig_addr != hookp->dyld_afterInitMain) {
      // Restore the original hookp->dyld_runInitializers method(s) that we
      // disabled above in process_hook_cast().
      proc_copyout(proc_map, &hookp->orig_dyld_runInitializers,
                   hookp->dyld_runInitializers,
                   sizeof(hookp->orig_dyld_runInitializers));
      if (hookp->dyld_runInitializers2) {
        proc_copyout(proc_map, &hookp->orig_dyld_runInitializers2,
                     hookp->dyld_runInitializers2,
                     sizeof(hookp->orig_dyld_runInitializers2));
      }

      // On macOS 12 (Monterey) and up, unless we have already done so above,
      // we need to temporarily alter dyld to ensure that our hook library's
      // initializers (and those of its dependents) run along with all the
      // other initializers. Patch dyld3::MachOFile::isMainExecutable() to
      // always "return false". Then undo this change as soon as possible
      // below.
      uint32_t new_code;
      if (intr_state->flavor == x86_SAVED_STATE64) {
        new_code = RETURN_NULL_64BIT_INT;
      } else {     // flavor == x86_SAVED_STATE32
        new_code = RETURN_NULL_32BIT_INT;
      }
      proc_copyout(proc_map, &new_code, hookp->dyld_isMainExecutable,
                   sizeof(new_code));

      // Shift our breakpoint and wait for the new breakpoint to be hit --
      // after which all the currently loaded modules' initializers should
      // have finished running. Then (on the next call to
      // process_hook_landed()) undo the change we just made to
      // dyld3::MachOFile::isMainExecutable().
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        // Since we're about to run dyld::initializeMainExecutable(), reset
        // the thread state to what it was just before we hit its breakpoint
        // for the first time.
        memcpy(intr_state, &hookp->orig_intr_state, sizeof(x86_saved_state_t));

        if (intr_state->flavor == x86_SAVED_STATE64) {
          intr_state->ss_64.isf.rip = hookp->orig_addr;
        } else {     // flavor == x86_SAVED_STATE32
          intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
        }

        hookp->orig_addr = hookp->dyld_afterInitMain;
        hookp->orig_code = hookp->orig_dyld_afterInitMain;

        uint16_t new_code = HC_INT1_OPCODE_SHORT;
        if (proc_copyout(proc_map, &new_code, hookp->orig_addr,
                         sizeof(new_code)))
        {
          next_hook_state = hook_state_landed;
        } else {
          next_hook_state = hook_state_broken;
        }
      }
    } else {
      // All loaded modules' initializers should have finished running. Undo
      // the change we made above to dyld3::MachOFile::isMainExecutable().
      proc_copyout(proc_map, &hookp->orig_dyld_isMainExecutable,
                   hookp->dyld_isMainExecutable,
                   sizeof(hookp->orig_dyld_isMainExecutable));
    }

    // If we've delayed our call to set_interpose_hooks() until after our
    // process has called its initializers, make the call here.
    if ((next_hook_state == hook_state_floating) &&
        hookp->set_interpose_hooks_delayed)
    {
      set_interpose_hooks(proc, proc_map, hookp,
                          hookp->interpose_hooks,
                          hookp->num_interpose_hooks);
    }
  }

  if (next_hook_state == hook_state_floating) {
    // If we're about to run dyld::initializeMainExecutable(), reset the
    // thread state to what it was just before we hit its breakpoint for the
    // first time.
    if (hookp->orig_addr == hookp->dyld_initMain) {
      memcpy(intr_state, &hookp->orig_intr_state, sizeof(x86_saved_state_t));
    }
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code)))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
    } else {
      next_hook_state = hook_state_broken;
    }
  }

  hookp->state = next_hook_state;

  vm_map_deallocate(proc_map);
}

// We've hit a breakpoint in the original method hooked by one of our patch
// hooks.  If we have a caller for the original method (if it has a standard
// C/C++ prologue), set up a call to either it or the hook, as appropriate.
// Otherwise unset the breakpoint and set up a call to the hook.  In that case
// the hook will need to reset the breakpoint by calling reset_hook() in the
// hook library.
void process_hook_set(hook_t *hookp, x86_saved_state_t *intr_state)
{
  if (!hookp || !intr_state) {
    return;
  }

  proc_t proc = current_proc();

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  uint64_t unique_pid = proc_uniqueid(proc);

  user_addr_t call_orig_func_addr = hookp->call_orig_func_addr;

  user_addr_t return_address = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    proc_copyin(proc_map, intr_state->ss_64.isf.rsp,
                &return_address, sizeof(uint64_t));
  } else {     // flavor == x86_SAVED_STATE32
    proc_copyin(proc_map, intr_state->ss_32.uesp,
                &return_address, sizeof(uint32_t));
  }
  user_addr_t hook_textseg = hookp->inserted_dylib_textseg;
  user_addr_t hook_textseg_end =
    hook_textseg + hookp->inserted_dylib_textseg_len;
  bool called_from_hook_library =
    ((return_address >= hook_textseg) && (return_address < hook_textseg_end));

  if (call_orig_func_addr) {
    if (called_from_hook_library) {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = call_orig_func_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) call_orig_func_addr;
      }
    } else {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->hook_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->hook_addr;
      }
    }
  } else {
    // Do what we can to alleviate thread contention if we have to unset the
    // breakpoint here and reset it in reset_hook() below.  This imposes a
    // large cost, but otherwise the user process may get very crashy.
    if (lock_hook(hookp->patch_hook_lock)) {
      task_t task = proc_task(proc);
      if (task) {
        task_reference(task);
        if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
          task_hold_and_wait(task);
        } else {
          task_hold(task);
          task_wait(task, false);
        }
      }
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code)))
      {
        hookp->state = hook_state_unset;
      }
      if (called_from_hook_library) {
        if (intr_state->flavor == x86_SAVED_STATE64) {
          intr_state->ss_64.isf.rip = hookp->orig_addr;
        } else {     // flavor == x86_SAVED_STATE32
          intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
        }
      } else {
        if (intr_state->flavor == x86_SAVED_STATE64) {
          intr_state->ss_64.isf.rip = hookp->hook_addr;
        } else {     // flavor == x86_SAVED_STATE32
          intr_state->ss_32.eip = (uint32_t) hookp->hook_addr;
        }
      }
      if (task) {
        task_release(task);
        task_deallocate(task);
      }
      unlock_hook(hookp->patch_hook_lock);
    }
  }

  // Keep g_all_hook_thread_infos up to date.
  hook_thread_info_t *infop =
    find_hook_thread_info(current_thread(), unique_pid, hookp->hook_addr);
  if (!infop) {
    infop = create_hook_thread_info();
    if (infop) {
      infop->patch_hook = hookp;
      infop->hook_thread = current_thread();
      infop->unique_pid = unique_pid;
      add_hook_thread_info(infop);
    }
  // Since different patch hooks (with different orig_addr) may share the same
  // hook_addr and run on the same thread, the value of infop->patch-hook may
  // need to change over time. We update it here to prepare for possible calls
  // to get_dynamic_caller() and reset_hook() in the hook -- to ensure they
  // find the right patch hook, and get_dynamic_caller() returns the right
  // caller. Since this hook_thread_info_t list_entry's patch_hook is only
  // changed here, and can only be changed again on the same thread, the value
  // returned by get_dynamic_caller() will remain correct for at least as long
  // as the hook is running. We assume the patch hooks' original methods (at
  // hookp->orig_addr) can't call each other, which is unlikely if they're
  // event handlers for different events. The primary use for dynamic patch
  // hooks is to hook event handlers, and only for event handlers do we
  // sometimes need to make different hooks share the same hook_addr.
  } else if (infop->patch_hook != hookp) {
    if (check_init_locks()) {
      all_hooks_lock_write();
      infop->patch_hook = hookp;
      all_hooks_unlock_write();
    }
  }

  vm_map_deallocate(proc_map);
}

void check_hook_state(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }
  user_addr_t orig_addr;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    orig_addr = intr_state->ss_64.isf.rip - 2;
  } else { // flavor == x86_SAVED_STATE32
    orig_addr = intr_state->ss_32.eip - 2;
  }
  hook_t *hookp = find_hook(orig_addr, proc_uniqueid(current_proc()));
  if (!hookp) {
    return;
  }

  switch(hookp->state) {
    case hook_state_cast:
      process_hook_cast(hookp, intr_state);
      break;
    case hook_state_flying:
      process_hook_flying(hookp, intr_state);
      break;
    case hook_state_landed:
      process_hook_landed(hookp, intr_state);
      break;
    case hook_state_set:
      process_hook_set(hookp, intr_state);
      break;
    default:
      break;
  }
}

// A hook has called reset_hook() in the hook library.  We don't need to do
// anything if it's not a patch hook, or if its original method doesn't have a
// standard C/C++ prologue -- in either of those cases, the hook's state won't
// be hook_state_unset.  Note that we can't call IOMalloc() every time this
// method runs, directly or indirectly.  Calling IOMalloc() that often and
// that quickly triggers an Apple bug in the kernel's memory allocation code,
// which causes kernel panics with error messages like "Element
// 0xNNNNNNNNNNNNNNNN from zone kalloc.32 caught being freed to wrong zone
// kalloc.16".
void reset_hook(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }

  proc_t proc = current_proc();

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  user_addr_t hook_addr = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    hook_addr = intr_state->ss_64.rdi;
  } else { // flavor == x86_SAVED_STATE32
    uint32_t stack[3];
    bzero(stack, sizeof(stack));
    proc_copyin(proc_map, intr_state->ss_32.ebp, stack, sizeof(stack));
    hook_addr = stack[2];
  }
  if (!hook_addr) {
    vm_map_deallocate(proc_map);
    return;
  }

  hook_t *hookp =
    find_hook_by_thread_and_hook_addr(current_thread(), proc_uniqueid(proc),
                                      hook_addr);
  if (!hookp || (hookp->state != hook_state_unset)) {
    vm_map_deallocate(proc_map);
    return;
  }

  // As in process_hook_set() we need to take precautions against thread
  // contention -- even though they impose a high cost in CPU time.  See
  // process_hook_set() for more information.
  if (lock_hook(hookp->patch_hook_lock)) {
    task_t task = proc_task(proc);
    if (task) {
      task_reference(task);
      if (macOS_Sequoia() || macOS_Sonoma_4_or_greater()) {
        task_hold_and_wait(task);
      } else {
        task_hold(task);
        task_wait(task, false);
      }
    }
    uint16_t new_code = HC_INT1_OPCODE_SHORT;
    if (proc_copyout(proc_map, &new_code, hookp->orig_addr,
                     sizeof(new_code)))
    {
      hookp->state = hook_state_set;
    }
    if (task) {
      task_release(task);
      task_deallocate(task);
    }
    unlock_hook(hookp->patch_hook_lock);
  }

  vm_map_deallocate(proc_map);
}

// If appropriate, this is called every time a new module is added to the user
// process.  Check if any hooks need to be set in the new module.
void on_add_image(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }

  proc_t proc = current_proc();

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  hook_t *hookp = find_hook_with_add_image_func(proc_uniqueid(proc));
  if (!hookp || (hookp->state != hook_state_floating)) {
    vm_map_deallocate(proc_map);
    return;
  }

  user_addr_t mh = 0;
  uint64_t vmaddr_slide = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    mh = intr_state->ss_64.rdi;
    vmaddr_slide = intr_state->ss_64.rsi;
  } else { // flavor == x86_SAVED_STATE32
    uint32_t stack[4];
    bzero(stack, sizeof(stack));
    proc_copyin(proc_map, intr_state->ss_32.ebp, stack, sizeof(stack));
    mh = stack[2];
    vmaddr_slide = stack[3];
  }

  module_info_t module_info;
  if (!get_module_info(proc, NULL, mh, &module_info)) {
    vm_map_deallocate(proc_map);
    return;
  }

  wait_interrupt_t old_state = thread_interrupt_level(THREAD_UNINT);

  if (hookp->interpose_hooks) {
    set_interpose_hooks_for_module(proc, proc_map, &module_info,
                                   hookp->interpose_hooks,
                                   hookp->num_interpose_hooks);
  }

  thread_interrupt_level(old_state);

  // set_interpose_hooks_for_module() can take so long that our hook has been
  // deleted by the time it finishes, leading to kernel panics in the code
  // below.  Check for this here.
  hook_t *old_hookp = hookp;
  hookp = find_hook_with_add_image_func(proc_uniqueid(proc));
  if ((hookp != old_hookp) || (hookp->state != hook_state_floating)) {
    vm_map_deallocate(proc_map);
    return;
  }

  old_state = thread_interrupt_level(THREAD_UNINT);

  if (hookp->patch_hooks) {
    int i;
    for (i = 0; i < hookp->num_patch_hooks; ++i) {
      if (!hookp->patch_hooks[i].hook_function) {
        continue;
      }
      if (strncmp(module_info.path, hookp->patch_hooks[i].orig_module_name,
                  strlen(hookp->patch_hooks[i].orig_module_name) + 1))
      {
        continue;
      }
      set_patch_hooks(proc, proc_map, hookp,
                      &(hookp->patch_hooks[i]), 1);
    }
  }

  thread_interrupt_level(old_state);

  vm_map_deallocate(proc_map);
}

// A hook has called add_patch_hook() in the hook library.  We don't need to
// do anything if the exact same patch hook has already been created (one with
// the same orig_func_addr and hook_addr).  And if a patch hook for
// orig_func_addr already exists with a different hook function, we change its
// hook_addr to point to the new hook function.  Otherwise we dynamically add
// a new patch hook.  Note that we can't call IOMalloc() every time this
// method runs, directly or indirectly.  Calling IOMalloc() that often and
// that quickly triggers an Apple bug in the kernel's memory allocation code,
// which causes kernel panics with error messages like "Element
// 0xNNNNNNNNNNNNNNNN from zone kalloc.32 caught being freed to wrong zone
// kalloc.16".
void add_patch_hook(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }

  proc_t proc = current_proc();

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  hook_t *cast_hookp = find_cast_hook(proc_uniqueid(proc));
  if (!cast_hookp) {
    vm_map_deallocate(proc_map);
    return;
  }

  pid_t pid = proc_pid(proc);
  char procname[PATH_MAX];
  proc_name(pid, procname, sizeof(procname));

  user_addr_t orig_func_addr = 0;
  user_addr_t hook_addr = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    orig_func_addr = intr_state->ss_64.rdi;
    hook_addr = intr_state->ss_64.rsi;
  } else { // flavor == x86_SAVED_STATE32
    uint32_t stack[4];
    bzero(stack, sizeof(stack));
    proc_copyin(proc_map, intr_state->ss_32.ebp, stack, sizeof(stack));
    orig_func_addr = stack[2];
    hook_addr = stack[3];
  }
  if (!orig_func_addr || !hook_addr) {
    vm_map_deallocate(proc_map);
    return;
  }

  hook_t *orig_func_hook = find_hook(orig_func_addr, proc_uniqueid(proc));

  // Do nothing if the exact same patch hook has already been created.
  if (orig_func_hook && (orig_func_hook->hook_addr == hook_addr)) {
    vm_map_deallocate(proc_map);
    return;
  }

  // If a patch hook for orig_func_addr already exists with a different hook
  // function, change its hook_addr to point to the new hook function.  But
  // don't allow this for a non-dynamically created hook.  An original
  // function can't be assigned more than one hook.
  if (orig_func_hook) {
    if (orig_func_hook->is_dynamic_hook) {
      printf("HookCase(%s[%d]): add_patch_hook(): Changing dynamic patch hook's (orig_addr \'0x%llx\') hook from \'0x%llx\' to \'0x%llx\'!\n",
             procname, pid, orig_func_addr, orig_func_hook->hook_addr, hook_addr);
      if (check_init_locks()) {
        all_hooks_lock_write();
        orig_func_hook->hook_addr = hook_addr;
        all_hooks_unlock_write();
      }
    }
    vm_map_deallocate(proc_map);
    return;
  }

  // Otherwise create a new patch hook with the appropriate settings.
  uint32_t prologue = 0;
  if (!proc_copyin(proc_map, orig_func_addr, &prologue, sizeof(prologue))) {
    printf("HookCase(%s[%d]): add_patch_hook(): \'0x%llx\' is an invalid address and cannot be patched\n",
           procname, pid, orig_func_addr);
    vm_map_deallocate(proc_map);
    return;
  }

  wait_interrupt_t old_state = thread_interrupt_level(THREAD_UNINT);

  hook_t *new_hook =
    create_patch_hook(proc, proc_map, cast_hookp, orig_func_addr,
                      hook_addr, 0, prologue,
                      intr_state->flavor == x86_SAVED_STATE64);
  if (new_hook) {
    new_hook->is_dynamic_hook = true;
  }

  thread_interrupt_level(old_state);

  vm_map_deallocate(proc_map);
}

// A dynamically added patch hook has called get_dynamic_caller() in the hook
// library.  This is because a single hook function may end up hooking
// more than one dynamically patched original function.  So we can't use a
// global "caller" variable there.  Note that we can't call IOMalloc() every
// time this method runs, directly or indirectly.  Calling IOMalloc() that
// often and that quickly triggers an Apple bug in the kernel's memory
// allocation code, which causes kernel panics with error messages like
// "Element 0xNNNNNNNNNNNNNNNN from zone kalloc.32 caught being freed to wrong
// zone kalloc.16".
void get_dynamic_caller(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }

  // Initialize "return value" to NULL.
  if (intr_state->flavor == x86_SAVED_STATE64) {
    intr_state->ss_64.rax = 0;
  } else { // flavor == x86_SAVED_STATE32
    intr_state->ss_32.eax = 0;
  }

  proc_t proc = current_proc();

  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  user_addr_t hook_addr = 0;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    hook_addr = intr_state->ss_64.rdi;
  } else { // flavor == x86_SAVED_STATE32
    uint32_t stack[3];
    bzero(stack, sizeof(stack));
    proc_copyin(proc_map, intr_state->ss_32.ebp, stack, sizeof(stack));
    hook_addr = stack[2];
  }
  if (!hook_addr) {
    vm_map_deallocate(proc_map);
    return;
  }

  hook_t *hookp =
    find_hook_by_thread_and_hook_addr(current_thread(), proc_uniqueid(proc),
                                      hook_addr);
  if (!hookp || !hookp->is_dynamic_hook) {
    vm_map_deallocate(proc_map);
    return;
  }

  user_addr_t caller_addr = hookp->orig_addr;
  if (hookp->call_orig_func_addr) {
    caller_addr = hookp->call_orig_func_addr;
  }

  // Set "return value".
  if (intr_state->flavor == x86_SAVED_STATE64) {
    intr_state->ss_64.rax = caller_addr;
  } else { // flavor == x86_SAVED_STATE32
    intr_state->ss_32.eax = (uint32_t) caller_addr;
  }

  vm_map_deallocate(proc_map);
}

// A hook has called config_watcher() in a hook library. This method sets or
// unsets a watchpoint (actually a "watch range"). On re-setting or unsetting
// a watchpoint it also copies information back to 'info_addr' (in user-land)
// on whatever code may have hit the watchpoint. It creates or destroys
// "watcher" objects, which are used to keep track of various watchpoints and
// collect information on whatever code "hits" them.
void config_watcher(x86_saved_state_t *intr_state)
{
  if (!intr_state) {
    return;
  }

  // Initialize "return value" to 'false'.
  if (intr_state->flavor == x86_SAVED_STATE64) {
    intr_state->ss_64.rax = 0;
  } else { // flavor == x86_SAVED_STATE32
    intr_state->ss_32.eax = 0;
  }

  proc_t proc = current_proc();
  vm_map_t proc_map = task_map_for_proc(proc);
  if (!proc_map) {
    return;
  }

  wait_interrupt_t old_state = thread_interrupt_level(THREAD_UNINT);

  user_addr_t watchpoint = 0;
  user_addr_t watchpoint_length = 0;
  user_addr_t info_addr = 0;
  watcher_state status = watcher_state_unset;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    watchpoint = intr_state->ss_64.rdi;
    watchpoint_length = intr_state->ss_64.rsi;
    info_addr = intr_state->ss_64.rdx;
    status = (watcher_state) intr_state->ss_64.rcx;
  } else { // flavor == x86_SAVED_STATE32
    uint32_t stack[6];
    bzero(stack, sizeof(stack));
    proc_copyin(proc_map, intr_state->ss_32.ebp, stack, sizeof(stack));
    watchpoint = stack[2];
    watchpoint_length = stack[3];
    info_addr = stack[4];
    status = (watcher_state) stack[5];
  }

  uint64_t unique_pid = proc_uniqueid(proc);
  pid_t pid = proc_pid(proc);
  char procname[PATH_MAX];
  proc_name(pid, procname, sizeof(procname));

  bool bad_info_addr = true;
  watcher_info_t user_watcher_info;
  if (info_addr) {
    if (proc_copyin(proc_map, info_addr, &user_watcher_info,
                    sizeof(watcher_info_t)))
    {
      bad_info_addr = false;
    }
  }
  if (bad_info_addr && (info_addr != 0)) {
    printf("HookCase(%s[%d]): config_watcher(): \"info\" address \'0x%llx\' is invalid\n",
           procname, pid, info_addr);
    info_addr = 0;
  }

  if (status > watcher_state_set_max) {
    printf("HookCase(%s[%d]): config_watcher(): \"status\" \'0x%x\' is invalid\n",
           procname, pid, status);
    watchpoint = 0;
  }

  if (!watchpoint_length) {
    watchpoint_length = PAGE_SIZE;
  }

  bool retval = false;

  if (watchpoint) {
    watcher_t *watcherp = NULL;
    if (status) {
      retval = set_watcher(proc_map, watchpoint, watchpoint_length,
                           info_addr, status, &watcherp);
    } else {
      user_addr_t range_start =
        vm_map_trunc_page(watchpoint, vm_map_page_mask(proc_map));
      user_addr_t range_end =
        vm_map_round_page(watchpoint + watchpoint_length,
                          vm_map_page_mask(proc_map));
      watcherp =
        find_watcher_by_range(range_start, range_end,
                              NULL, unique_pid);
      if (watcherp) {
        retval = unset_watcher(proc_map, watcherp);
      }
    }

    if (retval && watcherp) {
      bool bad_watcherp_info_addr = true;
      if (watcherp->info_addr) {
        if (proc_copyin(proc_map, watcherp->info_addr, &user_watcher_info,
                        sizeof(watcher_info_t)))
        {
          bad_watcherp_info_addr = false;
        }
      }

      if ((info_addr != watcherp->info_addr) && !bad_info_addr) {
        OSCompareAndSwap64(watcherp->info_addr, info_addr,
                           &watcherp->info_addr);
        bad_watcherp_info_addr = false;
      }

      if (!bad_watcherp_info_addr) {
        if (watcherp->info.hit) {
          retval = proc_copyout(proc_map, &watcherp->info,
                                watcherp->info_addr, sizeof(watcher_info_t));
          if (retval) {
            all_watchers_lock_write();
            bzero(&watcherp->info, sizeof(watcher_info_t));
            all_watchers_unlock_write();
          }
        } else {
          retval = true;
        }
      } else {
        retval = false;
      }
    }
  }

  thread_interrupt_level(old_state);

  // Set "return value".
  if (intr_state->flavor == x86_SAVED_STATE64) {
    intr_state->ss_64.rax = retval;
  } else { // flavor == x86_SAVED_STATE32
    intr_state->ss_32.eax = retval;
  }

  vm_map_deallocate(proc_map);
}

typedef struct _posix_spawnattr *_posix_spawnattr_t;
typedef struct _posix_spawn_file_actions *_posix_spawn_file_actions_t;
typedef struct _posix_spawn_port_actions *_posix_spawn_port_actions_t;
typedef struct _posix_spawn_mac_policy_extensions *_posix_spawn_mac_policy_extensions_t;

typedef struct _posix_spawnattr_fake {
  short psa_flags;
} *_posix_spawnattr_fake_t;

// From the xnu kernel's bsd/sys/spawn_internal.h
struct _posix_spawn_args_desc {
  __darwin_size_t attr_size;
  _posix_spawnattr_t attrp;
  __darwin_size_t file_actions_size;
  _posix_spawn_file_actions_t file_actions;
  __darwin_size_t port_actions_size;
  _posix_spawn_port_actions_t port_actions;
  __darwin_size_t mac_extensions_size;
  _posix_spawn_mac_policy_extensions_t mac_extensions;
  __darwin_size_t coal_info_size;
  struct _posix_spawn_coalition_info *coal_info;
  __darwin_size_t persona_info_size;
  struct _posix_spawn_persona_info *persona_info;
};

// From the Mavericks xnu kernel's bsd/sys/spawn_internal.h
struct user32__posix_spawn_args_desc {
  uint32_t attr_size;
  uint32_t attrp;
  uint32_t file_actions_size;
  uint32_t file_actions;
  uint32_t port_actions_size;
  uint32_t port_actions;
  uint32_t mac_extensions_size;
  uint32_t mac_extensions;
};

// From the Mavericks xnu kernel's bsd/sys/spawn_internal.h
struct user__posix_spawn_args_desc {
  user_size_t attr_size;
  user_addr_t attrp;
  user_size_t file_actions_size;
  user_addr_t file_actions;
  user_size_t port_actions_size;
  user_addr_t port_actions;
  user_size_t mac_extensions_size;
  user_addr_t mac_extensions;
};

// Offsets in the sysent table
#define EXIT_SYSENT_OFFSET             1
#define FORK_SYSENT_OFFSET             2
#define EXECVE_SYSENT_OFFSET           59
#define POSIX_SPAWN_SYSENT_OFFSET      244
#define MAC_EXECVE_SYSENT_OFFSET       380

struct exit_args {
  int rval;
};

struct execve_args {
  char *fname;
  char **argp;
  char **envp;
};

struct posix_spawn_args {
  pid_t *pid;
  const char *path;
  const struct _posix_spawn_args_desc *adesc;
  char **argv;
  char **envp;
};

struct mac_execve_args {
  char *fname;
  char **argp;
  char **envp;
  struct mac *mac_p;
};

typedef int (*exit_t)(proc_t, struct exit_args *, int *);
typedef int (*fork_t)(proc_t, void *, int *);
typedef int (*execve_t)(proc_t, struct execve_args *, int *);
typedef int (*posix_spawn_t)(proc_t, struct posix_spawn_args *, int *);
typedef int (*mac_execve_t)(proc_t, struct mac_execve_args *, int *);

exit_t g_exit_orig = NULL;
fork_t g_fork_orig = NULL;
execve_t g_execve_orig = NULL;
posix_spawn_t g_posix_spawn_orig = NULL;
mac_execve_t g_mac_execve_orig = NULL;

int hook_exit(proc_t p, struct exit_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_exit_orig) {
    remove_process_hooks(proc_uniqueid(current_proc()));
    retval = g_exit_orig(p, uap, retv);
    /* NOTREACHED */
  }
  return retval;
}

// A forked process is an exact copy of its parent, including all its hooks
// and hooking infrastructure. They work in the child without needing any
// changes. But (unless we do something about it) the child and parent share
// the same entries in g_all_hooks. So when one of them exits first, and all
// its g_all_hooks entries get deallocated, the other may crash. We need to
// make copies of the parent's entries and assign them to the child.
int hook_fork(proc_t p, void *unused, int *retv)
{
  int retval = ENOENT;
  if (g_fork_orig) {
    retval = g_fork_orig(p, unused, retv);
    // p is the parent process. On success, retv[0] is the pid of the child
    // process. We don't know the child's p_uniqueid here, and can't find it
    // -- proc_find(retv[0]) hangs. We'll only know it later, in
    // thread_bootstrap_return_hook() below. So we copy the parent's hook
    // list entries to the child process in two stages --
    // copy_process_hooks() called here, and assign_copied_hooks() called in
    // thread_bootstrap_return_hook().
    if ((retval == 0) && retv && (retv[0] != 0)) {
      copy_process_hooks(p, retv[0]);
    }
  }
  return retval;
}

//#define DEBUG_PROCESS_START 1

int hook_execve(proc_t p, struct execve_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_execve_orig) {
    retval = g_execve_orig(p, uap, retv);
#ifdef DEBUG_PROCESS_START
    proc_t proc = current_proc();
    char procname[PATH_MAX];
    proc_name(proc_pid(proc), procname, sizeof(procname));
    printf("HookCase: hook_execve(%s[%d:%lld])\n",
           procname, proc_pid(proc), proc_uniqueid(proc));
    report_proc_thread_state("HookCase: hook_execve()", current_thread());
#endif
    // execve(), like posix_spawn(), can be called twice on the "same"
    // process -- in which case it loads the "second" process over the first
    // one. If this happens we need to remove any hooks we may have created
    // for the "first" process. There's no harm in calling
    // remove_process_hooks() when it's not needed. Be sure to use 'p' and
    // not 'proc' -- the current process may still be the kernel process.
    remove_process_hooks(proc_uniqueid(p));
    // On all versions of OS X before Sierra, at this point the current
    // process is the user process that has just been "exec"-ed and is about
    // to start for the first time.  So we should call maybe_cast_hook() now.
    // But on Sierra and above the current process is still the kernel
    // process, so we can't call maybe_cast_hook() here.  Fortunately we can
    // still call it from thread_bootstrap_return_hook() below on Sierra and
    // above, by which time the current process will be the current user
    // process.
    //
    // As of macOS Ventura (13), the current process is already the user
    // process here. But we can still wait for maybe_cast_hook() to be called
    // from thread_bootstrap_return_hook().
#ifndef DEBUG_PROCESS_START
    if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave() &&
        !macOS_Catalina() && !macOS_BigSur() && !macOS_Monterey() &&
        !macOS_Ventura() && !macOS_Sonoma() && !macOS_Sequoia())
    {
      maybe_cast_hook(current_proc());
    }
#endif
  }
  return retval;
}

// Darwin supports a POSIX_SPAWN_SETEXEC flag that (as Apple puts it) turns
// posix_spawn() into an "execve() with options", which (basically) loads
// another binary into the current process.  This is used by /usr/bin/arch
// and /usr/libexec/xpcproxy, for example.
int hook_posix_spawn(proc_t p, struct posix_spawn_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_posix_spawn_orig) {
    proc_t proc = current_proc();
    bool is_64bit = IS_64BIT_PROCESS(proc);
    short psa_flags = 0;
    struct user__posix_spawn_args_desc spawn_args;
    struct user32__posix_spawn_args_desc spawn_args_32bit;
    int rv = 0;
    if (is_64bit) {
      rv = copyin((user_addr_t) uap->adesc, &spawn_args, sizeof(spawn_args));
    } else {
      rv = copyin((user_addr_t) uap->adesc, &spawn_args_32bit,
                  sizeof(spawn_args_32bit));
    }
    if (!rv) {
      user_size_t attr_size;
      user_addr_t attrp;
      if (is_64bit) {
        attr_size = spawn_args.attr_size;
        attrp = spawn_args.attrp;
      } else {
        attr_size = spawn_args_32bit.attr_size;
        attrp = spawn_args_32bit.attrp;
      }
      if (attr_size && attrp) {
        _posix_spawnattr_fake_t attr_local =
          (_posix_spawnattr_fake_t) IOMalloc(attr_size);
        if (attr_local) {
          if (!copyin(attrp, attr_local, attr_size)) {
            psa_flags = attr_local->psa_flags;
          }
          IOFree(attr_local, attr_size);
        }
      }
    }

    retval = g_posix_spawn_orig(p, uap, retv);

    task_thread_info info;
    get_task_thread_info(current_task(), &info);
    if ((info.num_threads == 1) && info.main_thread &&
        (psa_flags & POSIX_SPAWN_SETEXEC))
    {
#ifdef DEBUG_PROCESS_START
      char procname[PATH_MAX];
      proc_name(proc_pid(proc), procname, sizeof(procname));
      printf("HookCase: hook_posix_spawn(%s[%d:%lld])\n",
             procname, proc_pid(proc), proc_uniqueid(proc));
      report_proc_thread_state("HookCase: hook_posix_spawn()", current_thread());
#endif
      remove_process_hooks(proc_uniqueid(proc));
      // On all versions of OS X, thread_bootstrap_return_hook() has already
      // been called as the first thread started of the original process.
      // We've called maybe_cast_hook() from it, and possibly set hooks in it
      // (which were just removed in the call to remove_process_hooks()).  On
      // Sierra and above, thread_bootstrap_return_hook() will be called again
      // as the main thread of the "new" process restarts.  But this doesn't
      // happen on ElCapitan and below (or maybe it happens too late).  So on
      // ElCapitan and below we should call maybe_cast_hook() here.  But on
      // Sierra and above we should wait to call it in
      // thread_bootstrap_return_hook().
#ifndef DEBUG_PROCESS_START
      if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave() &&
          !macOS_Catalina() && !macOS_BigSur() && !macOS_Monterey() &&
          !macOS_Ventura() && !macOS_Sonoma() && !macOS_Sequoia())
      {
        maybe_cast_hook(proc);
      }
#endif
    }
  }
  return retval;
}

// As of HighSierra, this method doesn't seem ever to be used.  So maybe we
// shouldn't use it ourselves.  But in the meantime we do use it, and assume
// that it works like execve() above.
int hook_mac_execve(proc_t p, struct mac_execve_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_mac_execve_orig) {
    retval = g_mac_execve_orig(p, uap, retv);
#ifdef DEBUG_PROCESS_START
    proc_t proc = current_proc();
    char procname[PATH_MAX];
    proc_name(proc_pid(proc), procname, sizeof(procname));
    printf("HookCase: hook_mac_execve(%s[%d:%lld])\n",
           procname, proc_pid(proc), proc_uniqueid(proc));
    report_proc_thread_state("HookCase: hook_mac_execve()", current_thread());
#endif
    remove_process_hooks(proc_uniqueid(p));
#ifndef DEBUG_PROCESS_START
    if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave() &&
        !macOS_Catalina() && !macOS_BigSur() && !macOS_Monterey() &&
        !macOS_Ventura() && !macOS_Sonoma() && !macOS_Sequoia())
    {
      maybe_cast_hook(current_proc());
    }
#endif
  }
  return retval;
}

bool install_sysent_hooks()
{
  if (!find_kernel_private_functions()) {
    return false;
  }
  if (!hook_sysent_call(EXIT_SYSENT_OFFSET, (sy_call_t *) hook_exit,
                        (sy_call_t **) &g_exit_orig))
  {
    return false;
  }
  if (!hook_sysent_call(FORK_SYSENT_OFFSET, (sy_call_t *) hook_fork,
                        (sy_call_t **) &g_fork_orig))
  {
    return false;
  }
  if (!hook_sysent_call(EXECVE_SYSENT_OFFSET, (sy_call_t *) hook_execve,
                        (sy_call_t **) &g_execve_orig))
  {
    return false;
  }
  if (!hook_sysent_call(POSIX_SPAWN_SYSENT_OFFSET, (sy_call_t *) hook_posix_spawn,
                        (sy_call_t **) &g_posix_spawn_orig))
  {
    return false;
  }
  if (!hook_sysent_call(MAC_EXECVE_SYSENT_OFFSET, (sy_call_t *) hook_mac_execve,
                        (sy_call_t **) &g_mac_execve_orig))
  {
    return false;
  }
  return true;
}

void remove_sysent_hooks()
{
  if (!find_kernel_private_functions()) {
    return;
  }
  if (g_exit_orig) {
    hook_sysent_call(EXIT_SYSENT_OFFSET,
                     (sy_call_t *) g_exit_orig, NULL);
  }
  if (g_fork_orig) {
    hook_sysent_call(FORK_SYSENT_OFFSET,
                     (sy_call_t *) g_fork_orig, NULL);
  }
  if (g_execve_orig) {
    hook_sysent_call(EXECVE_SYSENT_OFFSET,
                     (sy_call_t *) g_execve_orig, NULL);
  }
  if (g_posix_spawn_orig) {
    hook_sysent_call(POSIX_SPAWN_SYSENT_OFFSET,
                     (sy_call_t *) g_posix_spawn_orig, NULL);
  }
  if (g_mac_execve_orig) {
    hook_sysent_call(MAC_EXECVE_SYSENT_OFFSET,
                     (sy_call_t *) g_mac_execve_orig, NULL);
  }
}

typedef void (*thread_bootstrap_return_t)();
typedef void (*thread_exception_return_t)();
typedef void (*dtrace_thread_bootstrap_t)();

static thread_bootstrap_return_t thread_bootstrap_return = NULL;
static thread_exception_return_t thread_exception_return = NULL;
static dtrace_thread_bootstrap_t dtrace_thread_bootstrap = NULL;

extern "C" void __attribute__ ((noinline))
thread_exception_return_caller_dummy()
{
  printf("Not called!\n");
}

// thread_bootstrap_return() gets called whenever a thread is "continued" --
// when it starts for the first time or restarts after haven been awoken.
// That is, unless something else has replaced thread_bootstrap_return() as
// the default "continue" handler.  We're interested in catching every case of
// a new process's main thread starting up for the first time.  As best I can
// tell, we can count on thread_bootstrap_return() always still being the
// "continue" handler in this case, or to have been called from the actual
// continue handler (like proc_wait_to_return() on ElCapitan and below or
// task_wait_to_return() on Sierra and above).  But we do need to distinguish
// this case from all other cases of a thread being "continued".  We should
// also only call maybe_cast_hook() here if it hasn't also been (or won't also
// be) called from one of our other hooks (like hook_execve() and
// hook_posix_spawn() above).  But, thanks to our checks in maybe_cast_hook(),
// this isn't an absolute requirement.
void thread_bootstrap_return_hook(x86_saved_state_t *intr_state,
                                  kern_hook_t *kern_hookp)
{
  // The original thread_bootstrap_return() calls dtrace_thread_bootstrap()
  // and falls through to thread_exception_return().
  dtrace_thread_bootstrap();
  intr_state->ss_64.isf.rip = (uint64_t) thread_exception_return;

  proc_t proc = current_proc();
  bool forked_only = forked_but_not_execd(proc);
  bool start_funcs_registered = (get_lflag(proc) & P_LREGISTER);
  task_thread_info info;
  get_task_thread_info(current_task(), &info);
  // If the current process is a forked child and is just starting up, we
  // already made copies of its parent process's hook list entries above in
  // hook_fork(). Here we call assign_copied_hooks() to finish assigning
  // these entries to the child process. Here we can't reliably know anything
  // about the parent process -- it might already have died. So we can't
  // combine copy_process_hooks() and assign_copied_hooks() into a single
  // function, callable here.
  if (forked_only && (info.num_threads == 1) && info.main_thread) {
    assign_copied_hooks(proc);
  }
#ifdef DEBUG_PROCESS_START
  if ((info.num_threads == 1) && info.main_thread) {
    char procname[PATH_MAX];
    proc_name(proc_pid(proc), procname, sizeof(procname));
    printf("HookCase: thread_bootstrap_return(%s[%d:%lld]): forked_only %d, start_funcs_registered %d\n",
           procname, proc_pid(proc), proc_uniqueid(proc), forked_only, start_funcs_registered);
    report_proc_thread_state("HookCase: thread_bootstrap_return()", current_thread());
  }
#endif
#ifndef DEBUG_PROCESS_START
  if ((info.num_threads == 1) && info.main_thread &&
      !forked_only && !start_funcs_registered)
  {
    maybe_cast_hook(proc);
  }
#endif
}

// Set an "int 0x30" breakpoint at the beginning of thread_bootstrap_return(),
// which will trigger calls to thread_bootstrap_return_hook().  We don't need
// to call the original method from our hook.
bool hook_thread_bootstrap_return()
{
  if (!thread_bootstrap_return) {
    thread_bootstrap_return = (thread_bootstrap_return_t)
      kernel_dlsym("_thread_bootstrap_return");
    if (!thread_bootstrap_return) {
      return false;
    }
  }
  // In some debug kernels, thread_bootstrap_return() falls through to
  // thread_exception_return_internal(), and there's a separate (and
  // inappropriate) thread_exception_return() method.  So we look first
  // for a thread_exception_return_internal() method, and if we don't
  // find it fall back to looking for thread_exception_return().
  if (!thread_exception_return) {
    thread_exception_return = (thread_exception_return_t)
      kernel_dlsym("_thread_exception_return_internal");
    if (!thread_exception_return) {
      thread_exception_return = (thread_exception_return_t)
        kernel_dlsym("_thread_exception_return");
    }
    if (!thread_exception_return) {
      return false;
    }
  }
  if (!dtrace_thread_bootstrap) {
    dtrace_thread_bootstrap = (dtrace_thread_bootstrap_t)
      kernel_dlsym("_dtrace_thread_bootstrap");
    if (!dtrace_thread_bootstrap) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)thread_bootstrap_return,
                       (vm_offset_t)thread_bootstrap_return_hook,
                       (vm_offset_t)thread_exception_return_caller_dummy,
                       NULL);
}

typedef void (*vm_page_validate_cs_t)(vm_page_t page);
extern "C" vm_page_validate_cs_t vm_page_validate_cs = NULL;

// Under circumstance that I haven't been able to figure out, we sometimes get
// kernel panics in vm_page_validate_cs() with the message "page is slid", at
// least on ElCapitan.  Though these only happen when HookCase.kext is (or has
// been) loaded, I figure this has to be some kind of Apple bug.  To work
// around it we need to hook vm_page_validate_cs().  Since this method has a
// standard C/C++ prologue, we can use vm_page_validate_cs_caller() to call
// the original method from the hook (without having to unset the breakpoint
// temporarily).  Page and object exist, and object is already locked ... but
// it's probably wise not to assume this.
//
// This bug appears to have been fixed in macOS 10.14 (Mojave).  So as of
// Mojave we no longer need to use this hook.
void vm_page_validate_cs_hook(x86_saved_state_t *intr_state,
                              kern_hook_t *kern_hookp)
{
  vm_page_t page = (vm_page_t) intr_state->ss_64.rdi;

  bool page_slid = false;
  bool object_code_signed = false;
  bool object_slid = false;

  if (page) {
    page_slid = page_is_slid(page);
    vm_object_t object = page_object(page);
    if (object) {
      object_code_signed = object_is_code_signed(object);
      object_slid = object_is_slid(object);
    }
  }

  if (page_slid && !object_slid) {
    page_set_slid(page, false);
    page_slid = false;
  }

  if (object_code_signed && !page_slid) {
    vm_page_validate_cs_t caller = (vm_page_validate_cs_t)
      kern_hookp->caller_addr;
    caller(page);
  } else {
    // The following line fixes a bug that can be reproduced as follows:
    // 1) Load HookCase.kext into the kernel.
    // 2) Run Safari or Chrome with HC_INSERT_LIBRARY set, for example from
    //    Terminal, to make the app load a hook library.
    // 3) Quit the app.
    // 4) Unload HookCase.kext from the kernel.
    // 5) Run the app from step 2 again in exactly the same way.  Without the
    //    following line, this will result in a "page is slid" kernel panic.
    page_set_cs_validated(page, 1);
  }

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

// Set an "int 0x30" breakpoint at the beginning of vm_page_validate_cs(),
// which will trigger calls to vm_page_validate_cs_hook().  Because this
// method has a standard C/C++ prologue, we can use a CALLER to call the
// original method from the hook.  See CALLER in HookCase.s.
bool hook_vm_page_validate_cs()
{
  if (!vm_page_validate_cs) {
    vm_page_validate_cs = (vm_page_validate_cs_t)
      kernel_dlsym("_vm_page_validate_cs");
    if (!vm_page_validate_cs) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)vm_page_validate_cs,
                       (vm_offset_t)vm_page_validate_cs_hook,
                       (vm_offset_t)vm_page_validate_cs_caller,
                       NULL);
}

typedef int (*mac_file_check_library_validation_t)(proc_t proc,
                                                   struct fileglob *fg,
                                                   off_t slice_offset,
                                                   user_long_t error_message,
                                                   size_t error_message_size);
extern "C" mac_file_check_library_validation_t
  mac_file_check_library_validation = NULL;

// On macOS Sierra (as of macOS 10.12.4?) Apple started preventing unsigned
// hook libraries (or those with non-Apple signatures) from being loaded into
// certain applications (like Safari) that are signed by Apple.  This happens
// even with rootless mode off (which is required for HookCase.kext to load),
// and is definitely excessive.  It continues in HighSierra, and has now (as
// of Apple's implementation of KPTI in ElCapitan and above) been backported
// to ElCapitan.  We need to work around it for our own hook libraries.
//
// This behavior is implemented in the AppleMobileFileIntegrity kernel
// extension, which (like the Sandbox kernel extension) is a MAC Framework --
// specifically in methods that check for "file_check_library_validation" (on
// Sierra and above) and "file_check_mmap" (on ElCapitan and above).  We can
// prevent these checks from running on our hook libraries by hooking
// mac_file_check_library_validation() and/or mac_file_check_mmap() in the
// kernel.
void mac_file_check_library_validation_hook(x86_saved_state_t *intr_state,
                                            kern_hook_t *kern_hookp)
{
  proc_t proc = (proc_t) intr_state->ss_64.rdi;
  struct fileglob *fg = (struct fileglob *) intr_state->ss_64.rsi;
  off_t slice_offset = (off_t) intr_state->ss_64.rdx;
  user_long_t error_message = (user_long_t) intr_state->ss_64.rcx;
  size_t error_message_size = (size_t) intr_state->ss_64.r8;

  int retval = 0;
  if (!process_has_hooks(proc_uniqueid(current_proc()))) {
    mac_file_check_library_validation_t caller =
      (mac_file_check_library_validation_t) kern_hookp->caller_addr;
    retval = caller(proc, fg, slice_offset, error_message, error_message_size);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_file_check_library_validation()
{
  if (!mac_file_check_library_validation) {
    mac_file_check_library_validation = (mac_file_check_library_validation_t)
      kernel_dlsym("_mac_file_check_library_validation");
    if (!mac_file_check_library_validation) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)mac_file_check_library_validation,
                       (vm_offset_t)mac_file_check_library_validation_hook,
                       (vm_offset_t)mac_file_check_library_validation_caller,
                       NULL);
}

typedef int (*mac_file_check_mmap_t)(struct ucred *cred, struct fileglob *fg,
                                     int prot, int flags, uint64_t offset,
                                     int *maxprot);
extern "C" mac_file_check_mmap_t mac_file_check_mmap = NULL;

void mac_file_check_mmap_hook(x86_saved_state_t *intr_state,
                              kern_hook_t *kern_hookp)
{
  struct ucred *cred = (struct ucred *) intr_state->ss_64.rdi;
  struct fileglob *fg = (struct fileglob *) intr_state->ss_64.rsi;
  int prot = (int) intr_state->ss_64.rdx;
  int flags = (int) intr_state->ss_64.rcx;
  uint64_t offset = (uint64_t) intr_state->ss_64.r8;
  int *maxprot = (int *) intr_state->ss_64.r9;

  int retval = 0;
  if (!process_has_hooks(proc_uniqueid(current_proc()))) {
    mac_file_check_mmap_t caller =
      (mac_file_check_mmap_t) kern_hookp->caller_addr;
    retval = caller(cred, fg, prot, flags, offset, maxprot);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_file_check_mmap()
{
  if (!mac_file_check_mmap) {
    mac_file_check_mmap = (mac_file_check_mmap_t)
      kernel_dlsym("_mac_file_check_mmap");
    if (!mac_file_check_mmap) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)mac_file_check_mmap,
                       (vm_offset_t)mac_file_check_mmap_hook,
                       (vm_offset_t)mac_file_check_mmap_caller,
                       NULL);
}

// As of macOS Catalina (10.15), when filesystem protections are enabled (via
// csrutil), calling dlopen() from a sandboxed process (like xpcproxy) will
// result in the Sandbox kernel extension checking "vnode open" permissions on
// the module to be dlopened. In process_hook_cast() above, we set up a call
// to dlopen() on our hook library (if HC_INSERT_LIBRARY has been set in the
// process).  Without our intervention here, the kernel will always deny
// "vnode open" permission on our hook library unless that permission has been
// given in the process's sandbox rules (which it generally won't have been),
// and the call to dlopen() will fail (with a Sandbox error message about
// denying "file-read-data").  To get around this we hook
// mac_vnode_check_open() in the kernel and grant "vnode open" permission on
// our hook library every time the Sandbox kernel extension asks for it (if
// we're trying to load a hook library in the process).
//
// For compatibility with PySerialPortLogger, we also need to prevent access
// failures to TTY devices (like /dev/ttys003) from hook libraries.

extern "C" const char *vnode_getname(vnode_t vp);
extern "C" void vnode_putname(const char *name);

// Don't use IOMalloc() here.  Apple's documentation says it "may block and
// so should not be called from interrupt level."  This may be behind the
// trouble with IOMalloc() in reset_hook(), add_patch_hook() and
// get_dynamic_caller() above.
bool get_vnode_path(struct vnode *vp, char *path, vm_size_t path_size)
{
  if (!path || !path_size) {
    return false;
  }
  path[0] = 0;

  char vnode_path[MAXPATHLEN];
  vnode_path[0] = 0;
  if (vp) {
    int length = MAXPATHLEN;
    if (vn_getpath(vp, vnode_path, &length) != 0) {
      vnode_path[0] = 0;
    }
  }
  if (vnode_path[0] == 0) {
    return false;
  }

  strncpy(path, vnode_path, path_size);
  return true;
}

typedef int (*mac_vnode_check_open_t)(vfs_context_t ctx, struct vnode *vp, int acc_mode);

// Build 19H2026 of macOS 10.15.7 suddenly (and possibly mistakenly) includes
// mac_vnode_check_open() in its list of supported kernel calls (in
// /System/Library/Extensions/System.kext/PlugIns/MACFramework.kext). This
// means that, unless the following pointer has its name changed from
// 'mac_vnode_check_open', HookCase.kext will refuse to load, complaining
// about the 'mac_vnode_check_open' symbol having more than one definition.
// This is issue #36.
extern "C" mac_vnode_check_open_t mac_vnode_check_open_ptr = NULL;

void mac_vnode_check_open_hook(x86_saved_state_t *intr_state,
                               kern_hook_t *kern_hookp)
{
  vfs_context_t ctx = (vfs_context_t) intr_state->ss_64.rdi;
  struct vnode *vp = (struct vnode *) intr_state->ss_64.rsi;
  int acc_mode = (int) intr_state->ss_64.rdx;

  bool skip_vnode_check = false;
  bool is_tty = vnode_istty(vp);
  hook_t *cast_hookp = NULL;
  if (!(acc_mode & FWRITE) || is_tty) {
    cast_hookp = find_cast_hook(proc_uniqueid(current_proc()));
  }
  if (cast_hookp) {
    if (is_tty) {
      skip_vnode_check = true;
    } else {
      char vnode_path[MAXPATHLEN];
      if (get_vnode_path(vp, vnode_path, sizeof(vnode_path))) {
        skip_vnode_check =
          !strncmp(vnode_path, cast_hookp->inserted_dylib_path,
                   strlen(cast_hookp->inserted_dylib_path) + 1);
      }
    }
  }

  int retval = 0;
  if (!skip_vnode_check) {
    mac_vnode_check_open_t caller =
      (mac_vnode_check_open_t) kern_hookp->caller_addr;
    retval = caller(ctx, vp, acc_mode);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_vnode_check_open()
{
  if (!mac_vnode_check_open_ptr) {
    mac_vnode_check_open_ptr = (mac_vnode_check_open_t)
      kernel_dlsym("_mac_vnode_check_open");
    if (!mac_vnode_check_open_ptr) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)mac_vnode_check_open_ptr,
                       (vm_offset_t)mac_vnode_check_open_hook,
                       (vm_offset_t)mac_vnode_check_open_ptr_caller,
                       NULL);
}

// Sandboxing can interfere with ioctl() calls, and thereby with TTY
// operations. Now that we use PySerialPortLogger, this can mess up
// logging from a HookCase hook library. So we need to let all
// mac_vnode_check_ioctl() checks pass when the current process has hooks
// and the call is in regard to a TTY.

typedef int (*mac_vnode_check_ioctl_t)(vfs_context_t ctx, struct vnode *vp, u_long cmd);

extern "C" mac_vnode_check_ioctl_t mac_vnode_check_ioctl_ptr = NULL;

void mac_vnode_check_ioctl_hook(x86_saved_state_t *intr_state,
                                kern_hook_t *kern_hookp)
{
  vfs_context_t ctx = (vfs_context_t) intr_state->ss_64.rdi;
  struct vnode *vp = (struct vnode *) intr_state->ss_64.rsi;
  u_long cmd = (u_long) intr_state->ss_64.rdx;

  bool skip_vnode_check = false;
  bool is_tty = vnode_istty(vp);
  hook_t *cast_hookp = NULL;
  if (is_tty) {
    cast_hookp = find_cast_hook(proc_uniqueid(current_proc()));
  }
  if (cast_hookp) {
    skip_vnode_check = true;
  }

  int retval = 0;
  if (!skip_vnode_check) {
    mac_vnode_check_ioctl_t caller =
      (mac_vnode_check_ioctl_t) kern_hookp->caller_addr;
    retval = caller(ctx, vp, cmd);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_vnode_check_ioctl()
{
  if (!mac_vnode_check_ioctl_ptr) {
    mac_vnode_check_ioctl_ptr = (mac_vnode_check_ioctl_t)
      kernel_dlsym("_mac_vnode_check_ioctl");
    if (!mac_vnode_check_ioctl_ptr) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)mac_vnode_check_ioctl_ptr,
                       (vm_offset_t)mac_vnode_check_ioctl_hook,
                       (vm_offset_t)mac_vnode_check_ioctl_ptr_caller,
                       NULL);
}

// As of macOS 12 (Monterey) Apple supports two new kinds of sandboxing --
// system call filtering and message filtering. These can be applied to Unix
// and Mach system calls (which are allowed or denied by call number), to
// IOConnectCallMethod() (allowing or denying certain kinds of IOUserClient
// interaction with the kernel), and to XPC and Mach RPC (allowing or
// denying certain kinds of MIG messages). As best I can tell this isn't
// (yet) documented. But the *.sb file syntax can be seen at
// https://opensource.apple.com/source/WebKit2/WebKit2-7611.3.10.1.3/WebProcess/com.apple.WebProcess.sb.in.auto.html.
// Search on "syscall-unix", "syscall-mach" and "apply-message-filter".
//
// Sandbox filtering can interfere with aspects of hook library logging --
// particularly with use of the CoreSymbolication framework. So we need to
// allow all filtering checks to pass when the current process has hooks.

typedef int (*mac_proc_check_syscall_unix_t)(proc_t curp, int scnum);

extern "C" mac_proc_check_syscall_unix_t mac_proc_check_syscall_unix_ptr = NULL;

void mac_proc_check_syscall_unix_hook(x86_saved_state_t *intr_state,
                                      kern_hook_t *kern_hookp)
{
  proc_t proc = (proc_t) intr_state->ss_64.rdi;
  int scnum = (int) intr_state->ss_64.rsi;

  bool skip_check_syscall = false;
  hook_t *cast_hookp = find_cast_hook(proc_uniqueid(proc));
  if (cast_hookp) {
    skip_check_syscall = true;
  }

  int retval = 0;
  if (!skip_check_syscall) {
    syscall_filter_cbfunc_t caller =
      (syscall_filter_cbfunc_t) kern_hookp->caller_addr;
    retval = caller(proc, scnum);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

extern "C" syscall_filter_cbfunc_t *proc_check_syscall_mach_ptrptr = NULL;
extern "C" kobject_filter_cbfunc_t *proc_check_migroutine_invoke_ptrptr = NULL;

extern "C" syscall_filter_cbfunc_t proc_check_syscall_mach_ptr = NULL;
extern "C" kobject_filter_cbfunc_t proc_check_migroutine_invoke_ptr = NULL;

extern "C" struct io_filter_callbacks **gIOUCFilterCallbacks_ptr = NULL;
extern "C" io_filter_applier_t io_filter_applier_ptr = NULL;

void proc_check_syscall_mach_hook(x86_saved_state_t *intr_state,
                                  kern_hook_t *kern_hookp)
{
  proc_t proc = (proc_t) intr_state->ss_64.rdi;
  int num = (int) intr_state->ss_64.rsi;

  bool skip_check_syscall = false;
  hook_t *cast_hookp = find_cast_hook(proc_uniqueid(proc));
  if (cast_hookp) {
    skip_check_syscall = true;
  }

  int retval = 0;
  if (!skip_check_syscall) {
    syscall_filter_cbfunc_t caller =
      (syscall_filter_cbfunc_t) kern_hookp->caller_addr;
    retval = caller(proc, num);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

void proc_check_migroutine_invoke_hook(x86_saved_state_t *intr_state,
                                       kern_hook_t *kern_hookp)
{
  proc_t proc = (proc_t) intr_state->ss_64.rdi;
  int msgid = (int) intr_state->ss_64.rsi;
  int idx = (int) intr_state->ss_64.rdx;

  bool skip_check_migroutine = false;
  hook_t *cast_hookp = find_cast_hook(proc_uniqueid(proc));
  if (cast_hookp) {
    skip_check_migroutine = true;
  }

  int retval = 0;
  if (!skip_check_migroutine) {
    kobject_filter_cbfunc_t caller =
      (kobject_filter_cbfunc_t) kern_hookp->caller_addr;
    retval = caller(proc, msgid, idx);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

void io_filter_applier_hook(x86_saved_state_t *intr_state,
                            kern_hook_t *kern_hookp)
{
  void *client = (void *) intr_state->ss_64.rdi;
  io_filter_policy_t filter = (io_filter_policy_t) intr_state->ss_64.rsi;
  io_filter_type_t type = (io_filter_type_t) intr_state->ss_64.rdx;
  uint32_t selector = (uint32_t) intr_state->ss_64.rcx;

  bool skip_apply_filter = false;
  hook_t *cast_hookp = find_cast_hook(proc_uniqueid(current_proc()));
  if (cast_hookp) {
    skip_apply_filter = true;
  }

  int retval = 0;
  if (!skip_apply_filter) {
    io_filter_applier_t caller =
      (io_filter_applier_t) kern_hookp->caller_addr;
    retval = caller(client, filter, type, selector);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_sandbox_filters()
{
  if (!mac_proc_check_syscall_unix_ptr) {
    mac_proc_check_syscall_unix_ptr = (mac_proc_check_syscall_unix_t)
      kernel_dlsym("_mac_proc_check_syscall_unix");
    if (!mac_proc_check_syscall_unix_ptr) {
      return false;
    }
  }
  if (!proc_check_syscall_mach_ptrptr) {
    proc_check_syscall_mach_ptrptr = (syscall_filter_cbfunc_t *)
      kernel_dlsym("_mac_task_mach_trap_evaluate");
    if (!proc_check_syscall_mach_ptrptr) {
      return false;
    }
  }
  if (!proc_check_migroutine_invoke_ptrptr) {
    proc_check_migroutine_invoke_ptrptr = (kobject_filter_cbfunc_t *)
      kernel_dlsym("_mac_task_kobj_msg_evaluate");
    if (!proc_check_migroutine_invoke_ptrptr) {
      return false;
    }
  }
  if (!gIOUCFilterCallbacks_ptr) {
    gIOUCFilterCallbacks_ptr = (struct io_filter_callbacks **)
      kernel_dlsym("_gIOUCFilterCallbacks");
    if (!gIOUCFilterCallbacks_ptr) {
      return false;
    }
  }

  proc_check_syscall_mach_ptr = *proc_check_syscall_mach_ptrptr;
  proc_check_migroutine_invoke_ptr = *proc_check_migroutine_invoke_ptrptr;
  io_filter_applier_ptr = (*gIOUCFilterCallbacks_ptr)->io_filter_applier;

  kern_hook_t *kern_hookp1 = NULL;
  kern_hook_t *kern_hookp2 = NULL;
  kern_hook_t *kern_hookp3 = NULL;
  if (!set_kern_hook((vm_offset_t)mac_proc_check_syscall_unix_ptr,
                     (vm_offset_t)mac_proc_check_syscall_unix_hook,
                     (vm_offset_t)mac_proc_check_syscall_unix_ptr_caller,
                     &kern_hookp1))
  {
    return false;
  }
  if (proc_check_syscall_mach_ptr) {
    if (!set_kern_hook((vm_offset_t)proc_check_syscall_mach_ptr,
                       (vm_offset_t)proc_check_syscall_mach_hook,
                       (vm_offset_t)proc_check_syscall_mach_ptr_caller,
                       &kern_hookp2))
    {
      if (kern_hookp1) {
        unset_kern_hook(kern_hookp1);
      }
      return false;
    }
  }
  if (proc_check_migroutine_invoke_ptr) {
    if (!set_kern_hook((vm_offset_t)proc_check_migroutine_invoke_ptr,
                       (vm_offset_t)proc_check_migroutine_invoke_hook,
                       (vm_offset_t)proc_check_migroutine_invoke_ptr_caller,
                       &kern_hookp3))
    {
      if (kern_hookp1) {
        unset_kern_hook(kern_hookp1);
      }
      if (kern_hookp2) {
        unset_kern_hook(kern_hookp2);
      }
      return false;
    }
  }
  if (io_filter_applier_ptr) {
    if (!set_kern_hook((vm_offset_t)io_filter_applier_ptr,
                       (vm_offset_t)io_filter_applier_hook,
                       (vm_offset_t)io_filter_applier_ptr_caller,
                       NULL))
    {
      if (kern_hookp1) {
        unset_kern_hook(kern_hookp1);
      }
      if (kern_hookp2) {
        unset_kern_hook(kern_hookp2);
      }
      if (kern_hookp3) {
        unset_kern_hook(kern_hookp3);
      }
      return false;
    }
  }

  return true;
}

#define pal_sti() __asm__ volatile ("sti")
#define pal_cli() __asm__ volatile ("cli")

typedef void (*user_trap_t)(x86_saved_state_t *state);

user_trap_t user_trap = NULL;

void user_trap_hook(x86_saved_state_t *intr_state, kern_hook_t *hookp)
{
  x86_saved_state_t *state = (x86_saved_state_t *) intr_state->ss_64.rdi;

  int type = 0;
  int code = 0;
  user_addr_t cr2 = 0;
  if (state->flavor == x86_SAVED_STATE64) {
    type = state->ss_64.isf.trapno;
    code = (int) (state->ss_64.isf.err & 0xffff);
    cr2 = state->ss_64.cr2;
  } else { // flavor == x86_SAVED_STATE32
    type = state->ss_32.trapno;
    code = (state->ss_32.err & 0xffff);
    cr2 = (user_addr_t) state->ss_32.cr2;
  }

  // Make sure interrupts are enabled for the code we run here to
  // support watchpoints. Otherwise we can get into trouble -- see
  // https://github.com/steven-michaud/HookCase/issues/26.
  pal_sti();

  // Check to see if our fault was triggered by hitting a watchpoint. If so,
  // unset the watchpoint and store information on the code that hit it.
  if (type == T_PAGE_FAULT) {
    proc_t proc = current_proc();
    uint64_t unique_pid = 0;
    if (proc) {
      unique_pid = proc_uniqueid(proc);
    }

    watcher_t *watcherp = find_watcher_by_addr(cr2, unique_pid);
    if (watcherp) {
      mach_port_name_t mach_thread = 0;
      thread_t thread = current_thread();
      task_t task = current_task();
      if (thread && task) {
        // Maybe we should use retrieve_thread_self_fast() here.
        // convert_port_to_thread() consumes a reference.
        thread_reference(thread);
        ipc_port_t port = convert_thread_to_port(thread);
        ipc_space_t space = get_task_ipcspace(task);
        if (port && space) {
          mach_thread = ipc_port_copyout_send(port, space);
        }
      }
      watcherp->info.mach_thread = mach_thread;
      watcherp->info.hit = cr2;
      watcherp->info.page_fault_code = code;

      vm_map_t proc_map = current_map();
      if (proc_map) {
        get_callstack(proc_map, state, watcherp->info.callstack);
        unset_watcher(proc_map, watcherp);
      }
    }
  }

  // The original user_trap() method expects interrupts to be disabled on
  // entry.
  pal_cli();

  user_trap_t caller = (user_trap_t) hookp->caller_addr;
  caller(state); // Might not return

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_user_trap()
{
  if (!user_trap) {
    user_trap = (user_trap_t) kernel_dlsym("_user_trap");
    if (!user_trap) {
      return false;
    }
  }

  return set_kern_hook((vm_offset_t)user_trap,
                       (vm_offset_t)user_trap_hook,
                       (vm_offset_t)user_trap_caller,
                       NULL);
}

boolean_t *g_no_shared_cr3_ptr = (boolean_t *) -1;
boolean_t *g_pmap_smap_enabled_ptr = (boolean_t *) -1;

boolean_t g_kpti_enabled = (boolean_t) -1;

boolean_t g_use_invpcid = (boolean_t) -1;

uint64_t g_cpu_active_thread_offset = (uint64_t) -1;
uint64_t g_cpu_number_offset = (uint64_t) -1;
uint64_t g_cpu_kernel_stack_offset = (uint64_t) -1;
uint64_t g_cpu_invpcid_target_offset = (uint64_t) -1;
uint64_t g_cpu_task_map_offset = (uint64_t) -1;
uint64_t g_cpu_task_cr3_offset = (uint64_t) -1;
uint64_t g_cpu_shadowtask_cr3_offset = (uint64_t) -1;
uint64_t g_cpu_kernel_cr3_offset = (uint64_t) -1;
uint64_t g_cpu_user_cr3_offset = (uint64_t) -1;
uint64_t g_cpu_uber_isf_offset = (uint64_t) -1;
uint64_t g_cpu_uber_tmp_offset = (uint64_t) -1;
uint64_t g_cpu_excstack_offset = (uint64_t) -1;

typedef struct __attribute__((packed)) {
  uint16_t size;
  void *ptr;
} idt_info;

static inline void sidt(idt_info *info)
{
  __asm__ volatile("sidt %0" : "=m" (*((uintptr_t *)info)));
}

typedef struct {
  uint32_t offset_low16:16,  /* offset 0..15 */
           selector16:16,    /* for segment */
           IST:3,            /* interrupt stack? */
           zeroes5:5,
           access8:8,        /* bit 0:     accessed */
                             /* bits 1..4: access type */
                             /* bits 5..6: access rights (kernel only or also user) */
                             /* bit 7:     segment present */
           offset_high16:16, /* offset 16..31 */
           offset_top32:32,  /* offset 32..63 */
           reserved32:32;    /* reserved/zero */
} idt64_entry;

idt64_entry old_hc_int1_idt_entry;
char old_hc_int1_stub[16];

idt64_entry old_hc_int2_idt_entry;
char old_hc_int2_stub[16];

idt64_entry old_hc_int3_idt_entry;
char old_hc_int3_stub[16];

idt64_entry old_hc_int4_idt_entry;
char old_hc_int4_stub[16];

idt64_entry old_hc_int5_idt_entry;
char old_hc_int5_stub[16];

idt64_entry old_hc_int6_idt_entry;
char old_hc_int6_stub[16];

bool s_installed_hc_int1_handler = false;
bool s_installed_hc_int2_handler = false;
bool s_installed_hc_int3_handler = false;
bool s_installed_hc_int4_handler = false;
bool s_installed_hc_int5_handler = false;
bool s_installed_hc_int6_handler = false;

// In the macOS 10.13.2 release Apple implemented KPTI (kernel page-table
// isolation) as a workaround for Intel's Meltdown bug
// (https://meltdownattack.com/).  They've now also backported it to Sierra
// and ElCapitan.  With KPTI, the user-mode page table (stored in the CR3
// register) no longer includes any memory in the kernel's standard range.
// Instead, Apple has mapped part of the kernel (the HIB segment) twice --
// once at an address in the standard kernel range, and a second time at a
// lower address that isn't part of user space, but is included in the
// user-mode page table.  The HIB segment is where the IDT lives.  This means
// that IDT entries can no longer point to handlers in kernel code (or in any
// kernel extension).  Instead each entry now points to a "stub" in the HIB
// segment, which in turn jumps to other code (still in the HIB segment) that
// plays the tricks needed (for example changing the CR3 register) to jump to
// code in the kernel proper.  We need a workaround to continue hooking
// software interrupts.
//
// The one I've adopted is to put handler code into empty space in the HIB
// segment (at the end of the idt64_hndl_table0 array), and to rewrite the
// appropriate "stubs" to jump to that code (instead of to Apple code).  My
// code is closely modeled on Apple's, and uses the same tricks to get to
// kernel code (or more correctly kernel extension code) and back from it.

bool is_kpti_enabled(idt64_entry **idt_base)
{
  idt_info info;
  if ((g_kpti_enabled == (boolean_t) -1) || idt_base) {
    sidt(&info);
  }
  if (idt_base) {
    *idt_base = (idt64_entry *) info.ptr;
  }

  if (g_kpti_enabled != (boolean_t) -1) {
    return g_kpti_enabled;
  }

  vm_map_offset_t idt_addr_fixed =
    vm_map_trunc_page((vm_map_offset_t) info.ptr, PAGE_MASK);

  // The HIB kernel's non-kernel (second) address range is included in
  // kernel_pmap but not in kernel_map.  So we can detect KPTI by
  // checking whether the IDT is in kernel_map or not.
  vm_map_entry_t first_entry;
  g_kpti_enabled =
    !vm_map_lookup_entry(kernel_map, idt_addr_fixed, &first_entry);
  return g_kpti_enabled;
}

void initialize_use_invpcid()
{
  if (!find_kernel_private_functions()) {
    return;
  }

  if (macOS_Mojave_less_than_5() ||
      (!macOS_Mojave() && !macOS_Catalina() && !macOS_BigSur() &&
       !macOS_Monterey() && !macOS_Ventura() && !macOS_Sonoma() &&
       !macOS_Sequoia()))
  {
    g_use_invpcid = false;
  } else {
    if ((cpuid_leaf7_features_ptr() & CPUID_LEAF7_FEATURE_INVPCID)) {
      g_use_invpcid = true;
    } else {
      g_use_invpcid = false;
    }
  }
}

bool initialize_cpu_data_offsets()
{
  if (!find_kernel_private_functions()) {
    return false;
  }

  if (!is_kpti_enabled(NULL)) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_t, cpu_kernel_stack);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_task_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_kernel_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_t, cpu_uber_tmp);
    return true;
  }

  if (OSX_ElCapitan() || macOS_Sierra()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_kernel_stack);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_task_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_kpti_elcapitan_sierra_t, cpu_excstack);
    return true;
  }

  if (macOS_HighSierra_less_than_4()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_kernel_stack);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_task_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_kpti_highsierra_t, cpu_excstack);
    return true;
  }

  if (macOS_HighSierra() || macOS_Mojave_less_than_5()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_kernel_stack);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_task_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_highsierra_mojave_t, cpu_excstack);
    return true;
  }

  if (macOS_Mojave() || macOS_Catalina_less_than_5()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_kernel_stack);
    g_cpu_invpcid_target_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_invpcid_target);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_shadowtask_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_mojave_catalina_t, cpu_excstack);
    return true;
  }

  if (macOS_Catalina_5_or_greater()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_kernel_stack);
    g_cpu_invpcid_target_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_invpcid_target);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_shadowtask_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_catalina_t, cpu_excstack);
    return true;
  }

  if (macOS_BigSur() || macOS_Monterey()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_kernel_stack);
    g_cpu_invpcid_target_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_invpcid_target);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_shadowtask_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_bigsur_t, cpu_excstack);
    return true;
  }

  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura()) {
    g_cpu_active_thread_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_active_thread);
    g_cpu_number_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_number);
    g_cpu_kernel_stack_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_kernel_stack);
    g_cpu_invpcid_target_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_invpcid_target);
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_task_map);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_task_cr3);
    g_cpu_shadowtask_cr3_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_shadowtask_cr3);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_kernel_cr3);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_user_cr3);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_uber_isf);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_uber_tmp);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_ventura_t, cpu_excstack);
    return true;
  }

  return false;
}

#define RETURN_FROM_KEXT_PAGE_OFFSET 0xFA8
#define DISPATCH_TO_KEXT_PAGE_OFFSET 0xFC0
#define STUB_HANDLER_ADDR_PAGE_OFFSET 0xFF0

int64_t g_doublemap_distance = 0;

// Addresses in the copy of the HIB segment mapped outside the kernel.
vm_offset_t g_idt64_hndl_table0_addr = 0;
vm_offset_t g_return_from_kext_addr = 0;
vm_offset_t g_dispatch_to_kext_addr = 0;

// Addresses in the copy of the HIB segment mapped inside the kernel.
vm_offset_t g_kernel_idt64_hndl_table0_addr = -1;
vm_offset_t g_kernel_return_from_kext_addr = 0;
vm_offset_t g_kernel_dispatch_to_kext_addr = 0;

vm_offset_t get_stub_address(int intr_num, bool in_kernel)
{
  idt_info info;
  sidt(&info);
  idt64_entry *idt = (idt64_entry *) info.ptr;
  idt64_entry *entry = &idt[intr_num];
  vm_offset_t retval = (entry->offset_low16 |
                        ((uint64_t) entry->offset_high16 << 16) |
                        ((uint64_t) entry->offset_top32 << 32));
  if (in_kernel) {
    retval += g_doublemap_distance;
  }
  return retval;
}

bool g_stub_dispatcher_installed = false;

// Install our HIB segment handler code to empty space at the end of the
// idt64_hndl_table0 array.  Note that since the HIB segment is mapped twice,
// we can write to (and read from) addresses in either range (inside or
// outside of the kernel proper).
bool install_stub_dispatcher()
{
  if (g_stub_dispatcher_installed) {
    return true;
  }

  idt64_entry *master_idt64;
  if (!is_kpti_enabled(&master_idt64)) {
    return true;
  }
  vm_offset_t master_idt64_addr = (vm_offset_t) master_idt64;

  if (g_kernel_idt64_hndl_table0_addr == -1) {
    g_kernel_idt64_hndl_table0_addr =
      (vm_offset_t) kernel_dlsym("_idt64_hndl_table0");
    if (!g_kernel_idt64_hndl_table0_addr) {
      return false;
    }
  }
  static vm_offset_t kernel_master_idt64_addr = -1;
  if (kernel_master_idt64_addr == -1) {
    kernel_master_idt64_addr =
      (vm_offset_t) kernel_dlsym("_master_idt64");
    if (!kernel_master_idt64_addr) {
      return false;
    }
  }
  static vm_offset_t kernel_gIOHibernateRestoreStack_addr = -1;
  if (kernel_gIOHibernateRestoreStack_addr == -1) {
    kernel_gIOHibernateRestoreStack_addr =
      (vm_offset_t) kernel_dlsym("_gIOHibernateRestoreStack");
    if (!kernel_gIOHibernateRestoreStack_addr) {
      return false;
    }
  }
  static vm_offset_t kernel_scfstks_addr = -1;
  if (kernel_scfstks_addr == -1) {
    kernel_scfstks_addr =
      (vm_offset_t) kernel_dlsym("_scfstks");
  }

  // On versions of macOS/OS X that support KPTI, idt64_hndl_table0 is either
  // just before gIOHibernateRestoreStack (ElCapitan and the HighSierra debug
  // kernel) or scfstks (macOS 12.3 and above) or master_idt64 (all the rest).
  // I don't know the reason for the variation.  Our main concern here is to
  // ensure that there's enough empty space at the end of idt64_hndl_table0.
  // We try to do that by ensuring that idt64_hndl_table0 and the "next" label
  // in the symbol table are page-aligned and one page apart.
  // (idt64_hndl_table1, which isn't in all kernels' symbol tables, is counted
  // as part of idt64_hndl_table0.)
  int64_t idt64_hndl_table0_size =
    kernel_master_idt64_addr - g_kernel_idt64_hndl_table0_addr;
  if (idt64_hndl_table0_size != PAGE_SIZE) {
    idt64_hndl_table0_size =
      kernel_gIOHibernateRestoreStack_addr - g_kernel_idt64_hndl_table0_addr;
    if (kernel_scfstks_addr && (idt64_hndl_table0_size != PAGE_SIZE)) {
      idt64_hndl_table0_size =
        kernel_scfstks_addr - g_kernel_idt64_hndl_table0_addr;
    }
  }
  if ((idt64_hndl_table0_size != PAGE_SIZE) ||
      (g_kernel_idt64_hndl_table0_addr & PAGE_MASK))
  {
    kprintf("HookCase: install_stub_dispatcher(): idt64_hndl_table0 must be 4096 bytes long and page-aligned\n");
    return false;
  }

  g_doublemap_distance =
    kernel_master_idt64_addr - master_idt64_addr;

  g_idt64_hndl_table0_addr =
    g_kernel_idt64_hndl_table0_addr - g_doublemap_distance;
  g_return_from_kext_addr =
    g_idt64_hndl_table0_addr + RETURN_FROM_KEXT_PAGE_OFFSET;
  g_dispatch_to_kext_addr =
    g_idt64_hndl_table0_addr + DISPATCH_TO_KEXT_PAGE_OFFSET;

  g_kernel_return_from_kext_addr =
    g_kernel_idt64_hndl_table0_addr + RETURN_FROM_KEXT_PAGE_OFFSET;
  g_kernel_dispatch_to_kext_addr =
    g_kernel_idt64_hndl_table0_addr + DISPATCH_TO_KEXT_PAGE_OFFSET;

  set_kernel_physmap_protection(g_idt64_hndl_table0_addr,
                                g_idt64_hndl_table0_addr + PAGE_SIZE,
                                VM_PROT_ALL, false);

  char return_from_kext_bytecodes[24];
  memset(return_from_kext_bytecodes, 0x90,
         sizeof(return_from_kext_bytecodes));

  // 58
  return_from_kext_bytecodes[0]  = 0x58; //    pop   %rax

  // 65 48 8B 00
  return_from_kext_bytecodes[1]  = 0x65; //    mov   %gs:(%rax), %rax
  return_from_kext_bytecodes[2]  = 0x48;
  return_from_kext_bytecodes[3]  = 0x8B;
  return_from_kext_bytecodes[4]  = 0x00;

  // 0F 22 D8
  return_from_kext_bytecodes[5]  = 0x0F; //    mov   %rax, %cr3
  return_from_kext_bytecodes[6]  = 0x22;
  return_from_kext_bytecodes[7]  = 0xD8;

  // 0F 01 F8
  return_from_kext_bytecodes[8]  = 0x0F; //    swapgs
  return_from_kext_bytecodes[9]  = 0x01;
  return_from_kext_bytecodes[10] = 0xF8;

  // 58
  return_from_kext_bytecodes[11] = 0x58; //    pop   %rax

  // 48 CF
  return_from_kext_bytecodes[12] = 0x48; //    iretq
  return_from_kext_bytecodes[13] = 0xCF;

  memcpy((void *) g_kernel_return_from_kext_addr, return_from_kext_bytecodes,
         sizeof(return_from_kext_bytecodes));

  vm_offset_t *stub_handler_addr = (vm_offset_t *)
    (g_kernel_idt64_hndl_table0_addr + STUB_HANDLER_ADDR_PAGE_OFFSET);
  *stub_handler_addr = (vm_offset_t) stub_handler;

  char dispatch_to_kext_bytecodes[48];

  // 48 83 7C 24 18 08
  dispatch_to_kext_bytecodes[0]  = 0x48; //    cmpq  $KERNEL64_CS, 0x18(%rsp)
  dispatch_to_kext_bytecodes[1]  = 0x83;
  dispatch_to_kext_bytecodes[2]  = 0x7C; //    (interrupt CS is on stack at
  dispatch_to_kext_bytecodes[3]  = 0x24; //    offset 0x18)
  dispatch_to_kext_bytecodes[4]  = 0x18;
  dispatch_to_kext_bytecodes[5]  = 0x08;

  // 74 1C
  dispatch_to_kext_bytecodes[6]  = 0x74; //    je    1f
  dispatch_to_kext_bytecodes[7]  = 0x1C;

  // 0F 01 F8
  dispatch_to_kext_bytecodes[8]  = 0x0F; //    swapgs
  dispatch_to_kext_bytecodes[9]  = 0x01;
  dispatch_to_kext_bytecodes[10] = 0xF8;

  // 48 8D 05 00 00 00 00
  dispatch_to_kext_bytecodes[11] = 0x48; //    lea   EXT(idt64_hndl_table0)(%rip), %rax
  dispatch_to_kext_bytecodes[12] = 0x8D;
  dispatch_to_kext_bytecodes[13] = 0x05;

  int32_t *displacement_addr = (int32_t *) &dispatch_to_kext_bytecodes[14];
  // 'ip' is the address of the beginning of the next instruction after our
  // 'lea' instruction.
  vm_offset_t ip = g_dispatch_to_kext_addr + 18;
  vm_offset_t displacement = g_idt64_hndl_table0_addr - ip;
  displacement_addr[0] = (int32_t) displacement;

  // 48 8B 40 10
  dispatch_to_kext_bytecodes[18] = 0x48; //    mov   0x10(%rax), %rax
  dispatch_to_kext_bytecodes[19] = 0x8B;
  dispatch_to_kext_bytecodes[20] = 0x40;
  dispatch_to_kext_bytecodes[21] = 0x10;

  // 65 48 8B 80 10 01 00 00
  dispatch_to_kext_bytecodes[22] = 0x65; //    mov   %gs:CPU_TASK_CR3(%rax), %rax
  dispatch_to_kext_bytecodes[23] = 0x48;
  dispatch_to_kext_bytecodes[24] = 0x8B;
  dispatch_to_kext_bytecodes[25] = 0x80;

  uint32_t *cpu_task_cr3_addr = (uint32_t *) &dispatch_to_kext_bytecodes[26];
  cpu_task_cr3_addr[0] = (uint32_t) g_cpu_shadowtask_cr3_offset;

  // 0F 22 D8
  dispatch_to_kext_bytecodes[30] = 0x0F; //    mov   %rax, %cr3
  dispatch_to_kext_bytecodes[31] = 0x22;
  dispatch_to_kext_bytecodes[32] = 0xD8;

  // 0F 01 F8
  dispatch_to_kext_bytecodes[33] = 0x0F; //    swapgs
  dispatch_to_kext_bytecodes[34] = 0x01;
  dispatch_to_kext_bytecodes[35] = 0xF8;

  // 48 8D 05 05 00 00 00
  dispatch_to_kext_bytecodes[36] = 0x48; // 1: lea   EXT(stub_handler_addr)(%rip), %rax
  dispatch_to_kext_bytecodes[37] = 0x8D;
  dispatch_to_kext_bytecodes[38] = 0x05;
  dispatch_to_kext_bytecodes[39] = 0x05; //    (Distance from next instruction to
  dispatch_to_kext_bytecodes[40] = 0x00; //    stub_handler_addr)
  dispatch_to_kext_bytecodes[41] = 0x00;
  dispatch_to_kext_bytecodes[42] = 0x00;

  // 48 8B 00
  dispatch_to_kext_bytecodes[43] = 0x48; //    mov   (%rax), %rax
  dispatch_to_kext_bytecodes[44] = 0x8B;
  dispatch_to_kext_bytecodes[45] = 0x00;

  // FF E0
  dispatch_to_kext_bytecodes[46] = 0xFF; //    jmp   *%rax
  dispatch_to_kext_bytecodes[47] = 0xE0;

  memcpy((void *) g_kernel_dispatch_to_kext_addr, dispatch_to_kext_bytecodes,
         sizeof(dispatch_to_kext_bytecodes));

  g_stub_dispatcher_installed = true;

  return true;
}

void remove_stub_dispatcher()
{
  if (!g_stub_dispatcher_installed) {
    return;
  }

  set_kernel_physmap_protection(g_idt64_hndl_table0_addr,
                                g_idt64_hndl_table0_addr + PAGE_SIZE,
                                VM_PROT_READ | VM_PROT_WRITE, false);

  bzero((void *) g_kernel_return_from_kext_addr,
        PAGE_SIZE - RETURN_FROM_KEXT_PAGE_OFFSET);

  g_stub_dispatcher_installed = false;
}

bool install_intr_blob(int intr_num, void *new_value,
                       void *previous_value, bool is_stub)
{
  if (!new_value) {
    return false;
  }

  idt64_entry *idt;
  bool kpti_enabled = is_kpti_enabled(&idt);
  idt64_entry *entry = &idt[intr_num];
  vm_offset_t prev_offset = (entry->offset_low16 |
                             ((uint64_t) entry->offset_high16 << 16) |
                             ((uint64_t) entry->offset_top32 << 32));
  char *stub = (char *) prev_offset;

  void *target;
  size_t target_size;
  if (is_stub) {
    target = stub;
    target_size = sizeof(char[16]);
  } else {
    target = entry;
    target_size = sizeof(idt64_entry);
  }
  vm_map_offset_t target_offset = (vm_map_offset_t) target;
  if (previous_value) {
    memcpy(previous_value, target, target_size);
  }

  if (kpti_enabled && !is_stub) {
    idt64_entry *new_entry = (idt64_entry *) new_value;
    new_entry->offset_low16 = entry->offset_low16;
    new_entry->offset_high16 = entry->offset_high16;
    new_entry->offset_top32 = entry->offset_top32;
  }

  boolean_t org_int_level = ml_set_interrupts_enabled(false);
  disable_preemption();
  uintptr_t org_cr0 = get_cr0();
  set_cr0(org_cr0 & ~CR0_WP);

  bool retval = true;

  if ((cpuid_features_ptr() & CPUID_FEATURE_CX16)) {
    __uint128_t *target_int128 = (__uint128_t *) target_offset;
    __uint128_t old_value = target_int128[0];
    if (!OSCompareAndSwap128(old_value, ((__uint128_t *)new_value)[0],
                             target_int128))
    {
      retval = false;
    }
  } else {
    memcpy((void *) target_offset, new_value, target_size);
  }

  set_cr0(org_cr0);
  enable_preemption();
  ml_set_interrupts_enabled(org_int_level);

  return retval;
}

bool install_intr_handler(int intr_num)
{
  idt64_entry *old_idt_entry;
  char *old_stub;
  vm_offset_t raw_handler;
  switch(intr_num) {
    case HC_INT1:
      if (s_installed_hc_int1_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int1_idt_entry;
      old_stub = old_hc_int1_stub;
      raw_handler = (vm_offset_t) hc_int1_raw_handler;
      break;
    case HC_INT2:
      if (s_installed_hc_int2_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int2_idt_entry;
      old_stub = old_hc_int2_stub;
      raw_handler = (vm_offset_t) hc_int2_raw_handler;
      break;
    case HC_INT3:
      if (s_installed_hc_int3_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int3_idt_entry;
      old_stub = old_hc_int3_stub;
      raw_handler = (vm_offset_t) hc_int3_raw_handler;
      break;
    case HC_INT4:
      if (s_installed_hc_int4_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int4_idt_entry;
      old_stub = old_hc_int4_stub;
      raw_handler = (vm_offset_t) hc_int4_raw_handler;
      break;
    case HC_INT5:
      if (s_installed_hc_int5_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int5_idt_entry;
      old_stub = old_hc_int5_stub;
      raw_handler = (vm_offset_t) hc_int5_raw_handler;
      break;
    case HC_INT6:
      if (s_installed_hc_int6_handler) {
        return true;
      }
      old_idt_entry = &old_hc_int6_idt_entry;
      old_stub = old_hc_int6_stub;
      raw_handler = (vm_offset_t) hc_int6_raw_handler;
      break;
    default:
      return false;
  }

  idt64_entry our_idt_entry;
  bzero(&our_idt_entry, sizeof(idt64_entry));
  our_idt_entry.selector16 = KERNEL64_CS;
  our_idt_entry.access8 = U_INTR_GATE;
  vm_offset_t offset = (vm_offset_t) raw_handler;
  our_idt_entry.offset_low16 = (offset & 0xffff);
  our_idt_entry.offset_high16 = ((offset >> 16) & 0xffff);
  our_idt_entry.offset_top32 = ((offset >> 32) & 0xffffffff);

  if (!install_intr_blob(intr_num, &our_idt_entry, old_idt_entry, false)) {
    return false;
  }

  bool retval = true;

  if (is_kpti_enabled(NULL)) {
    // Copy our stub code over Apple's, to make the intr_num interrupts use
    // our handlers.
    char our_stub[16];
    memset(our_stub, 0x90, sizeof(our_stub));

    // 50
    our_stub[0]  = 0x50;     //   push   %rax
    // 6A NN
    our_stub[1]  = 0x6A;     //   pushq  $(0xNN)
    our_stub[2]  = intr_num; //   (Do *not* use the 0x68 form of this instruction)
    // E9 00 00 00 00
    our_stub[3]  = 0xE9;     //   jmp    _dispatch_to_kext

    int32_t *displacement_addr = (int32_t *) &our_stub[4];
    // 'ip' is the address of the beginning of the next instruction after our
    // 'jmp' instruction.
    vm_offset_t ip = get_stub_address(intr_num, false) + 8;
    vm_offset_t displacement = g_dispatch_to_kext_addr - ip;
    displacement_addr[0] = (int32_t) displacement;

    retval = install_intr_blob(intr_num, &our_stub, old_stub, true);
  }

  switch(intr_num) {
    case HC_INT1:
      s_installed_hc_int1_handler = true;
      break;
    case HC_INT2:
      s_installed_hc_int2_handler = true;
      break;
    case HC_INT3:
      s_installed_hc_int3_handler = true;
      break;
    case HC_INT4:
      s_installed_hc_int4_handler = true;
      break;
    case HC_INT5:
      s_installed_hc_int5_handler = true;
      break;
    case HC_INT6:
      s_installed_hc_int6_handler = true;
      break;
    default:
      break;
  }

  return retval;
}

void remove_intr_handler(int intr_num)
{
  idt64_entry *old_idt_entry;
  char *old_stub;
  switch(intr_num) {
    case HC_INT1:
      if (!s_installed_hc_int1_handler) {
        return;
      }
      old_idt_entry = &old_hc_int1_idt_entry;
      old_stub = old_hc_int1_stub;
      break;
    case HC_INT2:
      if (!s_installed_hc_int2_handler) {
        return;
      }
      old_idt_entry = &old_hc_int2_idt_entry;
      old_stub = old_hc_int2_stub;
      break;
    case HC_INT3:
      if (!s_installed_hc_int3_handler) {
        return;
      }
      old_idt_entry = &old_hc_int3_idt_entry;
      old_stub = old_hc_int3_stub;
      break;
    case HC_INT4:
      if (!s_installed_hc_int4_handler) {
        return;
      }
      old_idt_entry = &old_hc_int4_idt_entry;
      old_stub = old_hc_int4_stub;
      break;
    case HC_INT5:
      if (!s_installed_hc_int5_handler) {
        return;
      }
      old_idt_entry = &old_hc_int5_idt_entry;
      old_stub = old_hc_int5_stub;
      break;
    case HC_INT6:
      if (!s_installed_hc_int6_handler) {
        return;
      }
      old_idt_entry = &old_hc_int6_idt_entry;
      old_stub = old_hc_int6_stub;
      break;
    default:
      return;
  }

  install_intr_blob(intr_num, old_idt_entry, NULL, false);
  if (is_kpti_enabled(NULL)) {
    install_intr_blob(intr_num, old_stub, NULL, true);
  }

  switch(intr_num) {
    case HC_INT1:
      s_installed_hc_int1_handler = false;
      break;
    case HC_INT2:
      s_installed_hc_int2_handler = false;
      break;
    case HC_INT3:
      s_installed_hc_int3_handler = false;
      break;
    case HC_INT4:
      s_installed_hc_int4_handler = false;
      break;
    case HC_INT5:
      s_installed_hc_int5_handler = false;
      break;
    case HC_INT6:
      s_installed_hc_int6_handler = false;
      break;
    default:
      break;
  }
}

// Uncomment this to disable watchpoint support. HookCase 5.0.4 made changes
// to resolve https://github.com/steven-michaud/HookCase/issues/26. But the
// watchpoint code is complex, and might still cause trouble.
//#define DISABLE_WATCHPOINTS 1

bool install_intr_handlers()
{
  if (!find_kernel_private_functions()) {
    return false;
  }
  if (g_no_shared_cr3_ptr == (boolean_t *) -1) {
    g_no_shared_cr3_ptr = (boolean_t *) kernel_dlsym("_no_shared_cr3");
    if (!g_no_shared_cr3_ptr) {
      return false;
    }
  }
  if (g_pmap_smap_enabled_ptr == (boolean_t *) -1) {
    g_pmap_smap_enabled_ptr = (boolean_t *) kernel_dlsym("_pmap_smap_enabled");
  }

  if (!install_stub_dispatcher()) {
    return false;
  }

  if (!install_intr_handler(HC_INT1)) {
    return false;
  }
  if (!install_intr_handler(HC_INT2)) {
    return false;
  }
  if (!install_intr_handler(HC_INT3)) {
    return false;
  }
  if (!install_intr_handler(HC_INT4)) {
    return false;
  }
  if (!install_intr_handler(HC_INT5)) {
    return false;
  }
  if (!install_intr_handler(HC_INT6)) {
    return false;
  }

  if (!macOS_Mojave() && !macOS_Catalina() && !macOS_BigSur() &&
      !macOS_Monterey() && !macOS_Ventura() && !macOS_Sonoma() &&
      !macOS_Sequoia())
  {
    if (!hook_vm_page_validate_cs()) {
      return false;
    }
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey() || macOS_BigSur() || macOS_Catalina() ||
      macOS_Mojave() || macOS_HighSierra() || macOS_Sierra())
  {
    if (!hook_mac_file_check_library_validation()) {
      return false;
    }
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey() || macOS_BigSur() || macOS_Catalina() ||
      macOS_Mojave() || macOS_HighSierra() || macOS_Sierra() ||
      OSX_ElCapitan())
  {
    if (!hook_mac_file_check_mmap()) {
      return false;
    }
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey() || macOS_BigSur() || macOS_Catalina())
  {
    if (!hook_mac_vnode_check_open()) {
      return false;
    }
    if (!hook_mac_vnode_check_ioctl()) {
      return false;
    }
  }
  if (macOS_Sequoia() || macOS_Sonoma() || macOS_Ventura() ||
      macOS_Monterey() || macOS_BigSur())
  {
    if (!hook_sandbox_filters()) {
      return false;
    }
  }
#ifndef DISABLE_WATCHPOINTS
  if (!hook_user_trap()) {
    return false;
  }
#endif
  return hook_thread_bootstrap_return();
}

void remove_intr_handlers()
{
  if (!find_kernel_private_functions()) {
    return;
  }
  unset_all_kern_hooks();
  remove_intr_handler(HC_INT1);
  remove_intr_handler(HC_INT2);
  remove_intr_handler(HC_INT3);
  remove_intr_handler(HC_INT4);
  remove_intr_handler(HC_INT5);
  remove_intr_handler(HC_INT6);
  remove_stub_dispatcher();
}

extern "C" void handle_user_hc_int1(x86_saved_state_t *intr_state)
{
  check_hook_state(intr_state);
}

extern "C" void handle_user_hc_int2(x86_saved_state_t *intr_state)
{
  on_add_image(intr_state);
}

extern "C" void handle_user_hc_int3(x86_saved_state_t *intr_state)
{
  reset_hook(intr_state);
}

extern "C" void handle_user_hc_int4(x86_saved_state_t *intr_state)
{
  add_patch_hook(intr_state);
}

extern "C" void handle_user_hc_int5(x86_saved_state_t *intr_state)
{
  get_dynamic_caller(intr_state);
}

extern "C" void handle_user_hc_int6(x86_saved_state_t *intr_state)
{
  config_watcher(intr_state);
}

extern "C" void handle_kernel_hc_int1(x86_saved_state_t *intr_state)
{
  do_kern_hook(intr_state);
}

extern "C" kern_return_t HookCase_start(kmod_info_t * ki, void *d);
extern "C" kern_return_t HookCase_stop(kmod_info_t *ki, void *d);

kern_return_t HookCase_start(kmod_info_t * ki, void *d)
{
  if (OSX_Version_Unsupported()) {
    // We use kprintf() for error messages for conditions under which we must
    // fail HookCase_start().  The reason for this is an Apple bug that
    // effects the new logging subsystem used by macOS 10.12 and up:  Neither
    // the Console app nor the log app will ever display messages sent by an
    // extension that fails its start() method.  The workaround is to use
    // kprintf() for these error messages, because kprintf() can (under
    // certain circumstances) write to a serial port, and we can tell people
    // to look for output from that port.  For more information on the bug see
    // Examples/kernel-logging.
    //
    // Though Macs haven't included a serial port for ages, macOS and OSX
    // still support them.  Many kinds of VM software allow you to add a
    // serial port to their virtual machines.  In VMware Fusion, everything
    // written to such a serial port shows up in a file on the virtual
    // machine's host.
    //
    // macOS/OSX supports serial ports in user-mode and the kernel, but not
    // in both at the same time.  You can make the kernel send output from
    // kprintf() to a serial port by doing 'nvram boot-args="debug=0x8"', then
    // rebooting.  But this makes the kernel "capture" the serial port -- it's
    // no longer available to user-mode code, and drivers for it no longer show
    // up in the /dev directory.
    kprintf("HookCase requires OS X Mavericks (10.9), Yosemite (10.10), El Capitan (10.11), macOS Sierra (10.12), macOS High Sierra (10.13), macOS Mojave (10.14), macOS Catalina (10.15), macOS Big Sur (11), macOS Monterey (12), macOS Ventura (13), macOS Sonoma (14) or macOS Sequoia (15): current version %s\n",
            gOSVersionString ? gOSVersionString : "null");
    if (gOSVersionString) {
      IOFree(gOSVersionString, gOSVersionStringLength);
    }
    return KERN_NOT_SUPPORTED;
  }

  if (!find_kernel_private_functions()) {
    return KERN_FAILURE;
  }

  if (kernel_type_is_unknown()) {
    kprintf("HookCase: Unknown kernel type\n");
    return KERN_FAILURE;
  }
  if (!initialize_thread_offsets()) {
    return KERN_FAILURE;
  }
  if (!initialize_cpu_data_offsets()) {
    return KERN_FAILURE;
  }
  initialize_use_invpcid();
  if (!install_intr_handlers()) {
    remove_intr_handlers();
    destroy_all_lists();
    return KERN_FAILURE;
  }
  if (!install_sysent_hooks()) {
    remove_intr_handlers();
    remove_sysent_hooks();
    destroy_all_lists();
    return KERN_FAILURE;
  }
  return KERN_SUCCESS;
}

kern_return_t HookCase_stop(kmod_info_t *ki, void *d)
{
  remove_intr_handlers();
  remove_sysent_hooks();
  destroy_all_lists();
  return KERN_SUCCESS;
}

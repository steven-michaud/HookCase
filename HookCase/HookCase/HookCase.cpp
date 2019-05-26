// The MIT License (MIT)
//
// Copyright (c) 2018 Steven Michaud
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
// HookCase.kext you need to turn off Apple's System Integrity Protection
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
// "INTERRUPT(0xNN)".  But note that the ranges 0xD0-0xFF and 0x50-0x5F are
// reserved for APIC interrupts (see the xnu kernel's osfmk/i386/lapic.h).
// So we're reasonably safe reserving the range 0x30-0x37 for our own use,
// though we currently only use 0x30-0x33.  And aside from plenty of them
// being available, there are other advantages to using interrupts as
// breakpoints:  They're short (they take up just two bytes of machine code),
// but provide more information than other instructions of equal length (like
// syscall, which doesn't have different "interrupt numbers").  Software
// interrupts work equally well from user mode and kernel mode (again unlike
// syscall).  Interrupts also (like syscall) have very good support for making
// the transition between different privilege levels (for example between user
// mode and kernel mode).

// HookCase.kext is compatible with DYLD_INSERT_LIBRARIES, and doesn't stomp on
// any of the changes it may have been used to make.  So a
// DYLD_INTERPOSE_LIBRARIES hook will always override the "same" HookCase.kext
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
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/spawn.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <kern/host.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/OSAtomic.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>

#include <IOKit/IOLib.h>

#include "HookCase.h"

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

// If DEBUG_LOG is defined, HookCase.kext will attempt to log debugging
// information to the system log via sandboxmirrord from the SandboxMirror
// project (https://github.com/steven-michaud/SandboxMirror).

//#define DEBUG_LOG 1

// "kern.osrelease" is what's returned by 'uname -r', which uses a different
// numbering system than the "standard" one.  These defines translate from
// that (kernel) system to the "standard" one.

#define MAC_OS_X_VERSION_10_9_HEX  0x00000D00
#define MAC_OS_X_VERSION_10_10_HEX 0x00000E00
#define MAC_OS_X_VERSION_10_11_HEX 0x00000F00
#define MAC_OS_X_VERSION_10_12_HEX 0x00001000
#define MAC_OS_X_VERSION_10_13_HEX 0x00001100
#define MAC_OS_X_VERSION_10_14_HEX 0x00001200

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

bool OSX_Version_Unsupported()
{
  return (((OSX_Version() & 0xFF00) < MAC_OS_X_VERSION_10_9_HEX) ||
          ((OSX_Version() & 0xFF00) > MAC_OS_X_VERSION_10_14_HEX));
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
  if (macOS_Mojave()) {
    if (type == kernel_type_debug) {
      type = kernel_type_unknown;
    }
  }

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

#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12) || \
             defined(MAC_OS_X_VERSION_10_13) || defined(MAC_OS_X_VERSION_10_14)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  // vm_kernel_unslide_or_perm_external() is only available on OS X 10.11 and up.
  if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    vm_offset_t func_address = (vm_offset_t) vm_kernel_unslide_or_perm_external;
    vm_offset_t func_address_unslid = 0;
    vm_kernel_unslide_or_perm_external(func_address, &func_address_unslid);
    g_kernel_slide = func_address - func_address_unslid;
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
          (header->cputype != CPU_TYPE_X86_64 ) ||
          (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
          (header->filetype != MH_EXECUTE) ||
          (header->flags != (MH_NOUNDEFS | MH_PIE)))
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
#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12) || \
             defined(MAC_OS_X_VERSION_10_13) || defined(MAC_OS_X_VERSION_10_14)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  }
#endif

  g_kernel_header = (struct mach_header_64 *)
    (KERNEL_HEADER_ADDR + g_kernel_slide);

  return true;
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

  static bool found_symbol_table = false;

  static vm_offset_t symbolTableOffset = 0;
  static vm_offset_t stringTableOffset = 0;
  static uint32_t symbols_index = 0;
  static uint32_t symbols_count = 0;

  // Find the symbol table
  if (!found_symbol_table) {
    vm_offset_t linkedit_fileoff_increment = 0;
    bool found_linkedit_segment = false;
    bool found_symtab_segment = false;
    bool found_dysymtab_segment = false;
    uint32_t num_commands = g_kernel_header->ncmds;
    const struct load_command *load_command = (struct load_command *)
      ((vm_offset_t)g_kernel_header + sizeof(struct mach_header_64));
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
          if (!strcmp(command->segname, "__LINKEDIT")) {
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
          found_symtab_segment = true;
          break;
        }
        case LC_DYSYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct dysymtab_command *command =
            (struct dysymtab_command *) load_command;
          symbols_index = command->iextdefsym;
          symbols_count = symbols_index + command->nextdefsym;
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
    if (stringTableItem && !strcmp(stringTableItem, symbol)) {
      return (void *) symbolTableItem->n_value;
    }
  }

  return NULL;
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    data_segment_name = "__CONST";
    const_section_name = "__constdata";
  } else {
    data_segment_name = "__DATA";
    const_section_name = "__const";
  }

  // The definition of the sysent table is "const struct sysent sysent[]",
  // so we look for it in the __DATA segment's __const section (on ElCapitan
  // and below) or in the __CONST segment's __constdata section (on Sierra and
  // above). Note that this section's contents have been set read-only, which
  // we need to work around below in hook_sysent_call().
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
        if (!strcmp(command->segname, data_segment_name)) {
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
    if (!strcmp(data_sections[i].sectname, const_section_name)) {
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

bool set_kernel_physmap_protection(vm_map_offset_t start, vm_map_offset_t end,
                                   vm_prot_t new_prot, bool use_pmap_protect);

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

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    if (!set_kernel_physmap_protection((vm_map_offset_t) orig_addr,
                                       (vm_map_offset_t) orig_addr + sizeof(void *),
                                       VM_PROT_READ | VM_PROT_WRITE, true))
    {
      return false;
    }
  }

  bool retval = true;

  if (!OSCompareAndSwapPtr((void *) orig_local, (void *) hook,
                           (void **) orig_addr))
  {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) orig_addr,
                                  (vm_map_offset_t) orig_addr + sizeof(void *),
                                  VM_PROT_READ, true);
  }

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

// HC_NOKIDS -- Operate on a single process, excluding its children
//
// By default HookCase.kext operates on a parent process and all its child
// processes, including XPC children.  Set this to make it only effect the
// parent process.

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

extern "C" void lck_mtx_lock_spin(lck_mtx_t *lck);

// From the xnu kernel's osfmk/i386/locks.h
struct __lck_mtx_t__ {
 unsigned long opaque[2];
};

// From the xnu kernel's osfmk/vm/vm_page.h
typedef struct vm_locks_array {
  char pad  __attribute__ ((aligned (64)));
  lck_mtx_t vm_page_queue_lock2 __attribute__ ((aligned (64)));
  lck_mtx_t vm_page_queue_free_lock2 __attribute__ ((aligned (64)));
  char pad2  __attribute__ ((aligned (64)));
} vm_locks_array_t;

// Kernel private globals (begin)

vm_locks_array_t *g_vm_page_locks = NULL;
#define vm_page_queue_lock (g_vm_page_locks->vm_page_queue_lock2)
#define vm_page_unlock_queues() lck_mtx_unlock(&vm_page_queue_lock)
#define vm_page_lockspin_queues() lck_mtx_lock_spin(&vm_page_queue_lock)

uint64_t *g_max_mem = NULL; /* Size of physical memory (bytes), adjusted by maxmem */
uint64_t *g_mem_actual = NULL;

unsigned int *g_vm_page_wire_count = NULL;
uint32_t *g_vm_lopage_free_count = NULL;
vm_map_size_t *g_vm_global_no_user_wire_amount = NULL;
vm_map_size_t *g_vm_global_user_wire_limit = NULL;
vm_map_size_t *g_vm_user_wire_limit = NULL;

// Only used on Sierra (and up).
vm_page_t *g_vm_pages = NULL;
vm_page_t *g_vm_page_array_beginning_addr = NULL;
vm_page_t *g_vm_page_array_ending_addr = NULL;

// Kernel private globals (end)

// From the xnu kernel's osfmk/mach/vm_types.h
typedef uint8_t vm_tag_t;

// From the xnu kernel's osfmk/mach/thread_status.h
typedef natural_t *thread_state_t; /* Variable-length array */

// From the xnu kernel's osfmk/mach/thread_info.h
typedef natural_t thread_flavor_t;

// Kernel private functions needed by code below

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
typedef vm_map_t (*vm_map_switch_t)(vm_map_t map);
typedef uint16_t (*thread_get_tag_t)(thread_t);
typedef void (*task_act_iterate_wth_args_t)(task_t task,
                                            void (*func_callback)(thread_t, void *),
                                            void *func_arg);
typedef uthread_t (*get_bsdthread_info_t)(thread_t th);
typedef void (*fp_load_t)(thread_t thr_act);
typedef kern_return_t (*vm_map_region_recurse_64_t)(vm_map_t map,
                                                    vm_map_offset_t *address,        /* IN/OUT */
                                                    vm_map_size_t *size,             /* OUT */
                                                    natural_t *depth,                /* IN/OUT */
                                                    vm_region_submap_info_64_t info, /* IN/OUT */
                                                    mach_msg_type_number_t *count);  /* IN/OUT */
typedef kern_return_t (*task_hold_t)(task_t task);
typedef kern_return_t (*task_release_t)(task_t task);
typedef kern_return_t (*task_wait_t)(task_t task, boolean_t until_not_runnable);
typedef uint64_t (*cpuid_features_t)();
typedef uint64_t (*cpuid_leaf7_features_t)();
typedef kern_return_t (*vm_fault_t)(vm_map_t map,
                                    vm_map_offset_t vaddr,
                                    vm_prot_t fault_type,
                                    boolean_t change_wiring,
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
typedef void (*vm_map_clip_start_t)(vm_map_t map,
                                    vm_map_entry_t entry,
                                    vm_map_offset_t startaddr);
typedef void (*vm_map_clip_end_t)(vm_map_t map,
                                  vm_map_entry_t entry,
                                  vm_map_offset_t endaddr);
typedef void (*pmap_change_wiring_t)(pmap_t map, vm_map_offset_t vaddr,
                                     boolean_t wired);
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
typedef vm_page_t (*vm_page_lookup_t)(vm_object_t object,
                                      vm_object_offset_t offset);
typedef void (*vm_page_wire_t)(vm_page_t page,
                               vm_tag_t tag,
                               boolean_t check_memorystatus);
typedef vm_page_t (*vm_page_alloc_t)(vm_object_t object, vm_object_offset_t offset);
typedef void (*vm_object_lock_t)(vm_object_t object);
typedef void (*pmap_sync_page_attributes_phys_t)(ppnum_t pa);
typedef task_t (*get_threadtask_t)(thread_t th);
typedef void (*task_coalition_ids_t)(task_t task,
                                     uint64_t ids[2 /* COALITION_NUM_TYPES */]);
typedef coalition_t (*coalition_find_by_id_t)(uint64_t coal_id);
typedef void (*coalition_release_t)(coalition_t coal);
typedef int (*coalition_get_pid_list_t)(coalition_t coal, uint32_t rolemask,
                                        int sort_order, int *pid_list, int list_sz);
typedef void (*vm_object_unlock_t)(vm_object_t object);

static get_task_map_reference_t get_task_map_reference = NULL;
static vm_map_copyin_t vm_map_copyin = NULL;
static vm_map_copy_overwrite_t vm_map_copy_overwrite = NULL;
static vm_map_copyout_t vm_map_copyout = NULL;
static vm_map_copy_discard_t vm_map_copy_discard = NULL;
static vm_map_switch_t vm_map_switch = NULL;
static thread_get_tag_t thread_get_tag = NULL;
static task_act_iterate_wth_args_t task_act_iterate_wth_args = NULL;
static get_bsdthread_info_t get_bsdthread_info = NULL;
static fp_load_t fp_load = NULL;
static vm_map_region_recurse_64_t vm_map_region_recurse_64 = NULL;
static task_hold_t task_hold = NULL;
static task_release_t task_release = NULL;
static task_wait_t task_wait = NULL;
static cpuid_features_t cpuid_features_ptr = NULL;
static cpuid_leaf7_features_t cpuid_leaf7_features_ptr = NULL;
static vm_fault_t vm_fault = NULL;
static vm_map_page_mask_t vm_map_page_mask = NULL;
static vm_map_page_size_t vm_map_page_size = NULL;
static vm_map_lookup_entry_t vm_map_lookup_entry = NULL;
static vm_map_lookup_locked_t vm_map_lookup_locked = NULL;
static vm_map_clip_start_t vm_map_clip_start = NULL;
static vm_map_clip_end_t vm_map_clip_end = NULL;
static pmap_change_wiring_t pmap_change_wiring = NULL;
static pmap_protect_t pmap_protect = NULL;
static pmap_enter_t pmap_enter = NULL;
static vm_page_lookup_t vm_page_lookup = NULL;
static vm_page_wire_t vm_page_wire = NULL;
static vm_page_alloc_t vm_page_alloc = NULL;
static vm_object_lock_t vm_object_lock = NULL;
static pmap_sync_page_attributes_phys_t pmap_sync_page_attributes_phys = NULL;
static get_threadtask_t get_threadtask = NULL;
// Only on ElCapitan and up (begin)
static task_coalition_ids_t task_coalition_ids = NULL;
static coalition_find_by_id_t coalition_find_by_id = NULL;
static coalition_release_t coalition_release = NULL;
static coalition_get_pid_list_t coalition_get_pid_list = NULL;
// Only on ElCapitan and up (end)
// Only on Sierra and up (begin)
static vm_object_unlock_t vm_object_unlock_ptr = NULL;
// Only on Sierra and up (end)

bool s_kernel_private_functions_found = false;

bool find_kernel_private_functions()
{
  if (s_kernel_private_functions_found) {
    return true;
  }

  if (!g_vm_page_locks) {
    g_vm_page_locks = (vm_locks_array_t *)
      kernel_dlsym("_vm_page_locks");
    if (!g_vm_page_locks) {
      return false;
    }
  }
  if (!g_max_mem) {
    g_max_mem = (uint64_t *)
      kernel_dlsym("_max_mem");
    if (!g_max_mem) {
      return false;
    }
  }
  if (!g_mem_actual) {
    g_mem_actual = (uint64_t *)
      kernel_dlsym("_mem_actual");
    if (!g_mem_actual) {
      return false;
    }
  }
  if (!g_vm_page_wire_count) {
    g_vm_page_wire_count = (unsigned int *)
      kernel_dlsym("_vm_page_wire_count");
    if (!g_vm_page_wire_count) {
      return false;
    }
  }
  if (!g_vm_lopage_free_count) {
    g_vm_lopage_free_count = (uint32_t *)
      kernel_dlsym("_vm_lopage_free_count");
    if (!g_vm_lopage_free_count) {
      return false;
    }
  }
  if (!g_vm_global_no_user_wire_amount) {
    g_vm_global_no_user_wire_amount = (vm_map_size_t *)
      kernel_dlsym("_vm_global_no_user_wire_amount");
    if (!g_vm_global_no_user_wire_amount) {
      return false;
    }
  }
  if (!g_vm_global_user_wire_limit) {
    g_vm_global_user_wire_limit = (vm_map_size_t *)
      kernel_dlsym("_vm_global_user_wire_limit");
    if (!g_vm_global_user_wire_limit) {
      return false;
    }
  }
  if (!g_vm_user_wire_limit) {
    g_vm_user_wire_limit = (vm_map_size_t *)
      kernel_dlsym("_vm_user_wire_limit");
    if (!g_vm_user_wire_limit) {
      return false;
    }
  }
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    if (!g_vm_pages) {
      g_vm_pages = (vm_page_t *)
        kernel_dlsym("_vm_pages");
      if (!g_vm_pages) {
        return false;
      }
    }
    if (!g_vm_page_array_beginning_addr) {
      g_vm_page_array_beginning_addr = (vm_page_t *)
        kernel_dlsym("_vm_page_array_beginning_addr");
      if (!g_vm_page_array_beginning_addr) {
        return false;
      }
    }
    if (!g_vm_page_array_ending_addr) {
      g_vm_page_array_ending_addr = (vm_page_t *)
        kernel_dlsym("_vm_page_array_ending_addr");
      if (!g_vm_page_array_ending_addr) {
        return false;
      }
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
  if (!vm_map_switch) {
    vm_map_switch = (vm_map_switch_t)
      kernel_dlsym("_vm_map_switch");
    if (!vm_map_switch) {
      return false;
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
  if (!fp_load) {
    fp_load = (fp_load_t)
      kernel_dlsym("_fp_load");
    if (!fp_load) {
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
  if (!task_hold) {
    task_hold = (task_hold_t)
      kernel_dlsym("_task_hold");
    if (!task_hold) {
      return false;
    }
  }
  if (!task_release) {
    task_release = (task_release_t)
      kernel_dlsym("_task_release");
    if (!task_release) {
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
  if (!vm_map_lookup_locked) {
    vm_map_lookup_locked = (vm_map_lookup_locked_t)
      kernel_dlsym("_vm_map_lookup_locked");
    if (!vm_map_lookup_locked) {
      return false;
    }
  }
  if (!vm_map_clip_start) {
    vm_map_clip_start = (vm_map_clip_start_t)
      kernel_dlsym("_vm_map_clip_start");
    if (!vm_map_clip_start) {
      return false;
    }
  }
  if (!vm_map_clip_end) {
    vm_map_clip_end = (vm_map_clip_end_t)
      kernel_dlsym("_vm_map_clip_end");
    if (!vm_map_clip_end) {
      return false;
    }
  }
  if (!pmap_change_wiring) {
    pmap_change_wiring = (pmap_change_wiring_t)
      kernel_dlsym("_pmap_change_wiring");
    if (!pmap_change_wiring) {
      return false;
    }
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
  if (!vm_page_lookup) {
    vm_page_lookup = (vm_page_lookup_t)
      kernel_dlsym("_vm_page_lookup");
    if (!vm_page_lookup) {
      return false;
    }
  }
  if (!vm_page_wire) {
    vm_page_wire = (vm_page_wire_t)
      kernel_dlsym("_vm_page_wire");
    if (!vm_page_wire) {
      return false;
    }
  }
  if (!vm_page_alloc) {
    vm_page_alloc = (vm_page_alloc_t)
      kernel_dlsym("_vm_page_alloc");
    if (!vm_page_alloc) {
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
  if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
    if (!vm_object_unlock_ptr) {
      vm_object_unlock_ptr = (vm_object_unlock_t)
        kernel_dlsym("_vm_object_unlock");
      if (!vm_object_unlock_ptr) {
        return false;
      }
    }
  }
  s_kernel_private_functions_found = true;
  return true;
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

pmap_t vm_map_pmap(vm_map_t map)
{
  if (!map) {
    return NULL;
  }
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  unsigned int retval;
  if (macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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

bool vm_map_entry_get_superpage_size(vm_map_entry_t entry)
{
  if (!entry) {
    return false;
  }
  bool retval = false;
  if (OSX_ElCapitan() || macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Mojave()) {
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
  if (macOS_Mojave()) {
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

vm_object_t map_entry_object(vm_map_entry_t entry)
{
  if (!entry) {
    return NULL;
  }
  vm_map_entry_fake_t entry_local = (vm_map_entry_fake_t) entry;
  return entry_local->vme_object.vmo_object;
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
  uint64_t pad1[5];
  vm_object_t object;  /* which object am I in (O&P) */ // Offset 0x28
  vm_object_offset_t offset; /* offset into that object (O,P) */
  uint32_t pad2;
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
  uint64_t pad1[4];
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
  uint64_t pad1[4];
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
typedef vm_page_packed_t vm_page_object_t;

typedef struct vm_page_fake_sierra {
  uint64_t pad1[3];
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_page_object_t vm_page_object;  /* which object am I in (O&P) */ // Offset 0x20
  uint32_t pad2[2];
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
  uint64_t pad1[3];
  vm_object_offset_t offset; /* offset into that object (O,P) */
  vm_page_object_t vm_page_object;  /* which object am I in (O&P) */ // Offset 0x20
  uint32_t pad2[2];
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

// Modified from the Sierra xnu kernel's osfmk/vm/vm_page.h (begin)

#define VM_PACKED_POINTER_ALIGNMENT 64  /* must be a power of 2 */
#define VM_PACKED_POINTER_SHIFT  6

#define VM_PACKED_FROM_VM_PAGES_ARRAY 0x80000000

vm_page_packed_t vm_page_pack_ptr(uintptr_t p)
{
  if (!p || (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave())) {
    return 0;
  }

  vm_page_fake_sierra_t vm_page_array_beginning_addr = (vm_page_fake_sierra_t)
    *g_vm_page_array_beginning_addr;
  vm_page_fake_sierra_t vm_page_array_ending_addr = (vm_page_fake_sierra_t)
    *g_vm_page_array_ending_addr;

  // Sanity check
  if (((uint64_t) vm_page_array_ending_addr - (uint64_t) vm_page_array_beginning_addr) %
      sizeof(struct vm_page_fake_sierra))
  {
    return 0;
  }

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
  if (!p || (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave())) {
    return 0;
  }

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

  vm_page_fake_sierra_t vm_pages = (vm_page_fake_sierra_t) *g_vm_pages;

  if (p & VM_PACKED_FROM_VM_PAGES_ARRAY) {
    return (uintptr_t) &vm_pages[(uint32_t) (p & ~VM_PACKED_FROM_VM_PAGES_ARRAY)];
  }

  return (p << VM_PACKED_POINTER_SHIFT) + (uintptr_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS;
}

// Modified from the Sierra xnu kernel's osfmk/vm/vm_page.h (end)

ppnum_t page_phys_page(vm_page_t page)
{
  if (!page) {
    return 0;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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

void page_set_wpmapped(vm_page_t page, bool flag)
{
  if (!page) {
    return;
  }
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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

bool page_is_cs_validated(vm_page_t page)
{
  if (!page) {
    return false;
  }
  bool retval = false;
  if (macOS_HighSierra() || macOS_Mojave()) {
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

void page_set_cs_validated(vm_page_t page, bool flag)
{
  if (!page) {
    return;
  }
  if (macOS_HighSierra() || macOS_Mojave()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_validated = flag;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_validated = flag;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_validated = flag;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_validated = flag;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->cs_validated = flag;
  }
}

bool page_is_cs_tainted(vm_page_t page)
{
  if (!page) {
    return false;
  }
  bool retval = false;
  if (macOS_HighSierra() || macOS_Mojave()) {
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

void page_set_cs_tainted(vm_page_t page, bool flag)
{
  if (!page) {
    return;
  }
  if (macOS_HighSierra() || macOS_Mojave()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_tainted = flag;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_tainted = flag;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_tainted = flag;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_tainted = flag;
  } else if (OSX_Mavericks()) {
    vm_page_fake_mavericks_t page_local = (vm_page_fake_mavericks_t) page;
    page_local->cs_tainted = flag;
  }
}

bool page_is_cs_nx(vm_page_t page)
{
  if (!page) {
    return false;
  }
  bool retval = false;
  if (macOS_HighSierra() || macOS_Mojave()) {
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

void page_set_cs_nx(vm_page_t page, bool flag)
{
  if (!page) {
    return;
  }
  if (macOS_HighSierra() || macOS_Mojave()) {
    vm_page_fake_highsierra_t page_local = (vm_page_fake_highsierra_t) page;
    page_local->cs_nx = flag;
  } else if (macOS_Sierra()) {
    vm_page_fake_sierra_t page_local = (vm_page_fake_sierra_t) page;
    page_local->cs_nx = flag;
  } else if (OSX_ElCapitan()) {
    vm_page_fake_elcapitan_t page_local = (vm_page_fake_elcapitan_t) page;
    page_local->cs_nx = flag;
  } else if (OSX_Yosemite()) {
    vm_page_fake_yosemite_t page_local = (vm_page_fake_yosemite_t) page;
    page_local->cs_nx = flag;
  }
}

bool page_is_slid(vm_page_t page)
{
  // As best I can tell, the notion of slid pages is absent in macOS Mojave.
  if (!page || macOS_Mojave()) {
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
  // As best I can tell, the notion of slid pages is absent in macOS Mojave.
  if (!page || macOS_Mojave()) {
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
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
    if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  // As best I can tell, the notion of slid objects is absent in macOS Mojave.
  if (!object || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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
  if (macOS_Sierra() || macOS_HighSierra() || macOS_Mojave()) {
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

static uint64_t proc_uniqueid(proc_t proc)
{
  if (!proc) {
    return 0;
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
  if (macOS_Mojave()) {
    proc_fake_mojave_t p = (proc_fake_mojave_t) proc;
    return p->task;
  }
  proc_fake_mavericks_t p = (proc_fake_mavericks_t) proc;
  return p->task;
}

static bool IS_64BIT_PROCESS(proc_t proc)
{
  if (!proc) {
    return false;
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

// "struct x86_fx_thread_state" and "struct x86_avx_thread_state" are defined
// in the xnu kernel's osfmk/mach/i386/fp_reg.h.  "struct thread" is defined
// in osfmk/kern/thread.h.  "struct machine_thread" is defined in
// osfmk/i386/thread.h.  For the offsets of fp_valid and ifps, look at the
// machine code for fp_setvalid().  For the offset of iotier_override, look at
// the machine code for set_thread_iotier_override().

typedef struct x86_fx_thread_state_fake
{
  uint64_t pad1[20];
  unsigned short fx_XMM_reg[8][16];
  uint64_t pad2[10];
  unsigned int fp_valid; // Offset 0x1f0
  fp_save_layout_t fp_save_layout;
} x86_fx_thread_state_fake_t;

typedef struct x86_avx_thread_state_fake
{
  uint64_t pad1[20];
  unsigned short fx_XMM_reg[8][16];
  uint64_t pad2[10];
  unsigned int fp_valid; // Offset 0x1f0
  fp_save_layout_t fp_save_layout;
  uint64_t pad3[8];
  unsigned int x_YMMH_reg[4][16];
} x86_avx_thread_state_fake_t;

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
    if (macOS_Mojave()) {
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

#if (0)
x86_fx_thread_state_fake_t *get_fp_thread_state()
{
  thread_t thread = current_thread();
  if (!thread) {
    return NULL;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Mojave()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mojave, ifps);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_development, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_debug, ifps);
      }
    } else if (macOS_HighSierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_highsierra, ifps);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_development, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_debug, ifps);
      }
    } else if (macOS_Sierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_sierra, ifps);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_development, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_debug, ifps);
      }
    } else if (OSX_ElCapitan()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_elcapitan, ifps);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_development, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_debug, ifps);
      }
    } else if (OSX_Yosemite()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_yosemite, ifps);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_development, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_debug, ifps);
      }
    } else if (OSX_Mavericks()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mavericks, ifps);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mavericks_debug, ifps);
      }
    }
  }

  x86_fx_thread_state_fake_t *retval = NULL;
  if (offset_in_struct != -1) {
    retval = *((x86_fx_thread_state_fake_t **)
               ((vm_map_offset_t) thread + offset_in_struct));
  }

  return retval;
}
#endif

#if (0)
vm_map_t thread_map(thread_t thread)
{
  if (!thread) {
    return NULL;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Mojave()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mojave, map);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_development, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_debug, map);
      }
    } else if (macOS_HighSierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_highsierra, map);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_development, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_debug, map);
      }
    } else if (macOS_Sierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_sierra, map);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_development, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_debug, map);
      }
    } else if (OSX_ElCapitan()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_elcapitan, map);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_development, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_debug, map);
      }
    } else if (OSX_Yosemite()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_yosemite, map);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_development, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_debug, map);
      }
    } else if (OSX_Mavericks()) {
      if (kernel_type_is_release()) {
        offset_in_struct = offsetof(struct thread_fake_mavericks, map);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mavericks_debug, map);
      }
    }
  }

  vm_map_t retval = NULL;
  if (offset_in_struct != -1) {
    retval = *((vm_map_t *)((vm_map_offset_t)thread + offset_in_struct));
  }

  return retval;
}
#endif

#if (0)
// Is floating point currently in use (in user space) with an invalid
// state?  Returns false if there isn't any floating point thread state
// (which indicates that floating point isn't currently in use).  Don't do
// too much here -- interrupts are cleared!  For example, the kernel panics
// if you call get_kernel_type() for the first time, or if you call printf()!
//
// This method is probably unnecessary, so from now on we'll try to do
// without it.
extern "C" bool invalid_fp_thread_state()
{
  bool retval = false;
  x86_fx_thread_state_fake_t *thread_state = get_fp_thread_state();
  if (thread_state) {
    retval = (thread_state->fp_valid == 0);
  }
  return retval;
}
#endif

#if (0)
// Don't do too much here -- interrupts are cleared!  For example, the kernel
// panics if you call get_kernel_type() for the first time, or if you call
// printf() at all!
//
// This method causes trouble with the development kernel in recent minor
// updates on macOS 12 and 13 -- kernel panics, often with the message
// "Assertion failed: thread->user_promotion_basepri == 0".  And it is
// probably unnecessary.  So from now on we'll try to do without it.
extern "C" void reset_iotier_override()
{
  thread_t thread = current_thread();
  if (!thread) {
    return;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Mojave()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave, iotier_override);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mojave_debug, iotier_override);
      }
    } else if (macOS_HighSierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra, iotier_override);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_highsierra_debug, iotier_override);
      }
    } else if (macOS_Sierra()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra, iotier_override);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_sierra_debug, iotier_override);
      }
    } else if (OSX_ElCapitan()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan, iotier_override);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_elcapitan_debug, iotier_override);
      }
    } else if (OSX_Yosemite()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite, iotier_override);
      } else if (kernel_type_is_development()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_development, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_yosemite_debug, iotier_override);
      }
    } else if (OSX_Mavericks()) {
      if (kernel_type_is_release()) {
        offset_in_struct =
          offsetof(struct thread_fake_mavericks, iotier_override);
      } else if (kernel_type_is_debug()) {
        offset_in_struct =
          offsetof(struct thread_fake_mavericks_debug, iotier_override);
      }
    }
  }

  if (offset_in_struct != -1) {
    *((int *)((vm_map_offset_t)thread + offset_in_struct)) =
      THROTTLE_LEVEL_NONE;
  }
}
#endif

#if (0)
// Don't do too much here -- interrupts are cleared!  For example, the kernel
// panics if you call get_kernel_type() for the first time, or if you call
// printf() at all!
//
// This method is probably unnecessary, so from now on we'll try to do
// without it.
extern "C" void restore_fp()
{
  thread_t current = current_thread();
  if (current && get_fp_thread_state()) {
    fp_load(current);
  }
}
#endif

// Possible value for uu_flag.
#define UT_NOTCANCELPT 0x00000004  /* not a cancelation point */

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
    if (macOS_Mojave()) {
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
  u_short acflag = -1;
  unsigned int lflag = -1;
  unsigned int flag = -1;
  char procname[PATH_MAX];
  if (proc) {
    pid = proc_pid(proc);
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

  printf("%s: report_proc_thread_state(): proc %s[%d], acflag \'0x%x\', lflag \'0x%x\', flag \'0x%x\', tag \'0x%x\', uu_flag \'0x%x\'\n",
         header, procname, pid, acflag, lflag, flag, tag, uu_flag);
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
// This method no longer works properly on macOS Mojave (10.14) -- neither
// pmap_protect() nor pmap_enter().  pmap_enter() returns no error (when you
// use it), but attempting to write the target memory still triggers a
// write-protect page fault (error code 3, T_PF_PROT | T_PF_WRITE).  This
// only happens when VM_PROT_WRITE is newly added (not when it was already
// present).  It doesn't happen when VM_PROT_EXECUTE is newly added.  I don't
// know what tricks Apple has played, though I may learn more when they
// release the source code for Mojave's xnu kernel.  In the meantime we'll use
// use brute force where necessary -- by changing CR0's write protect bit.
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
  if (!macOS_Mojave()) {
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

  if (!macOS_Mojave()) {
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
    vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

    if (an_entry->is_sub_map) {
      vm_map_offset_t submap_start = map_entry_offset(entry);
      vm_map_offset_t submap_end =
        map_entry_offset(entry) + end_fixed - entry_start;
      vm_submap_iterate_entries(an_entry->vme_object.vmo_submap,
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
    vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

    if (an_entry->is_sub_map) {
      vm_map_offset_t submap_start = map_entry_offset(entry);
      vm_map_offset_t submap_end = 
        map_entry_offset(entry) + end_fixed - entry_start;
      vm_submap_iterate_entries(an_entry->vme_object.vmo_submap,
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

bool user_region_codesigned(vm_map_t map, vm_map_offset_t start,
                            vm_map_offset_t end);
void sign_user_pages(vm_map_t map, vm_map_offset_t start,
                     vm_map_offset_t end);
void unsign_user_pages(vm_map_t map, vm_map_offset_t start,
                       vm_map_offset_t end);

bool proc_copyout(vm_map_t proc_map, const void *source,
                  user_addr_t dest, size_t len,
                  bool needs_exec_prot, bool needs_write_prot)
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
    if (macOS_Mojave()) {
      // Though shared libraries are all "copy on write", Mojave somehow needs
      // us to request this specifically, if SIP is only disabled for kernel
      // extensions.
      if (info.share_mode == SM_COW) {
        new_prot |= VM_PROT_COPY;
      }
    }
    // If we're writing to a "private" region that's codesigned, we should
    // first "unsign" it -- otherwise the OS may give us trouble for setting
    // write permission on a region that should remain unchanged.  We don't
    // need to worry about this for a shared region, because the region we
    // write to will be a private copy of it (generated via COW).  On Mojave
    // we need to do this for all private regions.
    if (info.share_mode == SM_PRIVATE) {
      if (macOS_Mojave() || codesigned) {
        unsign_user_pages(proc_map, dest, dest + len);
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
  }

  // This call to vm_fault() finishes the job of preparing the region that
  // contains 'dest' for writing.  It maps in an unnested region (created
  // above by the call to vm_protect()), or unnests part of a shared region
  // that already had write permission.  This call to vm_fault() also helps
  // to remedy some kind of race condition -- without it we sometimes panic
  // with a write-protect GPF.
  kern_return_t rv =
    vm_fault(proc_map, dest_rounded, new_prot, false, THREAD_UNINT, NULL, 0);
  if (rv == KERN_SUCCESS) {
    vm_map_t oldmap = vm_map_switch(proc_map);
    rv = copyout(source, dest, len);
    vm_map_switch(oldmap);
  }

  // If we've altered a write-protected codesigned region, we need to "sign"
  // it ourselves to prevent later rechecks from finding the signature no
  // longer matches.  On macOS 10.14 (Mojave) we need to "sign" every
  // write-protected page we change, whether or not it's codesigned.
  if (prot_needs_restore) {
    if (macOS_Mojave() || codesigned) {
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
#if (0)
    // As best I can tell, these are no longer necessary, now that we've fixed
    // how we call vm_map_region_recurse_64() in vm_region_get_info() above.
    // I'll probably remove 'needs_exec_prot' and 'needs_write_prot' in a
    // future version of HookCase.
    if (needs_exec_prot) {
      old_prot |= VM_PROT_EXECUTE;
    }
    if (needs_write_prot) {
      old_prot |= VM_PROT_WRITE;
    }
#endif
    vm_protect(proc_map, dest_rounded, len_rounded, false, old_prot);
  }

  return (rv == KERN_SUCCESS);
}

bool proc_mapout(vm_map_t proc_map, const void *source,
                 vm_map_offset_t *target, size_t len,
                 bool src_destroy)
{
  if (!proc_map || !source || !target || !len) {
    return false;
  }
  if (!find_kernel_private_functions()) {
    return false;
  }
  *target = 0;

  vm_map_copy_t copy;
  kern_return_t rv = vm_map_copyin(kernel_map, (vm_map_address_t) source,
                                   len, src_destroy, &copy);
  if (rv != KERN_SUCCESS) {
    return false;
  }
  vm_map_offset_t out;
  rv = vm_map_copyout(proc_map, &out, copy);
  if (rv != KERN_SUCCESS) {
    vm_map_copy_discard(copy);
    return false;
  }
  // On macOS 10.14 (Mojave) we need to "sign" every page we add to proc_map.
  if (macOS_Mojave()) {
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

  vm_map_t oldmap = vm_map_switch(proc_map);
  size_t size;
  kern_return_t rv = copyinstr(source, dest, len, &size);
  vm_map_switch(oldmap);

  return (rv == KERN_SUCCESS);
}

char *basename(const char *path)
{
  static char holder[PATH_MAX];
  if (!path || !path[0]) {
    strncpy(holder, ".", sizeof(holder));
    return holder;
  }

  strncpy(holder, path, sizeof(holder));
  char *retval = NULL;
  char *remaining = holder;
  while (remaining) {
    char *token = strsep(&remaining, "/");
    if (token) {
      retval = token;
    }
  }

  if (!retval) {
    strncpy(holder, path, sizeof(holder));
    return holder;
  }
  return retval;
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
      (!OSX_ElCapitan() && !macOS_Sierra() &&
       !macOS_HighSierra() && !macOS_Mojave()))
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
  if (macOS_Mojave()) {
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
  uint64_t pad2[86];
  volatile uint32_t t_flags; /* Offset 0x300, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x308
  mach_vm_size_t all_image_info_size;    // Offset 0x310
} *task_fake_mavericks_t;

typedef struct _task_fake_yosemite {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[87];
  volatile uint32_t t_flags; /* Offset 0x310, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x318
  mach_vm_size_t all_image_info_size;    // Offset 0x320
} *task_fake_yosemite_t;

typedef struct _task_fake_elcapitan {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[91];
  volatile uint32_t t_flags; /* Offset 0x330, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x338
  mach_vm_size_t all_image_info_size;    // Offset 0x340
} *task_fake_elcapitan_t;

typedef struct _task_fake_sierra {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[108];
  volatile uint32_t t_flags; /* Offset 0x3b8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3c0
  mach_vm_size_t all_image_info_size;    // Offset 0x3c8
} *task_fake_sierra_t;

typedef struct _task_fake_highsierra {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[7];
  queue_head_t threads; // Size 0x10, offset 0x48
  uint64_t pad2[110];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_highsierra_t;

// Apple messed with the development and debug versions of this structure in
// the macOS 10.14.2 release :-(
typedef struct _task_fake_mojave {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[6];
  queue_head_t threads; // Size 0x10, offset 0x40
  uint64_t pad2[109];
  volatile uint32_t t_flags; /* Offset 0x3b8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3c0
  mach_vm_size_t all_image_info_size;    // Offset 0x3c8
} *task_fake_mojave_t;

// Only valid on macOS 10.14.2 and up
typedef struct _task_fake_mojave_dev_debug {
  lck_mtx_t lock;       // Size 0x10
  uint64_t pad1[8];
  queue_head_t threads; // Size 0x10, offset 0x50
  uint64_t pad2[109];
  volatile uint32_t t_flags; /* Offset 0x3c8, general-purpose task flags protected by task_lock (TL) */
  uint32_t pad3[1];
  mach_vm_address_t all_image_info_addr; // Offset 0x3d0
  mach_vm_size_t all_image_info_size;    // Offset 0x3d8
} *task_fake_mojave_dev_debug_t;

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
    return NULL;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Mojave()) {
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

  mach_vm_address_t retval = NULL;
  if (offset_in_struct != -1) {
    retval = *((mach_vm_address_t *)
               ((vm_map_offset_t) task + offset_in_struct));
  }

  return retval;
}

mach_vm_size_t task_all_image_info_size(task_t task)
{
  if (!task) {
    return NULL;
  }

  static vm_map_offset_t offset_in_struct = -1;
  if (offset_in_struct == -1) {
    if (macOS_Mojave()) {
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

  mach_vm_size_t retval = NULL;
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
    if (macOS_Mojave()) {
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
  vm_address_t stubs_table;
  vm_size_t stubs_table_size;
  user_addr_t stubs_table_addr;
  vm_offset_t slide;
  vm_offset_t module_size;
  vm_offset_t pagezero_size;
  // If symbol_type == symbol_type_defined, symbol_index and symbol_count
  // refer to the symbol table itself.  But for symbol_type_undef, they
  // refer to the indirect symbol table.
  uint32_t symbol_index; // Index to "interesting" symbols
  uint32_t symbol_count; // Number of "interesting" symbols
  symbol_type_t symbol_type;
  bool is_64bit;
  bool is_in_shared_cache;
} symbol_table_t;

typedef struct _module_info {
  char path[PATH_MAX];
  user_addr_t load_address; // Slid
  vm_offset_t shared_cache_slide;
  bool libSystem_initialized;
  proc_t proc;
} module_info_t;

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

  vm_offset_t data_sections_offset = 0;
  uint32_t num_data_sections = 0;
  vm_offset_t lazy_ptr_table_offset = 0;
  vm_size_t lazy_ptr_table_size = 0;
  uint32_t lazy_ptr_indirect_symbol_index = 0;
  vm_offset_t stubs_table_offset = 0;
  vm_size_t stubs_table_size = 0;
  uint32_t stubs_indirect_symbol_index = 0;

  bool found_symbol_table = false;
  bool found_indirect_symbol_table = false;
  bool found_linkedit_segment = false;
  bool found_symtab_segment = false;
  bool found_dysymtab_segment = false;

  bool found_data_segment = false;
  bool found_lazy_ptr_table = false;
  bool found_stubs_table = false;

  vm_offset_t module_size = mh_size + cmds_size;
  vm_offset_t pagezero_size = 0;
  uint32_t num_commands = mh_local.ncmds;
  const struct load_command *load_command =
    (struct load_command *) cmds_local;
  vm_offset_t linkedit_fileoff_increment = 0;
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
          slide = module_info->load_address - vmaddr;
        }
        if (!strcmp(segname, "__PAGEZERO")) {
          pagezero_size = vmsize;
        } else {
          vm_offset_t segment_end = vmaddr + slide + vmsize;
          vm_offset_t size_to_segment_end =
            segment_end - module_info->load_address;
          if (size_to_segment_end > module_size) {
            module_size = size_to_segment_end;
          }
        }
        if (!strcmp(segname, "__DATA")) {
          data_sections_offset = sections_offset;
          num_data_sections = nsects;
          found_data_segment = true;
        } else if (!strcmp(segname, "__LINKEDIT")) {
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

  if (found_data_segment && found_indirect_symbol_table &&
      (symbol_type == symbol_type_undef))
  {
    vm_offset_t section_offset = data_sections_offset;
    for (i = 1; i <= num_data_sections; ++i) {
      uint64_t addr;
      uint64_t size;
      bool expected_lazy_align;
      uint8_t type;
      uint32_t indirect_symbol_index;
      bool is_self_modifying = false;
      uint32_t stubs_table_item_size = 0;
      if (is_64bit) {
        struct section_64 *section = (struct section_64 *) section_offset;
        addr = section->addr;
        size = section->size;
        expected_lazy_align = (section->align == 3);
        type = (section->flags & SECTION_TYPE);
        indirect_symbol_index = section->reserved1;
      } else {
        struct section *section = (struct section *) section_offset;
        addr = section->addr;
        size = section->size;
        expected_lazy_align = (section->align == 2);
        type = (section->flags & SECTION_TYPE);
        indirect_symbol_index = section->reserved1;
        is_self_modifying =
          ((section->flags & S_ATTR_SELF_MODIFYING_CODE) != 0);
        stubs_table_item_size = section->reserved2;
      }

      if ((type == S_LAZY_SYMBOL_POINTERS) && size && expected_lazy_align) {
        lazy_ptr_table_offset = addr + slide;
        lazy_ptr_table_size = size;
        lazy_ptr_indirect_symbol_index = indirect_symbol_index;
        found_lazy_ptr_table = true;
      }

      if (!is_64bit) {
        if ((type == S_SYMBOL_STUBS) && is_self_modifying &&
            (stubs_table_item_size == 5) && size)
        {
          stubs_table_offset = addr + slide;
          stubs_table_size = size;
          stubs_indirect_symbol_index = indirect_symbol_index;
          found_stubs_table = true;
        }
      }

      if (is_64bit) {
        section_offset += sizeof(struct section_64);
      } else {
        section_offset += sizeof(struct section);
      }
    }
  }

  vm_deallocate(kernel_map, (vm_map_offset_t) cmds_local, cmds_size);

  if (!found_symbol_table) {
    vm_map_deallocate(proc_map);
    return false;
  }
  if (symbol_type == symbol_type_undef) {
    if (is_64bit) {
      if (!found_lazy_ptr_table) {
        vm_map_deallocate(proc_map);
        return false;
      }
    } else {
      if (!found_lazy_ptr_table && !found_stubs_table) {
        vm_map_deallocate(proc_map);
        return false;
      }
    }
    if (found_lazy_ptr_table) {
      interesting_symbol_index += lazy_ptr_indirect_symbol_index;
      interesting_symbol_count -= lazy_ptr_indirect_symbol_index;
    } else {
      interesting_symbol_index += stubs_indirect_symbol_index;
      interesting_symbol_count -= stubs_indirect_symbol_index;
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
    vm_map_deallocate(proc_map);
    return false;
  }
  vm_map_offset_t string_table_local;
  if (!proc_mapin(proc_map, string_table_offset, &string_table_local,
                  string_table_size))
  {
    vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
    vm_map_deallocate(proc_map);
    return false;
  }
  vm_map_offset_t indirect_symbol_table_local = 0;
  vm_map_offset_t lazy_ptr_table_local = 0;
  vm_map_offset_t stubs_table_local = 0;
  if (symbol_type == symbol_type_undef) {
    if (!proc_mapin(proc_map, indirect_symbol_table_offset,
                    &indirect_symbol_table_local, indirect_symbol_table_size))
    {
      vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
      vm_deallocate(kernel_map, string_table_local, string_table_size);
      vm_map_deallocate(proc_map);
      return false;
    }
    if (found_lazy_ptr_table) {
      if (!proc_mapin(proc_map, lazy_ptr_table_offset, &lazy_ptr_table_local,
                      lazy_ptr_table_size))
      {
        vm_deallocate(kernel_map, symbol_table_local, symbol_table_size);
        vm_deallocate(kernel_map, string_table_local, string_table_size);
        vm_deallocate(kernel_map, indirect_symbol_table_local,
                      indirect_symbol_table_size);
        vm_map_deallocate(proc_map);
        return false;
      }
    } else {
      if (!proc_mapin(proc_map, stubs_table_offset, &stubs_table_local,
                      stubs_table_size))
      {
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
  symbol_table->stubs_table = (vm_address_t) stubs_table_local;
  symbol_table->stubs_table_size = stubs_table_size;
  symbol_table->stubs_table_addr = stubs_table_offset;
  symbol_table->slide = slide;
  symbol_table->module_size = module_size;
  symbol_table->pagezero_size = pagezero_size;
  symbol_table->symbol_index = interesting_symbol_index;
  symbol_table->symbol_count = interesting_symbol_count;
  symbol_table->symbol_type = symbol_type;
  symbol_table->is_64bit = is_64bit;
  symbol_table->is_in_shared_cache = is_in_shared_cache;
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

  if (module_name && module_name[0] &&
      !strcmp(basename(module_name), "dyld"))
  {
    // dyld_image_load_address is inaccurate (zero or unslid) if the process's
    // executable image hasn't yet been initialized (if _dyld_start hasn't
    // yet been called).  So we need to look for the header (and compute its
    // slide) ourselves.
    if (!libSystem_initialized) {
      // all_image_info_addr is always in dyld, and dyld's size is about 1MB.
      int64_t search_start =
        (all_image_info_addr & 0xfffffffffff00000) - 0x100000;
      if (search_start > dyld_image_load_address) {
        dyld_image_load_address = search_start;
      }

      vm_map_offset_t buffer = 0;
      vm_offset_t dyld_slide = 0;
      vm_size_t copyin_size = DYLD_SLIDE_SEARCH_COPYIN_SIZE;
      for (; dyld_slide < DYLD_SLIDE_SEARCH_LIMIT;
           dyld_slide += DYLD_SLIDE_SEARCH_INCREMENT)
      {
        vm_offset_t buffer_offset =
          (dyld_slide % DYLD_SLIDE_SEARCH_COPYIN_SIZE);

        if (!buffer_offset || (copyin_size == DYLD_SLIDE_SEARCH_INCREMENT)) {
          if (buffer) {
            vm_deallocate(kernel_map, buffer, copyin_size);
            buffer = 0;
          }
          if (!buffer_offset) {
            copyin_size = DYLD_SLIDE_SEARCH_COPYIN_SIZE;
          }
          vm_map_copy_t copy;
          kern_return_t rv =
            vm_map_copyin(proc_map, dyld_image_load_address + dyld_slide,
                          copyin_size, false, &copy);
          if (rv != KERN_SUCCESS) {
            vm_size_t old_copyin_size = copyin_size;
            copyin_size = DYLD_SLIDE_SEARCH_INCREMENT;
            if (copyin_size != old_copyin_size) {
              rv = vm_map_copyin(proc_map, dyld_image_load_address + dyld_slide,
                                 copyin_size, false, &copy);
            }
            if (rv != KERN_SUCCESS) {
              continue;
            }
          }
          rv = vm_map_copyout(kernel_map, &buffer, copy);
          if (rv != KERN_SUCCESS) {
            vm_map_copy_discard(copy);
            break;
          }
        }

        addr64_t addr;
        if (copyin_size == DYLD_SLIDE_SEARCH_COPYIN_SIZE) {
          addr = buffer + buffer_offset;
        } else {
          addr = buffer;
        }
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
        vm_deallocate(kernel_map, buffer, copyin_size);
        dyld_image_load_address += dyld_slide;
        break;
      }
    }

    vm_map_deallocate(proc_map);
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
    module_name_is_basename =
      (strcmp(basename(module_name), module_name) == 0);
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
    if (module_name && module_name[0]) {
      if (module_name_is_basename) {
        matched = 
          (strnstr_ptr(basename(path_local), module_name, sizeof(path_local)) != NULL);
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
    if (strcmp(symbol_name, string_table_item)) {
      continue;
    }
    retval = value + symbol_table->slide;
    break;
  }

  return retval;
}

// If DEBUG_LOG is defined, HookCase.kext will attempt to log debugging
// information to the system log via sandboxmirrord from the SandboxMirror
// project (https://github.com/steven-michaud/SandboxMirror).

#ifdef DEBUG_LOG

#define SM_FILENAME_SIZE 1024
typedef char sm_filename_t[SM_FILENAME_SIZE];
#define SM_PATH_SIZE 1024
typedef char sm_path_t[SM_PATH_SIZE];
#define SM_REPORT_SIZE 2048
typedef char sm_report_t[SM_REPORT_SIZE];

void get_proc_path(sm_path_t proc_path)
{
  if (!proc_path) {
    return;
  }
  proc_path[0] = 0;

  char *path_ptr = NULL;
  char **envp = NULL;
  vm_size_t envp_size = 0;
  void *buffer = NULL;
  vm_size_t buf_size = 0;
  if (!get_proc_info(proc_selfpid(), &path_ptr, &envp, &envp_size,
                     &buffer, &buf_size))
  {
    return;
  }

  if (path_ptr) {
    strncpy(proc_path, path_ptr, SM_PATH_SIZE);
  }

  if (envp) {
    IOFree(envp, envp_size);
  }
  IOFree(buffer, buf_size);
}

// We need a "host port" to communicate with sandboxmirrord.  But in recent
// versions of the OS X kernel, Apple reserves all "legal" host ports for its
// own purposes.  So, if possible, we need to steal one.  Apple's CHUD kernel
// extension is obsolete, and very unlikely to be present.  So it's very
// likely that we can safely steal its "host port".
mach_port_t get_server_port()
{
  mach_port_t server_port = 0;
  host_get_special_port(host_priv_self(), HOST_LOCAL_NODE,
                        HOST_CHUD_PORT, &server_port);
  return server_port;
}

// sm_report() and its associated structures and defines are derived from the
// sm_report* files that come with the sandboxmirrord distro -- specifically
// from the files that are generated from sm_report.defs by running 'mig' on
// it.  'mig' "generates" an "interface" whereby we can send Mach messages to
// sandboxmirrord (and receive messages from it).

#define MSGID_BASE 666

#pragma pack(4)
typedef struct {
  mach_msg_header_t Head;
  /* start of the kernel processed data */
  mach_msg_body_t msgh_body;
  mach_msg_port_descriptor_t task;
  /* end of the kernel processed data */
  NDR_record_t NDR;
  int32_t do_stacktrace;
  int32_t pid;
  uint64_t tid;
  mach_msg_type_number_t log_fileOffset; /* MiG doesn't use it */
  mach_msg_type_number_t log_fileCnt;
  char log_file[SM_FILENAME_SIZE];
  mach_msg_type_number_t proc_pathOffset; /* MiG doesn't use it */
  mach_msg_type_number_t proc_pathCnt;
  char proc_path[SM_PATH_SIZE];
  mach_msg_type_number_t reportOffset; /* MiG doesn't use it */
  mach_msg_type_number_t reportCnt;
  char report[SM_REPORT_SIZE];
} Request;

typedef struct {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
} Reply;
#pragma pack()

#define _WALIGN_(x) (((x) + 3) & ~3)

// Kernel private functions needed by sm_report().
typedef mach_port_t (*convert_task_to_port_t)(task_t);
typedef void (*ipc_port_release_send_t)(ipc_port_t port);

kern_return_t sm_report(mach_port_t server_port,
                        task_t task,
                        int32_t do_stacktrace,
                        int32_t pid,
                        uint64_t tid,
                        sm_filename_t log_file,
                        sm_path_t proc_path,
                        sm_report_t report)
{
  static convert_task_to_port_t convert_task_to_port = NULL;
  if (!convert_task_to_port) {
    convert_task_to_port = (convert_task_to_port_t)
      kernel_dlsym("_convert_task_to_port");
    if (!convert_task_to_port) {
      return KERN_FAILURE;
    }
  }
  static ipc_port_release_send_t ipc_port_release_send = NULL;
  if (!ipc_port_release_send) {
    ipc_port_release_send = (ipc_port_release_send_t)
      kernel_dlsym("_ipc_port_release_send");
    if (!ipc_port_release_send) {
      return KERN_FAILURE;
    }
  }

  Request Out;

  Out.msgh_body.msgh_descriptor_count = 1;
  if (task && do_stacktrace) {
    task_reference(task);
    Out.task.name = convert_task_to_port(task);
  } else {
    Out.task.name = MACH_PORT_NULL;
  }
  Out.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  Out.task.type = MACH_MSG_PORT_DESCRIPTOR;

  Out.NDR = NDR_record;
  Out.do_stacktrace = do_stacktrace;
  Out.pid = pid;
  Out.tid = tid;

  Out.log_fileCnt =
    mig_strncpy(Out.log_file, log_file, SM_FILENAME_SIZE);
  unsigned int msgh_size_delta = _WALIGN_(Out.log_fileCnt);
  unsigned int msgh_size = (mach_msg_size_t)
    (sizeof(Request) - (SM_FILENAME_SIZE + SM_PATH_SIZE + SM_REPORT_SIZE)) +
    msgh_size_delta;

  Request *OutP = (Request *)
    (((pointer_t) &Out) + msgh_size_delta - SM_FILENAME_SIZE);
  OutP->proc_pathCnt = mig_strncpy(OutP->proc_path, proc_path, SM_PATH_SIZE);
  msgh_size_delta = _WALIGN_(OutP->proc_pathCnt);
  msgh_size += msgh_size_delta;

  OutP = (Request *)
    (((pointer_t) OutP) + msgh_size_delta - SM_PATH_SIZE);
  OutP->reportCnt = mig_strncpy(OutP->report, report, SM_REPORT_SIZE);
  msgh_size += _WALIGN_(OutP->reportCnt);

  Out.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                       MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  Out.Head.msgh_remote_port = server_port;
  Out.Head.msgh_local_port = mig_get_reply_port();
  Out.Head.msgh_id = MSGID_BASE;

  // This method sends a Mach message concurrently to sandboxmirrord, which
  // makes it possible for sandboxmirrord to take an up-to-date snapshot of
  // the current process.
  mach_msg_return_t msg_result =
    mach_msg_rpc_from_kernel(&Out.Head, msgh_size,
                             (mach_msg_size_t) sizeof(Reply));

  if (msg_result != KERN_SUCCESS) {
    ipc_port_release_send(Out.task.name);
  }

  return msg_result;
}

void do_report(sm_report_t report)
{
  if (!report) {
    return;
  }

  sm_path_t proc_path;
  sm_filename_t log_file;
  get_proc_path(proc_path);
  log_file[0] = 0;

  uint32_t pid = proc_selfpid();
  uint64_t tid = thread_tid(current_thread());
  task_t task = current_task();

  sm_report(get_server_port(), task, true, pid, tid,
            log_file, proc_path, report);
}

#endif // #ifdef DEBUG_LOG

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
  bool page_cs_validated = false;
  bool page_cs_tainted = false;
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
  object = an_entry->vme_object.vmo_object;
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

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

  vm_object_t object = an_entry->vme_object.vmo_object;
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

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

  vm_object_t object = an_entry->vme_object.vmo_object;
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
      page_set_cs_validated(page, true);
      page_set_wpmapped(page, false);
    } else {
      page_set_cs_validated(page, false);
    }

    vm_object_unlock(object);

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

#if (0)
typedef struct ensure_user_region_wired_info {
  bool retval;
} *ensure_user_region_wired_info_t;

void ensure_user_region_wired_iterator(vm_map_t map, vm_map_entry_t entry,
                                       uint32_t submap_level, void *info)
{
  if (!map || !entry || !info) {
    return;
  }
  ensure_user_region_wired_info_t info_local =
    (ensure_user_region_wired_info_t) info;

  vm_map_entry_fake_t an_entry = (vm_map_entry_fake_t) entry;

  if (an_entry->wired_count) {
    return;
  }

  vm_prot_t entry_prot = an_entry->protection;
  vm_map_offset_t entry_start = an_entry->vme_start;
  vm_map_offset_t entry_end = an_entry->vme_end;
  vm_object_t object = an_entry->vme_object.vmo_object;
  vm_object_offset_t offset = map_entry_offset(entry);

  if (!object) {
    info_local->retval = false;
    return;
  }

  uint32_t total_wire_count = *g_vm_page_wire_count + *g_vm_lopage_free_count;
  vm_map_size_t entry_size = entry_end - entry_start;
  vm_map_size_t map_wired_size = vm_map_user_wire_size(map);
  vm_map_size_t global_wired_size = ptoa_64(total_wire_count);
  vm_map_size_t map_wired_limit =
    MIN(vm_map_user_wire_limit(map), *g_vm_user_wire_limit);
  vm_map_size_t global_wired_limit =
    MIN(*g_vm_global_user_wire_limit, 
        *g_max_mem - *g_vm_global_no_user_wire_amount);
  if ((entry_size + map_wired_size > map_wired_limit) ||
      (entry_size + global_wired_size > global_wired_limit))
  {
    info_local->retval = false;
    return;
  }

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

  ++an_entry->wired_count;
  ++an_entry->user_wired_count;
  vm_map_set_user_wire_size(map, map_wired_size + entry_size);

  if (page) {
    vm_page_lockspin_queues();
    vm_page_wire(page, VM_PROT_MEMORY_TAG(entry_prot), false);
    vm_page_unlock_queues();
  }

  pmap_t pmap = vm_map_pmap(map);
  if (pmap) {
    ppnum_t page_num = pmap_find_phys(pmap, entry_start);
    if (page_num) {
      pmap_change_wiring(pmap, entry_start, true);
    }
  }

  vm_object_unlock(object);
}

bool ensure_user_region_wired(vm_map_t map, vm_map_offset_t start,
                              vm_map_offset_t end)
{
  if (!map || (map == kernel_map)) {
    return false;
  }

  struct ensure_user_region_wired_info info;
  bzero(&info, sizeof(info));
  info.retval = true;

  vm_map_iterate_entries(map, start, end, ensure_user_region_wired_iterator, &info);

  return info.retval;
}
#endif

// At the heart of HookCase.kext's infrastructure is a lock-protected linked
// list of hook_t structures.  Think of these as something like fish hooks.
// There are "cast hooks" and "user hooks".  There are also two different
// kinds of "user hook":  "patch hooks" and "interpose hooks".  Each is only
// valid for a particular process (identified by its 64-bit "unique id").
//
// Exactly one hook_t structure is created (and added to the linked list) as a
// cast hook for a process in which we want to set hooks.  It usually lives as
// long as the process itself.  It's used to keep track of the work needed to
// create user hooks.
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
// We've hit the breakpoint a second time, and the call to dlopen() has
// succeeded or failed.  If it succeeded we've looked for hook descriptions
// in the hook library and have tried to set user hooks accordingly (in
// process_hook_flying()).  We've also unset the hook that prevents calls to
// C++ initializers.  If there was no more work to do (whether we succeeded or
// failed), we'll have unset our breakpoint and deleted the cast hook.  In
// that case we won't have reached this point.  But if there might be more
// work to do in the future (on modules that haven't yet been loaded), we've
// set up a call to _dyld_register_func_for_add_image(), and are waiting for
// our breakpoint to be hit a third time (indicating the call has happened).
// If it succeeds, on_add_image() will be called every time a new module is
// loaded.
//
// hook_state_floating
//
// We've hit the breakpoint a third time, and the call to
// _dyld_register_func_for_add_image() has happened (we don't know whether it
// succeeded or failed).  In process_hook_landed() we've unset the breakpoint
// we set in maybe_cast_hook().  Our cast hook is being kept alive for future
// reference.

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
// method itself.  A process's binary is loaded by the parent process, via a
// call (indirectly) to parse_machfile() in the xnu kernel's
// bsd/kern/mach_loader.c.  Among other things, this loads a (shared) copy of
// the /usr/lib/dyld module into the image of every new process (via a call to
// load_dylinker()).  dyld's man page calls it the "dynamic link editor", and
// it's what runs first (starting from _dyld_start in dyld's
// src/dyldStartup.s) as a new process starts up.  Not coincidentally, dyld is
// what implements Apple's support for the DYLD_INSERT_LIBRARIES environment
// variable.  dyld::initializeMainExecutable() is called (from _main()) after
// all the automatically linked shared libraries (including those specified by
// DYLD_INSERT_LIBRARIES) are loaded, but before any of those libraries' C++
// initializers have run (which happens in dyld::initializeMainExecutable()
// itself).  This seems an ideal place to intervene.
//
// As of macOS 10.13, dyld has an alternate way of launching 64-bit executables
// that bypasses dyld::initializeMainExecutable() -- dyld::launchWithClosure().
// But dyld::launchWithClosure() fails over to dyld's "traditional" code path,
// which does use dyld::initializeMainExecutable().  So, in a 64-bit process
// where we might want to set hooks on macOS 10.13, we patch
// dyld::launchWithClosure() to "return false" unconditionally.  Future
// versions of HookCase.kext may need to know more about how this closure
// subsystem works.
//
// maybe_cast_hook() is called just before the new process's execution begins
// at _dyld_start.  There, if appropriate, we write an "int 0x30" breakpoint
// to the beginning of dyld::initializeMainExecutable(), and wait for the
// breakpoint to be hit.  When dealing with a 64-bit process on macOS 10.13,
// we also patch dyld::launchWithClosure() to always "return false".
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
//   4) Set the stack's "return address" to dyld::initializeMainExecutable()
//   5) Set RIP/EIP to dlopen()
//
// Later, in process_hook_landed(), we may set up another call, to
// _dyld_register_func_for_add_image().  This time we need user mode code for
// this method's 'func' argument.  We allocate a page of kernel memory and
// copy to it the appropriate machine code (which contains an "int 0x31"
// instruction).  Then we remap that page into the user process and set the
// 'func' argument accordingly.  We also set RIP/EIP to
// _dyld_register_func_for_add_image() and the "return address" to
// dyld::initializeMainExecutable().  Our int 0x31 handler calls
// on_add_image().
//
// When we're all done, we return the thread state to what it was before the
// first call to dyld::initializeMainExecutable(), remove our breakpoint, set
// RIP/EIP to dyld::initializeMainExecutable(), and allow that call to happen
// as originally intended.

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
    user_addr_t caller_func_ptr;     // const void *
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
    user32_addr_t caller_func_ptr;   // const void *
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
    user_addr_t caller_func_ptr;
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
  user_addr_t orig_addr;
  user_addr_t hook_addr;
  user_addr_t inserted_dylib_textseg;
  vm_size_t inserted_dylib_textseg_len;
  user_addr_t call_orig_func_addr;      // Only used in patch hook
  IORecursiveLock *patch_hook_lock;     // Only used in patch hook
  x86_saved_state_t orig_intr_state;    // Only used in cast hook
  user_addr_t dyld_runInitializers;     // Only used in cast hook
  user_addr_t add_image_func_addr;      // Only used in cast hook
  user_addr_t call_orig_func_block;     // Only used in cast hook
  hook_desc *patch_hooks;               // Only used in cast hook
  hook_desc *interpose_hooks;           // Only used in cast hook
  task_t held_parent_task;              // Only used in cast hook
  pid_t hooked_parent;                  // Only used in cast hook
  uint32_t orig_dyld_runInitializers;   // Only used in cast hook
  uint32_t num_call_orig_funcs;         // Only used in cast hook
  uint32_t num_patch_hooks;             // Only used in cast hook
  uint32_t num_interpose_hooks;         // Only used in cast hook
  bool no_numerical_addrs;              // Only used in cast hook
  uint16_t orig_code;
} hook_t;

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

bool g_locks_inited = false;

lck_grp_attr_t *all_hooks_grp_attr = NULL;
lck_grp_t *all_hooks_grp = NULL;
lck_attr_t *all_hooks_attr = NULL;
lck_mtx_t *all_hooks_mlock = NULL;
LIST_HEAD(hook_list, _hook);
struct hook_list g_all_hooks;

bool check_init_locks()
{
  if (g_locks_inited) {
    return true;
  }

  LIST_INIT(&g_all_hooks);
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
  all_hooks_mlock = lck_mtx_alloc_init(all_hooks_grp, all_hooks_attr);
  if (!all_hooks_mlock) {
    return false;
  }

  g_locks_inited = true;
  return true;
}

void all_hooks_lock()
{
  if (check_init_locks()) {
    lck_mtx_lock(all_hooks_mlock);
  }
}

void all_hooks_unlock()
{
  if (check_init_locks()) {
    lck_mtx_unlock(all_hooks_mlock);
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

void add_hook(hook_t *hookp)
{
  if (!hookp || !check_init_locks()) {
    return;
  }
  all_hooks_lock();
  LIST_INSERT_HEAD(&g_all_hooks, hookp, list_entry);
  all_hooks_unlock();
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
  if (hookp->held_parent_task) {
    task_release(hookp->held_parent_task);
    task_deallocate(hookp->held_parent_task);
  }
  IOFree(hookp, sizeof(hook_t));
}

void remove_hook(hook_t *hookp)
{
  if (!hookp || !check_init_locks()) {
    return;
  }
  all_hooks_lock();
  LIST_REMOVE(hookp, list_entry);
  free_hook(hookp);
  all_hooks_unlock();
}

hook_t *find_hook(user_addr_t orig_addr, uint64_t unique_pid)
{
  if (!check_init_locks() || !orig_addr || !unique_pid) {
    return NULL;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->orig_addr == orig_addr) &&
        (hookp->unique_pid == unique_pid))
    {
      break;
    }
  }
  all_hooks_unlock();
  return hookp;
}

hook_t *find_hook_with_hook_addr(user_addr_t hook_addr, uint64_t unique_pid)
{
  if (!check_init_locks() || !hook_addr || !unique_pid) {
    return NULL;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->hook_addr == hook_addr) &&
        (hookp->unique_pid == unique_pid))
    {
      break;
    }
  }
  all_hooks_unlock();
  return hookp;
}

hook_t *find_hook_with_add_image_func(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return NULL;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if ((hookp->unique_pid == unique_pid) && hookp->add_image_func_addr) {
      break;
    }
  }
  all_hooks_unlock();
  return hookp;
}

void remove_process_hooks(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    if (hookp->unique_pid == unique_pid) {
      LIST_REMOVE(hookp, list_entry);
      free_hook(hookp);
    }
  }
  all_hooks_unlock();
}

bool process_has_hooks(uint64_t unique_pid)
{
  if (!check_init_locks() || !unique_pid) {
    return false;
  }
  bool retval = false;
  all_hooks_lock();
  hook_t *hookp = NULL;
  LIST_FOREACH(hookp, &g_all_hooks, list_entry) {
    if (hookp->unique_pid == unique_pid) {
      retval = true;
      break;
    }
  }
  all_hooks_unlock();
  return retval;
}

#if (0)
// This is unsafe -- proc_find() sometimes hangs, possibly when its pid_t
// parameter is itself a zombie process.  Until we find a safe way to do it,
// we can't remove "dead" hooks.
void remove_zombie_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    proc_t proc = proc_find(hookp->pid);
    if (!proc || (hookp->unique_pid != proc_uniqueid(proc))) {
      LIST_REMOVE(hookp, list_entry);
      free_hook(hookp);
    }
  }
  all_hooks_unlock();
}
#endif

void destroy_locks()
{
  if (!g_locks_inited) {
    return;
  }

  if (all_hooks_mlock && all_hooks_grp) {
    lck_mtx_free(all_hooks_mlock, all_hooks_grp);
    all_hooks_mlock = NULL;
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

  g_locks_inited = false;
}

void destroy_all_hooks()
{
  if (!check_init_locks()) {
    return;
  }
  all_hooks_lock();
  hook_t *hookp = NULL;
  hook_t *tmp_hookp = NULL;
  LIST_FOREACH_SAFE(hookp, &g_all_hooks, list_entry, tmp_hookp) {
    LIST_REMOVE(hookp, list_entry);
    free_hook(hookp);
  }
  all_hooks_unlock();

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

// Check if 'proc' (or its XPC parent) has an HC_INSERT_LIBRARY, HC_NOKIDS or
// HC_NO_NUMERICAL_ADDRS environment variable that we should pay attention to.
bool get_cast_info(proc_t proc, hc_path_t proc_path, hc_path_t dylib_path,
                   pid_t *hooked_parent, bool *no_numerical_addrs)
{
  if (!proc || !proc_path || !dylib_path ||
      !hooked_parent || !no_numerical_addrs)
  {
    return false;
  }
  proc_path[0] = 0;
  dylib_path[0] = 0;
  *hooked_parent = 0;
  *no_numerical_addrs = false;

  char *path_ptr = NULL;
  char **envp = NULL;
  vm_size_t envp_size = 0;
  void *buffer = NULL;
  vm_size_t buf_size = 0;
  if (!get_proc_info(proc_pid(proc), &path_ptr, &envp, &envp_size,
                     &buffer, &buf_size))
  {
    return false;
  }

  if (path_ptr) {
    strncpy(proc_path, path_ptr, HC_PATH_SIZE);
  }

  // Though it's very unlikely, we might have a process path and no
  // environment.
  if (!envp) {
    IOFree(buffer, buf_size);
    return false;
  }

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
      if (!strcmp(key, HC_INSERT_LIBRARY_ENV_VAR)) {
        strncpy(dylib_path, value, HC_PATH_SIZE);
        found_insert_file_variable = true;
        found_trigger_variable = true;
      } else if (!strcmp(key, HC_NOKIDS_ENV_VAR)) {
        no_kids = true;
        found_trigger_variable = true;
      } else if (!strcmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR)) {
        *no_numerical_addrs = true;
        found_trigger_variable = true;
      }
    }
  }
  IOFree(envp, envp_size);
  IOFree(buffer, buf_size);

  bool is_child = false;

  if (found_trigger_variable) {
    pid_t normal_parent = proc_ppid(proc);
    if ((normal_parent > 0) && (normal_parent != 1)) {
      if (get_proc_info(normal_parent, &path_ptr,
                        &envp, &envp_size, &buffer, &buf_size))
      {
        if (envp) {
          for (i = 0; envp[i]; ++i) {
            char *value = envp[i];
            char *key = strsep(&value, "=");
            if (key && value && value[0]) {
              if (!strcmp(key, HC_INSERT_LIBRARY_ENV_VAR) ||
                  !strcmp(key, HC_NOKIDS_ENV_VAR) ||
                  !strcmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR))
              {
                is_child = true;
                *hooked_parent = normal_parent;
                break;
              }
            }
          }
          IOFree(envp, envp_size);
        }
        IOFree(buffer, buf_size);
      }
    }
  } else {
    pid_t xpc_parent = get_xpc_parent(proc_pid(proc));
    if (xpc_parent) {
      if (get_proc_info(xpc_parent, &path_ptr, &envp, &envp_size,
                        &buffer, &buf_size))
      {
        if (envp) {
          for (i = 0; envp[i]; ++i) {
            char *value = envp[i];
            char *key = strsep(&value, "=");
            if (key && value && value[0]) {
              if (!strcmp(key, HC_INSERT_LIBRARY_ENV_VAR)) {
                strncpy(dylib_path, value, HC_PATH_SIZE);
                found_insert_file_variable = true;
                is_child = true;
                *hooked_parent = xpc_parent;
              } else if (!strcmp(key, HC_NOKIDS_ENV_VAR)) {
                no_kids = true;
                is_child = true;
                *hooked_parent = xpc_parent;
              } else if (!strcmp(key, HC_NO_NUMERICAL_ADDRS_ENV_VAR)) {
                *no_numerical_addrs = true;
                is_child = true;
                *hooked_parent = xpc_parent;
              }
            }
          }
          IOFree(envp, envp_size);
        }
        IOFree(buffer, buf_size);
      }
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
  pid_t hooked_parent;
  bool no_numerical_addrs;
  bool rv = get_cast_info(proc, proc_path, dylib_path,
                          &hooked_parent, &no_numerical_addrs);
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

  // We start setting hooks just before dyld::initializeMainExecutable() runs.
  // It's called (from _main()) after all the automatically linked shared
  // libraries are loaded, but before any of those libraries' C++ initializers
  // have run (which happens in dyld::InitializeMainExecutable() itself).
  // This seems an ideal place to intervene.
  user_addr_t initializeMainExecutable = 0;
  user_addr_t dyld_runInitializers = 0;
  user_addr_t dyld_launchWithClosure = 0;
  user_addr_t dyld_buildLaunchClosure = 0;
  module_info_t module_info;
  symbol_table_t symbol_table;
  if (get_module_info(proc, "dyld", 0, &module_info)) {
    if (copyin_symbol_table(&module_info, &symbol_table,
                            symbol_type_defined))
    {
      initializeMainExecutable =
        find_symbol("__ZN4dyld24initializeMainExecutableEv", &symbol_table);
      dyld_runInitializers =
        find_symbol("__ZN4dyld15runInitializersEP11ImageLoader", &symbol_table);
      if (IS_64BIT_PROCESS(proc)) {
        if (macOS_Mojave()) {
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

  uint32_t orig_dyld_runInitializers = 0;
  if (!proc_copyin(proc_map, dyld_runInitializers, &orig_dyld_runInitializers,
                   sizeof(orig_dyld_runInitializers)))
  {
    vm_map_deallocate(proc_map);
    return false;
  }

  hook_t *hookp = create_hook();
  if (!hookp) {
    vm_map_deallocate(proc_map);
    return false;
  }

  hookp->pid = proc_pid(proc);
  hookp->unique_pid = unique_pid;
  strncpy(hookp->proc_path, proc_path, sizeof(hc_path_t));
  strncpy(hookp->inserted_dylib_path, dylib_path, sizeof(hc_path_t));
  hookp->orig_addr = initializeMainExecutable;
  hookp->orig_code = orig_code;
  hookp->dyld_runInitializers = dyld_runInitializers;
  hookp->orig_dyld_runInitializers = orig_dyld_runInitializers;
  hookp->no_numerical_addrs = no_numerical_addrs;

  // If debug logging is on, suspend the parent process if we might have hooks
  // in it.  Our initialization can take a while if debug logging is on, and
  // might confuse timers running in our parent.  (Suspending the parent also
  // suspends its timers, of course.)  If it hasn't already happened by other
  // means, the parent gets resumed when our cast hook is deleted.
  if (hooked_parent) {
    hookp->hooked_parent = hooked_parent;
#ifdef DEBUG_LOG
    proc_t parent_proc = proc_find(hooked_parent);
    if (parent_proc) {
      task_t parent_task = proc_task(parent_proc);
      proc_rele(parent_proc);
      if (parent_task) {
        task_reference(parent_task);
        task_hold(parent_task);
        task_wait(parent_task, false);
        hookp->held_parent_task = parent_task;
      }
    }
#endif
  }

  uint16_t new_code = HC_INT1_OPCODE_SHORT;
  bool rv1 = proc_copyout(proc_map, &new_code, initializeMainExecutable,
                          sizeof(new_code), true, false);
  bool rv2 = true, rv3 = true;
  // If a 64-bit process is being launched on macOS 10.13 or 10.14, dyld might
  // call dyld::launchWithClosure(), and take a code path that never calls
  // dyld::initializeMainExecutable().  To prevent this we patch
  // dyld::launchWithClosure() to make it always "return false".  This makes
  // dyld fail over to the code path that calls
  // dyld::initializeMainExecutable().  On 10.14 dyld::launchWithClosure() is
  // (potentially) called twice, and dyld::buildLaunchClosure() is called if
  // first call fails.  So on 10.14 we also need to make
  // dyld::buildLaunchClosure() "return NULL".  This prevents the second call
  // to dyld::launchWithClosure(), and stops us wasting time to rebuild
  // closures that already exist.
  uint32_t new_lwc = RETURN_NULL_64BIT_INT;
  if (dyld_launchWithClosure) {
    rv2 = proc_copyout(proc_map, &new_lwc, dyld_launchWithClosure,
                       sizeof(new_lwc), true, false);
  }
  if (dyld_buildLaunchClosure) {
    rv3 = proc_copyout(proc_map, &new_lwc, dyld_buildLaunchClosure,
                       sizeof(new_lwc), true, false);
  }
  vm_map_deallocate(proc_map);
  if (!rv1 || !rv2 || !rv3) {
    free_hook(hookp);
    return false;
  }

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "maybe_cast_hook(): dyld::initializeMainExecutable \'0x%llx\', pid \'%d\', unique_pid \'%lld\'",
           initializeMainExecutable, proc_pid(proc), unique_pid);
  do_report(report);
#endif

  hookp->state = hook_state_cast;
  add_hook(hookp);
  return true;
}

// Our breakpoint at dyld::initializeMainExecutable() has been hit for the
// first time.  Set up a call to dlopen() our hook library and wait for it to
// be hit again, triggering a call to process_hook_flying().  Also hook
// dyld::runInitializers() to prevent the call to dlopen() from triggering any
// calls to C++ initializers.  (Otherwise some of those initializers would run
// before we had a chance to hook methods they call.)
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
                     sizeof(hookp->orig_code), true, false))
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
                      inserted_dylib_path, path_len, false, true) ||
        !proc_copyout(proc_map, &hookp->orig_addr,
                      return_address, sizeof(uint64_t), false, true))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code), true, false))
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
                      inserted_dylib_path, path_len, false, true) ||
        !proc_copyout(proc_map, args, args_base, sizeof(args), false, true))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code), true, false))
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

  // Patch dyld::runInitializers() to always "return 0".  This prevents calls
  // to C++ initializers from being triggered by our call to dlopen().
  // Without this, C++ initializers might call methods before we've had a
  // chance to hook them.  We'll restore the original method later in
  // process_hook_flying().
  uint32_t new_code;
  if (intr_state->flavor == x86_SAVED_STATE64) {
    new_code = RETURN_NULL_64BIT_INT;
  } else {     // flavor == x86_SAVED_STATE32
    new_code = RETURN_NULL_32BIT_INT;
  }
  proc_copyout(proc_map, &new_code, hookp->dyld_runInitializers,
               sizeof(new_code), true, false);

  vm_map_deallocate(proc_map);
  hookp->state = hook_state_flying;

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "process_hook_cast(): pid \'%d\', unique_pid \'%lld\'",
           proc_pid(proc), proc_uniqueid(proc));
  do_report(report);
#endif
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
      if (!user_hooks[i].caller_func_ptr) {
        printf("HookCase(%s[%d]): get_valid_user_hooks(%s): No caller specified for function \"%s\" in module \"%s\"\n",
               procname, proc_pid(proc), inserted_dylib_path, user_hooks[i].orig_function_name, user_hooks[i].orig_module_name);
        user_hooks[i].hook_function = 0;
        continue;
      }
      // If possible, canonicalize orig_module_name.
      hc_path_t fixed_module_name;
      fixed_module_name[0] = 0;
      vfs_context_t context = vfs_context_create(NULL);
      if (context) {
        vnode_t module_vnode;
        if (!vnode_lookup(user_hooks[i].orig_module_name, 0,
                          &module_vnode, context))
        {
          int len = sizeof(fixed_module_name);
          vn_getpath(module_vnode, fixed_module_name, &len);
          vnode_put(module_vnode);
        }
        vfs_context_rele(context);
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
          !patch_hooks[i].caller_func_ptr ||
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

// Get the user hook information contained in our hook library.
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
        if (!strcmp(segname, "__TEXT")) {
          cast_hookp->inserted_dylib_textseg = vmaddr + slide;
          cast_hookp->inserted_dylib_textseg_len = vmsize;
        }
        if (!strcmp(segname, "__DATA")) {
          data_sections_offset = sections_offset;
          num_data_sections = nsects;
          found_data_segment = true;
          i = num_commands + 1;
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

  vm_offset_t section_offset = data_sections_offset;
  for (i = 1; i <= num_data_sections; ++i) {
    char *sectname;
    uint64_t addr;
    uint64_t size;
    if (is_64bit) {
      struct section_64 *section = (struct section_64 *) section_offset;
      sectname = section->sectname;
      addr = section->addr;
      size = section->size;
    } else {
      struct section *section = (struct section *) section_offset;
      sectname = section->sectname;
      addr = section->addr;
      size = section->size;
    }

    if (!strcmp(sectname, "__hook")) {
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
      section_offset += sizeof(struct section_64);
    } else {
      section_offset += sizeof(struct section);
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
                   code_buffer_len, true, false))
  {
    if (!proc_copyout(proc_map, &orig_addr, orig_func_ptr_addr,
                      sizeof(orig_addr), false, false))
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
  if (proc_mapout(proc_map, page_buffer, &block, 2 * PAGE_SIZE, true)) {
    vm_protect(proc_map, block, PAGE_SIZE, false,
               VM_PROT_READ | VM_PROT_EXECUTE);
    vm_protect(proc_map, block + PAGE_SIZE, PAGE_SIZE, false,
               VM_PROT_READ);
    cast_hookp->call_orig_func_block = block;
  } else {
    IOFreePageable(page_buffer, 2 * PAGE_SIZE);
    rv = false;
  }

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
        !patch_hooks[i].caller_func_ptr ||
        !patch_hooks[i].orig_function_name[0] ||
        !patch_hooks[i].orig_module_name[0])
    {
      continue;
    }

    if (find_hook_with_hook_addr(patch_hooks[i].hook_function, unique_pid)) {
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
    uint16_t orig_code = (uint16_t) (prologue & 0xffff);

    hook_t *hookp = create_hook();
    if (!hookp) {
      continue;
    }

    hookp->patch_hook_lock = IORecursiveLockAlloc();
    if (!hookp->patch_hook_lock) {
      free_hook(hookp);
      continue;
    }

    bool use_call_orig_func =
      can_use_call_orig_func(proc, cast_hookp, prologue);
    if (use_call_orig_func) {
      if (!set_call_orig_func(proc, proc_map, hookp, cast_hookp, orig_addr)) {
        free_hook(hookp);
        continue;
      }
    }

    user_addr_t caller_addr = orig_addr;
    if (use_call_orig_func) {
      caller_addr = hookp->call_orig_func_addr;
    }
    size_t sizeof_caller_addr;
    if (is_64bit) {
      sizeof_caller_addr = sizeof(uint64_t);
    } else {
      sizeof_caller_addr = sizeof(uint32_t);
    }
    if (!proc_copyout(proc_map, &caller_addr, patch_hooks[i].caller_func_ptr,
                      sizeof_caller_addr, false, true))
    {
      free_hook(hookp);
      continue;
    }

    uint16_t new_code = HC_INT1_OPCODE_SHORT;
    if (!proc_copyout(proc_map, &new_code, orig_addr,
                      sizeof(new_code), true, false))
    {
      free_hook(hookp);
      continue;
    }

#if (0)
    // I'm not sure this really helps.
    if (use_call_orig_func) {
      ensure_user_region_wired(proc_map, orig_addr,
                               orig_addr + sizeof(new_code));
    }
#endif

    hookp->pid = cast_hookp->pid;
    hookp->unique_pid = cast_hookp->unique_pid;
    strncpy(hookp->proc_path, cast_hookp->proc_path,
            sizeof(hookp->proc_path));
    strncpy(hookp->inserted_dylib_path, cast_hookp->inserted_dylib_path,
            sizeof(hookp->inserted_dylib_path));
    hookp->inserted_dylib_textseg = cast_hookp->inserted_dylib_textseg;
    hookp->inserted_dylib_textseg_len = cast_hookp->inserted_dylib_textseg_len;
    hookp->orig_addr = orig_addr;
    hookp->orig_code = orig_code;
    hookp->hook_addr = patch_hooks[i].hook_function;

    patch_hooks[i].hook_function = 0;

    hookp->state = hook_state_set;
    add_hook(hookp);
  }
}

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

    char *string_table_item;
    if (symbol_table.is_64bit) {
      struct nlist_64 *symbol_table_item = (struct nlist_64 *)
        (symbol_table.symbol_table +
          *indirectSymbolTableItem * sizeof(struct nlist_64));
      string_table_item = (char *)
        (symbol_table.string_table + symbol_table_item->n_un.n_strx);
    } else {
      struct nlist *symbol_table_item = (struct nlist *)
        (symbol_table.symbol_table +
          *indirectSymbolTableItem * sizeof(struct nlist));
      string_table_item = (char *)
        (symbol_table.string_table + symbol_table_item->n_un.n_strx);
    }

    for (j = 0; j < num_interpose_hooks; ++j) {
      if (!interpose_hooks[j].hook_function ||
          !interpose_hooks[j].orig_function_name[0])
      {
        continue;
      }
      if (!strcmp(string_table_item, interpose_hooks[j].orig_function_name)) {
        user_addr_t module_begin = module_info->load_address;
        user_addr_t module_end = module_begin + symbol_table.module_size;
        uint32_t target_index = i - symbol_table.symbol_index;
        if (symbol_table.lazy_ptr_table) {
          if (is_64bit) {
            uint64_t new_lazy_ptr = interpose_hooks[j].hook_function;
            uint64_t old_lazy_ptr =
              ((uint64_t *)(symbol_table.lazy_ptr_table))[target_index];
            user_addr_t old_lazy_ptr_offset = symbol_table.lazy_ptr_table_addr +
              target_index * sizeof(old_lazy_ptr);
            // Don't change 'old_lazy_ptr' if it's already been changed --
            // presumably via DYLD_INSERT_LIBRARIES.  But note that it won't
            // be NULL if it's not yet been initialized -- it will point to a
            // local method for lazily setting it to the correct (external)
            // value.
            bool uninitialized = (!symbol_table.is_in_shared_cache &&
                                 (old_lazy_ptr > module_begin) &&
                                 (old_lazy_ptr < module_end));
            if (!interpose_hooks[j].orig_function || uninitialized ||
                (old_lazy_ptr == interpose_hooks[j].orig_function))
            {
              proc_copyout(proc_map, &new_lazy_ptr, old_lazy_ptr_offset,
                           sizeof(new_lazy_ptr), false, true);
            }
          } else {
            uint32_t new_lazy_ptr =
              (uint32_t) interpose_hooks[j].hook_function;
            uint32_t old_lazy_ptr =
              ((uint32_t *)(symbol_table.lazy_ptr_table))[target_index];
            user_addr_t old_lazy_ptr_offset = symbol_table.lazy_ptr_table_addr +
              target_index * sizeof(old_lazy_ptr);
            // Don't change 'old_lazy_ptr' if it's already been changed --
            // presumably via DYLD_INSERT_LIBRARIES.  But note that it won't
            // be NULL if it's not yet been initialized -- it will point to a
            // local method for lazily setting it to the correct (external)
            // value.
            bool uninitialized = (!symbol_table.is_in_shared_cache &&
                                 (old_lazy_ptr > module_begin) &&
                                 (old_lazy_ptr < module_end));
            if (!interpose_hooks[j].orig_function || uninitialized ||
                (old_lazy_ptr == (uint32_t) interpose_hooks[j].orig_function))
            {
              proc_copyout(proc_map, &new_lazy_ptr, old_lazy_ptr_offset,
                           sizeof(new_lazy_ptr), false, true);
            }
          }
        } else {
          unsigned char old_entry[5];
          memcpy(old_entry, (void *)
                 (symbol_table.stubs_table + target_index * sizeof(old_entry)),
                 sizeof(old_entry));
          user_addr_t old_entry_offset = symbol_table.stubs_table_addr +
            target_index * sizeof(old_entry);

          int32_t eip = (int32_t) symbol_table.stubs_table_addr +
            (target_index + 1) * sizeof(old_entry);
          int32_t *displacementAddr = (int32_t *) (old_entry + 1);
          int32_t old_function = *displacementAddr + eip;

          unsigned char new_entry[5];
          unsigned char *opcodeAddr = (unsigned char *) new_entry;
          displacementAddr = (int32_t *) (opcodeAddr + 1);
          int32_t new_displacement =
            (int32_t) (interpose_hooks[j].hook_function) - eip;
          *displacementAddr = new_displacement;
          *opcodeAddr = 0xE9;

          // Don't change 'old_function' if it's already been changed --
          // presumably via DYLD_INSERT_LIBRARIES.  But note that it won't
          // be NULL if it's not yet been initialized -- it will point to a
          // local method for lazily setting it to the correct (external)
          // value.
          bool uninitialized = (!symbol_table.is_in_shared_cache &&
                                (old_function > module_begin) &&
                                (old_function < module_end));
          if (!interpose_hooks[j].orig_function || uninitialized ||
              (old_function == (uint32_t) interpose_hooks[j].orig_function))
          {
            proc_copyout(proc_map, new_entry, old_entry_offset,
                         sizeof(new_entry), true, true);
          }
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
    // Don't set any interpose hooks in our hook library.  That would prevent
    // calls from hooks to their original functions from working properly.
    if (!strcmp(path_local, cast_hookp->inserted_dylib_path)) {
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

bool set_hooks(proc_t proc, vm_map_t proc_map, hook_t *cast_hookp)
{
  if (!proc || !proc_map || !cast_hookp) {
    return false;
  }

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
    set_interpose_hooks(proc, proc_map, cast_hookp,
                        interpose_hooks, num_interpose_hooks);
    cast_hookp->interpose_hooks = interpose_hooks;
    cast_hookp->num_interpose_hooks = num_interpose_hooks;
  }
  if (patch_hooks) {
    set_patch_hooks(proc, proc_map, cast_hookp,
                    patch_hooks, num_patch_hooks);
    cast_hookp->patch_hooks = patch_hooks;
    cast_hookp->num_patch_hooks = num_patch_hooks;
  }

  thread_interrupt_level(old_state);

  if (!check_for_pending_user_hooks(patch_hooks, num_patch_hooks,
                                    interpose_hooks, num_interpose_hooks))
  {
    retval = false;
  }

  return retval;
}

// Our breakpoint at dyld::initializeMainExecutable() has been hit for the
// second time.  If dlopen() loaded our hook library, try to set the hooks it
// describes.  Then if there's no more to do, delete our cast hook, unset our
// breakpoint at dyld::initializeMainExecutable(), and pay no further
// attention to the current user process.  Otherwise set up a call to
// _dyld_register_func_for_add_image(), which (if it succeeds) will trigger
// calls to on_add_image() (below) whenever a new module is loaded.  Then wait
// for our dyld::initializeMainExecutable() breakpoint to be hit again,
// triggering a call to process_hook_landed() below.
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

  // Restore the original dyld::runInitializers() method that we disabled
  // above in process_hook_cast().  Our hook library's C++ initializers (and
  // those of its dependencies) will run along with those from the remaining
  // modules in our host process, when dyld::runInitializers() is called again
  // from dyld::initializeMainExecutable().
  proc_copyout(proc_map, &hookp->orig_dyld_runInitializers,
               hookp->dyld_runInitializers,
               sizeof(hookp->orig_dyld_runInitializers), true, false);

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

  bool user_hooks_pending = false;
  if (dlopen_result) {
    if (set_hooks(proc, proc_map, hookp)) {
      user_hooks_pending = true;
    }
  } else {
    printf("HookCase(%s[%d]): process_hook_flying(): Library \"%s\" not found or can't be loaded\n",
           procname, proc_pid(proc), hookp->inserted_dylib_path);
  }

  if (!user_hooks_pending) {
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code), true, false))
    {
      if (intr_state->flavor == x86_SAVED_STATE64) {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      } else {     // flavor == x86_SAVED_STATE32
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
    }
    vm_map_deallocate(proc_map);

#ifdef DEBUG_LOG
    sm_report_t report;
    snprintf(report, sizeof(report),
             "process_hook_flying(): pid \'%d\', unique_pid \'%lld\', dlopen_result \'0x%llx\'",
              proc_pid(proc), proc_uniqueid(proc), dlopen_result);
    do_report(report);
#endif

    remove_hook(hookp);
    return;
  }

  user_addr_t dyld_register_func_for_add_image = 0;
  module_info_t module_info;
  symbol_table_t symbol_table;
  if (get_module_info(proc, "/usr/lib/system/libdyld.dylib", 0,
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
    if (proc_mapout(proc_map, func_buffer, &on_add_image, PAGE_SIZE, true)) {
      vm_protect(proc_map, on_add_image, PAGE_SIZE, false,
                 VM_PROT_READ | VM_PROT_EXECUTE);
      hookp->add_image_func_addr = on_add_image;
    } else {
      IOFreePageable(func_buffer, PAGE_SIZE);
    }
  }

  if (!dyld_register_func_for_add_image || !on_add_image) {
    if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                     sizeof(hookp->orig_code), true, false))
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
                      return_address, sizeof(uint64_t), false, true))
    {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code), true, false))
      {
        intr_state->ss_64.isf.rip = hookp->orig_addr;
      }
      vm_map_deallocate(proc_map);
      remove_hook(hookp);
      return;
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
    if (!proc_copyout(proc_map, args, args_base, sizeof(args), false, true)) {
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code), true, false))
      {
        intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
      }
      vm_map_deallocate(proc_map);
      remove_hook(hookp);
      return;
    }
    intr_state->ss_32.uesp = stack_base;
    intr_state->ss_32.eip = (uint32_t) dyld_register_func_for_add_image;
  }

  vm_map_deallocate(proc_map);
  hookp->state = hook_state_landed;

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "process_hook_flying(): pid \'%d\', unique_pid \'%lld\', dlopen_result \'0x%llx\'",
           proc_pid(proc), proc_uniqueid(proc), dlopen_result);
  do_report(report);
#endif
}

// Our breakpoint at dyld::initializeMainExecutable() has been hit for the
// third time.  Unset that breakpoint and keep our cast hook alive for future
// reference.  Also resume our parent task, if we suspended it above in
// maybe_cast_hook() above.
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

  // Reset the thread state to what it was just before we hit our
  // dyld::initializeMainExecutable() breakpoint for the first time.
  memcpy(intr_state, &hookp->orig_intr_state, sizeof(x86_saved_state_t));

  if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                   sizeof(hookp->orig_code), true, false))
  {
    if (intr_state->flavor == x86_SAVED_STATE64) {
      intr_state->ss_64.isf.rip = hookp->orig_addr;
    } else {     // flavor == x86_SAVED_STATE32
      intr_state->ss_32.eip = (uint32_t) hookp->orig_addr;
    }
  }

  vm_map_deallocate(proc_map);

  hookp->state = hook_state_floating;

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "process_hook_landed(): pid \'%d\', unique_pid \'%lld\'",
           proc_pid(proc), proc_uniqueid(proc));
  do_report(report);
#endif

  // Resume the parent process if we suspended it in maybe_cast_hook() above.
  if (hookp->held_parent_task) {
    task_release(hookp->held_parent_task);
    task_deallocate(hookp->held_parent_task);
    hookp->held_parent_task = 0;
  }
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
  bool called_from_hook =
    ((return_address >= hook_textseg) && (return_address < hook_textseg_end));

  if (call_orig_func_addr) {
    if (called_from_hook) {
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
        task_hold(task);
        task_wait(task, false);
      }
      if (proc_copyout(proc_map, &hookp->orig_code, hookp->orig_addr,
                       sizeof(hookp->orig_code), true, false))
      {
        hookp->state = hook_state_unset;
      }
      if (called_from_hook) {
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

  vm_map_deallocate(proc_map);

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "process_hook_set(): pid \'%d\', unique_pid \'%lld\'",
           proc_pid(proc), proc_uniqueid(proc));
  do_report(report);
#endif
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
// be hook_state_unset.
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
    find_hook_with_hook_addr(hook_addr, proc_uniqueid(proc));
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
      task_hold(task);
      task_wait(task, false);
    }
    uint16_t new_code = HC_INT1_OPCODE_SHORT;
    if (proc_copyout(proc_map, &new_code, hookp->orig_addr,
                     sizeof(new_code), true, false))
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

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "reset_hook(): pid \'%d\', unique_pid \'%lld\'",
           proc_pid(proc), proc_uniqueid(proc));
  do_report(report);
#endif
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

  if (hookp->patch_hooks) {
    int i;
    for (i = 0; i < hookp->num_patch_hooks; ++i) {
      if (!hookp->patch_hooks[i].hook_function) {
        continue;
      }
      if (strcmp(module_info.path, hookp->patch_hooks[i].orig_module_name)) {
        continue;
      }
      set_patch_hooks(proc, proc_map, hookp,
                      &(hookp->patch_hooks[i]), 1);
    }
  }

  thread_interrupt_level(old_state);

  // Delete our cast hook if we have no more use for it.
  if (!check_for_pending_user_hooks(hookp->patch_hooks,
                                    hookp->num_patch_hooks,
                                    hookp->interpose_hooks,
                                    hookp->num_interpose_hooks))
  {
    remove_hook(hookp);
  }

  vm_map_deallocate(proc_map);

#ifdef DEBUG_LOG
  sm_report_t report;
  snprintf(report, sizeof(report),
           "on_add_image(): pid \'%d\', unique_pid \'%lld\', image \"%s\"",
           proc_pid(proc), proc_uniqueid(proc), module_info.path);
  do_report(report);
#endif
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
typedef int (*execve_t)(proc_t, struct execve_args *, int *);
typedef int (*posix_spawn_t)(proc_t, struct posix_spawn_args *, int *);
typedef int (*mac_execve_t)(proc_t, struct mac_execve_args *, int *);

exit_t g_exit_orig = NULL;
execve_t g_execve_orig = NULL;
posix_spawn_t g_posix_spawn_orig = NULL;
mac_execve_t g_mac_execve_orig = NULL;

int hook_exit(proc_t p, struct exit_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_exit_orig) {
    remove_process_hooks(proc_uniqueid(current_proc()));
    //remove_zombie_hooks();
    retval = g_exit_orig(p, uap, retv);
    /* NOTREACHED */
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
    printf("HookCase: hook_execve(%s[%d])\n",
           procname, proc_pid(proc));
    report_proc_thread_state("HookCase: hook_execve()", current_thread());
#endif
    // On all versions of OS X before Sierra, at this point the current
    // process is the user process that has just been "exec"-ed and is about
    // to start for the first time.  So we should call maybe_cast_hook() now.
    // But on Sierra and above the current process is still the kernel
    // process, so we can't call maybe_cast_hook() here.  Fortunately we can
    // still call it from thread_bootstrap_return_hook() below on Sierra and
    // above, by which time the current process will be the current user
    // process.
#ifndef DEBUG_PROCESS_START
    if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave()) {
      maybe_cast_hook(current_proc());
    }
#endif
  }
  return retval;
}

// Darwin supports a POSIX_SPAWN_SETEXEC flag that (as Apple puts it) turns
// posix_spawn() into an "execve() with options", which (basically) loads
// another binary into the current process.  This is used by /usr/bin/arch
// and /usr/libexec/xpcproxy, for example.  When that flag is present we need
// to call maybe_cast_hook() here, as we do in hook_execve() above.  But
// unlike in hook_execve(), we also first need to remove any hooks that we may
// have created for the process before the call to posix_spawn().
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
      printf("HookCase: hook_posix_spawn(%s[%d])\n",
             procname, proc_pid(proc));
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
      if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave()) {
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
    printf("HookCase: hook_mac_execve(%s[%d])\n",
           procname, proc_pid(proc));
    report_proc_thread_state("HookCase: hook_mac_execve()", current_thread());
#endif
#ifndef DEBUG_PROCESS_START
    if (!macOS_Sierra() && !macOS_HighSierra() && !macOS_Mojave()) {
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

uint32_t thread_bootstrap_return_begin = 0;

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
void thread_bootstrap_return_hook(x86_saved_state_t *intr_state)
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
#ifdef DEBUG_PROCESS_START
  if ((info.num_threads == 1) && info.main_thread) {
    char procname[PATH_MAX];
    proc_name(proc_pid(proc), procname, sizeof(procname));
    printf("HookCase: thread_bootstrap_return(%s[%d]): forked_only %d, start_funcs_registered %d\n",
           procname, proc_pid(proc), forked_only, start_funcs_registered);
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
  if (thread_bootstrap_return_begin) {
    return true;
  }

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

  bool retval = true;

  uint32_t *target = (uint32_t *) thread_bootstrap_return;
  thread_bootstrap_return_begin = target[0];

  uint32_t new_begin = thread_bootstrap_return_begin;
  new_begin &= 0xffff0000;
  new_begin |= HC_INT1_OPCODE_SHORT;

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    if (!set_kernel_physmap_protection((vm_map_offset_t) target,
                                       (vm_map_offset_t) target + sizeof(uint32_t),
                                       VM_PROT_ALL, true))
    {
      return false;
    }
  }

  if (!OSCompareAndSwap(thread_bootstrap_return_begin, new_begin, target)) {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  return retval;
}

bool unhook_thread_bootstrap_return()
{
  if (!thread_bootstrap_return_begin) {
    return false;
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) thread_bootstrap_return;
  uint32_t current_value = target[0];

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_ALL, true);
  }

  if (!OSCompareAndSwap(current_value, thread_bootstrap_return_begin, target)) {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  thread_bootstrap_return_begin = 0;

  return retval;
}

typedef void (*vm_page_validate_cs_t)(vm_page_t page);
extern "C" vm_page_validate_cs_t vm_page_validate_cs = NULL;

uint32_t vm_page_validate_cs_begin = 0;

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
void vm_page_validate_cs_hook(x86_saved_state_t *intr_state)
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
    vm_page_validate_cs_caller(page);
  } else {
    // The following line fixes a bug that can be reproduced as follows:
    // 1) Load HookCase.kext into the kernel.
    // 2) Run Safari or Chrome with HC_INSERT_LIBRARY set, for example from
    //    Terminal, to make the app load a hook library.
    // 3) Quit the app.
    // 4) Unload HookCase.kext from the kernel.
    // 5) Run the app from step 2 again in exactly the same way.  Without the
    //    following line, this will result in a "page is slid" kernel panic.
    page_set_cs_validated(page, true);
  }

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

// Set an "int 0x31" breakpoint at the beginning of vm_page_validate_cs(),
// which will trigger calls to vm_page_validate_cs_hook().  Because this
// method has a standard C/C++ prologue, we can use a CALLER to call the
// original method from the hook.  See CALLER in HookCase.s.
bool hook_vm_page_validate_cs()
{
  if (vm_page_validate_cs_begin) {
    return true;
  }

  if (!vm_page_validate_cs) {
    vm_page_validate_cs = (vm_page_validate_cs_t)
      kernel_dlsym("_vm_page_validate_cs");
    if (!vm_page_validate_cs) {
      return false;
    }
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) vm_page_validate_cs;
  vm_page_validate_cs_begin = target[0];

  uint32_t new_begin = vm_page_validate_cs_begin;
  new_begin &= 0xffff0000;
  new_begin |= HC_INT2_OPCODE_SHORT;

  if (!set_kernel_physmap_protection((vm_map_offset_t) target,
                                     (vm_map_offset_t) target + sizeof(uint32_t),
                                     VM_PROT_ALL, true))
  {
    return false;
  }

  if (!OSCompareAndSwap(vm_page_validate_cs_begin, new_begin, target)) {
    retval = false;
  }

  set_kernel_physmap_protection((vm_map_offset_t) target,
                                (vm_map_offset_t) target + sizeof(uint32_t),
                                VM_PROT_READ | VM_PROT_EXECUTE, true);

  return retval;
}

bool unhook_vm_page_validate_cs()
{
  if (!vm_page_validate_cs_begin) {
    return false;
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) vm_page_validate_cs;
  uint32_t current_value = target[0];

  set_kernel_physmap_protection((vm_map_offset_t) target,
                                (vm_map_offset_t) target + sizeof(uint32_t),
                                VM_PROT_ALL, true);

  if (!OSCompareAndSwap(current_value, vm_page_validate_cs_begin, target)) {
    retval = false;
  }

  set_kernel_physmap_protection((vm_map_offset_t) target,
                                (vm_map_offset_t) target + sizeof(uint32_t),
                                VM_PROT_READ | VM_PROT_EXECUTE, true);

  vm_page_validate_cs_begin = 0;

  return retval;
}

typedef int (*mac_file_check_library_validation_t)(proc_t proc,
                                                   struct fileglob *fg,
                                                   off_t slice_offset,
                                                   user_long_t error_message,
                                                   size_t error_message_size);
extern "C" mac_file_check_library_validation_t
  mac_file_check_library_validation = NULL;

uint32_t mac_file_check_library_validation_begin = 0;

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
void mac_file_check_library_validation_hook(x86_saved_state_t *intr_state)
{
  proc_t proc = (proc_t) intr_state->ss_64.rdi;
  struct fileglob *fg = (struct fileglob *) intr_state->ss_64.rsi;
  off_t slice_offset = (off_t) intr_state->ss_64.rdx;
  user_long_t error_message = (user_long_t) intr_state->ss_64.rcx;
  size_t error_message_size = (size_t) intr_state->ss_64.r8;

  int retval = 0;
  if (!process_has_hooks(proc_uniqueid(current_proc()))) {
    retval =
      mac_file_check_library_validation_caller(proc, fg, slice_offset,
                                               error_message,
                                               error_message_size);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_file_check_library_validation()
{
  if (mac_file_check_library_validation_begin) {
    return true;
  }

  if (!mac_file_check_library_validation) {
    mac_file_check_library_validation = (mac_file_check_library_validation_t)
      kernel_dlsym("_mac_file_check_library_validation");
    if (!mac_file_check_library_validation) {
      return false;
    }
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) mac_file_check_library_validation;
  mac_file_check_library_validation_begin = target[0];

  uint32_t new_begin = mac_file_check_library_validation_begin;
  new_begin &= 0xffff0000;
  new_begin |= HC_INT3_OPCODE_SHORT;

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    if (!set_kernel_physmap_protection((vm_map_offset_t) target,
                                       (vm_map_offset_t) target + sizeof(uint32_t),
                                       VM_PROT_ALL, true))
    {
      return false;
    }
  }

  if (!OSCompareAndSwap(mac_file_check_library_validation_begin,
                        new_begin, target))
  {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  return retval;
}

bool unhook_mac_file_check_library_validation()
{
  if (!mac_file_check_library_validation_begin) {
    return false;
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) mac_file_check_library_validation;
  uint32_t current_value = target[0];

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_ALL, true);
  }

  if (!OSCompareAndSwap(current_value,
                        mac_file_check_library_validation_begin,
                        target))
  {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  mac_file_check_library_validation_begin = 0;

  return retval;
}

typedef int (*mac_file_check_mmap_t)(struct ucred *cred, struct fileglob *fg,
                                     int prot, int flags, uint64_t offset,
                                     int *maxprot);
extern "C" mac_file_check_mmap_t mac_file_check_mmap = NULL;

uint32_t mac_file_check_mmap_begin = 0;

void mac_file_check_mmap_hook(x86_saved_state_t *intr_state)
{
  struct ucred *cred = (struct ucred *) intr_state->ss_64.rdi;
  struct fileglob *fg = (struct fileglob *) intr_state->ss_64.rsi;
  int prot = (int) intr_state->ss_64.rdx;
  int flags = (int) intr_state->ss_64.rcx;
  uint64_t offset = (uint64_t) intr_state->ss_64.r8;
  int *maxprot = (int *) intr_state->ss_64.r9;

  int retval = 0;
  if (!process_has_hooks(proc_uniqueid(current_proc()))) {
    retval = mac_file_check_mmap_caller(cred, fg, prot, flags,
                                        offset, maxprot);
  }
  intr_state->ss_64.rax = retval;

  uint64_t return_address = *((uint64_t *)(intr_state->ss_64.isf.rsp));
  intr_state->ss_64.isf.rsp += 8;
  intr_state->ss_64.isf.rip = return_address;
}

bool hook_mac_file_check_mmap()
{
  if (mac_file_check_mmap_begin) {
    return true;
  }

  if (!mac_file_check_mmap) {
    mac_file_check_mmap = (mac_file_check_mmap_t)
      kernel_dlsym("_mac_file_check_mmap");
    if (!mac_file_check_mmap) {
      return false;
    }
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) mac_file_check_mmap;
  mac_file_check_mmap_begin = target[0];

  uint32_t new_begin = mac_file_check_mmap_begin;
  new_begin &= 0xffff0000;
  new_begin |= HC_INT4_OPCODE_SHORT;

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    if (!set_kernel_physmap_protection((vm_map_offset_t) target,
                                       (vm_map_offset_t) target + sizeof(uint32_t),
                                       VM_PROT_ALL, true))
    {
      return false;
    }
  }

  if (!OSCompareAndSwap(mac_file_check_mmap_begin, new_begin, target)) {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  return retval;
}

bool unhook_mac_file_check_mmap()
{
  if (!mac_file_check_mmap_begin) {
    return false;
  }

  bool retval = true;

  uint32_t *target = (uint32_t *) mac_file_check_mmap;
  uint32_t current_value = target[0];

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_ALL, true);
  }

  if (!OSCompareAndSwap(current_value, mac_file_check_mmap_begin, target)) {
    retval = false;
  }

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    set_kernel_physmap_protection((vm_map_offset_t) target,
                                  (vm_map_offset_t) target + sizeof(uint32_t),
                                  VM_PROT_READ | VM_PROT_EXECUTE, true);
  }

  mac_file_check_mmap_begin = 0;

  return retval;
}

boolean_t *g_no_shared_cr3_ptr = (boolean_t *) -1;
boolean_t *g_pmap_smap_enabled_ptr = (boolean_t *) -1;

boolean_t g_kpti_enabled = (boolean_t) -1;

boolean_t g_use_invpcid = (boolean_t) -1;

uint64_t g_cpu_invpcid_target_offset = (uint64_t) -1;
uint64_t g_cpu_task_map_offset = (uint64_t) -1;
uint64_t g_cpu_task_cr3_offset = (uint64_t) -1;
uint64_t g_cpu_task_cr3_minus_offset = (uint64_t) -1;
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

bool s_installed_hc_int1_handler = false;
bool s_installed_hc_int2_handler = false;
bool s_installed_hc_int3_handler = false;
bool s_installed_hc_int4_handler = false;

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

  if (!macOS_Mojave() || macOS_Mojave_less_than_5()) {
    g_use_invpcid = false;
  } else {
    if ((cpuid_leaf7_features_ptr() & CPUID_LEAF7_FEATURE_INVPCID)) {
      g_use_invpcid = true;
    } else {
      g_use_invpcid = false;
    }
  }
}

void initialize_cpu_data_offsets()
{
  if (!find_kernel_private_functions()) {
    return;
  }

  g_cpu_invpcid_target_offset =
    offsetof(cpu_data_fake_t, cpu_invpcid_target);
  g_cpu_task_map_offset =
    offsetof(cpu_data_fake_t, cpu_task_map);
  g_cpu_task_cr3_offset =
    offsetof(cpu_data_fake_t, cpu_task_cr3);
  g_cpu_task_cr3_minus_offset =
    offsetof(cpu_data_fake_t, cpu_task_cr3);
  g_cpu_kernel_cr3_offset =
    offsetof(cpu_data_fake_t, cpu_kernel_cr3);
  g_cpu_user_cr3_offset =
    offsetof(cpu_data_fake_t, cpu_user_cr3);
  g_cpu_uber_isf_offset =
    offsetof(cpu_data_fake_t, cpu_uber_isf);
  g_cpu_uber_tmp_offset =
    offsetof(cpu_data_fake_t, cpu_uber_tmp);
  g_cpu_excstack_offset =
    offsetof(cpu_data_fake_t, cpu_excstack);

  if (!is_kpti_enabled(NULL)) {
    return;
  }

  if (macOS_HighSierra_less_than_4()) {
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_kernel_cr3_goofed);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_user_cr3_goofed);
    return;
  }

  if (macOS_HighSierra() || macOS_Mojave_less_than_5()) {
    return;
  }

  if (macOS_Mojave()) {
    g_cpu_task_map_offset =
      offsetof(cpu_data_fake_t, cpu_task_map_mds);
    g_cpu_task_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_task_cr3_mds);
    g_cpu_task_cr3_minus_offset =
      offsetof(cpu_data_fake_t, cpu_task_cr3_minus);
    g_cpu_kernel_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_kernel_cr3_mds);
    g_cpu_user_cr3_offset =
      offsetof(cpu_data_fake_t, cpu_user_cr3_mds);
    g_cpu_uber_isf_offset =
      offsetof(cpu_data_fake_t, cpu_uber_isf_mds);
    g_cpu_uber_tmp_offset =
      offsetof(cpu_data_fake_t, cpu_uber_tmp_mds);
    g_cpu_excstack_offset =
      offsetof(cpu_data_fake_t, cpu_excstack_mds);
    return;
  }

  // KPTI enabled, backported to 10.12.6 and 10.11.6
  g_cpu_excstack_offset =
    offsetof(cpu_data_fake_t, cpu_excstack_bp);
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

  // On versions of macOS/OS X that support KPTI, idt64_hndl_table0 is either
  // just before gIOHibernateRestoreStack (ElCapitan and the HighSierra debug
  // kernel) or master_idt64 (all the rest).  I don't know the reason for the
  // variation.  Our main concern here is to ensure that there's enough empty
  // space at the end of idt64_hndl_table0.  We try to do that by ensuring
  // that idt64_hndl_table0 and the "next" label in the symbol table are page-
  // aligned and one page apart.  (idt64_hndl_table1, which isn't in all
  // kernels' symbol tables, is counted as part of idt64_hndl_table0.)
  int64_t idt64_hndl_table0_size =
    kernel_master_idt64_addr - g_kernel_idt64_hndl_table0_addr;
  if (idt64_hndl_table0_size != PAGE_SIZE) {
    idt64_hndl_table0_size =
      kernel_gIOHibernateRestoreStack_addr - g_kernel_idt64_hndl_table0_addr;
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
  dispatch_to_kext_bytecodes[11] = 0x48; //    lea   _idt64_hndl_table0(%rip), %rax
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
  //dispatch_to_kext_bytecodes[26] = 0x10;
  //dispatch_to_kext_bytecodes[27] = 0x01;
  //dispatch_to_kext_bytecodes[28] = 0x00;
  //dispatch_to_kext_bytecodes[29] = 0x00;

  uint32_t *cpu_task_cr3_addr = (uint32_t *) &dispatch_to_kext_bytecodes[26];
  cpu_task_cr3_addr[0] = (uint32_t) g_cpu_task_cr3_offset;

  // 0F 22 D8
  dispatch_to_kext_bytecodes[30] = 0x0F; //    mov   %rax, %cr3
  dispatch_to_kext_bytecodes[31] = 0x22;
  dispatch_to_kext_bytecodes[32] = 0xD8;

  // 0F 01 F8
  dispatch_to_kext_bytecodes[33] = 0x0F; //    swapgs
  dispatch_to_kext_bytecodes[34] = 0x01;
  dispatch_to_kext_bytecodes[35] = 0xF8;

  // 48 8D 05 05 00 00 00
  dispatch_to_kext_bytecodes[36] = 0x48; // 1: lea   _kext_handler(%rip), %rax
  dispatch_to_kext_bytecodes[37] = 0x8D;
  dispatch_to_kext_bytecodes[38] = 0x05;
  dispatch_to_kext_bytecodes[39] = 0x05;
  dispatch_to_kext_bytecodes[40] = 0x00;
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

  // On macOS 10.14 (Mojave), set_kernel_physmap_protection() is no longer
  // able to add VM_PROT_WRITE where it wasn't already present, so we need to
  // use brute force here.  Changing CR0's write protect bit has caused us
  // trouble in the past -- sometimes a write-protect page fault still
  // happened when we tried to change kernel memory.  Hopefully we'll be able
  // to avoid that by temporarily disabling preemption and interrupts.
  boolean_t org_int_level = false;
  uintptr_t org_cr0 = 0;
  if (macOS_Mojave()) {
    org_int_level = ml_set_interrupts_enabled(false);
    disable_preemption();
    org_cr0 = get_cr0();
    set_cr0(org_cr0 & ~CR0_WP);
  } else {
    vm_prot_t new_prot = VM_PROT_READ | VM_PROT_WRITE;
    if (is_stub) {
      new_prot |= VM_PROT_EXECUTE;
    }
    if (!set_kernel_physmap_protection(target_offset, target_offset + target_size,
                                       new_prot, true))
    {
      return false;
    }
  }

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

  if (macOS_Mojave()) {
    set_cr0(org_cr0);
    enable_preemption();
    ml_set_interrupts_enabled(org_int_level);
  } else {
    vm_prot_t old_prot = VM_PROT_READ;
    if (is_stub) {
      old_prot |= VM_PROT_EXECUTE;
    }
    set_kernel_physmap_protection(target_offset, target_offset + target_size,
                                  old_prot, true);
  }

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
    default:
      break;
  }
}

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

  if (!macOS_Mojave()) {
    if (!hook_vm_page_validate_cs()) {
      return false;
    }
  }
  if (macOS_HighSierra() || macOS_Sierra() || macOS_Mojave()) {
    if (!hook_mac_file_check_library_validation()) {
      return false;
    }
  }
  if (macOS_HighSierra() || macOS_Sierra() || OSX_ElCapitan() || macOS_Mojave()) {
    if (!hook_mac_file_check_mmap()) {
      return false;
    }
  }
  return hook_thread_bootstrap_return();
}

void remove_intr_handlers()
{
  if (!find_kernel_private_functions()) {
    return;
  }
  unhook_thread_bootstrap_return();
  unhook_mac_file_check_mmap();
  unhook_mac_file_check_library_validation();
  unhook_vm_page_validate_cs();
  remove_intr_handler(HC_INT1);
  remove_intr_handler(HC_INT2);
  remove_intr_handler(HC_INT3);
  remove_intr_handler(HC_INT4);
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
}

extern "C" void handle_kernel_hc_int1(x86_saved_state_t *intr_state)
{
  thread_bootstrap_return_hook(intr_state);
}

extern "C" void handle_kernel_hc_int2(x86_saved_state_t *intr_state)
{
  vm_page_validate_cs_hook(intr_state);
}

extern "C" void handle_kernel_hc_int3(x86_saved_state_t *intr_state)
{
  mac_file_check_library_validation_hook(intr_state);
}

extern "C" void handle_kernel_hc_int4(x86_saved_state_t *intr_state)
{
  mac_file_check_mmap_hook(intr_state);
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
    kprintf("HookCase requires OS X Mavericks (10.9), Yosemite (10.10), El Capitan (10.11), macOS Sierra (10.12), macOS High Sierra (10.13) or macOS Mojave (10.14): current version %s\n",
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
  initialize_use_invpcid();
  initialize_cpu_data_offsets();
  if (!install_intr_handlers()) {
    remove_intr_handlers();
    return KERN_FAILURE;
  }
  if (!install_sysent_hooks()) {
    remove_intr_handlers();
    remove_sysent_hooks();
    return KERN_FAILURE;
  }
  return KERN_SUCCESS;
}

kern_return_t HookCase_stop(kmod_info_t *ki, void *d)
{
  remove_intr_handlers();
  remove_sysent_hooks();
  destroy_all_hooks();
  return KERN_SUCCESS;
}

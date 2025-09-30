// The MIT License (MIT)
//
// Copyright (c) 2025 Steven Michaud
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

// Template for a hook library that can be used to hook C/C++ methods and/or
// swizzle Objective-C methods for debugging/reverse-engineering.
//
// A number of methods are provided to be called from your hooks, including
// ones that make use of Apple's CoreSymbolication framework (which though
// undocumented is heavily used by Apple utilities such as atos, ReportCrash,
// crashreporterd and dtrace).  Particularly useful are LogWithFormat() and
// PrintStackTrace().
//
// Once the hook library is built, use it as follows:
//
// A) From a Terminal prompt:
//    1) HC_INSERT_LIBRARY=/full/path/to/hook.dylib /path/to/application
//
// B) From gdb:
//    1) set HC_INSERT_LIBRARY /full/path/to/hook.dylib
//    2) run
//
// C) From lldb:
//    1) env HC_INSERT_LIBRARY=/full/path/to/hook.dylib
//    2) run

#include <asl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <libproc.h>
#include <stdarg.h>
#include <time.h>
#import <Cocoa/Cocoa.h>
#import <Carbon/Carbon.h>
#import <objc/Object.h>
extern "C" {
#include <mach-o/getsect.h>
}
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/vm_map.h>
#include <libgen.h>
#include <execinfo.h>
#include <termios.h>

pthread_t gMainThreadID = 0;

bool IsMainThread()
{
  return (!gMainThreadID || (gMainThreadID == pthread_self()));
}

bool sGlobalInitDone = false;

void basic_init()
{
  if (!sGlobalInitDone) {
    gMainThreadID = pthread_self();
    sGlobalInitDone = true;
    // Needed for LogWithFormat() to work properly both before and after the
    // CoreFoundation framework is initialized.
    tzset();
    tzsetwall();
  }
}

bool sCFInitialized = false;

void (*__CFInitialize_caller)() = NULL;

static void Hooked___CFInitialize()
{
  __CFInitialize_caller();
  if (!sCFInitialized) {
    basic_init();
  }
  sCFInitialized = true;
}

bool CanUseCF()
{
  return sCFInitialized;
}

#define MAC_OS_X_VERSION_10_9_HEX  0x00000A90
#define MAC_OS_X_VERSION_10_10_HEX 0x00000AA0
#define MAC_OS_X_VERSION_10_11_HEX 0x00000AB0
#define MAC_OS_X_VERSION_10_12_HEX 0x00000AC0
#define MAC_OS_X_VERSION_10_13_HEX 0x00000AD0
#define MAC_OS_X_VERSION_10_14_HEX 0x00000AE0
#define MAC_OS_X_VERSION_10_15_HEX 0x00000AF0
#define MAC_OS_X_VERSION_11_00_HEX 0x00000B00
#define MAC_OS_X_VERSION_12_00_HEX 0x00000C00
#define MAC_OS_X_VERSION_13_00_HEX 0x00000D00
#define MAC_OS_X_VERSION_14_00_HEX 0x00000E00
#define MAC_OS_X_VERSION_15_00_HEX 0x00000F00

char gOSVersionString[PATH_MAX] = {0};

int32_t OSX_Version()
{
  if (!CanUseCF()) {
    return 0;
  }

  static int32_t version = -1;
  if (version != -1) {
    return version;
  }

  CFURLRef url =
    CFURLCreateWithString(kCFAllocatorDefault,
                          CFSTR("file:///System/Library/CoreServices/SystemVersion.plist"),
                          NULL);
  CFReadStreamRef stream =
    CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
  CFReadStreamOpen(stream);
  CFDictionaryRef sysVersionPlist = (CFDictionaryRef)
    CFPropertyListCreateWithStream(kCFAllocatorDefault,
                                   stream, 0, kCFPropertyListImmutable,
                                   NULL, NULL);
  CFReadStreamClose(stream);
  CFRelease(stream);
  CFRelease(url);

  CFStringRef versionString = (CFStringRef)
    CFDictionaryGetValue(sysVersionPlist, CFSTR("ProductVersion"));
  CFStringGetCString(versionString, gOSVersionString,
                     sizeof(gOSVersionString), kCFStringEncodingUTF8);

  CFArrayRef versions =
    CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,
                                           versionString, CFSTR("."));
  CFIndex count = CFArrayGetCount(versions);
  version = 0;
  for (int i = 0; i < count; ++i) {
    CFStringRef component = (CFStringRef) CFArrayGetValueAtIndex(versions, i);
    int value = CFStringGetIntValue(component);
    version += (value << ((2 - i) * 4));
  }
  CFRelease(sysVersionPlist);
  CFRelease(versions);

  return version;
}

bool OSX_Mavericks()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_9_HEX);
}

bool OSX_Yosemite()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_10_HEX);
}

bool OSX_ElCapitan()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_11_HEX);
}

bool macOS_Sierra()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_12_HEX);
}

bool macOS_HighSierra()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_13_HEX);
}

bool macOS_Mojave()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_14_HEX);
}

bool macOS_Catalina()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_15_HEX);
}

bool macOS_BigSur()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_11_00_HEX);
}

bool macOS_Monterey()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_12_00_HEX);
}

bool macOS_Ventura()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_13_00_HEX);
}

bool macOS_Sonoma()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_14_00_HEX);
}

bool macOS_Sequoia()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_15_00_HEX);
}

class nsAutoreleasePool {
public:
    nsAutoreleasePool()
    {
        mLocalPool = [[NSAutoreleasePool alloc] init];
    }
    ~nsAutoreleasePool()
    {
        [mLocalPool release];
    }
private:
    NSAutoreleasePool *mLocalPool;
};

typedef struct _CSTypeRef {
  unsigned long type;
  void *contents;
} CSTypeRef;

static CSTypeRef initializer = {0};

const char *GetOwnerName(void *address, CSTypeRef owner = initializer);
const char *GetAddressString(void *address, CSTypeRef owner = initializer);
void PrintAddress(void *address, CSTypeRef symbolicator = initializer);
void PrintStackTrace();
BOOL SwizzleMethods(Class aClass, SEL orgMethod, SEL posedMethod, BOOL classMethods);

char gProcPath[PROC_PIDPATHINFO_MAXSIZE] = {0};

static void MaybeGetProcPath()
{
  if (gProcPath[0]) {
    return;
  }
  proc_pidpath(getpid(), gProcPath, sizeof(gProcPath) - 1);
}

static void GetThreadName(char *name, size_t size)
{
  pthread_getname_np(pthread_self(), name, size);
}

// Though Macs haven't included a serial port for ages, macOS and OSX still
// support them.  Many kinds of VM software allow you to add a serial port to
// their virtual machines.  When you do this, /dev/tty.serial1 and
// /dev/cu.serial1 appear on reboot.  In VMware Fusion, everything written to
// such a serial port shows up in a file on the virtual machine's host.
//
// Note that macOS/OSX supports serial ports in user-mode and the kernel, but
// not in both at the same time.  You can make the kernel send output from
// kprintf() to a serial port by doing 'nvram boot-args="debug=0x8"', then
// rebooting.  But this makes the kernel "capture" the serial port -- it's no
// longer available to user-mode code, and drivers for it no longer show up in
// the /dev directory.

bool g_serial1_checked = false;
int g_serial1 = -1;
FILE *g_serial1_FILE = NULL;

// It's always been difficult to log output from hook libraries -- especially
// from secondary processes. STDOUT and STDERR are often redirected to
// /dev/null. And sometimes Apple even blocks system log output. As mentioned
// above, a hardware serial port can be used for output. But it's tricky to
// use if you're not running macOS in a VM. It's easier to create a virtual
// serial port inside macOS and use that for logging output. You can do this
// with https://github.com/steven-michaud/PySerialPortLogger. Install it and
// run 'serialportlogger'. Observe the name of its virtual serial port, make
// the definition of VIRTUAL_SERIAL_PORT match it, then uncomment it. If
// you're loading your hook library from the command line, it's also possible
// to redirect logging output (all of it) to your current Terminal session.
// Run the "tty" command in it to find its tty name.
//#define VIRTUAL_SERIAL_PORT "/dev/ttys003"
bool g_virtual_serial_checked = false;
int g_virtual_serial = -1;
FILE *g_virtual_serial_FILE = NULL;

// TTY pipes are *very* finicky. They don't like it when you write too much
// data all at once, or perform sequences of writes too quickly. Doing either
// will make fputs() return EAGAIN ("Resource temporarily unavailable"). To
// avoid this, we break our data into reasonable sized chunks, and do
// tcdrain() after each call to fputs(), to wait until each chunk of data has
// been written to the TTY. _PC_PIPE_BUF is the maximum number of bytes that
// can be written atomically to our TTY pipe. Note that breaking up a UTF-8
// string like this can make parts of it invalid. The software that implements
// our virtual serial port needs to suppress formatting errors to avoid
// trouble from this.
void tty_fputs(const char *s, FILE *stream)
{
  if (!s || !stream) {
    return;
  }

  long pipe_max = fpathconf(fileno(stream), _PC_PIPE_BUF);
  if (pipe_max == -1) {
    fputs(s, stream);
    tcdrain(fileno(stream));
    return;
  }
  char *block = (char *) malloc(pipe_max + 1);
  if (!block) {
    return;
  }

  size_t total_length = strlen(s);
  size_t to_do = pipe_max;
  if (to_do > total_length) {
    to_do = total_length;
  }
  for (size_t done = 0; done < total_length; done += to_do) {
    if (to_do > total_length - done) {
      to_do = total_length - done;
    }
    bzero(block, pipe_max + 1);
    strncpy(block, s + done, to_do);
    int rv = fputs(block, stream);
    tcdrain(fileno(stream));
    if (rv == EOF) {
      break;
    }
  }

  free(block);
}

#ifdef DEBUG_VIRTUAL_SERIAL_PORT
static void LogWithFormat(bool decorate, const char *format, ...);
#endif

static void LogWithFormatV(bool decorate, const char *format, va_list args)
{
  MaybeGetProcPath();

  if (!format || !format[0]) {
    return;
  }

  char *message;
  if (CanUseCF()) {
    CFStringRef formatCFSTR =
      CFStringCreateWithCString(kCFAllocatorDefault, format,
                                kCFStringEncodingUTF8);
    CFStringRef messageCFSTR =
      CFStringCreateWithFormatAndArguments(kCFAllocatorDefault, NULL,
                                           formatCFSTR, args);
    CFRelease(formatCFSTR);
    int length =
      CFStringGetMaximumSizeForEncoding(CFStringGetLength(messageCFSTR),
                                        kCFStringEncodingUTF8);
    message = (char *) calloc(length + 1, 1);
    CFStringGetCString(messageCFSTR, message, length, kCFStringEncodingUTF8);
    CFRelease(messageCFSTR);
  } else {
    vasprintf(&message, format, args);
  }

  char *finished = (char *) calloc(strlen(message) + 1024, 1);
  char timestamp[30] = {0};
  if (CanUseCF()) {
    const time_t currentTime = time(NULL);
    ctime_r(&currentTime, timestamp);
    timestamp[strlen(timestamp) - 1] = 0;
  }
  if (decorate) {
    char threadName[PROC_PIDPATHINFO_MAXSIZE] = {0};
    GetThreadName(threadName, sizeof(threadName) - 1);
    if (CanUseCF()) {
      sprintf(finished, "(%s) %s[%u] %s[%p] %s\n",
              timestamp, gProcPath, getpid(), threadName, pthread_self(), message);
    } else {
      sprintf(finished, "%s[%u] %s[%p] %s\n",
              gProcPath, getpid(), threadName, pthread_self(), message);
    }
  } else {
    sprintf(finished, "%s\n", message);
  }
  free(message);

  char stdout_path[PATH_MAX] = {0};
  fcntl(STDOUT_FILENO, F_GETPATH, stdout_path);
#ifdef VIRTUAL_SERIAL_PORT
  if (!g_virtual_serial_checked) {
    g_virtual_serial_checked = true;
    g_virtual_serial =
      open(VIRTUAL_SERIAL_PORT, O_WRONLY | O_NONBLOCK | O_NOCTTY);
    if (g_virtual_serial >= 0) {
      g_virtual_serial_FILE = fdopen(g_virtual_serial, "w");
    }
#ifdef DEBUG_VIRTUAL_SERIAL_PORT
    if (!g_virtual_serial_FILE) {
      LogWithFormat(true, "Hook.mm: g_virtual_serial %i, g_virtual_serial_FILE %p, errno %i, stdout_path %s",
             g_virtual_serial, g_virtual_serial_FILE, errno, stdout_path);
    }
#endif
  }
#endif
  if (g_virtual_serial_FILE) {
    tty_fputs(finished, g_virtual_serial_FILE);
  } else {
    if (!strcmp("/dev/console", stdout_path) ||
        !strcmp("/dev/null", stdout_path))
    {
      if (CanUseCF()) {
        aslclient asl = asl_open(NULL, "com.apple.console", ASL_OPT_NO_REMOTE);
        aslmsg msg = asl_new(ASL_TYPE_MSG);
        asl_set(msg, ASL_KEY_LEVEL, "3"); // kCFLogLevelError
        asl_set(msg, ASL_KEY_MSG, finished);
        asl_send(asl, msg);
        asl_free(msg);
        asl_close(asl);
      } else {
        if (!g_serial1_checked) {
          g_serial1_checked = true;
          g_serial1 =
            open("/dev/tty.serial1", O_WRONLY | O_NONBLOCK | O_NOCTTY);
          if (g_serial1 >= 0) {
            g_serial1_FILE = fdopen(g_serial1, "w");
          }
        }
        if (g_serial1_FILE) {
          fputs(finished, g_serial1_FILE);
        }
      }
    } else {
      fputs(finished, stdout);
    }
  }

#ifdef DEBUG_STDOUT
  struct stat stdout_stat;
  fstat(STDOUT_FILENO, &stdout_stat);
  char *stdout_info = (char *) calloc(4096, 1);
  sprintf(stdout_info, "stdout: pid \'%i\', path \"%s\", st_dev \'%i\', st_mode \'0x%x\', st_nlink \'%i\', st_ino \'%lli\', st_uid \'%i\', st_gid \'%i\', st_rdev \'%i\', st_size \'%lli\', st_blocks \'%lli\', st_blksize \'%i\', st_flags \'0x%x\', st_gen \'%i\'\n",
          getpid(), stdout_path, stdout_stat.st_dev, stdout_stat.st_mode, stdout_stat.st_nlink,
          stdout_stat.st_ino, stdout_stat.st_uid, stdout_stat.st_gid, stdout_stat.st_rdev,
          stdout_stat.st_size, stdout_stat.st_blocks, stdout_stat.st_blksize,
          stdout_stat.st_flags, stdout_stat.st_gen);

  if (g_virtual_serial_FILE) {
    fputs(finished, g_virtual_serial_FILE);
  } else {
    if (CanUseCF()) {
      aslclient asl = asl_open(NULL, "com.apple.console", ASL_OPT_NO_REMOTE);
      aslmsg msg = asl_new(ASL_TYPE_MSG);
      asl_set(msg, ASL_KEY_LEVEL, "3"); // kCFLogLevelError
      asl_set(msg, ASL_KEY_MSG, stdout_info);
      asl_send(asl, msg);
      asl_free(msg);
      asl_close(asl);
    } else {
      if (!g_serial1_checked) {
        g_serial1_checked = true;
        g_serial1 =
          open("/dev/tty.serial1", O_WRONLY | O_NONBLOCK | O_NOCTTY);
        if (g_serial1 >= 0) {
          g_serial1_FILE = fdopen(g_serial1, "w");
        }
      }
      if (g_serial1_FILE) {
        fputs(stdout_info, g_serial1_FILE);
      }
    }
  }
  free(stdout_info);
#endif

  free(finished);
}

static void LogWithFormat(bool decorate, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  LogWithFormatV(decorate, format, args);
  va_end(args);
}

extern "C" void hooklib_LogWithFormatV(bool decorate, const char *format, va_list args)
{
  LogWithFormatV(decorate, format, args);
}

extern "C" void hooklib_PrintStackTrace()
{
  PrintStackTrace();
}

const struct dyld_all_image_infos *get_all_image_infos()
{
  static dyld_all_image_infos *retval = NULL;

  if (!retval) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t) &info, &count) == KERN_SUCCESS)
    {
      retval = (dyld_all_image_infos *) info.all_image_info_addr;
    }
  }

  return retval;
}

const struct dyld_all_image_infos *(*_dyld_get_all_image_infos)() = NULL;
bool s_dyld_get_all_image_infos_initialized = false;

// Bit in mach_header.flags that indicates whether or not the (dylib) module
// is in the shared cache.
#define MH_SHAREDCACHE 0x80000000

// Helper method for GetModuleHeaderAndSlide() below.
static
#ifdef __LP64__
uintptr_t GetImageSlide(const struct mach_header_64 *mh)
#else
uintptr_t GetImageSlide(const struct mach_header *mh)
#endif
{
  if (!mh) {
    return 0;
  }

  uintptr_t retval = 0;

  if (_dyld_get_all_image_infos && ((mh->flags & MH_SHAREDCACHE) != 0)) {
    const struct dyld_all_image_infos *info = _dyld_get_all_image_infos();
    if (info) {
      retval = info->sharedCacheSlide;
    }
    return retval;
  }

  uint32_t numCommands = mh->ncmds;

#ifdef __LP64__
  const struct segment_command_64 *aCommand = (struct segment_command_64 *)
    ((uintptr_t)mh + sizeof(struct mach_header_64));
#else
  const struct segment_command *aCommand = (struct segment_command *)
    ((uintptr_t)mh + sizeof(struct mach_header));
#endif

  for (uint32_t i = 0; i < numCommands; ++i) {
#ifdef __LP64__
    if (aCommand->cmd != LC_SEGMENT_64)
#else
    if (aCommand->cmd != LC_SEGMENT)
#endif
    {
      break;
    }

    if (!aCommand->fileoff && aCommand->filesize) {
      retval = (uintptr_t) mh - aCommand->vmaddr;
      break;
    }

    aCommand =
#ifdef __LP64__
      (struct segment_command_64 *)
#else
      (struct segment_command *)
#endif
      ((uintptr_t)aCommand + aCommand->cmdsize);
  }

  return retval;
}

// Helper method for module_dysym() below.
static
void GetModuleHeaderAndSlide(const char *moduleName,
#ifdef __LP64__
                             const struct mach_header_64 **pMh,
#else
                             const struct mach_header **pMh,
#endif
                             intptr_t *pVmaddrSlide)
{
  if (pMh) {
    *pMh = NULL;
  }
  if (pVmaddrSlide) {
    *pVmaddrSlide = 0;
  }
  if (!moduleName) {
    return;
  }

  char basename_local[PATH_MAX];
  strncpy(basename_local, basename((char *)moduleName),
          sizeof(basename_local));

  // If moduleName's base name is "dyld", we take it to mean the copy of dyld
  // that's present in every Mach executable.
  if (_dyld_get_all_image_infos && (strcmp(basename_local, "dyld") == 0)) {
    const struct dyld_all_image_infos *info = _dyld_get_all_image_infos();
    if (!info || !info->dyldImageLoadAddress) {
      return;
    }
    if (pMh) {
      *pMh =
#ifdef __LP64__
      (const struct mach_header_64 *)
#endif
      info->dyldImageLoadAddress;
    }
    if (pVmaddrSlide) {
      *pVmaddrSlide = GetImageSlide(
#ifdef __LP64__
        (const struct mach_header_64 *)
#endif
        info->dyldImageLoadAddress);
    }
    return;
  }

  bool moduleNameIsBasename = (strcmp(basename_local, moduleName) == 0);
  char moduleName_local[PATH_MAX] = {0};
  if (moduleNameIsBasename) {
    strncpy(moduleName_local, moduleName, sizeof(moduleName_local));
  } else {
    // Get the canonical path for moduleName (which may be a symlink or
    // otherwise non-canonical).
    int fd = open(moduleName, O_RDONLY);
    if (fd > 0) {
      if (fcntl(fd, F_GETPATH, moduleName_local) == -1) {
        strncpy(moduleName_local, moduleName, sizeof(moduleName_local));
      }
      close(fd);
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 110000
    } else {
      strncpy(moduleName_local, moduleName, sizeof(moduleName_local));
    }
#else // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 110000
    // On macOS 11 (Big Sur), open() generally doesn't work on moduleName,
    // because it generally isn't in the file system (only in the dyld shared
    // cache). As best I can tell, there's no general workaround for this
    // design flaw. But because all (or almost all) frameworks have a
    // 'Resources' soft link in the same directory where there used to be a
    // soft link to the framework binary, we can hack together a workaround
    // for frameworks.
    } else {
      char holder[PATH_MAX];
      strncpy(holder, moduleName, sizeof(holder));
      size_t fixed_to = 0;
      bool done = false;

      while (!done) {
        char proxy_path[PATH_MAX];
        strncpy(proxy_path, holder, sizeof(proxy_path));
        const char *subpath_tag = ".framework/";
        char *subpath_ptr =
          strnstr(proxy_path + fixed_to,
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

          fd = open(proxy_path, O_RDONLY);
          if (fd > 0) {
            if (fcntl(fd, F_GETPATH, holder) != -1) {
              fixed_to = strlen(holder) - proxy_name_len;
              holder[fixed_to] = 0;
              strncat(holder, subpath, sizeof(holder) - fixed_to);

              const char *frameworks_tag = "Frameworks";
              if (strncmp(holder + fixed_to, frameworks_tag,
                          strlen(frameworks_tag)) != 0)
              {
                strncpy(moduleName_local, holder, sizeof(moduleName_local));
                done = true;
              }
            } else {
              done = true;
            }
            close(fd);
          } else {
            done = true;
          }
        } else {
          done = true;
        }
      }

      if (!moduleName_local[0]) {
        strncpy(moduleName_local, moduleName, sizeof(moduleName_local));
      }
    }
#endif // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 110000
  }

  for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
    const char *name = _dyld_get_image_name(i);
    bool match = false;
    if (moduleNameIsBasename) {
      match = (strstr(basename((char *)name), moduleName_local) != NULL);
    } else {
      match = (strstr(name, moduleName_local) != NULL);
    }
    if (match) {
      if (pMh) {
        *pMh =
#ifdef __LP64__
        (const struct mach_header_64 *)
#endif
        _dyld_get_image_header(i);
      }
      if (pVmaddrSlide) {
        *pVmaddrSlide = _dyld_get_image_vmaddr_slide(i);
      }
      break;
    }
  }
}

// Helper method for module_dysym() below.
static const
#ifdef __LP64__
struct segment_command_64 *
GetSegment(const struct mach_header_64* mh,
#else
struct segment_command *
GetSegment(const struct mach_header* mh,
#endif
           const char *segname,
           uint32_t *numFollowingCommands)
{
  if (numFollowingCommands) {
    *numFollowingCommands = 0;
  }
  uint32_t numCommands = mh->ncmds;

#ifdef __LP64__
  const struct segment_command_64 *aCommand = (struct segment_command_64 *)
    ((uintptr_t)mh + sizeof(struct mach_header_64));
#else
  const struct segment_command *aCommand = (struct segment_command *)
    ((uintptr_t)mh + sizeof(struct mach_header));
#endif

  for (uint32_t i = 1; i <= numCommands; ++i) {
#ifdef __LP64__
    if (aCommand->cmd != LC_SEGMENT_64)
#else
    if (aCommand->cmd != LC_SEGMENT)
#endif
    {
      break;
    }
    if (strcmp(segname, aCommand->segname) == 0) {
      if (numFollowingCommands) {
        *numFollowingCommands = numCommands-i;
      }
      return aCommand;
    }
    aCommand =
#ifdef __LP64__
      (struct segment_command_64 *)
#else
      (struct segment_command *)
#endif
      ((uintptr_t)aCommand + aCommand->cmdsize);
  }

  return NULL;
}

// A variant of dlsym() that can find non-exported (non-public) symbols.
// Unlike with dlsym() and friends, 'symbol' should be specified exactly as it
// appears in the symbol table (and the output of programs like 'nm').  In
// other words, 'symbol' should (most of the time) be prefixed by an "extra"
// underscore.  The reason is that some symbols (especially non-public ones)
// don't have any underscore prefix, even in the symbol table.
extern "C" void *module_dlsym(const char *module_name, const char *symbol)
{
  if (!s_dyld_get_all_image_infos_initialized) {
    s_dyld_get_all_image_infos_initialized = true;
    _dyld_get_all_image_infos = (const struct dyld_all_image_infos *(*)())
      module_dlsym("/usr/lib/system/libdyld.dylib", "__dyld_get_all_image_infos");
    if (!_dyld_get_all_image_infos) {
      _dyld_get_all_image_infos = get_all_image_infos;
    }
  }

#ifdef __LP64__
  const struct mach_header_64 *mh = NULL;
#else
  const struct mach_header *mh = NULL;
#endif
  intptr_t vmaddr_slide = 0;
  GetModuleHeaderAndSlide(module_name, &mh, &vmaddr_slide);
  if (!mh) {
    return NULL;
  }

  uint32_t numFollowingCommands = 0;
#ifdef __LP64__
  const struct segment_command_64 *linkeditSegment =
#else
  const struct segment_command *linkeditSegment =
#endif
    GetSegment(mh, "__LINKEDIT", &numFollowingCommands);
  if (!linkeditSegment) {
    return NULL;
  }
  uintptr_t fileoffIncrement =
    linkeditSegment->vmaddr - linkeditSegment->fileoff;

  struct symtab_command *symtab = (struct symtab_command *)
    ((uintptr_t)linkeditSegment + linkeditSegment->cmdsize);
  for (uint32_t i = 1;; ++i) {
    if (symtab->cmd == LC_SYMTAB) {
      break;
    }
    if (i == numFollowingCommands) {
      return NULL;
    }
    symtab = (struct symtab_command *)
      ((uintptr_t)symtab + symtab->cmdsize);
  }
  uintptr_t symbolTableOffset =
    symtab->symoff + fileoffIncrement + vmaddr_slide;
  uintptr_t stringTableOffset =
    symtab->stroff + fileoffIncrement + vmaddr_slide;

  struct dysymtab_command *dysymtab = (struct dysymtab_command *)
    ((uintptr_t)symtab + symtab->cmdsize);
  if (dysymtab->cmd != LC_DYSYMTAB) {
    return NULL;
  }

  void *retval = NULL;
  for (int i = 1; i <= 2; ++i) {
    uint32_t index;
    uint32_t count;
    if (i == 1) {
      index = dysymtab->ilocalsym;
      count = index + dysymtab->nlocalsym;
    } else {
      index = dysymtab->iextdefsym;
      count = index + dysymtab->nextdefsym;
    }

    for (uint32_t j = index; j < count; ++j) {
#ifdef __LP64__
      struct nlist_64 *symbolTableItem = (struct nlist_64 *)
        (symbolTableOffset + j * sizeof(struct nlist_64));
#else
      struct nlist *symbolTableItem = (struct nlist *)
        (symbolTableOffset + j * sizeof(struct nlist));
#endif
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
      if (strcmp(symbol, stringTableItem)) {
        continue;
      }
      retval = (void *) (symbolTableItem->n_value + vmaddr_slide);
      break;
    }
  }

  return retval;
}

// dladdr() is normally used from libdyld.dylib.  But this isn't safe before
// our execution environment is fully initialized.  So instead we use it from
// the copy of dyld loaded in every Mach executable, which has no external
// dependencies.

int (*dyld_dladdr_caller)(const void *addr, Dl_info *info) = NULL;

int dyld_dladdr(const void *addr, Dl_info *info)
{
  if (!dyld_dladdr_caller) {
    dyld_dladdr_caller = (int (*)(const void*, Dl_info *))
      module_dlsym("dyld", "_dladdr");
    if (!dyld_dladdr_caller) {
      // But fall back to "normal" dladdr() if we can't find dladdr() in dyld.
      dyld_dladdr_caller = dladdr;
      if (!dyld_dladdr_caller) {
        return 0;
      }
    }
  }
  return dyld_dladdr_caller(addr, info);
}

// Call this from a hook to get the filename of the module from which the hook
// was called -- which of course is also the module from which the original
// method was called.
const char *GetCallerOwnerName()
{
  static char holder[1024] = {0};

  const char *ownerName = "";
  Dl_info addressInfo = {0};
  void **addresses = (void **) calloc(3, sizeof(void *));
  if (addresses) {
    int count = backtrace(addresses, 3);
    if (count == 3) {
      if (dyld_dladdr(addresses[2], &addressInfo)) {
        ownerName = basename((char *)addressInfo.dli_fname);
      }
    }
    free(addresses);
  }

  strncpy(holder, ownerName, sizeof(holder));
  return holder;
}

// Reset a patch hook after it's been unset (as it was called).  Not always
// required -- most patch hooks don't get unset when called.  But using it
// when not required does no harm. Note that, as of HookCase version 2.1, we
// changed which interrupt is used here -- from 0x22 to 0x32.
void reset_hook(void *hook)
{
  __asm__ ("int %0" :: "N" (0x32));
}

// Dynamically add a patch hook for orig_func(). Note that it's best to patch
// orig_func() before it's actually in use -- otherwise there's some danger
// of a race condition, especially if orig_func() can be used on different
// threads from the one that calls add_patch_hook().
void add_patch_hook(void *orig_func, void *hook)
{
  __asm__ ("int %0" :: "N" (0x33));
}

// Since several dynamically added patch hooks may share the same hook
// function, we can't use a global "caller" variable.  So instead we use
// the following to get an appropriate value into a local "caller" variable.
void *get_dynamic_caller(void *hook)
{
  void *retval;
#ifdef __i386__
  __asm__ volatile("int %0" :: "N" (0x34));
  __asm__ volatile("mov %%eax, %0" : "=r" (retval));
#else
  __asm__ volatile("int %0" :: "N" (0x34));
  __asm__ volatile("mov %%rax, %0" : "=r" (retval));
#endif
  return retval;
}

class loadHandler
{
public:
  loadHandler();
  ~loadHandler();
};

// In Apple's 32-bit mode code, internal (non-exported) methods often use a
// non-standard ABI to speed things up -- something called "fastcc".  If we
// hook such methods, our hooks will crash unless we also use that ABI.  The
// basic rules are to put the first two integer/pointer parameters into ECX
// and EDX, and to put floating point parameters into the XMM registers.
// Also, fastcc is never used with varargs functions.  But fastcc is only for
// internal use, and is deliberately non-standardized.  So using it can be
// tricky.  One needs to build the hook library with tools that are as
// compatible as possible with those used to build the OS itself.  I've had
// good luck up through Sierra with the LLVM 3.9.0 Clang download:
// http://releases.llvm.org/3.9.0/clang+llvm-3.9.0-x86_64-apple-darwin.tar.xz.
// HighSierra seems to require the LLVM 4.0.0 Clang download:
// http://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-apple-darwin.tar.xz.
//
// Note that the "fastcall" calling convention is *not* the same as the
// "fastcc" calling convention.  But (as it's deliberately non-standard),
// there's no way to specify a "fastcc" method in C/C++ code.  There *is*,
// though, a way to specify it in LLVM intermediate language.  So we need to
// take more steps to build a hook library that hooks non-exported methods in
// 32-bit code.  One of them generates an LLVM intermediate language file
// (ending in *.iii), which we use sed to transform into a file (ending in
// *.ii) where instances of "x86_fastcallcc" (the internal name for the
// fastcall calling convention) are replaced by "fastcc".  See our makefile
// for more information.
#ifdef __i386__
#define FASTI386 __attribute__((fastcall))
#else
#define FASTI386
#endif

// As reported by CGSEventRecordLength()/SLSEventRecordLength(), this
// structure is 0xF8 (248) bytes long on Mavericks through Ventura in 64-bit
// mode, and 0xD0 (208) bytes long in 32-bit mode. On Sonoma it's 0x100 (256)
// bytes long. On Sequoia it's back to 0xF8 (248) bytes long. A full
// definition (though without member names) is present in the class-dump
// output for the AppKit framework.
typedef struct _CGSEventRecord {
  unsigned short unknown1;
  unsigned short unknown2;
  unsigned int length;
  unsigned int type;
  struct CGPoint location;
  struct CGPoint windowLocation;
  unsigned long long timestamp;
  unsigned int flags;
#ifdef __i386__
  uint32_t pad[42];
#else
#if (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 140000) && \
    (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 150000)
  uint32_t pad[49];
#else
  uint32_t pad[47];
#endif
#endif
} CGSEventRecord;

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101400
// CGEventGetEventRecord() copies sizeof(CGSEventRecord) bytes from a CGEvent
// structure pointer at offset 0x18 in 64-bit mode and 0xC in 32-bit mode.
typedef struct __CGEvent {
  uintptr_t pad[3];
  CGSEventRecord *eventRecord;
} CGEvent, *CGEventRef;
#else
// CGEventGetEventRecord() copies sizeof(CGSEventRecord) bytes from a CGEvent
// structure starting at offset 0x18 in 64-bit mode and 0xC in 32-bit mode.
typedef struct __CGEvent {
  uintptr_t pad[3];
  CGSEventRecord eventRecord;
} CGEvent, *CGEventRef;
#endif

CFStringRef (*CopyEventDescription)(EventRef event, Boolean verbose) = NULL;
CFStringRef (*AEDescribeDesc)(CFAllocatorRef alloc, const AEDesc *desc, Boolean verbose) = NULL;
CGEventRef (*CGEventCreateWithEventRecord)(CGSEventRecord *eventRecord,
                                           uint32_t eventRecordLength) = NULL;
bool *sToolboxEventNotifyDoubleTapModifierInvalidation = NULL;

loadHandler::loadHandler()
{
  basic_init();
#if (0)
  LogWithFormat(true, "Hook.mm: loadHandler()");
  PrintStackTrace();
#endif

  CopyEventDescription = (CFStringRef (*)(EventRef, Boolean))
    module_dlsym("/System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox",
                 "_CopyEventDescription");
  AEDescribeDesc = (CFStringRef (*)(CFAllocatorRef, const AEDesc *, Boolean))
    module_dlsym("/System/Library/Frameworks/CoreServices.framework/Frameworks/AE.framework/AE",
                 "_AEDescribeDesc");
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 101200
  CGEventCreateWithEventRecord = (CGEventRef (*)(CGSEventRecord *, uint32_t))
    module_dlsym("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
                 "_CGEventCreateWithEventRecord");
#else
  CGEventCreateWithEventRecord = (CGEventRef (*)(CGSEventRecord *, uint32_t))
    module_dlsym("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
                 "_SLEventCreateWithEventRecord");
#endif
  sToolboxEventNotifyDoubleTapModifierInvalidation = (bool *)
    module_dlsym("/System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox",
                 "__ZL48sToolboxEventNotifyDoubleTapModifierInvalidation");
}

loadHandler::~loadHandler()
{
  if (g_serial1_FILE) {
    fclose(g_serial1_FILE);
  }
  if (g_serial1) {
    close(g_serial1);
  }
  if (g_virtual_serial_FILE) {
    fclose(g_virtual_serial_FILE);
  }
  if (g_virtual_serial) {
    close(g_virtual_serial);
  }
}

loadHandler handler = loadHandler();

static BOOL gMethodsSwizzled = NO;
static void InitSwizzling()
{
  if (!gMethodsSwizzled) {
#if (0)
    LogWithFormat(true, "Hook.mm: InitSwizzling()");
    PrintStackTrace();
#endif
    gMethodsSwizzled = YES;
    // Swizzle methods here
#if (0)
    Class ExampleClass = ::NSClassFromString(@"Example");
    SwizzleMethods(ExampleClass, @selector(doSomethingWith:),
                   @selector(Example_doSomethingWith:), NO);
#endif

    SwizzleMethods([NSAppleEventManager class],
                   @selector(dispatchRawAppleEvent:withRawReply:handlerRefCon:),
                   @selector(NSAppleEventManager_dispatchRawAppleEvent:withRawReply:handlerRefCon:),
                   NO);
  }
}

extern "C" void *NSPushAutoreleasePool();

static void *Hooked_NSPushAutoreleasePool()
{
  void *retval = NSPushAutoreleasePool();
  if (IsMainThread()) {
    InitSwizzling();
  }
  return retval;
}

#if (0)
// An example of a hook function for a dynamically added patch hook.  Since
// there's no way to prevent more than one original function from sharing this
// hook function, we can't use a global "caller".  So instead we call
// get_dynamic_caller() to get an appropriate value into a local "caller"
// variable.
typedef int (*dynamic_patch_example_caller)(char *arg);

static int dynamic_patch_example(char *arg)
{
  dynamic_patch_example_caller caller = (dynamic_patch_example_caller)
    get_dynamic_caller(reinterpret_cast<void*>(dynamic_patch_example));
  int retval = caller(arg);
  LogWithFormat(true, "Hook.mm: dynamic_patch_example(): arg \"%s\", returning \'%i\'",
                arg, retval);
  PrintStackTrace();
  // Not always required, but using it when not required does no harm.
  reset_hook(reinterpret_cast<void*>(dynamic_patch_example));
  return retval;
}

// If the PATCH_FUNCTION macro is used below, this will be set to the correct
// value by the HookCase extension.
int (*patch_example_caller)(char *arg1, int (*arg2)(char *)) = NULL;

static int Hooked_patch_example(char *arg1, int (*arg2)(char *))
{
  int retval = patch_example_caller(arg1, arg2);
  LogWithFormat(true, "Hook.mm: patch_example(): arg1 \"%s\", arg2 \'%p\', returning \'%i\'",
                arg1, arg2, retval);
  PrintStackTrace();
  // Example of using add_patch_hook() to dynamically add a patch hook for
  // 'arg2'.
  add_patch_hook(reinterpret_cast<void*>(arg2),
                 reinterpret_cast<void*>(dynamic_patch_example));
  // Not always required, but using it when not required does no harm.
  reset_hook(reinterpret_cast<void*>(Hooked_patch_example));
  return retval;
}

// An example of setting a patch hook at a function's numerical address.  The
// hook function's name must start with "sub_" and finish with its address (in
// the module where it's located) in hexadecimal (base 16) notation.  To hook
// a function whose actual name (in the symbol table) follows this convention,
// set the HC_NO_NUMERICAL_ADDRS environment variable.
int (*sub_123abc_caller)(char *arg) = NULL;

static int Hooked_sub_123abc(char *arg)
{
  int retval = sub_123abc_caller(arg);
  LogWithFormat(true, "Hook.mm: sub_123abc(): arg \"%s\", returning \'%i\'", arg, retval);
  PrintStackTrace();
  // Not always required, but using it when not required does no harm.
  reset_hook(reinterpret_cast<void*>(Hooked_sub_123abc));
  return retval;
}

extern "C" int interpose_example(char *arg1, int (*arg2)(char *));

static int Hooked_interpose_example(char *arg1, int (*arg2)(char *))
{
  int retval = interpose_example(arg1, arg2);
  LogWithFormat(true, "Hook.mm: interpose_example(): arg1 \"%s\", arg2 \'%p\', returning \'%i\'",
                arg1, arg2, retval);
  PrintStackTrace();
  // Example of using add_patch_hook() to dynamically add a patch hook for
  // 'arg2'.
  add_patch_hook(reinterpret_cast<void*>(arg2),
                 reinterpret_cast<void*>(dynamic_patch_example));
  return retval;
}

@interface NSObject (ExampleMethodSwizzling)
- (id)Example_doSomethingWith:(id)whatever;
@end

@implementation NSObject (ExampleMethodSwizzling)

- (id)Example_doSomethingWith:(id)whatever
{
  id retval = [self Example_doSomethingWith:whatever];
  Class ExampleClass = ::NSClassFromString(@"Example");
  if ([self isKindOfClass:ExampleClass]) {
    LogWithFormat(true, "Hook.mm: [Example doSomethingWith:]: self %@, whatever %@, returning %@",
                  self, whatever, retval);
  }
  return retval;
}

@end
#endif // #if (0)

// Put other hooked methods and swizzled classes here

// There are two basic kinds of (non-synthetic) events -- "high-level" and
// "low-level".  High-level events are Apple events, which may be used for
// application scripting.  They're delivered to applications via the Mach
// messaging system (as described under "AE Mach API" in the AE framework's
// AEMach.h).  Low-level events are everything else -- things like keyboard
// and mouse events.  Applications pull them from WindowServer (a system
// daemon from the CoreGraphics framework).  There are also "synthetic"
// events (either high-level or low-level), created and posted by the app
// itself (or one of its dylibs), and not delivered from an external source.

// Logging stack traces on a secondary thread generally only works properly
// if we don't also try to log stack traces on other threads (like the main
// thread).
//#define LOG_NSEVENTTHREAD_STACKS 1

enum {
  kEventClassCGS = 'cgs '
};

static char *GetFourCharCode(OSType type)
{
  char *retval = (char *) calloc(5, 1);
  if (!type) {
    strcpy(retval, "none");
    return retval;
  }
  retval[0] = ((type & 0xff000000) >> 24);
  retval[1] = ((type & 0x00ff0000) >> 16);
  retval[2] = ((type & 0x0000ff00) >> 8);
  retval[3] = (type & 0x000000ff);
  return retval;
}

typedef uint32_t CGSConnectionID;
typedef uint32_t CGSError;
#define kCGSErrorSuccess 0
#define kCGEventMouseMoved 5

class AEEventImpl;

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101300
uint32_t CGSEventRecordLength()
{
  return sizeof(CGSEventRecord);
}
#else
extern "C" uint32_t CGSEventRecordLength();
#endif

extern "C" CGEventRef CGEventCreate(CGEventSourceRef source);
extern "C" OSStatus CreateEventWithCGEvent(CFAllocatorRef inAllocator,
                                           CGEventRef inCGEvent,
                                           EventAttributes inAttributes,
                                           EventRef *outEvent);

OSStatus (*CreateEventWithCGEvent_caller)(CFAllocatorRef inAllocator,
                                          CGEventRef inEvent,
                                          EventAttributes inAttributes,
                                          EventRef *outEvent) = NULL;

// CreateEventWithCGEvent() is nearly always called before a synthetic event
// is posted.  So this hook can be useful for finding unexpected ways for
// this to happen.
OSStatus Hooked_CreateEventWithCGEvent(CFAllocatorRef inAllocator,
                                       CGEventRef inEvent,
                                       EventAttributes inAttributes,
                                       EventRef *outEvent)
{
  OSStatus retval = CreateEventWithCGEvent_caller(inAllocator, inEvent,
                                                  inAttributes, outEvent);

#if (0)
  if (retval == noErr) {
    OSType evClass = GetEventClass(*outEvent);
    UInt32 kind = GetEventKind(*outEvent);
    char *evClassString = GetFourCharCode(evClass);
    CFStringRef description = CopyEventDescription(*outEvent, true);

    LogWithFormat(true, "HookEvents: CreateEventWithCGEvent(): outEvent %@ (class %s, kind %i)",
                  description, evClassString, kind);
    PrintStackTrace();

    if (description) {
      CFRelease(description);
    }
    free(evClassString);
  }
#endif

  return retval;
}

EventRef EventFromCGSEventRecord(CGSEventRecord *eventRecord)
{
  if (!eventRecord) {
    return NULL;
  }
  CGEventRef cgEvent =
    CGEventCreateWithEventRecord(eventRecord, CGSEventRecordLength());
  if (!cgEvent) {
    return NULL;
  }
  // Temporarily turning off this setting can avoid crashes in code called by
  // TSMAdjustDoubleTapAction(), by avoiding the call altogether.
  bool old_notify = *sToolboxEventNotifyDoubleTapModifierInvalidation;
  if (old_notify) {
    *sToolboxEventNotifyDoubleTapModifierInvalidation = false;
  }
  EventRef retval = NULL;
  OSStatus rv =
    CreateEventWithCGEvent_caller(NULL, cgEvent, kEventAttributeNone,
                                  &retval);
  if (rv != noErr) {
    retval = NULL;
  }
  if (old_notify) {
    *sToolboxEventNotifyDoubleTapModifierInvalidation = old_notify;
  }
  return retval;
}

// This is called (via _CGEventCreateNextEvent()) from
// PullEventsFromWindowServerOnConnection(), which pulls events from
// WindowServer on the com.apple.NSEventThread (not the main thread).
// PullEventsFromWindowServerOnConnection() then pushes the newly created
// CGEvent on to the CGEvent queue.  Later, on the main thread, the CGEvent is
// removed from the CGEvent queue, converted to a Carbon event, and posted to
// the main event queue (using Convert1CGEvent()).  This method is called
// SLSGetNextEventRecordInternal() on macOS Sierra and HighSierra, and is in a
// different framework (the SkyLight framework).
extern "C" CGSError CGSGetNextEventRecordInternal(CGSConnectionID cid,
                                                  CGSEventRecord *eventRecord);

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101100
FASTI386 CGSError (*CGSGetNextEventRecordInternal_caller)(CGSConnectionID, CGSEventRecord *) = NULL;

static FASTI386 CGSError Hooked_CGSGetNextEventRecordInternal(CGSConnectionID cid,
                                                              CGSEventRecord *eventRecord)
#else
CGSError (*CGSGetNextEventRecordInternal_caller)(CGSConnectionID, CGSEventRecord *) = NULL;

static CGSError Hooked_CGSGetNextEventRecordInternal(CGSConnectionID cid,
                                                     CGSEventRecord *eventRecord)
#endif
{
  CGSError retval = CGSGetNextEventRecordInternal_caller(cid, eventRecord);
  if ((retval == kCGSErrorSuccess) && eventRecord->type &&
      (eventRecord->type != kCGEventMouseMoved))
  {
    OSType evClass = 0;
    UInt32 kind = 0;
    CFStringRef description = NULL;
    EventRef event = EventFromCGSEventRecord(eventRecord);
    if (event) {
      evClass = GetEventClass(event);
      kind = GetEventKind(event);
      description = CopyEventDescription(event, true);
      ReleaseEvent(event);
    }
    char *evClassString = GetFourCharCode(evClass);
    LogWithFormat(true, "HookEvents: CGSGetNextEventRecordInternal(): event %@ (class %s, kind %i)",
                  description, evClassString, kind);
#ifdef LOG_NSEVENTTHREAD_STACKS
    PrintStackTrace();
#endif
    if (description) {
      CFRelease(description);
    }
    free(evClassString);
  }
  return retval;
}

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 110000

extern "C" CGSEventRecord *SLSGetNextEventRecordInternal();

FASTI386 CGSEventRecord *(*SLSGetNextEventRecordInternal_caller)() = NULL;

static FASTI386 CGSEventRecord *Hooked_SLSGetNextEventRecordInternal()
{
  CGSEventRecord *retval = SLSGetNextEventRecordInternal_caller();
  if (retval && retval->type && (retval->type != kCGEventMouseMoved)) {
    OSType evClass = 0;
    UInt32 kind = 0;
    CFStringRef description = NULL;
    EventRef event = EventFromCGSEventRecord(retval);
    if (event) {
      evClass = GetEventClass(event);
      kind = GetEventKind(event);
      description = CopyEventDescription(event, true);
      ReleaseEvent(event);
    }
    char *evClassString = GetFourCharCode(evClass);
    LogWithFormat(true, "HookEvents: SLSGetNextEventRecordInternal(): event %@ (class %s, kind %i)",
                  description, evClassString, kind);
#ifdef LOG_NSEVENTTHREAD_STACKS
    PrintStackTrace();
#endif
    if (description) {
      CFRelease(description);
    }
    free(evClassString);
  }
  return retval;
}

#else // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 110000

extern "C" CGSError SLSGetNextEventRecordInternal(CGSConnectionID cid,
                                                  CGSEventRecord *eventRecord);

FASTI386 CGSError (*SLSGetNextEventRecordInternal_caller)(CGSConnectionID, CGSEventRecord *) = NULL;

static FASTI386 CGSError Hooked_SLSGetNextEventRecordInternal(CGSConnectionID cid,
                                                              CGSEventRecord *eventRecord)
{
  CGSError retval = SLSGetNextEventRecordInternal_caller(cid, eventRecord);
  if ((retval == kCGSErrorSuccess) && eventRecord->type &&
      (eventRecord->type != kCGEventMouseMoved))
  {
    OSType evClass = 0;
    UInt32 kind = 0;
    CFStringRef description = NULL;
    EventRef event = EventFromCGSEventRecord(eventRecord);
    if (event) {
      evClass = GetEventClass(event);
      kind = GetEventKind(event);
      description = CopyEventDescription(event, true);
      ReleaseEvent(event);
    }
    char *evClassString = GetFourCharCode(evClass);
    LogWithFormat(true, "HookEvents: SLSGetNextEventRecordInternal(): event %@ (class %s, kind %i)",
                  description, evClassString, kind);
#ifdef LOG_NSEVENTTHREAD_STACKS
    PrintStackTrace();
#endif
    if (description) {
      CFRelease(description);
    }
    free(evClassString);
  }
  return retval;
}

#endif // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 110000

// This pulls high-level and low-level events from the main event queue for
// all apps (Cocoa and Carbon).
extern "C" OSStatus ReceiveNextEventCommon(ItemCount inNumTypes,
                                           const EventTypeSpec *inList,
                                           EventTimeout inTimeout,
                                           void *inOptions,
                                           Boolean inPullEvent,
                                           EventRef *outEvent,
                                           CFStringRef inMode,
                                           Boolean inUnknown);

FASTI386 OSStatus (*ReceiveNextEventCommon_caller)(ItemCount inNumTypes,
                                                   const EventTypeSpec *inList,
                                                   EventTimeout inTimeout,
                                                   void *inOptions,
                                                   Boolean inPullEvent,
                                                   EventRef *outEvent,
                                                   CFStringRef inMode,
                                                   Boolean inUnknown) = NULL;

static FASTI386 OSStatus Hooked_ReceiveNextEventCommon(ItemCount inNumTypes,
                                                       const EventTypeSpec *inList,
                                                       EventTimeout inTimeout,
                                                       void *inOptions,
                                                       Boolean inPullEvent,
                                                       EventRef *outEvent,
                                                       CFStringRef inMode,
                                                       Boolean inUnknown)
{
  OSStatus retval =
    ReceiveNextEventCommon_caller(inNumTypes, inList, inTimeout, inOptions,
                                  inPullEvent, outEvent, inMode, inUnknown);
  if (retval == noErr) {
    OSType evClass = GetEventClass(*outEvent);
    UInt32 kind = GetEventKind(*outEvent);
    if (!((evClass == kEventClassMouse) && (kind == kEventMouseMoved)) &&
        // Firefox sends lots of these events
        !((evClass == kEventClassCGS) && (kind == NSApplicationDefined)))
    {
      char *evClassString = GetFourCharCode(evClass);
      CFStringRef description = CopyEventDescription(*outEvent, true);
      LogWithFormat(true, "HookEvents: ReceiveNextEventCommon(): event %@ (class %s, kind %i)",
                    description, evClassString, kind);
#ifndef LOG_NSEVENTTHREAD_STACKS
      PrintStackTrace();
#endif
      if (description) {
        CFRelease(description);
      }
      free(evClassString);
    }
  }
  return retval;
}

// _DPSNextEvent() processes both high-level and low-level Carbon events in
// Cocoa apps, delivering them to their handlers.  'cid' is usually the result
// of CGSMainConnectionID().
//
// The definition of _DPSNextEvent() changed considerably in Sierra, so we
// compile different versions of its hook, depending on which version of OS X
// we're compiling on.
extern "C" CGSEventRecord _DPSNextEvent_Mavericks(CGSConnectionID cid,   // in
                                                  unsigned long mask,    // in, unsigned long
                                                  NSDate *expiration,    // in
                                                  NSString *mode,        // in
                                                  BOOL dequeue,          // in
                                                  EventRef *eventCopy);  // out if not null

extern "C" CGSEventRecord _DPSNextEvent_ElCapitan(CGSConnectionID cid,  // in
                                                  NSEventMask mask,     // in, long long
                                                  NSDate *expiration,   // in
                                                  NSString *mode,       // in
                                                  BOOL dequeue,         // in
                                                  EventRef *eventCopy); // out if not null

extern "C" CGEventRef _DPSNextEvent_Sierra(CGSConnectionID cid,         // in
                                           NSEventMask mask,            // in, long long
                                           NSDate *expiration,          // in
                                           NSString *mode,              // in
                                           BOOL dequeue,                // in
                                           BOOL unknown,                // in
                                           EventRef *eventCopy);        // out if not null

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ <= 101000

CGSEventRecord (*_DPSNextEvent_caller)(CGSConnectionID cid,
                                       unsigned long mask,
                                       NSDate *expiration,
                                       NSString *mode,
                                       BOOL dequeue,
                                       EventRef *eventCopy) = NULL;

static CGSEventRecord Hooked__DPSNextEvent(CGSConnectionID cid,
                                           unsigned long mask,
                                           NSDate *expiration,
                                           NSString *mode,
                                           BOOL dequeue,
                                           EventRef *eventCopy)
{
  EventRef holder = NULL;
  if (!eventCopy) {
    eventCopy = &holder;
  }

  CGSEventRecord retval = _DPSNextEvent_caller(cid, mask, expiration,
                                               mode, dequeue, eventCopy);

  NSEvent *cocoaEvent = NULL;
  if (retval.type) {
    cocoaEvent = (NSEvent *)
      objc_msgSend([NSEvent alloc], @selector(_initWithCGSEvent:eventRef:),
                   retval, *eventCopy);
  }
  if (cocoaEvent) {
    NSEventType cocoaType = [cocoaEvent type];
    NSEventType subtype = 0;
    NSInteger data1 = 0;
    NSInteger data2 = 0;
    if (cocoaType == NSApplicationDefined) {
      subtype = [cocoaEvent subtype];
      data1 = [cocoaEvent data1];
      data2 = [cocoaEvent data2];
    }
    if ((cocoaType != NSMouseMoved) &&
        // Firefox uses lots of NSApplicationDefined events with data1 and
        // data2 set to 0, and subtype set to 0 or 1 (kEventSubtypeTrace).
        ((cocoaType != NSApplicationDefined) ||
          ((subtype != 0) && (subtype != 1)) ||
          (data1 != 0) ||
          (data2 != 0)))
    {
      LogWithFormat(true, "HookEvents: _DPSNextEvent(): event %@", cocoaEvent);
    }
    RetainEvent(*eventCopy);
    [cocoaEvent release];
  }

  if (holder) {
    ReleaseEvent(holder);
  }
  return retval;
}

#elif __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101200

CGEventRef (*_DPSNextEvent_caller)(CGSConnectionID cid, NSEventMask mask,
                                   NSDate *expiration, NSString *mode,
                                   BOOL dequeue, BOOL unknown,
                                   EventRef *eventCopy) = NULL;

static CGEventRef Hooked__DPSNextEvent(CGSConnectionID cid,
                                       NSEventMask mask,
                                       NSDate *expiration,
                                       NSString *mode,
                                       BOOL dequeue,
                                       BOOL unknown,
                                       EventRef *eventCopy)
{
  EventRef holder = NULL;
  if (!eventCopy) {
    eventCopy = &holder;
  }

  CGEventRef retval = _DPSNextEvent_caller(cid, mask, expiration, mode,
                                           dequeue, unknown, eventCopy);

  NSEvent *cocoaEvent = NULL;
  if (retval && CGEventGetType(retval)) {
    cocoaEvent = (NSEvent *)
      objc_msgSend([NSEvent alloc], @selector(_initWithCGEvent:eventRef:),
                   retval, *eventCopy);
  }
  if (cocoaEvent) {
    NSEventType cocoaType = [cocoaEvent type];
    NSEventSubtype subtype = (NSEventSubtype) 0;
    NSInteger data1 = 0;
    NSInteger data2 = 0;
    if (cocoaType == NSApplicationDefined) {
      subtype = [cocoaEvent subtype];
      data1 = [cocoaEvent data1];
      data2 = [cocoaEvent data2];
    }
    if ((cocoaType != NSMouseMoved) &&
        // Firefox uses lots of NSApplicationDefined events with data1 and
        // data2 set to 0, and subtype set to 0 or 1 (kEventSubtypeTrace).
        ((cocoaType != NSApplicationDefined) ||
          ((subtype != 0) && (subtype != 1)) ||
          (data1 != 0) ||
          (data2 != 0)))
    {
      LogWithFormat(true, "HookEvents: _DPSNextEvent(): event %@", cocoaEvent);
    }
    RetainEvent(*eventCopy);
    [cocoaEvent release];
  }

  if (holder) {
    ReleaseEvent(holder);
  }
  return retval;
}

#else  // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 101200

CGSEventRecord (*_DPSNextEvent_caller)(CGSConnectionID cid, NSEventMask mask,
                                       NSDate *expiration, NSString *mode,
                                       BOOL dequeue, EventRef *eventCopy) = NULL;

static CGSEventRecord Hooked__DPSNextEvent(CGSConnectionID cid,
                                           NSEventMask mask,
                                           NSDate *expiration,
                                           NSString *mode,
                                           BOOL dequeue,
                                           EventRef *eventCopy)
{
  EventRef holder = NULL;
  if (!eventCopy) {
    eventCopy = &holder;
  }

  CGSEventRecord retval = _DPSNextEvent_caller(cid, mask, expiration,
                                               mode, dequeue, eventCopy);

  NSEvent *cocoaEvent = NULL;
  if (retval.type) {
    cocoaEvent = (NSEvent *)
      objc_msgSend([NSEvent alloc], @selector(_initWithCGSEvent:eventRef:),
                   retval, *eventCopy);
  }
  if (cocoaEvent) {
    NSEventType cocoaType = [cocoaEvent type];
    NSEventType subtype = 0;
    NSInteger data1 = 0;
    NSInteger data2 = 0;
    if (cocoaType == NSApplicationDefined) {
      subtype = [cocoaEvent subtype];
      data1 = [cocoaEvent data1];
      data2 = [cocoaEvent data2];
    }
    if ((cocoaType != NSMouseMoved) &&
        // Firefox uses lots of NSApplicationDefined events with data1 and
        // data2 set to 0, and subtype set to 0 or 1 (kEventSubtypeTrace).
        ((cocoaType != NSApplicationDefined) ||
          ((subtype != 0) && (subtype != 1)) ||
          (data1 != 0) ||
          (data2 != 0)))
    {
      LogWithFormat(true, "HookEvents: _DPSNextEvent(): event %@", cocoaEvent);
    }
    RetainEvent(*eventCopy);
    [cocoaEvent release];
  }

  if (holder) {
    ReleaseEvent(holder);
  }
  return retval;
}

#endif // __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__

// This is where an Apple event first appears in a process.  It gets wrapped
// in the Carbon event created here.  CreateHighLevelEvent() is called from
// enqueueHighLevelEvent(AEEventImpl*) in the AE framework, which then calls
// PostEventToQueueInternal() to post the event.  enqueueHighLevelEvent() is
// in turn called (via AEProcessMessage()) from
// _aeMachPortCallback(__CFMachPort*, void*, long, void*), which is a
// "callout" for the Mach port used to receive incoming Mach messages that
// contain Apple events sent from another process.
extern "C" OSStatus CreateHighLevelEvent(EventRecord *inEventRecord,
                                         AEEventImpl *inAEEvent,
                                         EventRef *outEvent);

OSStatus (*CreateHighLevelEvent_caller)(EventRecord *inEventRecord,
                                        AEEventImpl *inAEEvent,
                                        EventRef *outEvent) = NULL;

static OSStatus Hooked_CreateHighLevelEvent(EventRecord *inEventRecord,
                                            AEEventImpl *inAEEvent,
                                            EventRef *outEvent)
{
  OSStatus retval =
    CreateHighLevelEvent_caller(inEventRecord, inAEEvent, outEvent);
  if (retval == noErr) {
    OSType evClass = GetEventClass(*outEvent);
    UInt32 kind = GetEventKind(*outEvent);
    char *evClassString = GetFourCharCode(evClass);
    CFStringRef description = CopyEventDescription(*outEvent, true);
    LogWithFormat(true, "HookEvents: CreateHighLevelEvent(): event %@ (class %s, kind %i)",
                  description, evClassString, kind);
#ifndef LOG_NSEVENTTHREAD_STACKS
    PrintStackTrace();
#endif
    if (description) {
      CFRelease(description);
    }
    free(evClassString);
  }
  return retval;
}

// This is what delivers Apple events to their handlers in Cocoa apps.  It's
// called from _DPSNextEvent() (via AEProcessAppleEvent()).
@interface NSAppleEventManager (MethodSwizzling)
- (OSErr)NSAppleEventManager_dispatchRawAppleEvent:(const AppleEvent *)theAppleEvent
                                      withRawReply:(AppleEvent *)theReply
                                     handlerRefCon:(SRefCon)handlerRefCon;
@end

@implementation NSAppleEventManager (MethodSwizzling)

- (OSErr)NSAppleEventManager_dispatchRawAppleEvent:(const AppleEvent *)theAppleEvent
                                      withRawReply:(AppleEvent *)theReply
                                     handlerRefCon:(SRefCon)handlerRefCon
{
  OSErr retval =
    [self NSAppleEventManager_dispatchRawAppleEvent:theAppleEvent
                                       withRawReply:theReply
                                      handlerRefCon:handlerRefCon];
  CFStringRef description = AEDescribeDesc(kCFAllocatorDefault, theAppleEvent, NO);
  LogWithFormat(true, "HookEvents: [NSAppleEventManager dispatchRawAppleEvent:...]: theAppleEvent %@",
                description);
#ifndef LOG_NSEVENTTHREAD_STACKS
  PrintStackTrace();
#endif
  if (description) {
    CFRelease(description);
  }
  return retval;
}

@end

extern "C" OSStatus PostEventToQueueInternal(EventQueueRef inQueue,
                                             EventRef inEvent,
                                             EventPriority inPriority,
                                             Boolean inSignalRunLoop);

OSStatus (*PostEventToQueueInternal_caller)(EventQueueRef inQueue,
                                            EventRef inEvent,
                                            EventPriority inPriority,
                                            Boolean inSignalRunLoop) = NULL;

// Both low-level and high-level events are posted to the "Carbon event" queue
// using this method, after they've been converted from CGS events or CG
// events.  Most (all?) synthetic events are also posted using this method.
static OSStatus Hooked_PostEventToQueueInternal(EventQueueRef inQueue,
                                                EventRef inEvent,
                                                EventPriority inPriority,
                                                Boolean inSignalRunLoop)
{
  OSStatus retval =
    PostEventToQueueInternal_caller(inQueue, inEvent, inPriority,
                                    inSignalRunLoop);
  if (retval == noErr) {
    OSType evClass = GetEventClass(inEvent);
    UInt32 kind = GetEventKind(inEvent);
    if (!((evClass == kEventClassMouse) && (kind == kEventMouseMoved)) &&
        // Firefox sends lots of these events
        !((evClass == kEventClassCGS) && (kind == NSApplicationDefined)))
    {
      char *evClassString = GetFourCharCode(evClass);
      CFStringRef description = CopyEventDescription(inEvent, true);
      LogWithFormat(true, "HookEvents: PostEventToQueueInternal(): event %@ (class %s, kind %i)",
                    description, evClassString, kind);
#if (0)
#ifndef LOG_NSEVENTTHREAD_STACKS
      if (IsMainThread()) {
        PrintStackTrace();
      }
#endif
#endif
      if (description) {
        CFRelease(description);
      }
      free(evClassString);
    }
  }
  return retval;
}

extern "C" Boolean Convert1CGEvent(Boolean wakeup);

FASTI386 Boolean (*_ZL15Convert1CGEventh_caller)(Boolean) = NULL;

static FASTI386 Boolean Hooked__ZL15Convert1CGEventh(Boolean wakeup)
{
  Boolean retval = _ZL15Convert1CGEventh_caller(wakeup);
  LogWithFormat(true, "HookEvents: Convert1CGEvent(): wakeup %i, returning %i",
                wakeup, retval);
#ifndef LOG_NSEVENTTHREAD_STACKS
  PrintStackTrace();
#endif
  return retval;
}

extern "C" void _PostCGEventToQueue(CGEventRef cgEvent, bool arg1);

extern "C" EventRef AcquireEventFromQueue(EventQueueRef inQueue,
                                          ItemCount inNumTypes,
                                          const EventTypeSpec *inList,
                                          void *inOptions,
                                          Boolean inPullEvent);

// This may be called from AEPredispatchHandler() (via AEProcessAppleEvent()
// via _DPSNextEvent()) to create additional Carbon events wrapping Apple
// events, presumably for delivery to their handlers.  Presumably these Apple
// events are not handled via NSAppleEventManager.
extern "C" OSStatus _CreateEventWithAppleEvents(AEEventClass inEventClass,
                                                AEEventID inEventID,
                                                EventTime inWhen,
                                                EventAttributes inAttributes,
                                                const AEDesc *inFromDesc,
                                                AEDesc *inToDesc,
                                                Boolean inUnknown,
                                                EventRef *outEvent);

typedef struct _hook_desc {
  const void *hook_function;
  union {
    // For interpose hooks
    const void *orig_function;
    // For patch hooks
    const void *caller_func_ptr;
  };
  const char *orig_function_name;
  const char *orig_module_name;
} hook_desc;

#define PATCH_FUNCTION(function, module)               \
  { reinterpret_cast<const void*>(Hooked_##function),  \
    reinterpret_cast<const void*>(&function##_caller), \
    "_" #function,                                     \
    #module }

#define INTERPOSE_FUNCTION(function)                   \
  { reinterpret_cast<const void*>(Hooked_##function),  \
    reinterpret_cast<const void*>(function),           \
    "_" #function,                                     \
    "" }

__attribute__((used)) static const hook_desc user_hooks[]
  __attribute__((section("__DATA, __hook"))) =
{
  INTERPOSE_FUNCTION(NSPushAutoreleasePool),
  PATCH_FUNCTION(__CFInitialize, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation),

  PATCH_FUNCTION(CreateEventWithCGEvent, /System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox),
  PATCH_FUNCTION(ReceiveNextEventCommon, /System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox),
  PATCH_FUNCTION(_DPSNextEvent, /System/Library/Frameworks/AppKit.framework/AppKit),
  PATCH_FUNCTION(CreateHighLevelEvent, /System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox),
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101200
  PATCH_FUNCTION(SLSGetNextEventRecordInternal, /System/Library/PrivateFrameworks/SkyLight.framework/SkyLight),
#else
  PATCH_FUNCTION(CGSGetNextEventRecordInternal, /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics),
#endif
  PATCH_FUNCTION(PostEventToQueueInternal, /System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox),
  //PATCH_FUNCTION(_ZL15Convert1CGEventh, /System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox),
};

// What follows are declarations of the CoreSymbolication APIs that we use to
// get stack traces.  This is an undocumented, private framework available on
// OS X 10.6 and up.  It's used by Apple utilities like atos and ReportCrash.

// Defined above
#if (0)
typedef struct _CSTypeRef {
  unsigned long type;
  void *contents;
} CSTypeRef;
#endif

typedef struct _CSRange {
  unsigned long long location;
  unsigned long long length;
} CSRange;

// Defined above
typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSourceInfoRef;

typedef unsigned long long CSArchitecture;

#define kCSNow LONG_MAX

extern "C" {
uint32_t CSSymbolicatorGetFlagsForNListOnlyData(void);
CSSymbolicatorRef CSSymbolicatorCreateWithTaskFlagsAndNotification(task_t task,
                                                                   uint32_t flags,
                                                                   uint32_t notification);
CSSymbolicatorRef CSSymbolicatorCreateWithPid(pid_t pid);
CSSymbolicatorRef CSSymbolicatorCreateWithPidFlagsAndNotification(pid_t pid,
                                                                  uint32_t flags,
                                                                  uint32_t notification);
CSArchitecture CSSymbolicatorGetArchitecture(CSSymbolicatorRef symbolicator);
CSSymbolOwnerRef CSSymbolicatorGetSymbolOwnerWithAddressAtTime(CSSymbolicatorRef symbolicator,
                                                               unsigned long long address,
                                                               long time);

const char *CSSymbolOwnerGetName(CSSymbolOwnerRef owner);
unsigned long long CSSymbolOwnerGetBaseAddress(CSSymbolOwnerRef owner);
CSSymbolRef CSSymbolOwnerGetSymbolWithAddress(CSSymbolOwnerRef owner,
                                              unsigned long long address);
CSSourceInfoRef CSSymbolOwnerGetSourceInfoWithAddress(CSSymbolOwnerRef owner,
                                                      unsigned long long address);

const char *CSSymbolGetName(CSSymbolRef symbol);
CSRange CSSymbolGetRange(CSSymbolRef symbol);

const char *CSSourceInfoGetFilename(CSSourceInfoRef info);
uint32_t CSSourceInfoGetLineNumber(CSSourceInfoRef info);

CSTypeRef CSRetain(CSTypeRef);
void CSRelease(CSTypeRef);
bool CSIsNull(CSTypeRef);
void CSShow(CSTypeRef);
const char *CSArchitectureGetFamilyName(CSArchitecture);
} // extern "C"

CSSymbolicatorRef gSymbolicator = {0};

void CreateGlobalSymbolicator()
{
  if (CSIsNull(gSymbolicator)) {
    // Unless we limit ourselves to NList data, it will take too long to get a
    // stack trace where Dwarf debugging info is available (about 15 seconds
    // with Firefox).
    gSymbolicator =
      CSSymbolicatorCreateWithTaskFlagsAndNotification(mach_task_self(),
                                                       CSSymbolicatorGetFlagsForNListOnlyData(),
                                                       0);
  }
}

// Does nothing (and returns 'false') if *symbolicator is already non-null.
// Otherwise tries to set it appropriately.  Returns 'true' if the returned
// *symbolicator will need to be released after use (because it isn't the
// global symbolicator).
bool GetSymbolicator(CSSymbolicatorRef *symbolicator)
{
  bool retval = false;
  if (CSIsNull(*symbolicator)) {
    if (!CSIsNull(gSymbolicator)) {
      *symbolicator = gSymbolicator;
    } else {
      // 0x40e0000 is the value returned by
      // uint32_t CSSymbolicatorGetFlagsForNListOnlyData(void).  We don't use
      // this method directly because it doesn't exist on OS X 10.6.  Unless
      // we limit ourselves to NList data, it will take too long to get a
      // stack trace where Dwarf debugging info is available (about 15 seconds
      // with Firefox).  This means we won't be able to get a CSSourceInfoRef,
      // or line number information.  Oh well.
      *symbolicator =
        CSSymbolicatorCreateWithTaskFlagsAndNotification(mach_task_self(), 0x40e0000, 0);
      if (!CSIsNull(*symbolicator)) {
        retval = true;
      }
    }
  }
  return retval;
}

const char *GetOwnerName(void *address, CSTypeRef owner)
{
  static char holder[1024] = {0};

  const char *ownerName = "unknown";

  bool symbolicatorNeedsRelease = false;
  CSSymbolicatorRef symbolicator = {0};

  if (CSIsNull(owner)) {
    symbolicatorNeedsRelease = GetSymbolicator(&symbolicator);
    if (!CSIsNull(symbolicator)) {
      owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
                symbolicator,
                (unsigned long long) address,
                kCSNow);
      // Sometimes we need to do this a second time.  I've no idea why, but it
      // seems to be more likely in 32bit mode.
      if (CSIsNull(owner)) {
        owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
                  symbolicator,
                  (unsigned long long) address,
                  kCSNow);
      }
    }
  }

  if (!CSIsNull(owner)) {
    ownerName = CSSymbolOwnerGetName(owner);
  }

  snprintf(holder, sizeof(holder), "%s", ownerName);
  if (symbolicatorNeedsRelease) {
    CSRelease(symbolicator);
  }

  return holder;
}

const char *GetAddressString(void *address, CSTypeRef owner)
{
  static char holder[1024] = {0};

  const char *addressName = "unknown";
  unsigned long long addressOffset = 0;
  bool addressOffsetIsBaseAddress = false;

  bool symbolicatorNeedsRelease = false;
  CSSymbolicatorRef symbolicator = {0};

  if (CSIsNull(owner)) {
    symbolicatorNeedsRelease = GetSymbolicator(&symbolicator);
    if (!CSIsNull(symbolicator)) {
      owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
                symbolicator,
                (unsigned long long) address,
                kCSNow);
      // Sometimes we need to do this a second time.  I've no idea why, but it
      // seems to be more likely in 32bit mode.
      if (CSIsNull(owner)) {
        owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
                  symbolicator,
                  (unsigned long long) address,
                  kCSNow);
      }
    }
  }

  if (!CSIsNull(owner)) {
    CSSymbolRef symbol =
      CSSymbolOwnerGetSymbolWithAddress(owner, (unsigned long long) address);
    bool symbol_is_null = CSIsNull(symbol);
    if (!symbol_is_null) {
      addressName = CSSymbolGetName(symbol);
    }
    if (!symbol_is_null && addressName) {
      CSRange range = CSSymbolGetRange(symbol);
      addressOffset = (unsigned long long) address;
      if (range.location <= addressOffset) {
        addressOffset -= range.location;
      } else {
        addressOffsetIsBaseAddress = true;
      }
    } else {
      addressOffset = (unsigned long long) address;
      unsigned long long baseAddress = CSSymbolOwnerGetBaseAddress(owner);
      if (baseAddress <= addressOffset) {
        addressOffset -= baseAddress;
      } else {
        addressOffsetIsBaseAddress = true;
      }
      if (!addressName) {
        addressOffsetIsBaseAddress = true;
      }
    }
  }

  if (addressOffsetIsBaseAddress) {
    if (addressName) {
      snprintf(holder, sizeof(holder), "%s 0x%llx",
               addressName, addressOffset);
    } else {
      snprintf(holder, sizeof(holder), "0x%llx", addressOffset);
    }
  } else {
    snprintf(holder, sizeof(holder), "%s + 0x%llx",
             addressName, addressOffset);
  }
  if (symbolicatorNeedsRelease) {
    CSRelease(symbolicator);
  }

  return holder;
}

void PrintAddress(void *address, CSTypeRef symbolicator)
{
  const char *ownerName = "unknown";
  const char *addressString = "unknown";

  bool symbolicatorNeedsRelease = false;
  CSSymbolOwnerRef owner = {0};

  if (CSIsNull(symbolicator)) {
    symbolicatorNeedsRelease = GetSymbolicator(&symbolicator);
  }

  if (!CSIsNull(symbolicator)) {
    owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
              symbolicator,
              (unsigned long long) address,
              kCSNow);
    // Sometimes we need to do this a second time.  I've no idea why, but it
    // seems to be more likely in 32bit mode.
    if (CSIsNull(owner)) {
      owner = CSSymbolicatorGetSymbolOwnerWithAddressAtTime(
                symbolicator,
                (unsigned long long) address,
                kCSNow);
    }
  }

  ownerName = GetOwnerName(address, owner);
  addressString = GetAddressString(address, owner);

  LogWithFormat(false, "    (%s) %s", ownerName, addressString);

  if (symbolicatorNeedsRelease) {
    CSRelease(symbolicator);
  }
}

#define STACK_MAX 256

void PrintStackTrace()
{
  if (!CanUseCF()) {
    return;
  }

  CreateGlobalSymbolicator();

  void **addresses = (void **) calloc(STACK_MAX, sizeof(void *));
  if (!addresses) {
    return;
  }

  CSSymbolicatorRef symbolicator = {0};
  bool symbolicatorNeedsRelease = GetSymbolicator(&symbolicator);
  if (CSIsNull(symbolicator)) {
    LogWithFormat(true, "Hook.mm: PrintStackTrace(): symbolicator not found.");
    free(addresses);
    return;
  }

  uint32_t count = backtrace(addresses, STACK_MAX);
  for (uint32_t i = 0; i < count; ++i) {
    PrintAddress(addresses[i], symbolicator);
  }

  if (symbolicatorNeedsRelease) {
    CSRelease(symbolicator);
  }
  free(addresses);
}

BOOL SwizzleMethods(Class aClass, SEL orgMethod, SEL posedMethod, BOOL classMethods)
{
  Method original = nil;
  Method posed = nil;

  if (classMethods) {
    original = class_getClassMethod(aClass, orgMethod);
    posed = class_getClassMethod(aClass, posedMethod);
  } else {
    original = class_getInstanceMethod(aClass, orgMethod);
    posed = class_getInstanceMethod(aClass, posedMethod);
  }

  if (!original || !posed)
    return NO;

  method_exchangeImplementations(original, posed);

  return YES;
}

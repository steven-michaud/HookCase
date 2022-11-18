// The MIT License (MIT)
//
// Copyright (c) 2022 Steven Michaud
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

#include <xpc/xpc.h>
#include <uuid/uuid.h>

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

void Initialize_CF_If_Needed()
{
  if (!sCFInitialized && __CFInitialize_caller) {
    Hooked___CFInitialize();
  }
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

#define STACK_MAX 256
typedef uint64_t callstack_t[STACK_MAX];

const char *GetOwnerName(void *address, CSTypeRef owner = initializer);
const char *GetAddressString(void *address, CSTypeRef owner = initializer);
void PrintAddress(void *address, CSTypeRef symbolicator = initializer);
void PrintCallstack(callstack_t callstack);
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

// It's sometimes useful to find out whether a hook is currently running
// (on the current thread), or if it's been re-entered (and how many times
// it's been re-entered). The following macro offers a safe, comprehensive
// way to do this.

#define GET_SET_IN_FUNCS(name)                       \
pthread_key_t s_in_##name;                           \
int32_t s_in_##name##_initialized = 0;               \
bool get_in_##name()                                 \
{                                                    \
  if (!s_in_##name##_initialized) {                  \
    OSAtomicIncrement32(&s_in_##name##_initialized); \
    pthread_key_create(&s_in_##name, NULL);          \
  }                                                  \
  long value = (long)                                \
    pthread_getspecific(s_in_##name);                \
  return (value > 0);                                \
}                                                    \
long get_in_##name##_count()                         \
{                                                    \
  if (!s_in_##name##_initialized) {                  \
    OSAtomicIncrement32(&s_in_##name##_initialized); \
    pthread_key_create(&s_in_##name, NULL);          \
  }                                                  \
  return (long) pthread_getspecific(s_in_##name);    \
}                                                    \
void set_in_##name(bool flag)                        \
{                                                    \
  if (!s_in_##name##_initialized) {                  \
    OSAtomicIncrement32(&s_in_##name##_initialized); \
    pthread_key_create(&s_in_##name, NULL);          \
  }                                                  \
  long value = (long)                                \
    pthread_getspecific(s_in_##name);                \
  if (flag) {                                        \
    ++value;                                         \
  } else {                                           \
    --value;                                         \
  }                                                  \
  pthread_setspecific(s_in_##name, (void *) value);  \
}

GET_SET_IN_FUNCS(LogWithFormatV)

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
    if (rv == EOF) {
      break;
    }
    tcdrain(fileno(stream));
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

  set_in_LogWithFormatV(true);

  char *message;
  long message_length;
  if (CanUseCF()) {
    CFStringRef formatCFSTR =
      CFStringCreateWithCString(kCFAllocatorDefault, format,
                                kCFStringEncodingMacRoman);
    CFStringRef messageCFSTR =
      CFStringCreateWithFormatAndArguments(kCFAllocatorDefault, NULL,
                                           formatCFSTR, args);
    CFRelease(formatCFSTR);
    message_length =
      CFStringGetMaximumSizeForEncoding(CFStringGetLength(messageCFSTR),
                                        kCFStringEncodingMacRoman);
    message = (char *) calloc(message_length + 1, 1);
    CFStringGetBytes(messageCFSTR, CFRangeMake(0, message_length),
                     kCFStringEncodingMacRoman, '?', true,
                     (unsigned char *) message, message_length, NULL);
    CFRelease(messageCFSTR);
  } else {
    vasprintf(&message, format, args);
    message_length = strlen(message);
  }

  char *finished = (char *) calloc(message_length + 1024, 1);
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
  set_in_LogWithFormatV(false);
}

static void LogWithFormat(bool decorate, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  LogWithFormatV(decorate, format, args);
  va_end(args);
}

// The hook for __CFGetConverter() works around a bug or design flaw in the
// CoreFoundation framework's CFStringCreateWithFormatAndArguments() function,
// called from LogWithFormatV(): It always uses the string encoding associated
// with the "preferred language" setting (misleadingly called the "system
// encoding").
//
// For languages that use Latin scripts the "system encoding" is
// kCFStringEncodingMacRoman, which is appropriate for use in
// LogWithFormatV(): It can handle strings that combine characters from many
// different encodings (like Roman letters and Chinese characters). It's also
// the encoding used by macOS itself at the most basic level (the
// LC_C_LOCALE). But if your "preferred language" doesn't use a Latin script
// (for example Chinese or Japanese) the "system encoding" is one specifically
// associated with that language. It generally doesn't allow you to combine
// characters from different encoding systems in a single string. If you try,
// it replaces unrecognized characters with "?", or sometimes refuses to
// process it at all. This happens in CFStringCreateWithFormatAndArguments()
// when, for example, your "preferred language" is Russian, Greek,
// "Traditional Chinese" or "Simplified Chinese", and one of the arguments is
// a string that combines Roman letters and Chinese characters.
//
// Many CoreFoundation string functions allow you to specify the string
// encoding -- for example CFStringCreateWithCString() and CFStringGetBytes().
// CFStringCreateWithFormatAndArguments() really should, too. But for as long
// as it doesn't, we can use the following hook to force it to use
// kCFStringEncodingMacRoman when called from LogWithFormatV().
//
// This workaround isn't available for 32-bit hook libraries. This is because
// __CFGetConverter() uses the "fastcc" calling convention in 32-bit system
// libraries, which isn't supported by any compiler. It *is* supported in
// LLVM intermediate language, but frankly it's not worth the trouble to use
// that here.

//#define DEBUG_GET_CONVERTER 1

#ifdef DEBUG_GET_CONVERTER
GET_SET_IN_FUNCS(__CFGetConverter)
#endif

void *(*__CFGetConverter_caller)(uint32_t encoding) = NULL;

void *Hooked___CFGetConverter(uint32_t encoding)
{
#ifdef DEBUG_GET_CONVERTER
  set_in___CFGetConverter(true);
#endif

  if (get_in_LogWithFormatV()) {
    encoding = kCFStringEncodingMacRoman;
  }

  void *retval = __CFGetConverter_caller(encoding);

#ifdef DEBUG_GET_CONVERTER
  // The call to LogWithFormat() below can cause this function to be re-entered.
  if (get_in___CFGetConverter_count() == 1) {
    if (get_in_LogWithFormatV()) {
      LogWithFormat(true, "Hook.mm: __CFGetConverter(): encoding %u, returning %p",
                    encoding, retval);
      //PrintStackTrace();
    }
  }
#endif

#ifdef DEBUG_GET_CONVERTER
  set_in___CFGetConverter(false);
#endif
  return retval;
}

extern "C" void hooklib_LogWithFormatV(bool decorate, const char *format, va_list args)
{
  LogWithFormatV(decorate, format, args);
}

extern "C" void hooklib_PrintStackTrace()
{
  PrintStackTrace();
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
      return 0;
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

// Information collected by user_trap_hook() in HookCase.kext when a
// watchpoint is hit, then passed back to user mode when config_watcher() is
// called to unset the watchpoint (with 'set' == false).
typedef struct _watcher_info {
  // Stack trace of the code running when the watchpoint is hit.
  callstack_t callstack;
  // Exact address hit (inside the watchpoint's address range).
  uint64_t hit;
  // User-land equivalent of the thread (kernel-mode thread_t object) running
  // when the watchpoint is hit. Use pthread_from_mach_thread_np() to convert
  // it to a pthread object.
  uint32_t mach_thread;
  // Needed to make structure size the same in 64bit and 32bit modes.
  uint32_t pad;
} watcher_info_t;

// (Re)set or unset a watchpoint on a range of memory. A watchpoint is "hit"
// whenever something tries to write anywhere in its address range. When this
// happens, information on it is collected in a watcher_info_t structure. This
// includes a stack trace of the code running when the watchpoint was hit.
// This information is passed back to user-land when config_watcher() is
// called to unset the watchpoint (with 'set' == false). Watchpoints are
// implemented by (temporarily) changing memory access permissions to prevent
// writes. Writing to a watchpoint triggers a fault, which ends up being
// processed in HookCase.kext's user_trap_hook(). user_trap_hook() restores
// the original access permissions, records the requisite information, and
// saves it to a watcher_info_t structure. Memory access permissions are for
// a "page" of memory (usually 4096 bytes long). So calling config_watcher()
// to set a "watchpoint" on a particular memory address actually ends up
// setting a "watch range" on a particular page (block) of memory. To avoid
// confusion, it's best to set watchpoints only in buffers that are page-
// aligned.

bool config_watcher(void *watchpoint, watcher_info_t *info, bool set)
{
  bool retval;
  __asm__ volatile("int %0" :: "N" (0x35));
  __asm__ volatile("movb %%al, %0" : "=r" (retval));
  return retval;
}

class loadHandler
{
public:
  loadHandler();
  ~loadHandler();
};

loadHandler::loadHandler()
{
  basic_init();
  Initialize_CF_If_Needed();
#if (0)
  LogWithFormat(true, "Hook.mm: loadHandler()");
  PrintStackTrace();
#endif
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

    Class OSActivityStreamClass = ::NSClassFromString(@"OSActivityStream");
    SwizzleMethods(OSActivityStreamClass, @selector(streamEvent:error:),
                   @selector(OSActivityStream_streamEvent:error:), NO);

    Class CSKStreamViewControllerClass =
      ::NSClassFromString(@"CSKStreamViewController");
    SwizzleMethods(CSKStreamViewControllerClass,
                   @selector(initWithStreamSource:capacity:),
                   @selector(CSKStreamViewController_initWithStreamSource:capacity:),
                   NO);
    SwizzleMethods(CSKStreamViewControllerClass,
                   @selector(dealloc),
                   @selector(CSKStreamViewController_dealloc),
                   NO);

    Class CSKEntityClass =
      ::NSClassFromString(@"CSKEntity");
    SwizzleMethods(CSKEntityClass,
                   @selector(initWithIdentifier:processImagePath:libraryImagePath:timestamp:timeZone:isVolatile:),
                   @selector(CSKEntity_initWithIdentifier:processImagePath:libraryImagePath:timestamp:timeZone:isVolatile:),
                   NO);
    SwizzleMethods(CSKEntityClass,
                   @selector(dealloc),
                   @selector(CSKEntity_dealloc),
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

// An example of setting a watchpoint at a particular memory address (actually
// an address range), then unsetting it to collect information on whatever
// code (if any) triggered the watchpoint (by writing to its address range).
// Watchpoints are hit at most once between each pair of calls to
// config_watcher(true) and config_watcher(false). If a watchpoint has been
// triggered, it is already unset by the time config_watcher(false) is called
// (and we collect information on it). To find the next hit one must hook the
// method that triggered the first one, then set another watchpoint inside its
// hook. This example is quite trivial -- it sets a watchpoint and also
// triggers it. A more useful one would set a watchpoint to find out what
// other code can trigger it.
watcher_info_t s_watcher_info = {0};

int (*watcher_example_caller)(char *arg) = NULL;

static int Hooked_watcher_example(char *arg)
{
  int retval = watcher_example_caller(arg);
  unsigned char *pages = (unsigned char *) valloc(PAGE_SIZE);
  if (pages) {
    bzero(pages, PAGE_SIZE);
    void *watchpoint = pages;
    if (config_watcher(watchpoint, &s_watcher_info, true)) {
      pages[0] = 1;
      config_watcher(watchpoint, &s_watcher_info, false);
      if (s_watcher_info.hit) {
        pthread_t thread =
          pthread_from_mach_thread_np(s_watcher_info.mach_thread);
        char thread_name[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (thread) {
          pthread_getname_np(thread, thread_name, sizeof(thread_name) - 1);
        }
        LogWithFormat(true, "Hook.mm: watcher_example(): arg \"%s\", returning \'%i\', pages[0] \'0x%x\', watchpoint \'%p\', hit \'0x%llx\', thread %s[%p], mach_thread \'0x%x\'\n",
                      arg, retval, pages[0], watchpoint, s_watcher_info.hit, thread_name, thread, s_watcher_info.mach_thread);
        PrintCallstack(s_watcher_info.callstack);
      }
    }
    free(pages);
  }
  // Not always required, but using it when not required does no harm.
  reset_hook(reinterpret_cast<void*>(Hooked_watcher_example));
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

// Client-side stuff

static id s_current_CSKStreamViewController = NULL;
static id s_current_CSKMessage = NULL;

// From libclosure's BlockImplementation.txt
typedef struct _block_literal {
  void *isa;
  int flags;
  int reserved; 
  void (*invoke)(void *, ...);
  void *descriptor;
} block_literal, *block_literal_t;

typedef struct _stream_entry_handler_literal {
  void *isa;
  int flags;
  int reserved;
  bool (*invoke)(struct _stream_entry_handler_literal *, void *, unsigned int);
  void *descriptor;
  id activityStream; // An OSActivityStream object
  // OSActivityEvent objects that passed the filter but have (presumably) been
  // queued for later processing
  NSMutableArray *queuedActivityEvents;
} stream_entry_handler_literal, *stream_entry_handler_literal_t;

typedef bool
(*stream_entry_handler_block_invoke_caller)(stream_entry_handler_literal_t block,
                                            void *stream_entry, unsigned int code);

// Every message from diagnosticd comes through here, with no filtering at
// all. This handler is called directly from handler_block_invoke()'s original
// handler.
static bool
stream_entry_handler_block_invoke(stream_entry_handler_literal_t block,
                                  void *stream_entry, unsigned int code)
{
  stream_entry_handler_block_invoke_caller caller =
    (stream_entry_handler_block_invoke_caller)
    get_dynamic_caller(reinterpret_cast<void*>(stream_entry_handler_block_invoke));

  bool retval = caller(block, stream_entry, code);

  // 'caller()' may trigger basic filtering done by the LoggingSupport private
  // framework (in the original handler's call to
  // [NSPredicate evaluateWithObject:]). If s_current_CSKMessage is non-NULL,
  // the current message has passed that filtering. The filtering we may do
  // here is on top of that, and uses the infrastructure that implements the
  // filtering (if any) in the Console app's main window.
  bool should_log = false;
  NSArray *filters = (NSArray *)
    [s_current_CSKStreamViewController performSelector:@selector(currentFilters)];
  // 'predicate' is NULL if the 'filters' array is empty -- if no filtering is
  // being done in the Console app's main window.
  NSPredicate *predicate =
    [[NSPredicate class] performSelector:@selector(csk_predicateFromFilters:mapping:)
                              withObject:filters
                              withObject:NSClassFromString(@"CSKMessage")];
  if (s_current_CSKMessage) {
    if (!predicate) {
      should_log = true;
    } else {
      should_log = [predicate evaluateWithObject:s_current_CSKMessage];
    }
  }
  if (should_log) {
    LogWithFormat(true, "Hook.mm: stream_entry_handler_block_invoke(): invoke \'%p\', code \'0x%x\', returning \'0x%x\'",
                  block->invoke, code, retval);
  }

  return retval;
}

typedef struct _state_change_handler_literal {
  void *isa;
  int flags;
  int reserved;
  void (*invoke)(struct _state_change_handler_literal *, void *, unsigned int);
  void *descriptor;
  id activityStream; // An OSActivityStream object
} state_change_handler_literal, *state_change_handler_literal_t;

typedef void
(*state_change_handler_block_invoke_caller)(state_change_handler_literal_t block,
                                            void *unused, unsigned int code);

// This handler is called directly from handler_block_invoke()'s original
// handler.
static void
state_change_handler_block_invoke(state_change_handler_literal_t block,
                                  void *unused, unsigned int code)
{
  state_change_handler_block_invoke_caller caller =
    (state_change_handler_block_invoke_caller)
    get_dynamic_caller(reinterpret_cast<void*>(state_change_handler_block_invoke));

  caller(block, unused, code);

  LogWithFormat(true, "Hook.mm: state_change_handler_block_invoke(): invoke \'%p\', code \'0x%x\'",
                block->invoke, code);
}

// This structure is 0x60 bytes in 64-bit mode and 0x38 bytes in 32-bit mode.
typedef struct _os_activity_stream {
  stream_entry_handler_literal_t stream_entry_handler;
  state_change_handler_literal_t state_change_handler;
  xpc_connection_t connection;
} os_activity_stream, *os_activity_stream_t;

typedef struct _xpc_handler_literal {
  void *isa;
  int flags;
  int reserved;
  void (*invoke)(struct _xpc_handler_literal *, xpc_object_t);
  void *descriptor;
  const os_activity_stream_t stream;
} xpc_handler_literal, *xpc_handler_literal_t;

typedef void (*handler_block_invoke_caller)(xpc_handler_literal_t block,
                                            xpc_object_t object);

// This is our connection handler hook. Every message from diagnosticd comes
// through here (in 'object'), with no filtering at all. They are in their
// original format (as set in diagnosticd): A string from the "uuiddb" has
// already been inserted (into 'name' and 'formatstring'), but the contents
// of 'buffer' haven't yet been used to compose the final message (using the
// printf-like format variables in 'name' and 'formatstring').
static void handler_block_invoke(xpc_handler_literal_t block,
                                 xpc_object_t object)
{
  handler_block_invoke_caller caller = (handler_block_invoke_caller)
    get_dynamic_caller(reinterpret_cast<void*>(handler_block_invoke));

  caller(block, object);

  // 'caller()' may trigger basic filtering done by the LoggingSupport private
  // framework (in stream_entry_handler_block_invoke() above). If
  // s_current_CSKMessage is non-NULL, the current message has passed that
  // filtering. The filtering we may do here is on top of that, and uses the
  // infrastructure that implements the filtering (if any) in the Console
  // app's main window.
  bool should_log = false;
  NSArray *filters = (NSArray *)
    [s_current_CSKStreamViewController performSelector:@selector(currentFilters)];
  // 'predicate' is NULL if the 'filters' array is empty -- if no filtering is
  // being done in the Console app's main window.
  NSPredicate *predicate =
    [[NSPredicate class] performSelector:@selector(csk_predicateFromFilters:mapping:)
                              withObject:filters
                              withObject:NSClassFromString(@"CSKMessage")];
  if (s_current_CSKMessage) {
    if (!predicate) {
      should_log = true;
    } else {
      should_log = [predicate evaluateWithObject:s_current_CSKMessage];
    }
  }

  os_activity_stream_t stream = NULL;
  if (block && block->stream) {
    stream = block->stream;
  }

  if (should_log) {
    xpc_connection_t connection = NULL;
    if (stream) {
      connection = stream->connection;
    }
    pid_t peer_pid = -1;
    uid_t peer_uid = -1;
    if (connection) {
      peer_pid = xpc_connection_get_pid(connection);
      peer_uid = xpc_connection_get_euid(connection);
    }
    char peer_name[PATH_MAX] = {0};
    if (peer_pid && (peer_pid != -1)) {
      proc_name(peer_pid, peer_name, sizeof(peer_name));
    } else {
      strcpy(peer_name, "none");
    }

    char *object_desc = NULL;
    if (object) {
      object_desc = xpc_copy_description(object);
    }

    LogWithFormat(true, "Hook.mm: handler_block_invoke(): peer \"%s(%u)\", uid \'%i\', invoke \'%p\', object \"%s\"",
                  peer_name, peer_pid, peer_uid, block->invoke, object_desc ? object_desc : "null");

    if (object_desc) {
      free(object_desc);
    }
  }

  if (stream) {
    static bool stream_entry_handler_hooked = false;
    if (stream->stream_entry_handler && stream->stream_entry_handler->invoke &&
        !stream_entry_handler_hooked)
    {
      stream_entry_handler_hooked = true;
      add_patch_hook(reinterpret_cast<void*>(stream->stream_entry_handler->invoke),
                     reinterpret_cast<void*>(stream_entry_handler_block_invoke));
      LogWithFormat(true, "Hook.mm: handler_block_invoke(): stream_entry_handler->invoke \'%p\' hooked",
                    stream->stream_entry_handler->invoke);
    }
    static bool state_change_handler_hooked = false;
    if (stream->state_change_handler && stream->state_change_handler->invoke &&
        !state_change_handler_hooked)
    {
      state_change_handler_hooked = true;
      add_patch_hook(reinterpret_cast<void*>(stream->state_change_handler->invoke),
                     reinterpret_cast<void*>(state_change_handler_block_invoke));
      LogWithFormat(true, "Hook.mm: handler_block_invoke(): state_change_entry_handler->invoke \'%p\' hooked",
                    stream->state_change_handler->invoke);
    }
  }

  s_current_CSKMessage = NULL;
}

static void Hooked_xpc_connection_set_event_handler(xpc_connection_t connection, 
                                                    xpc_handler_t handler)
{
  bool is_LoggingSupport = false;
  const char *owner_name = GetCallerOwnerName();
  if (!strcmp(owner_name, "LoggingSupport")) {
    is_LoggingSupport = true;
  }

  if (is_LoggingSupport && handler) {
    xpc_handler_literal_t block = (xpc_handler_literal_t) handler;
    if (block->stream) {
      pid_t peer_pid = -1;
      uid_t peer_uid = -1;
      if (connection) {
        peer_pid = xpc_connection_get_pid(connection);
        peer_uid = xpc_connection_get_euid(connection);
      }
      char peer_name[PATH_MAX] = {0};
      if (peer_pid && (peer_pid != -1)) {
        proc_name(peer_pid, peer_name, sizeof(peer_name));
      } else {
        strcpy(peer_name, "none");
      }
      LogWithFormat(true, "Hook.mm: xpc_connection_set_event_handler(): peer \"%s(%u)\", uid \'%i\', invoke \'%p\'",
                    peer_name, peer_pid, peer_uid, block->invoke);
      PrintStackTrace();
      add_patch_hook(reinterpret_cast<void*>(block->invoke),
                     reinterpret_cast<void*>(handler_block_invoke));
    }
  }

  xpc_connection_set_event_handler(connection, handler);
}

xpc_connection_t Hooked_xpc_connection_create_mach_service(const char *name,
                                                           dispatch_queue_t targetq,
                                                           uint64_t flags)
{
  bool is_LoggingSupport = false;
  const char *owner_name = GetCallerOwnerName();
  if (!strcmp(owner_name, "LoggingSupport")) {
    is_LoggingSupport = true;
  }

  xpc_connection_t retval =
    xpc_connection_create_mach_service(name, targetq, flags);
  if (is_LoggingSupport) {
    LogWithFormat(true, "Hook.mm: xpc_connection_create_mach_service(): name \"%s\", flags \'0x%llx\'",
                  name, flags);
    PrintStackTrace();
  }
  return retval;
}

@interface NSObject (OSActivityStreamSwizzling)
- (BOOL)OSActivityStream_streamEvent:(id)event error:(id)error;
@end

@implementation NSObject (OSActivityStreamSwizzling)

// The messages that come through here have undergone basic filtering by the
// LoggingSupport private framework -- what appears in the Console without any
// Console filtering. They are no longer in their original format (as sent from
// diagnosticd). Their parts have been combined into one, user-readable string.
- (BOOL)OSActivityStream_streamEvent:(id)event error:(id)error
{
  BOOL retval = [self OSActivityStream_streamEvent:event error:error];

  // The filtering we may do here is on top of basic filtering by the
  // LoggingSupport private framework. It uses the infrastructure that
  // implements the filtering (if any) in the Console app's main window.
  bool should_log = false;
  NSArray *filters = (NSArray *)
    [s_current_CSKStreamViewController performSelector:@selector(currentFilters)];
  // 'predicate' is NULL if the 'filters' array is empty -- if no filtering is
  // being done in the Console app's main window.
  NSPredicate *predicate =
    [[NSPredicate class] performSelector:@selector(csk_predicateFromFilters:mapping:)
                              withObject:filters
                              withObject:NSClassFromString(@"CSKMessage")];
  if (s_current_CSKMessage) {
    if (!predicate) {
      should_log = true;
    } else {
      should_log = [predicate evaluateWithObject:s_current_CSKMessage];
    }
  } else if (error) {
    should_log = true;
  }
  if (should_log) {
    LogWithFormat(true, "Hook.mm: [OSActivityStream streamEvent:error:]: event (%@) %@, error %@, returning %i",
                  [event class], event, error, retval);
  }

  return retval;
}

@end

@interface NSObject (CSKStreamViewControllerSwizzling)
- (id)CSKStreamViewController_initWithStreamSource:(id)source capacity:(long)capacity;
- (void)CSKStreamViewController_dealloc;
@end

@implementation NSObject (CSKStreamViewControllerSwizzling)

- (id)CSKStreamViewController_initWithStreamSource:(id)source capacity:(long)capacity
{
  id retval = [self CSKStreamViewController_initWithStreamSource:source capacity:capacity];
  s_current_CSKStreamViewController = self;
  LogWithFormat(true, "Hook.mm: [CSKStreamViewController initWithStreamSource:capacity:]: self %@, source %@, capacity %ul",
                self, source, capacity);
  PrintStackTrace();
  return retval;
}

- (void)CSKStreamViewController_dealloc
{
  Class CSKStreamViewControllerClass =
    ::NSClassFromString(@"CSKStreamViewController");
  if ([self isKindOfClass:CSKStreamViewControllerClass]) {
    LogWithFormat(true, "Hook.mm: [CSKStreamViewController dealloc]: self %@", self);
    PrintStackTrace();
  }
  if (self == s_current_CSKStreamViewController) {
    s_current_CSKStreamViewController = NULL;
  }
  [self CSKStreamViewController_dealloc];
}

@end

// A CSKEntity, like an OSActivityEvent, is a stream event. CSKEntity is
// implemented in the ConsoleKit private framework, and OSActivityEvent in the
// LoggingSupport private framework. The "same" event is implemented using
// both kinds of object. CSKMessage is a subclass of CSKEntity. The Console
// app implements its filtering using CSKMessage objects.
@interface NSObject (CSKEntitySwizzling)
- (id)CSKEntity_initWithIdentifier:(NSNumber *)identifier
                  processImagePath:(NSString *)procPath
                  libraryImagePath:(NSString *)libPath
                         timestamp:(NSDate *)time
                          timeZone:(NSTimeZone *)zone
                        isVolatile:(bool)flag;
- (void)CSKEntity_dealloc;
@end

@implementation NSObject (CSKEntitySwizzling)

- (id)CSKEntity_initWithIdentifier:(NSNumber *)identifier
                  processImagePath:(NSString *)procPath
                  libraryImagePath:(NSString *)libPath
                         timestamp:(NSDate *)time
                          timeZone:(NSTimeZone *)zone
                        isVolatile:(bool)flag
{
  id retval =
    [self CSKEntity_initWithIdentifier:identifier
                      processImagePath:procPath
                      libraryImagePath:libPath
                             timestamp:time
                              timeZone:zone
                            isVolatile:flag];
  Class CSKMessageClass = ::NSClassFromString(@"CSKMessage");
  if ([self isKindOfClass:CSKMessageClass]) {
    s_current_CSKMessage = retval;
  }
  return retval;
}

- (void)CSKEntity_dealloc
{
  Class CSKMessageClass = ::NSClassFromString(@"CSKMessage");
  if ([self isKindOfClass:CSKMessageClass]) {
    if (self == s_current_CSKMessage) {
      s_current_CSKMessage = NULL;
    }
  }
  [self CSKEntity_dealloc];
}

@end

// Server-side stuff

// /usr/libexec/diagnosticd is a core component of the logging subsystem on
// macOS 10.12 and up.  It listens (as com.apple.diagnosticd) for connections
// from client apps like "log" and "Console".  While these client connections
// are live, it receives messages from other parts of the OS, which it passes
// along to its client(s). These messages come from user-level daemons (via
// their own connections to diagnosticd), and also from /dev/oslog_stream,
// which diagnosticd monitors for messages from the kernel (as long as it has
// at least one live connection to a client app).

// add_new_kext(), remove_new_kext() and friends give us a way to keep track of
// newly loaded and unloaded kexts, as information arrives from the kernel in
// the form of metadata log messages. See below near Hooked_read() for more
// information.

Boolean UUIDDataEqual(const void *value1, const void *value2)
{
  if (!value1 || !value2 ||
     (CFGetTypeID((CFTypeRef) value1) != CFDataGetTypeID()) ||
     (CFGetTypeID((CFTypeRef) value2) != CFDataGetTypeID()))
  {
    return false;
  }

  CFDataRef data1 = (CFDataRef) value1;
  CFDataRef data2 = (CFDataRef) value2;

  uint64_t *num1_ptr = (uint64_t *) CFDataGetBytePtr(data1);
  uint64_t *num2_ptr = (uint64_t *) CFDataGetBytePtr(data2);

  uint64_t num1_high = OSSwapInt64(num1_ptr[0]);
  uint64_t num1_low = OSSwapInt64(num1_ptr[1]);
  uint64_t num2_high = OSSwapInt64(num2_ptr[0]);
  uint64_t num2_low = OSSwapInt64(num2_ptr[1]);

  return ((num1_high == num2_high) && (num1_low == num2_low));
}

CFStringRef UUIDDataCopyDescription(const void *value)
{
  CFStringRef description = NULL;

  if (!value || (CFGetTypeID((CFTypeRef) value) != CFDataGetTypeID())) {
    description =
      CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
                               CFSTR("Invalid UUID (%p)"), value);
    return description;
  }

  CFDataRef data = (CFDataRef) value;
  char uuid_string[PATH_MAX] = {0};
  uuid_unparse(CFDataGetBytePtr(data), uuid_string);

  description =
    CFStringCreateWithCString(kCFAllocatorDefault, uuid_string,
                              kCFStringEncodingUTF8);

  return description;
}

static CFMutableArrayRef new_kexts = NULL;

static void ensure_new_kexts()
{
  if (!new_kexts) {
    CFArrayCallBacks our_callbacks = kCFTypeArrayCallBacks;
    our_callbacks.copyDescription = UUIDDataCopyDescription;
    our_callbacks.equal = UUIDDataEqual;
    new_kexts = CFArrayCreateMutable(kCFAllocatorDefault, 0, &our_callbacks);
  }
}

#define RANGE_ALL(a) CFRangeMake(0, CFArrayGetCount(a))

static void add_new_kext(uuid_t kext_uuid)
{
  ensure_new_kexts();
  CFDataRef item = CFDataCreate(kCFAllocatorDefault,
                                (const UInt8 *) kext_uuid, sizeof(uuid_t));
  if (!CFArrayContainsValue(new_kexts, RANGE_ALL(new_kexts), item)) {
    CFArrayAppendValue(new_kexts, item);
  }
  CFRelease(item);
}

static void remove_new_kext(uuid_t kext_uuid)
{
  if (!new_kexts) {
    return;
  }
  CFDataRef item = CFDataCreate(kCFAllocatorDefault,
                                (const UInt8 *) kext_uuid, sizeof(uuid_t));
  CFIndex offset =
    CFArrayGetFirstIndexOfValue(new_kexts, RANGE_ALL(new_kexts), item);
  if (offset != -1) {
    CFArrayRemoveValueAtIndex(new_kexts, offset);
  }
  CFRelease(item);
}

static bool has_new_kext(uuid_t kext_uuid)
{
  if (!new_kexts) {
    return false;
  }

  CFDataRef item = CFDataCreate(kCFAllocatorDefault,
                                (const UInt8 *) kext_uuid, sizeof(uuid_t));
  bool retval = CFArrayContainsValue(new_kexts, RANGE_ALL(new_kexts), item);
  CFRelease(item);
  return retval;
}

static bool has_new_kext_UTF8(char *kext_uuid)
{
  if (!new_kexts || !kext_uuid) {
    return false;
  }

  uuid_t uuid = {0};
  uuid_parse(kext_uuid, uuid);
  return has_new_kext(uuid);
}

static bool has_new_kext_CFSTR(CFStringRef kext_uuid)
{
  if (!new_kexts || !kext_uuid) {
    return false;
  }
  char uuid_cstring[PATH_MAX] = {0};
  CFStringGetCString(kext_uuid, uuid_cstring, sizeof(uuid_cstring),
                     kCFStringEncodingUTF8);
  return has_new_kext_UTF8(uuid_cstring);
}

bool is_new_kexts_empty()
{
  return (!new_kexts || (CFArrayGetCount(new_kexts) == 0));
}

static void uuid_parse_path(char *uuid_string, uuid_t uuid)
{
  bzero(uuid, sizeof(uuid_t));
  if (!uuid_string) {
    return;
  }

  char uuid_string_part1[PATH_MAX] = {0};
  char uuid_string_part2[PATH_MAX] = {0};

  uuid_string_part1[0] = uuid_string[0];
  uuid_string_part1[1] = uuid_string[1];
  uuid_string += 2;
  if (uuid_string[0] == '/') {
    uuid_string += 1;
  }
  strncat(uuid_string_part1, uuid_string, 14);
  uuid_string += 14;
  strncpy(uuid_string_part2, uuid_string, 16);

  uint64_t uuid_num_high = strtouq(uuid_string_part1, NULL, 16);
  uint64_t uuid_num_low = strtouq(uuid_string_part2, NULL, 16);

  uint64_t *uuid_ptr = (uint64_t *) uuid;
  uuid_ptr[0] = OSSwapInt64(uuid_num_high);
  uuid_ptr[1] = OSSwapInt64(uuid_num_low);
}

// diagnosticd calls _simple_asl_log() to log its activity. This doesn't work
// -- as best I can tell its output is simply lost. But we can log these calls
// ourselves by hooking _simple_asl_log().

extern "C" void _simple_asl_log(int __level, const char *__facility, const char *__message);

void Hooked__simple_asl_log(int __level, const char *__facility, const char *__message)
{
  _simple_asl_log(__level, __facility, __message);
  // Filter out "New connection from peer" messages, which appear very often
  if (!__message || (strncmp("New connection from peer", __message, 24) != 0)) {
    LogWithFormat(true, "Hook.mm: _simple_asl_log(): __level \'%i\', __facility \"%s\", __message \"%s\"",
                  __level, __facility ? __facility : "null", __message ? __message : "null");
  }
}

// Called by diagnosticd to open /dev/oslog_stream, on which it will listen
// for messages from the kernel.
static int Hooked_open(const char *path, int oflag, mode_t mode)
{
  bool is_diagnosticd = false;
  const char *owner_name = GetCallerOwnerName();
  if (!strcmp(owner_name, "diagnosticd")) {
    is_diagnosticd = true;
  }

  int retval = 1;
  if (oflag & O_CREAT) {
    retval = open(path, oflag, mode);
  } else {
    retval = open(path, oflag);
  }

  if (is_diagnosticd) {
    LogWithFormat(true, "Hook.mm: open(): path \"%s\", oflag \'0x%x\', returning \'%i\'",
                  path, oflag, retval);
  }

  return retval;
}

char *get_data_as_string(const void *data, size_t length)
{
  if (!data || !length) {
    return NULL;
  }
  size_t buffer_remaining = (4 * length);
  char *retval = (char *) calloc(buffer_remaining + 1, 1);
  if (!retval) {
    return NULL;
  }
  for (int i = 0; i < length; ++i) {
    const unsigned char item = ((const unsigned char *)data)[i];
    char item_string[5] = {0};
    if (i % 32 == 31) {
      snprintf(item_string, sizeof(item_string), "%02X|\n", item);
    } else if (i % 8 == 7) {
      snprintf(item_string, sizeof(item_string), "%02X|", item);
    } else {
      snprintf(item_string, sizeof(item_string), "%02X:", item);
    }
    strncat(retval, item_string, buffer_remaining);
    buffer_remaining -= strlen(item_string);
  }
  return retval;
}

// From the xnu kernel's libkern/firehose/firehose_types_private.h (begin)

OS_ENUM(firehose_tracepoint_namespace, uint8_t,
  firehose_tracepoint_namespace_activity        = 0x02,
  firehose_tracepoint_namespace_trace           = 0x03,
  firehose_tracepoint_namespace_log             = 0x04,
  firehose_tracepoint_namespace_metadata        = 0x05,
  firehose_tracepoint_namespace_signpost        = 0x06,
);

typedef uint8_t firehose_tracepoint_type_t;

OS_ENUM(_firehose_tracepoint_type_metadata, firehose_tracepoint_type_t,
  _firehose_tracepoint_type_metadata_dyld       = 0x01,
  _firehose_tracepoint_type_metadata_subsystem  = 0x02,
  _firehose_tracepoint_type_metadata_kext       = 0x03,
);

OS_ENUM(_firehose_tracepoint_type_log, firehose_tracepoint_type_t,
  _firehose_tracepoint_type_log_default         = 0x00,
  _firehose_tracepoint_type_log_info            = 0x01,
  _firehose_tracepoint_type_log_debug           = 0x02,
  _firehose_tracepoint_type_log_error           = 0x10,
  _firehose_tracepoint_type_log_fault           = 0x11,
);

OS_ENUM(firehose_tracepoint_flags, uint16_t,
  _firehose_tracepoint_flags_base_has_current_aid   = 0x0001,
#define _firehose_tracepoint_flags_pc_style_mask    (0x0007 << 1)
  _firehose_tracepoint_flags_pc_style_none          = 0x0000 << 1,
  _firehose_tracepoint_flags_pc_style_main_exe      = 0x0001 << 1,
  _firehose_tracepoint_flags_pc_style_shared_cache  = 0x0002 << 1,
  _firehose_tracepoint_flags_pc_style_main_plugin   = 0x0003 << 1,
  _firehose_tracepoint_flags_pc_style_absolute      = 0x0004 << 1,
  _firehose_tracepoint_flags_pc_style_uuid_relative = 0x0005 << 1,
  _firehose_tracepoint_flags_pc_style__unused6      = 0x0006 << 1,
  _firehose_tracepoint_flags_pc_style__unused7      = 0x0007 << 1,
  _firehose_tracepoint_flags_base_has_unique_pid    = 0x0010,
  _firehose_tracepoint_flags_base_has_large_offset  = 0x0020,
);

OS_ENUM(_firehose_tracepoint_flags_log, uint16_t,
  _firehose_tracepoint_flags_log_has_private_data   = 0x0100,
  _firehose_tracepoint_flags_log_has_subsystem      = 0x0200,
  _firehose_tracepoint_flags_log_has_rules          = 0x0400,
  _firehose_tracepoint_flags_log_has_oversize       = 0x0800,
  _firehose_tracepoint_flags_log_has_context_data   = 0x1000,
);

// These values are only for firehose_tracepoint_namespace_metadata. For
// firehose_tracepoint_namespace_log, _code is the module offset of the log
// message's format string (as determined by a call in the kernel to
// _os_trace_offset()).
OS_ENUM(firehose_tracepoint_code, uint32_t,
  firehose_tracepoint_code_load                 = 0x01,
  firehose_tracepoint_code_unload               = 0x02,
);

// From the xnu kernel's libkern/firehose/firehose_types_private.h (end)

// From the xnu kernel's libkern/firehose/tracepoint_private.h (begin)

typedef struct __attribute__((packed)) {
  firehose_tracepoint_namespace_t _namespace;
  firehose_tracepoint_type_t      _type;
  firehose_tracepoint_flags_t     _flags;
  // When 'namespace' is 'firehose_tracepoint_namespace_log', '_code' is the
  // offset in the caller's binary of the string in 'name' and 'formatstring'
  // (in the object passed to handler_block_invoke() above).
  uint32_t                        _code;
} firehose_tracepoint_id_t;

// This is the format of oslog_entry.data for
// firehose_tracepoint_namespace_metadata
typedef struct firehose_trace_uuid_info_s {
  uuid_t ftui_uuid;      /* uuid of binary */
  uint64_t ftui_address; /* load address of binary */
  uint64_t ftui_size;    /* load size of binary */
} *firehose_trace_uuid_info_t;

// From the xnu kernel's libkern/firehose/tracepoint_private.h (end)

// This is the format of oslog_entry.data for
// firehose_tracepoint_namespace_log and
// _firehose_tracepoint_flags_pc_style_main_exe.
typedef struct firehose_trace_log_exe_data_s {
  // Offset from the beginning of the binary to where (in kernel or kext
  // code) the logging call was made.
  uint32_t caller_addr;
  // This goes into the 'buffer' field of the 'object' passed to
  // handler_block_invoke() above.
  uint8_t data[];
} *firehose_trace_log_exe_data_t;

// This is the format of oslog_entry.data for
// firehose_tracepoint_namespace_log and
// _firehose_tracepoint_flags_pc_style_absolute.
typedef struct firehose_trace_log_other_data_s {
#if __LP64__
  // Absolute address (unslid, high word removed) of where (in kernel or
  // kext code) the logging call was made. Can be sign-extended to the full
  // 64-bits.
  uint16_t caller_addr[3];
#else
  uint32_t caller_addr;
#endif
  // This goes into the 'buffer' field of the 'object' passed to
  // handler_block_invoke() above.
  uint8_t data[];
} *firehose_trace_log_other_data_t;

typedef struct {
  uint64_t timestamp;
  firehose_tracepoint_id_t ftid;
  uint64_t thread;
  struct {
    uint64_t timestamp_delta : 48;
    uint64_t data_length : 16;
  };
  uint8_t data[];
} oslog_entry;

// read() is called from diagnosticd to read messages from the kernel (via
// /dev/oslog_stream). As best I can tell, these are either "metadata" or
// "log" messages. The "metadata" messages announce that a particular kext
// has been loaded or unloaded.
static ssize_t Hooked_read(int fildes, void *buf, size_t nbyte)
{
  bool is_diagnosticd = false;
  const char *owner_name = GetCallerOwnerName();
  if (!strcmp(owner_name, "diagnosticd")) {
    is_diagnosticd = true;
  }

  ssize_t retval = read(fildes, buf, nbyte);
  if (is_diagnosticd && nbyte && (retval > 0)) {
    char *data_string = get_data_as_string(buf, retval > 512 ? 512 : retval);
    if (data_string) {
      oslog_entry *entry = (oslog_entry *) buf;
      LogWithFormat(true, "Hook.mm: read(1): entry->ftid._namespace \'0x%x\', entry->ftid._type \'0x%x\', entry->ftid._flags \'0x%x\', entry->ftid._code \'0x%x\'",
                    entry->ftid._namespace, entry->ftid._type, entry->ftid._flags, entry->ftid._code);
      if ((entry->ftid._namespace == firehose_tracepoint_namespace_metadata) &&
          (entry->ftid._type == _firehose_tracepoint_type_metadata_kext))
      {
        firehose_trace_uuid_info_t uuid_info =
          (firehose_trace_uuid_info_t) &entry->data;
        uuid_t kext_uuid = {0};
        uuid_copy(kext_uuid, uuid_info->ftui_uuid);
        char uuid_string[PATH_MAX] = {0};
        uuid_unparse(kext_uuid, uuid_string);
        if (entry->ftid._code == firehose_tracepoint_code_load) {
          LogWithFormat(true, "Hook.mm: read(2): Kext \"%s\" loaded at offset \'%p\' with size \'%u\'",
                        uuid_string, uuid_info->ftui_address, uuid_info->ftui_size);
          add_new_kext(kext_uuid);
        } else if (entry->ftid._code == firehose_tracepoint_code_unload) {
          LogWithFormat(true, "Hook.mm: read(2): Kext \"%s\" unloaded, was at offset \'%p\' with size \'%u\'",
                        uuid_string, uuid_info->ftui_address, uuid_info->ftui_size);
          remove_new_kext(kext_uuid);
        }
      }
      // Calls from KernelLogging.kext are pretty recognizable. They're all
      // the same length, since they contain no 'data': None of its messages'
      // strings have any printf-style variables. And their '_code' values are
      // small, since KernelLogging.kext is itself small.
      bool from_KernelLogging_kext = false;
      if ((entry->ftid._namespace == firehose_tracepoint_namespace_log) &&
          (entry->ftid._type == _firehose_tracepoint_type_log_default) &&
          (entry->ftid._flags == _firehose_tracepoint_flags_pc_style_absolute) &&
          (retval == 40) && (entry->ftid._code < 0x1500))
      {
        from_KernelLogging_kext = true;
      }
      char fildes_path[PATH_MAX] = {0};
      fcntl(fildes, F_GETPATH, fildes_path);
      if (from_KernelLogging_kext) {
        LogWithFormat(true, "Hook.mm: read(3): fildes \"%s(%i)\", nbyte \'%u\', retval \'%i\', from KernelLogging.kext, buf\n%s",
                      fildes_path, fildes, nbyte, retval, data_string);
      } else {
        LogWithFormat(true, "Hook.mm: read(3): fildes \"%s(%i)\", nbyte \'%u\', retval \'%i\', buf\n%s",
                      fildes_path, fildes, nbyte, retval, data_string);
      }
      free(data_string);
    }
  }

  return retval;
}

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 101400
bool (*uuidpath_resolve_fd_caller)(int fd, uuid_t uuid, uint32_t name_offset, uint32_t arg3,
                                   char **name, char **arg5, char **imagepath, char **arg7) = NULL;

// Resolves the information from a kernel log message (received via
// read(/dev/oslog_stream)) into a "name" and "imagepath" for the outgoing
// message to the "log" or "Console" app. Fails if these strings aren't in the
// "uuiddb". Used on Mojave and up.
bool Hooked_uuidpath_resolve_fd(int fd, uuid_t uuid, uint32_t name_offset, uint32_t arg3,
                                char **name, char **arg5, char **imagepath, char **arg7)
{
  bool retval = uuidpath_resolve_fd_caller(fd, uuid, name_offset, arg3, name, arg5, imagepath, arg7);

  char fd_path[PATH_MAX] = {0};
  fcntl(fd, F_GETPATH, fd_path);
  char uuid_string[PATH_MAX] = {0};
  uuid_unparse(uuid, uuid_string);
  if (has_new_kext(uuid)) {
    LogWithFormat(true, "Hook.mm: uuidpath_resolve_fd(): fd \'%i\' (path \"%s\"), uuid \"%s\", name_offset \'0x%x\', arg3 \'0x%x\', name \"%s\", arg5 \"%s\", imagepath \"%s\", arg7 \"%s\", returning \'%i\'",
                  fd, fd_path, uuid_string, name_offset, arg3, (name && *name) ? *name : "null",
                  (arg5 && *arg5) ? *arg5 : "null", (imagepath && *imagepath) ? *imagepath : "null",
                  (arg7 && *arg7) ? *arg7 : "null", retval);
  }

  return retval;
}
#else
bool (*uuidpath_resolve_fd_caller)(int fd, uuid_t uuid, uint32_t name_offset,
                                   char **name, char **imagepath, char **arg5) = NULL;

// Resolves the information from a kernel log message (received via
// read(/dev/oslog_stream)) into a "name" and "imagepath" for the outgoing
// message to the "log" or "Console" app. Fails if these strings aren't in the
// "uuiddb". Used on Sierra and HighSierra.
bool Hooked_uuidpath_resolve_fd(int fd, uuid_t uuid, uint32_t name_offset,
                                char **name, char **imagepath, char **arg5)
{
  bool retval = uuidpath_resolve_fd_caller(fd, uuid, name_offset, name, imagepath, arg5);

  char fd_path[PATH_MAX] = {0};
  fcntl(fd, F_GETPATH, fd_path);
  char uuid_string[PATH_MAX] = {0};
  uuid_unparse(uuid, uuid_string);
  if (has_new_kext(uuid)) {
    LogWithFormat(true, "Hook.mm: uuidpath_resolve_fd(): fd \'%i\' (path \"%s\"), uuid \"%s\", name_offset \'0x%x\', name \"%s\", imagepath \"%s\", arg5 \'0x%x\', returning \'%i\'",
                  fd, fd_path, uuid_string, name_offset, (name && *name) ? *name : "null",
                  (imagepath && *imagepath) ? *imagepath : "null", arg5, retval);
  }

  return retval;
}
#endif

#pragma mark -

typedef struct _hook_desc {
  const void *hook_function;
  union {
    // For interpose hooks
    const void *orig_function;
    // For patch hooks
    const void *func_caller_ptr;
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
#ifndef __i386__
  PATCH_FUNCTION(__CFGetConverter, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation),
#endif

  // Client-side stuff

  INTERPOSE_FUNCTION(xpc_connection_create_mach_service),
  INTERPOSE_FUNCTION(xpc_connection_set_event_handler),

  // Server-side stuff

  INTERPOSE_FUNCTION(_simple_asl_log),
  INTERPOSE_FUNCTION(open),
  INTERPOSE_FUNCTION(read),
  PATCH_FUNCTION(uuidpath_resolve_fd, /System/Library/PrivateFrameworks/LoggingSupport.framework/LoggingSupport),
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
    // 0x40e0000 is the value returned by
    // uint32_t CSSymbolicatorGetFlagsForNListOnlyData(void).  We don't use
    // this method directly because it doesn't exist on OS X 10.6.  Unless
    // we limit ourselves to NList data, it will take too long to get a
    // stack trace where Dwarf debugging info is available (about 15 seconds
    // with Firefox).
    gSymbolicator =
      CSSymbolicatorCreateWithTaskFlagsAndNotification(mach_task_self(), 0x40e0000, 0);
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
    if (!CSIsNull(symbol)) {
      addressName = CSSymbolGetName(symbol);
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
    }
  }

  if (addressOffsetIsBaseAddress) {
    snprintf(holder, sizeof(holder), "%s 0x%llx",
             addressName, addressOffset);
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

void PrintCallstack(callstack_t callstack)
{
  if (!CanUseCF()) {
    return;
  }

  CreateGlobalSymbolicator();

  CSSymbolicatorRef symbolicator = {0};
  bool symbolicatorNeedsRelease = GetSymbolicator(&symbolicator);
  if (CSIsNull(symbolicator)) {
    return;
  }

  for (uint32_t i = 0; i < STACK_MAX; ++i) {
    uint64_t item = callstack[i];
    if (!item) {
      break;
    }
    void *address = (void *) item;
    PrintAddress(address, symbolicator);
  }

  if (symbolicatorNeedsRelease) {
    CSRelease(symbolicator);
  }
}

void PrintStackTrace()
{
  if (!CanUseCF()) {
    return;
  }

  callstack_t callstack = {0};
  void *addresses[STACK_MAX] = {0};
  uint32_t count = backtrace(addresses, STACK_MAX);
  for (uint32_t i = 0; i < count; ++i) {
    callstack[i] = (uint64_t) addresses[i];
  }

  PrintCallstack(callstack);
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

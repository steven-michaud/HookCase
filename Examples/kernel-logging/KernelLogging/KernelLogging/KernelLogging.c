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

#include <libkern/libkern.h>

#include <AvailabilityMacros.h>
#include <mach/mach_types.h>
#include <IOKit/IOLib.h>
#if (defined(MAC_OS_X_VERSION_10_12) || defined(MAC_OS_X_VERSION_10_13)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_12 / 100)
#include <os/log.h>
#endif

kern_return_t KernelLogging_start(kmod_info_t * ki, void *d);
kern_return_t KernelLogging_stop(kmod_info_t *ki, void *d);

#define FAIL_START 1

kern_return_t KernelLogging_start(kmod_info_t * ki, void *d)
{
  printf("KernelLogging(printf): KernelLogging_start()\n");
  IOLog("KernelLogging(IOLog): KernelLogging_start()\n");
#if (defined(MAC_OS_X_VERSION_10_12) || defined(MAC_OS_X_VERSION_10_13)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_12 / 100)
  os_log(OS_LOG_DEFAULT, "KernelLogging(os_log): KernelLogging_start()\n");
#endif
#ifdef FAIL_START
  return KERN_FAILURE;
#else
  return KERN_SUCCESS;
#endif
}

kern_return_t KernelLogging_stop(kmod_info_t *ki, void *d)
{
  printf("KernelLogging(printf): KernelLogging_stop()\n");
  IOLog("KernelLogging(IOLog): KernelLogging_stop()\n");
#if (defined(MAC_OS_X_VERSION_10_12) || defined(MAC_OS_X_VERSION_10_13)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_12 / 100)
  os_log(OS_LOG_DEFAULT, "KernelLogging(os_log): KernelLogging_stop()\n");
#endif
  return KERN_SUCCESS;
}

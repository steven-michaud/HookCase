# The MIT License (MIT)
#
# Copyright (c) 2019 Steven Michaud
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

CC=/usr/bin/clang++
MOJAVE_OR_ABOVE=$(shell expr `uname -r | cut -c 1-2` \>= 18)
# 32-bit builds no longer work on Mojave with some versions of XCode
ifeq ($(MOJAVE_OR_ABOVE), 1)
ARCHS=-arch x86_64
else
ARCHS=-arch i386 -arch x86_64
endif

all : diagnosticd-hook.dylib logger-hook.dylib

diagnosticd-hook.dylib : diagnosticd-hook.o
	$(CC) $(ARCHS) -o diagnosticd-hook.dylib diagnosticd-hook.o \
		-lobjc -framework Cocoa -framework Carbon \
		-Wl,-F/System/Library/PrivateFrameworks -framework CoreSymbolication \
		-framework LoggingSupport -dynamiclib

logger-hook.dylib : logger-hook.o
	$(CC) $(ARCHS) -o logger-hook.dylib logger-hook.o \
		-lobjc -framework Cocoa -framework Carbon \
		-Wl,-F/System/Library/PrivateFrameworks -framework CoreSymbolication \
		-dynamiclib

diagnosticd-hook.o : diagnosticd-hook.mm
	$(CC) $(ARCHS) -o diagnosticd-hook.o \
		-Wno-deprecated-declarations -c diagnosticd-hook.mm

logger-hook.o : logger-hook.mm
	$(CC) $(ARCHS) -o logger-hook.o \
		-Wno-deprecated-declarations -c logger-hook.mm

clean :
	rm diagnosticd-hook.o logger-hook.o diagnosticd-hook.dylib logger-hook.dylib

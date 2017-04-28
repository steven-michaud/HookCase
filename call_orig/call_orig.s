/* The MIT License (MIT)
 *
 * Copyright (c) 2017 Steven Michaud
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Template to test and generate code for user-mode "callers" that skip over the
 * breakpoint at the beginning of a method when calling it.  This allows a patch
 * hook to call the "original" method without having to unset and reset the
 * breakpoint.
 *
 * To accomplish this we need 1) to have a way to skip over the breakpoint and
 * 2) to use RIP/EIP relative addressing to make the caller expect to find a
 * pointer to the method's address at a given offset from the caller's own
 * address.
 *
 * 1) Skipping over the breakpoint
 *
 * For it to be possible to skip over the breakpoint at the beginning of a
 * method, at least the first two bytes of that method must have a predictable
 * content (two bytes is the length of our "int 0x2N" breakpoints).  For now,
 * at least, we only consider methods with standard C/C++ prologues to meet
 * this criterion.
 *
 * Standard C/C++ Prologues
 *
 * 64-bit                         32-bit
 *
 * push  %rbp                     push  %ebp
 * mov   %rsp, %rbp               mov   %esp, %ebp
 *
 * {0x55, 0x48, 0x89, 0xe5}       {0x55, 0x89, 0xe5}
 *
 * Given that the first N bytes of a breakpointed method are known, we can
 * have the caller "run" them itself, then jump to an address N bytes after
 * the beginning of the breakpointed method.
 *
 * Caller Methods
 *
 * 64-bit                         32-bit
 *
 * lea   _orig_addr(%rip), %r10   call  L_call_orig_1
 * mov   (%r10), %r10             L_call_orig_1:
 * add   $4, %r10                 pop   %eax
 * push  %rbp                     lea   _orig_addr-L_call_orig_1(%eax), %eax
 * mov   %rsp, %rbp               mov   (%eax), %eax
 * jmp   *%r10                    add   $3, %eax
 *                                push  %ebp
 *                                mov   %esp, %ebp
 *                                jmp   *%eax
 *
 * 2) Using RIP/EIP Relative Addressing to Access "Data"
 *
 * The two caller methods above use RIP/EIP relative addressing to access
 * 'orig_addr'.  To guarantee that the machine code for these methods expects
 * to find 'orig_addr' at a predictable address, we embed their source code
 * in this template and assemble/compile it.  The way we align them guarantees
 * that the code in the caller will expect to find 'orig_addr' at PAGE_SIZE
 * bytes from its own beginning.  See get_call_orig_func() in HookCase.cpp for
 * more information.
 */

/* Compile this with the following parameters:
 *   gcc -arch x86_64 -arch i386 call_orig.s -o call_orig
 *
 * Then load the 'call_orig' binary into a disassembler and copy the
 * 'call_orig' method's machine code into the appropriate locations in
 * HookCase.cpp -- g_call_orig_func_64bit and g_call_orig_func_32bit.
 */

/* void stuff(char *) */
_stuff:
#ifdef __x86_64__
  push    %rbp
  mov     %rsp, %rbp

  call    _puts

  pop     %rbp
  ret
#elif  __i386__
  push    %ebp
  mov     %esp, %ebp
  sub     $8, %esp

  mov     8(%ebp), %eax
  mov     %eax, (%esp)
  call    _puts

  add     $8, %esp
  pop     %ebp
  ret
#endif

_call_stuff:
#ifdef __x86_64__
  lea     _stuff_addr(%rip), %r10
  mov     (%r10), %r10
  add     $4, %r10

  push    %rbp
  mov     %rsp, %rbp
  jmp     *%r10
#elif  __i386__
  call    L_call_stuff_1
L_call_stuff_1:
  pop      %eax
  lea     _stuff_addr-L_call_stuff_1(%eax), %eax
  mov     (%eax), %eax
  add     $3, %eax

  push    %ebp
  mov     %esp, %ebp
  jmp     *%eax
#endif

.globl _main

_main:
#ifdef __x86_64__
  push    %rbp
  mov     %rsp, %rbp

  lea     _stuff(%rip), %rax
  mov     %rax, _stuff_addr(%rip)

  lea     _msg(%rip), %rdi
  call    _call_stuff

  xor     %rax, %rax
  pop     %rbp
  ret
#elif  __i386__
  push    %ebp
  mov     %esp, %ebp
  sub     $8, %esp

  call    L_main_1
L_main_1:
  pop     %ecx

  lea     _stuff-L_main_1(%ecx), %eax
  mov     %eax, _stuff_addr-L_main_1(%ecx)

  lea     _msg-L_main_1(%ecx), %eax
  mov     %eax, (%esp)
  call    _call_stuff

  xor     %eax, %eax
  add     $8, %esp
  pop     %ebp
  ret
#endif

/* Page-align 'call_orig' */
.align 12

_call_orig:
#ifdef __x86_64__
  lea     _orig_addr(%rip), %r10
  mov     (%r10), %r10
  add     $4, %r10

  push    %rbp
  mov     %rsp, %rbp
  jmp     *%r10
#elif  __i386__
  call    L_call_orig_1
L_call_orig_1:
  pop      %eax
  lea     _orig_addr-L_call_orig_1(%eax), %eax
  mov     (%eax), %eax
  add     $3, %eax

  push    %ebp
  mov     %esp, %ebp
  jmp     *%eax
#endif

/* Page-align 'orig_addr' -- which places it PAGE_SIZE bytes from the
 * beginning of 'call_orig'
 */
.align 12

_orig_addr:
  .quad 0

.data

_msg:
  .asciz "Hello World!\n"

_stuff_addr:
  .quad 0


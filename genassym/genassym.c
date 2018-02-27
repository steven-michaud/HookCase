// The MIT License (MIT)
//
// Copyright (c) 2017 Steven Michaud
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

// Modified from the xnu kernel's osfmk/i386/genassym.c.  Used to generate
// defines for structure offsets used in assembly code (like HookCase.s).

#include <stddef.h>

#include <sys/types.h>
#include <sys/kernel_types.h>
#include <mach/mach_types.h>

#define THREAD_STATE_NONE  13

#define x86_SAVED_STATE32  THREAD_STATE_NONE + 1
#define x86_SAVED_STATE64  THREAD_STATE_NONE + 2

/*
 * The format in which thread state is saved by Mach on this machine.  This
 * state flavor is most efficient for exception RPC's to kernel-loaded
 * servers, because copying can be avoided:
 */
struct x86_saved_state32 {
  uint32_t gs;
  uint32_t fs;
  uint32_t es;
  uint32_t ds;
  uint32_t edi;
  uint32_t esi;
  uint32_t ebp;
  uint32_t cr2; /* kernel esp stored by pusha - we save cr2 here later */
  uint32_t ebx;
  uint32_t edx;
  uint32_t ecx;
  uint32_t eax;
  uint16_t trapno;
  uint16_t cpu;
  uint32_t err;
  uint32_t eip;
  uint32_t cs;
  uint32_t efl;
  uint32_t uesp;
  uint32_t ss;
};
typedef struct x86_saved_state32 x86_saved_state32_t;

#define x86_SAVED_STATE32_COUNT ((mach_msg_type_number_t) \
  (sizeof (x86_saved_state32_t)/sizeof(unsigned int)))

#pragma pack(4)
/*
 * This is the state pushed onto the 64-bit interrupt stack
 * on any exception/trap/interrupt.
 */
struct x86_64_intr_stack_frame {
  uint16_t trapno;
  uint16_t cpu;
  uint32_t _pad;
  uint64_t trapfn;
  uint64_t err;
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
};
typedef struct x86_64_intr_stack_frame x86_64_intr_stack_frame_t;
/* Note: sizeof(x86_64_intr_stack_frame_t) must be a multiple of 16 bytes */

/*
 * thread state format for task running in 64bit long mode
 * in long mode, the same hardware frame is always pushed regardless
 * of whether there was a change in privlege level... therefore, there
 * is no need for an x86_saved_state64_from_kernel variant
 */
struct x86_saved_state64 {
  uint64_t rdi;  /* arg0 for system call */
  uint64_t rsi;
  uint64_t rdx;
  uint64_t r10;  /* R10 := RCX prior to syscall trap */
  uint64_t r8;
  uint64_t r9;  /* arg5 for system call */

  uint64_t cr2;
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t r11;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rax;

  uint32_t gs;
  uint32_t fs;

  uint64_t  _pad;

  struct x86_64_intr_stack_frame isf;
};
typedef struct x86_saved_state64 x86_saved_state64_t;
#define x86_SAVED_STATE64_COUNT ((mach_msg_type_number_t) \
  (sizeof (struct x86_saved_state64)/sizeof(unsigned int)))

/*
 * Unified, tagged saved state:
 */
typedef struct {
  uint32_t flavor; /* x86_SAVED_STATE64 or x86_SAVED_STATE32 */
  uint32_t _pad_for_16byte_alignment[3];
  union {
    x86_saved_state32_t ss_32;
    x86_saved_state64_t ss_64;
  } uss;
} x86_saved_state_t;
#define ss_32 uss.ss_32
#define ss_64 uss.ss_64
#pragma pack()


typedef enum {
  TASK_MAP_32BIT,   /* 32-bit user, compatibility mode */ 
  TASK_MAP_64BIT,   /* 64-bit user thread, shared space */ 
} task_map_t;

typedef struct cpu_data_fake
{
  uint32_t pad1[6];
  volatile int cpu_preemption_level;
  int cpu_number;                   /* Logical CPU */
  x86_saved_state_t *cpu_int_state; /* interrupt state */
  /* A stack's "top" is where it grows or shrinks with each push or pop */
  vm_offset_t cpu_active_stack;     /* kernel stack base */
  vm_offset_t cpu_kernel_stack;     /* kernel stack top */
  vm_offset_t cpu_int_stack_top;
  int cpu_interrupt_level;
  uint32_t pad2[47];
  volatile addr64_t cpu_active_cr3 __attribute((aligned(64)));
  union {
    volatile uint32_t cpu_tlb_invalid;
    struct {
      volatile uint16_t cpu_tlb_invalid_local;
      volatile uint16_t cpu_tlb_invalid_global;
    };
  };
  volatile task_map_t cpu_task_map;
  volatile addr64_t cpu_task_cr3;
  union {
    struct {
      addr64_t cpu_kernel_cr3;
    };
    struct {
      volatile addr64_t cpu_task_cr3_nokernel;
      addr64_t cpu_kernel_cr3_kpti;
      boolean_t cpu_pagezero_mapped;
      addr64_t cpu_uber_isf;
      uint64_t cpu_uber_tmp;
      addr64_t cpu_uber_user_gs_base;
      addr64_t cpu_user_stack;
    };
    struct {
      addr64_t cpu_kernel_cr3_kpti_bp;
      volatile addr64_t cpu_task_cr3_nokernel_bp;
      uint64_t pad3[5];
      addr64_t cpu_user_stack_bp;
    };
  };
} cpu_data_fake_t;


#define DECLARE(SYM,VAL) \
 __asm("DEFINITION__define__" SYM ":\t .ascii \"%0\"" : : "n"  ((u_int)(VAL)))

int main(
  int  argc,
  char  ** argv);

int
main(
 int argc,
 char **argv)
{

#define R_(x)  offsetof(x86_saved_state_t, ss_32.x)
  DECLARE("R32_CS", R_(cs));
  DECLARE("R32_SS", R_(ss));
  DECLARE("R32_DS", R_(ds));
  DECLARE("R32_ES", R_(es));
  DECLARE("R32_FS", R_(fs));
  DECLARE("R32_GS", R_(gs));
  DECLARE("R32_UESP", R_(uesp));
  DECLARE("R32_EBP", R_(ebp));
  DECLARE("R32_EAX", R_(eax));
  DECLARE("R32_EBX", R_(ebx));
  DECLARE("R32_ECX", R_(ecx));
  DECLARE("R32_EDX", R_(edx));
  DECLARE("R32_ESI", R_(esi));
  DECLARE("R32_EDI", R_(edi));
  DECLARE("R32_TRAPNO", R_(trapno));
  DECLARE("R32_CPU", R_(cpu));
  DECLARE("R32_ERR", R_(err));
  DECLARE("R32_EFLAGS", R_(efl));
  DECLARE("R32_EIP", R_(eip));
  DECLARE("R32_CR2", R_(cr2));
  DECLARE("ISS32_SIZE", sizeof (x86_saved_state32_t));

#define R64_(x)  offsetof(x86_saved_state_t, ss_64.x)
  DECLARE("R64_FS", R64_(fs));
  DECLARE("R64_GS", R64_(gs));
  DECLARE("R64_R8", R64_(r8));
  DECLARE("R64_R9", R64_(r9));
  DECLARE("R64_R10", R64_(r10));
  DECLARE("R64_R11", R64_(r11));
  DECLARE("R64_R12", R64_(r12));
  DECLARE("R64_R13", R64_(r13));
  DECLARE("R64_R14", R64_(r14));
  DECLARE("R64_R15", R64_(r15));
  DECLARE("R64_RBP", R64_(rbp));
  DECLARE("R64_RAX", R64_(rax));
  DECLARE("R64_RBX", R64_(rbx));
  DECLARE("R64_RCX", R64_(rcx));
  DECLARE("R64_RDX", R64_(rdx));
  DECLARE("R64_RSI", R64_(rsi));
  DECLARE("R64_RDI", R64_(rdi));
  DECLARE("R64_CS", R64_(isf.cs));
  DECLARE("R64_SS", R64_(isf.ss));
  DECLARE("R64_RSP", R64_(isf.rsp));
  DECLARE("R64_TRAPNO", R64_(isf.trapno));
  DECLARE("R64_CPU", R64_(isf.cpu));
  DECLARE("R64_TRAPFN", R64_(isf.trapfn));
  DECLARE("R64_ERR", R64_(isf.err));
  DECLARE("R64_RFLAGS", R64_(isf.rflags));
  DECLARE("R64_RIP", R64_(isf.rip));
  DECLARE("R64_CR2", R64_(cr2));
  DECLARE("ISS64_OFFSET", R64_(isf));
  DECLARE("ISS64_SIZE", sizeof (x86_saved_state64_t));

#define ISF64_(x)  offsetof(x86_64_intr_stack_frame_t, x)
  DECLARE("ISF64_TRAPNO", ISF64_(trapno));
  DECLARE("ISF64_CPU", ISF64_(cpu));
  DECLARE("ISF64_TRAPFN", ISF64_(trapfn));
  DECLARE("ISF64_ERR", ISF64_(err));
  DECLARE("ISF64_RIP", ISF64_(rip));
  DECLARE("ISF64_CS", ISF64_(cs));
  DECLARE("ISF64_RFLAGS", ISF64_(rflags));
  DECLARE("ISF64_RSP", ISF64_(rsp));
  DECLARE("ISF64_SS", ISF64_(ss));
  DECLARE("ISF64_SIZE", sizeof(x86_64_intr_stack_frame_t));

  DECLARE("SS_FLAVOR", offsetof(x86_saved_state_t, flavor));
  DECLARE("SS_32", x86_SAVED_STATE32);
  DECLARE("SS_64", x86_SAVED_STATE64);

  DECLARE("CPU_PREEMPTION_LEVEL",
    offsetof(cpu_data_fake_t, cpu_preemption_level));
  DECLARE("CPU_NUMBER",
    offsetof(cpu_data_fake_t, cpu_number));
  DECLARE("CPU_INT_STATE",
    offsetof(cpu_data_fake_t, cpu_int_state));
  DECLARE("CPU_ACTIVE_STACK",
    offsetof(cpu_data_fake_t, cpu_active_stack));
  DECLARE("CPU_KERNEL_STACK",
    offsetof(cpu_data_fake_t, cpu_kernel_stack));
  DECLARE("CPU_INT_STACK_TOP",
    offsetof(cpu_data_fake_t, cpu_int_stack_top));
  DECLARE("CPU_INTERRUPT_LEVEL",
    offsetof(cpu_data_fake_t, cpu_interrupt_level));
  DECLARE("CPU_ACTIVE_CR3",
    offsetof(cpu_data_fake_t, cpu_active_cr3));
  DECLARE("CPU_TLB_INVALID",
    offsetof(cpu_data_fake_t, cpu_tlb_invalid));
  DECLARE("CPU_TLB_INVALID_LOCAL",
    offsetof(cpu_data_fake_t, cpu_tlb_invalid_local));
  DECLARE("CPU_TLB_INVALID_GLOBAL",
    offsetof(cpu_data_fake_t, cpu_tlb_invalid_global));
  DECLARE("CPU_TASK_MAP",
    offsetof(cpu_data_fake_t, cpu_task_map));
  DECLARE("CPU_TASK_CR3",
    offsetof(cpu_data_fake_t, cpu_task_cr3));
  DECLARE("CPU_KERNEL_CR3",
    offsetof(cpu_data_fake_t, cpu_kernel_cr3));
  DECLARE("CPU_TASK_CR3_NOKERNEL",
    offsetof(cpu_data_fake_t, cpu_task_cr3_nokernel));
  DECLARE("CPU_KERNEL_CR3_KPTI",
    offsetof(cpu_data_fake_t, cpu_kernel_cr3_kpti));
  DECLARE("CPU_UBER_ISF",
    offsetof(cpu_data_fake_t, cpu_uber_isf));
  DECLARE("CPU_UBER_TMP",
    offsetof(cpu_data_fake_t, cpu_uber_tmp));
  DECLARE("CPU_USER_STACK",
    offsetof(cpu_data_fake_t, cpu_user_stack));
  DECLARE("CPU_KERNEL_CR3_KPTI_BP",
    offsetof(cpu_data_fake_t, cpu_kernel_cr3_kpti_bp));
  DECLARE("CPU_TASK_CR3_NOKERNEL_BP",
    offsetof(cpu_data_fake_t, cpu_task_cr3_nokernel_bp));
  DECLARE("CPU_USER_STACK_BP",
    offsetof(cpu_data_fake_t, cpu_user_stack_bp));

 return (0);
}

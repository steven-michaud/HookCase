/* The MIT License (MIT)
 *
 * Copyright (c) 2019 Steven Michaud
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

/* This file must be includable in HookCase.s.  So basically everything but
 * #defines should be isolated in "#ifndef __ASSEMBLER__" blocks.  And
 * don't use // comments.
 */

#ifndef HookCase_h
#define HookCase_h

/* From the xnu kernel's osfmk/i386/seg.h (begin) */

#define SZ_64  0x2   /* 64-bit segment */
#define SZ_32  0x4   /* 32-bit segment */
#define SZ_G   0x8   /* 4K limit field */

#define ACC_A    0x01   /* accessed */
#define ACC_TYPE 0x1e   /* type field: */

#define ACC_TYPE_SYSTEM 0x00   /* system descriptors: */

#define ACC_LDT          0x02       /* LDT */
#define ACC_CALL_GATE_16 0x04       /* 16-bit call gate */
#define ACC_TASK_GATE    0x05       /* task gate */
#define ACC_TSS          0x09       /* task segment */
#define ACC_CALL_GATE    0x0c       /* call gate */
#define ACC_INTR_GATE    0x0e       /* interrupt gate */
#define ACC_TRAP_GATE    0x0f       /* trap gate */

#define ACC_TSS_BUSY     0x02       /* task busy */

#define ACC_TYPE_USER    0x10   /* user descriptors */

#define ACC_DATA     0x10       /* data */
#define ACC_DATA_W   0x12       /* data, writable */
#define ACC_DATA_E   0x14       /* data, expand-down */
#define ACC_DATA_EW  0x16       /* data, expand-down,
                                   writable */
#define ACC_CODE     0x18       /* code */
#define ACC_CODE_R   0x1a       /* code, readable */
#define ACC_CODE_C   0x1c       /* code, conforming */
#define ACC_CODE_CR  0x1e       /* code, conforming,
                                   readable */
#define ACC_PL     0x60   /* access rights: */
#define ACC_PL_K   0x00   /* kernel access only */
#define ACC_PL_U   0x60   /* user access */
#define ACC_P      0x80   /* segment present */

/*
 * Components of a selector
 */
#define SEL_LDTS 0x04   /* local selector */
#define SEL_PL  0x03   /* privilege level: */
#define SEL_PL_K 0x00       /* kernel selector */
#define SEL_PL_U 0x03       /* user selector */

/*
 * Convert selector to descriptor table index.
 */
#define sel_idx(sel) (selector_to_sel(sel).index)
#define SEL_TO_INDEX(s) ((s)>>3)

#define NULL_SEG 0

/*
 * Kernel descriptors for MACH - 64-bit flat address space.
 */
#define KERNEL64_CS  0x08  /* 1:  K64 code */
#define SYSENTER_CS  0x0b  /*     U32 sysenter pseudo-segment */
#define KERNEL64_SS  0x10  /* 2:  KERNEL64_CS+8 for syscall */
#define USER_CS      0x1b  /* 3:  U32 code */
#define USER_DS      0x23  /* 4:  USER_CS+8 for sysret */
#define USER64_CS    0x2b  /* 5:  USER_CS+16 for sysret */
#define USER64_DS USER_DS  /*     U64 data pseudo-segment */
#define KERNEL_LDT   0x30  /* 6:  */
                           /* 7:  other 8 bytes of KERNEL_LDT */
#define KERNEL_TSS   0x40  /* 8:  */
                           /* 9:  other 8 bytes of KERNEL_TSS */
#define KERNEL32_CS  0x50  /* 10: */
#define USER_LDT     0x58  /* 11: */
                           /* 12: other 8 bytes of USER_LDT */
#define KERNEL_DS    0x68  /* 13: 32-bit kernel data */

#define SYSENTER_TF_CS (USER_CS|0x10000)
#define SYSENTER_DS KERNEL64_SS /* sysenter kernel data segment */

/*
 * 64-bit kernel LDT descriptors
 */
#define SYSCALL_CS    0x07 /* syscall pseudo-segment */
#define USER_CTHREAD  0x0f /* user cthread area */
#define USER_SETTABLE 0x1f /* start of user settable ldt entries */

/* From the xnu kernel's osfmk/i386/seg.h (end) */

/* From the xnu kernel's osfmk/i386/proc_reg.h */
#define CR0_TS        0x00000008 /* Task switch */
#define CR4_PGE       0x00000080 /* Page Global Enable */

/* From the xnu kernel's osfmk/i386/mp_desc.c */
#define K_INTR_GATE (ACC_P|ACC_PL_K|ACC_INTR_GATE)
#define U_INTR_GATE (ACC_P|ACC_PL_U|ACC_INTR_GATE)

/* From the xnu kernel's osfmk/i386/cpu_data.h (begin) */

#ifdef __ASSEMBLER__
#define TASK_MAP_32BIT 0
#define TASK_MAP_64BIT 1
#else
typedef enum {
  TASK_MAP_32BIT,   /* 32-bit user, compatibility mode */ 
  TASK_MAP_64BIT,   /* 64-bit user thread, shared space */ 
} task_map_t;
#endif

/* From the xnu kernel's osfmk/i386/cpu_data.h (end) */

/* From the xnu kernel's osfmk/mach/i386/thread_status.h (begin) */

#define THREAD_STATE_NONE  13

#define x86_SAVED_STATE32  THREAD_STATE_NONE + 1
#define x86_SAVED_STATE64  THREAD_STATE_NONE + 2

/* From the xnu kernel's osfmk/mach/i386/thread_status.h (end) */

/* These are the two GS bases that get swapped by the 'swapgs' instruction */
#define MSR_IA32_GS_BASE 0xC0000101 /* Current GS base -- kernel or user */
#define MSR_IA32_KERNEL_GS_BASE 0xC0000102 /* "Stored" GS base */

/*
 * Prior to version 2.1, HookCase used the interrupts from 0x20 through 0x23.
 * But this caused trouble with VMware Fusion running as host, so now we use
 * 0x30 through 0x33. The problem with VMware Fusion is reported at bug #5
 * (https://github.com/steven-michaud/HookCase/issues/5).
 */

/* Define the interrupts that HookCase will use internally. */
#define HC_INT1 0x30UL
#define HC_INT2 0x31UL
#define HC_INT3 0x32UL
#define HC_INT4 0x33UL
#define HC_INT5 0x34UL

#ifndef __ASSEMBLER__

/* From the xnu kernel's osfmk/i386/thread_status.h (begin) */

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
  uint64_t r9;   /* arg5 for system call */

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

/* From the xnu kernel's osfmk/i386/thread_status.h (end) */

/* Derived from the xnu kernel's osfmk/i386/cpu_data.h (start) */

typedef struct cpu_data_fake
{
  uint32_t pad1[6];
  volatile int cpu_preemption_level;  // Offset 0x18
  int cpu_number;                     // Logical CPU (offset 0x1c)
  x86_saved_state_t *cpu_int_state;   // Interrupt state (offset 0x20)
  /* A stack's "top" is where it grows or shrinks with each push or pop */
  vm_offset_t cpu_active_stack;       // Kernel stack base
  vm_offset_t cpu_kernel_stack;       // Kernel stack top
  vm_offset_t cpu_int_stack_top;      // Offset 0x38
  int cpu_interrupt_level;            // Offset 0x40
  uint32_t pad2[47];
  union {
    struct {
      volatile addr64_t cpu_active_cr3 __attribute((aligned(64))); // Offset 0x100
      union {                             // Offset 0x108
        volatile uint32_t cpu_tlb_invalid;
        struct {
          volatile uint16_t cpu_tlb_invalid_local;
          volatile uint16_t cpu_tlb_invalid_global;
        };
      };
      // MDS bug fix not present, 10.14.4 and prior
      volatile task_map_t cpu_task_map;   // Offset 0x10c
      // User-mode (per-task) CR3 with kernel mapped in
      volatile addr64_t cpu_task_cr3;     // Offset 0x110
      union {
        // KPTI not supported
        struct {
          addr64_t cpu_kernel_cr3;          // Offset 0x118
        };
        // KPTI enabled, 10.13.2 and above
        struct {
          union {
            // 10.13.2 and 10.13.3 (Apple goofed here, but fixed the mistake
            // in 10.13.4)
            struct {
              // User-mode (per-task) CR3 with kernel unmapped.
              volatile addr64_t cpu_user_cr3_goofed;  // Offset 0x118
              addr64_t cpu_kernel_cr3_goofed;         // Offset 0x120
            };
            // 10.13.4 and above
            struct {
              addr64_t cpu_kernel_cr3_kpti;           // Offset 0x118
              // User-mode (per-task) CR3 with kernel unmapped
              volatile addr64_t cpu_user_cr3;         // Offset 0x120, cpu_ucr3
            };
          };
          boolean_t cpu_pagezero_mapped;              // Offset 0x128
          addr64_t cpu_uber_isf;                      // Offset 0x130
          uint64_t cpu_uber_tmp;                      // Offset 0x138
          addr64_t cpu_uber_user_gs_base;             // Offset 0x140
          addr64_t cpu_excstack;                      // Offset 0x148, cd_estack
        };
        // KPTI enabled, backported to 10.12.6 and 10.11.6
        struct {
          addr64_t cpu_kernel_cr3_kpti_bp;            // Offset 0x118
          // User-mode (per-task) CR3 with kernel unmapped
          volatile addr64_t cpu_user_cr3_bp;          // Offset 0x120
          uint64_t pad3[5];
          addr64_t cpu_excstack_bp;                   // Offset 0x150
        };
      };
    };
    // MDS bug fix present and KDPI supported, 10.14.5 and above?
    // https://www.intel.com/content/www/us/en/architecture-and-technology/mds.html
    struct {
      uint64_t pad4[2];
      __uint128_t cpu_invpcid_target;         // Offset 0x110
      volatile task_map_t cpu_task_map_mds;   // Offset 0x120
      uint64_t cpu_task_cr3_minus;            // Offset 0x128
      addr64_t cpu_kernel_cr3_mds;            // Offset 0x130
      // User-mode (per-task) CR3 with kernel unmapped
      volatile addr64_t cpu_user_cr3_mds;     // Offset 0x138, cpu_ucr3
      // User-mode (per-task) CR3 with kernel mapped in
      volatile addr64_t cpu_task_cr3_mds;     // Offset 0x140
      boolean_t cpu_pagezero_mapped_mds;      // Offset 0x148
      addr64_t cpu_uber_isf_mds;              // Offset 0x150
      uint64_t cpu_uber_tmp_mds;              // Offset 0x158
      addr64_t cpu_uber_user_gs_base_mds;     // Offset 0x160
      addr64_t cpu_excstack_mds;              // Offset 0x168, cd_estack
    };
  };
} cpu_data_fake_t;

#define CPU_DATA_GET_FUNC_BODY(member,type)    \
  type ret;                                    \
  __asm__ volatile ("mov %%gs:%P1,%0"          \
    : "=r" (ret)                               \
    : "i" (offsetof(cpu_data_fake_t,member))); \
  return ret;

static inline int get_cpu_number(void)
{
  CPU_DATA_GET_FUNC_BODY(cpu_number,int)
}

/* Derived from the xnu kernel's osfmk/i386/cpu_data.h (end) */

extern "C" void hc_int1_raw_handler(void);
extern "C" void hc_int2_raw_handler(void);
extern "C" void hc_int3_raw_handler(void);
extern "C" void hc_int4_raw_handler(void);
extern "C" void hc_int5_raw_handler(void);

extern "C" void stub_handler(void);

extern "C" Boolean OSCompareAndSwap_fixed(UInt32 oldValue, UInt32 newValue,
                                          volatile UInt32 *address);
extern "C" Boolean OSCompareAndSwap64_fixed(UInt64 oldValue, UInt64 newValue,
                                            volatile UInt64 *address);
extern "C" Boolean OSCompareAndSwapPtr_fixed(void *oldValue, void *newValue,
                                             void * volatile *address);

#undef OSCompareAndSwap
#define OSCompareAndSwap OSCompareAndSwap_fixed
#undef OSCompareAndSwap64
#define OSCompareAndSwap64 OSCompareAndSwap64_fixed
#undef OSCompareAndSwapPtr
#define OSCompareAndSwapPtr OSCompareAndSwapPtr_fixed

extern "C" Boolean OSCompareAndSwap128(__uint128_t oldValue, __uint128_t newValue,
                                       volatile __uint128_t *address);

typedef struct vm_page *vm_page_t;
extern "C" void vm_page_validate_cs_caller(vm_page_t page);
struct fileglob;
extern "C" int mac_file_check_library_validation_caller(proc_t proc,
                                                        struct fileglob *fg,
                                                        off_t slice_offset,
                                                        user_long_t error_message,
                                                        size_t error_message_size);
extern "C" int mac_file_check_mmap_caller(struct ucred *cred, struct fileglob *fg,
                                          int prot, int flags, uint64_t offset,
                                          int *maxprot);

#endif /* #ifndef __ASSEMBLER__ */

#endif /* HookCase_h */

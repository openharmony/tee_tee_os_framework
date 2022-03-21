/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEED_PRIVATE_H
#define TEED_PRIVATE_H

#include <arch.h>
#include <context.h>
#include <interrupt_mgmt.h>
#include <platform_def.h>
#include <psci.h>

/*
 * Secure Payload PM state information e.g. SP is suspended, uninitialised etc
 * and macros to access the state information in the per-cpu 'state' flags
 */
#define TEE_PSTATE_OFF        0
#define TEE_PSTATE_ON         1
#define TEE_PSTATE_SUSPEND    2
#define TEE_PSTATE_SHIFT      0u
#define TEE_PSTATE_MASK       0x3u
#define get_tee_pstate(state) (((state) >> TEE_PSTATE_SHIFT) & TEE_PSTATE_MASK)

#define clr_tee_pstate(state)                        \
	do {                                              \
		((state) &= ~(TEE_PSTATE_MASK <<     \
		TEE_PSTATE_SHIFT));                  \
	} while (0)

#define set_tee_pstate(st, pst)                      \
	do {                                              \
		clr_tee_pstate(st);                  \
		(st) |= ((pst) & TEE_PSTATE_MASK) << \
		TEE_PSTATE_SHIFT;                    \
	} while (0)

/* smc id added for TEE */
#define TEE_STD_REE_SIQ                     0xb200000a
#define TEE_STD_CRASH                       0xb200000b
#define TEE_ENTRY_DONE_AARCH32              0xb2000000
#define TEE_ON_DONE_AARCH32                 0xb2000001
#define TEE_OFF_DONE_AARCH32                0xb2000002
#define TEE_SUSPEND_DONE_AARCH32            0xb2000003
#define TEE_RESUME_DONE_AARCH32             0xb2000004
#define TEE_PREEMPTED_AARCH32               0xb2000005
#define TEE_HANDLED_S_EL1_FIQ_AARCH32       0xb2000006

/*
 * Function identifiers to send smc request to SP from NS and the the repsonse
 * to NS from SP
 */
#define TEE_STD_REQUEST                     0xb2000008
#define TEE_STD_RESPONSE                    0xb2000009

#define CPU_INIT_DONE                            1
#define CPU_IDLE_STATE                           0
#define CPU_SUSPEND_STATE                        1
/*
 * This flag is used by the TEED to determine if the TEE is servicing a yielding
 * SMC request prior to programming the next entry into the TEE e.g. if TEE
 * execution is preempted by a non-secure interrupt and handed control to the
 * normal world. If another request which is distinct from what the TEE was
 * previously doing arrives, then this flag will be help the TEED to either
 * reject the new request or service it while ensuring that the previous context
 * is not corrupted.
 */
#define YIELD_SMC_ACTIVE_FLAG_SHIFT             2u
#define YIELD_SMC_ACTIVE_FLAG_MASK              1u
#define SMC_INACTIVE                            0
#define SMC_ACTIVE                              1
#define get_yield_smc_active_flag(state)                                  \
		(((state) >> YIELD_SMC_ACTIVE_FLAG_SHIFT)                 \
		 & YIELD_SMC_ACTIVE_FLAG_MASK)

#define set_yield_smc_active_flag(state)                                  \
	do {                                                              \
		((state) |=                                               \
		1u << YIELD_SMC_ACTIVE_FLAG_SHIFT);                       \
	} while (0)

#define clr_yield_smc_active_flag(state)                                  \
	do {                                                              \
		((state) &=                                               \
		~(YIELD_SMC_ACTIVE_FLAG_MASK                              \
		<< YIELD_SMC_ACTIVE_FLAG_SHIFT));                         \
	} while (0)
/*
 * This flag is used by the TEED to determine if the TEE has crashed in any way
 * and it is impossible to continue. The flag will disable forwarding any calls
 * to secure os system.
 */
#define INIT_CONTEXT_NOT_SAVED                0x0
#define INIT_CONTEXT_SAVED                    0x1
#define INVALID_PC_ADDR                       0x0
#define INVALID_C_RT_CTX                      0x0
#define STD_NO_CRASH_FLAG                     0x0
#define SECURE_WORLD_FLAG                     0x0
#define TEE_SETUP_FAIL                        0x1
#define STD_SMC_CRASH_FLAG_SHIFT              0x3u
#define STD_SMC_CRASH_FLAG_MASK               0x1u
#define get_std_crash_flag(state)                                              \
		(((state) >> STD_SMC_CRASH_FLAG_SHIFT) &                       \
		STD_SMC_CRASH_FLAG_MASK)

#define set_std_crash_flag(state)                                              \
	do {                                                                   \
		((state) |=                                                    \
		1 << STD_SMC_CRASH_FLAG_SHIFT);                                \
	} while (0)

/* Secure Payload execution state information i.e. aarch32 or aarch64 */
#define TEE_AARCH32		MODE_RW_32
#define TEE_AARCH64		MODE_RW_64

/* The SPD should know the type of Secure Payload */
#define TEE_TYPE_UP		PSCI_TOS_NOT_UP_MIG_CAP
#define TEE_TYPE_UPM    PSCI_TOS_UP_MIG_CAP
#define TEE_TYPE_MP		PSCI_TOS_NOT_PRESENT_MP

/*
 * Secure Payload migrate type information as known to the SPD. We assume that
 * the SPD is dealing with an MP Secure Payload.
 */
#define TEE_MIGRATE_INFO		TEE_TYPE_MP

/*
 * Number of cpus that the present on this platform. Rely on a topology
 * tree to determine this in the future to avoid assumptions about mpidr
 * allocation
 */
#define TEED_CORE_COUNT		PLATFORM_CORE_COUNT

/*
 * Constants that allow assembler code to preserve callee-saved registers of the
 * C runtime context while performing a security state switch.
 */
#define TEED_C_RT_CTX_X19          0x0
#define TEED_C_RT_CTX_X20          0x8
#define TEED_C_RT_CTX_X21          0x10
#define TEED_C_RT_CTX_X22          0x18
#define TEED_C_RT_CTX_X23          0x20
#define TEED_C_RT_CTX_X24          0x28
#define TEED_C_RT_CTX_X25          0x30
#define TEED_C_RT_CTX_X26          0x38
#define TEED_C_RT_CTX_X27          0x40
#define TEED_C_RT_CTX_X28          0x48
#define TEED_C_RT_CTX_X29          0x50
#define TEED_C_RT_CTX_X30          0x58
#define TEED_C_RT_CTX_SIZE         0x60
#define TEED_C_RT_CTX_ENTRIES      (TEED_C_RT_CTX_SIZE >> DWORD_SHIFT)

/*
 * Constants that allow assembler code to preserve caller-saved registers of the
 * SP context while performing a TEE preemption.
 * Note: These offsets have to match with the offsets for the corresponding
 * registers in cpu_context as we are using memcpy to copy the values from
 * cpu_context to sp_ctx.
 */
#define TEED_SP_CTX_X0             0x0
#define TEED_SP_CTX_X1             0x8
#define TEED_SP_CTX_X2             0x10
#define TEED_SP_CTX_X3             0x18
#define TEED_SP_CTX_X4             0x20
#define TEED_SP_CTX_X5             0x28
#define TEED_SP_CTX_X6             0x30
#define TEED_SP_CTX_X7             0x38
#define TEED_SP_CTX_X8             0x40
#define TEED_SP_CTX_X9             0x48
#define TEED_SP_CTX_X10            0x50
#define TEED_SP_CTX_X11            0x58
#define TEED_SP_CTX_X12            0x60
#define TEED_SP_CTX_X13            0x68
#define TEED_SP_CTX_X14            0x70
#define TEED_SP_CTX_X15            0x78
#define TEED_SP_CTX_X16            0x80
#define TEED_SP_CTX_X17            0x88
#define TEED_SP_CTX_SIZE           0x90
#define TEED_SP_CTX_ENTRIES        (TEED_SP_CTX_SIZE >> DWORD_SHIFT)

#ifndef __ASSEMBLY__

#include <stdint.h>

/*
 * The number of arguments to save during a SMC call for TEE.
 * Currently only x1 and x2 are used by TEE.
 */
#define TEE_NUM_ARGS              0x2

/* AArch64 callee saved general purpose register context structure. */
DEFINE_REG_STRUCT(c_rt_regs, TEED_C_RT_CTX_ENTRIES);

/*
 * Compile time assertion to ensure that both the compiler and linker
 * have the same double word aligned view of the size of the C runtime
 * register context.
 */
CASSERT(TEED_C_RT_CTX_SIZE == sizeof(c_rt_regs_t), \
	assert_spd_c_rt_regs_size_mismatch);

/* SEL1 Secure payload (SP) caller saved register context structure. */
DEFINE_REG_STRUCT(sp_ctx_regs, TEED_SP_CTX_ENTRIES);

/*
 * Compile time assertion to ensure that both the compiler and linker
 * have the same double word aligned view of the size of the C runtime
 * register context.
 */
CASSERT(TEED_SP_CTX_SIZE == sizeof(sp_ctx_regs_t), \
	assert_spd_sp_regs_size_mismatch);

/*
 * Structure which helps the SPD to maintain the per-cpu state of the SP.
 * 'spsr_el3' - temporary copy to allow S-EL1 interrupt handling when
 *                    the TEE has been preempted.
 * 'elr_el3'  - temporary copy to allow S-EL1 interrupt handling when
 *                    the TEE has been preempted.
 * 'state'          - collection of flags to track SP state e.g. on/off
 * 'mpidr'          - mpidr to associate a context with a cpu
 * 'rt_context'       - stack address to restore C runtime context from after
 *                    returning from a synchronous entry into the SP.
 * 'cpu_context'        - space to maintain SP architectural state
 * 'saved_tee_args' - space to store arguments for TEE arithmetic operations
 *                    which will queried using the TEE_GET_ARGS SMC by TEE.
 * 'sp_ctx'         - space to save the SEL1 Secure Payload(SP) caller saved
 *                    register context after it has been preempted by an EL3
 *                    routed NS interrupt and when a Secure Interrupt is taken
 *                    to SP.
 */
typedef struct tee_context {
	uint64_t elr_el3;
	uint32_t spsr_el3;
	uint32_t state;
	uint64_t mpidr;
	uint64_t rt_context;
	cpu_context_t cpu_context;
	uint64_t saved_tee_args[TEE_NUM_ARGS];
} tee_context_t;

typedef struct tee_vectors {
	uint32_t yield_smc_entry;
	uint32_t fast_smc_entry;
	uint32_t cpu_on_entry;
	uint32_t cpu_off_entry;
	uint32_t cpu_resume_entry;
	uint32_t cpu_suspend_entry;
	uint32_t sel1_intr_entry;
	uint32_t irq_return_entry;
	uint32_t s4_resume_entry;
	uint32_t s4_suspend_entry;
	uint32_t system_off_entry;
	uint32_t system_reset_entry;
	uint32_t abort_yield_smc_entry;
} tee_vectors_t;

typedef struct smc_registers {
	u_register_t x1;
	u_register_t x2;
	u_register_t x3;
	u_register_t x4;
} smc_registers_t;

/* Helper macros to store and retrieve tee args from tee_context */
#define store_tee_args(_tee_ctx, _x1, _x2)                           \
	do {                                                   \
		(_tee_ctx)->saved_tee_args[0] = _x1; \
		(_tee_ctx)->saved_tee_args[1] = _x2; \
	} while (0)

#define get_tee_args(_tee_ctx, _x1, _x2)                             \
	do {                                                   \
		_x1 = (_tee_ctx)->saved_tee_args[0]; \
		_x2 = (_tee_ctx)->saved_tee_args[1]; \
	} while (0)

/* TEED power management handlers */
const spd_pm_ops_t *get_teed_pm(void);

/* Forward declarations */
typedef struct tee_vectors tee_vectors_t;
tee_context_t* get_teed_sp_context(const uint32_t linear_id);
uint64_t get_teed_sp_context_size(void);
tee_context_t *get_teed_sp_context_ptr(void);
tee_context_t* get_teed_sp_init_context(void);
int64_t get_tee_init_context_saved(void);
void set_tee_init_context_saved(int64_t tee_init_context_saved);
uint64_t get_primary_cpu_mpidr(void);
void set_primary_cpu_mpidr(uint64_t primary_cpu_mpidr_in);
tee_vectors_t* get_tee_vectors_t(void);
void set_tee_vectors_t(tee_vectors_t *const tee_vectors_tmp);
uint64_t plat_arm_calc_core_pos(uint64_t mpidr);

#endif /* __ASSEMBLY__ */

#endif /* TEED_PRIVATE_H */

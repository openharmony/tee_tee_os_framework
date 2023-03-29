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

#include <errno.h>
#include <assert.h>
#include <arch_helpers.h>
#include <bl31.h>
#include <bl_common.h>
#include <context.h>
#include <context_mgmt.h>
#include <platform.h>
#include <runtime_svc.h>
#include "tee.h"
#include "teed_common.h"
#include "teed_private.h"

/*
 * This function is the handler registered for S-EL1 interrupts by the TEED
 * It validates the interrupt and upon success arranges entry into the TEE
 * at 'tee_sel1_intr_entry()' for handling the interrupt.
 */
static uint64_t teed_sel1_interrupt_handler(uint32_t id,
						 uint32_t flags,
						 void *handle,
						 void *cookie)
{
	uint32_t linear_id;
	tee_context_t *tee_ctx = NULL;

	/* Check the security state when the exception was generated */
	assert(get_interrupt_src_ss(flags) == NON_SECURE);

	/* Sanity check the pointer to this cpu's context */
	assert(handle == cm_get_context(NON_SECURE));

	/* Save the non-secure context before entering the TEE */
	cm_el1_sysregs_context_save(NON_SECURE);
	fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));

	/* Get a reference to this cpu's TEE context */
	linear_id = plat_my_core_pos();
	tee_ctx = get_teed_sp_context(linear_id);
	assert(tee_ctx != NULL);
	assert(&tee_ctx->cpu_context == cm_get_context(SECURE));

	/*
	 * Determine if the tee was previously preempted. Its last known
	 * context has to be preserved in this case.
	 * The tee should return control to the teeD after handling
	 * this S-EL1 interrupt. Preserve essential EL3 context to allow entry
	 * into the tee at the S-EL1 interrupt entry point using the
	 * 'cpu_context' structure. There is no need to save the secure system
	 * register context since the tee is supposed to preserve it
	 * during S-EL1 interrupt handling.
	 */
	if (get_yield_smc_active_flag(tee_ctx->state) == SMC_ACTIVE) {
		tee_ctx->spsr_el3 = (uint32_t)SMC_GET_EL3(&tee_ctx->cpu_context, CTX_SPSR_EL3);
		tee_ctx->elr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context, CTX_ELR_EL3);
	}

	cm_el1_sysregs_context_restore(SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
	tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();
	assert(tee_vectors_tmp != NULL);
	cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->sel1_intr_entry,
			    SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));

	cm_set_next_eret_context(SECURE);
	/*
	 * Tell the TEE that it has to handle a S-EL1 interrupt
	 * synchronously. It is safe to retrieve
	 * this address from ELR_EL3 as the secure context will not take effect
	 * until el3_exit().
	 */
	SMC_RET2((uintptr_t)&tee_ctx->cpu_context,
		 TEE_HANDLE_SEL1_INTR_AND_RETURN, read_elr_el3());
}

/*
 * This function passes control to the Secure Payload image (BL32) for the first
 * time on the primary cpu after a cold boot. It assumes that a valid secure
 * context has already been created by teed_setup() which can be directly
 * used. It also assumes that a valid non-secure context has been initialised by
 * PSCI so it does not need to save and restore any non-secure state. This
 * function performs a synchronous entry into the Secure payload. The SP passes
 * control back to this routine through a SMC.
 */
static int32_t teed_init(void)
{
	uint32_t linear_id = plat_my_core_pos();
	tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
	entry_point_info_t *tee_entry_point = NULL;
	uint64_t rc;
	uint64_t mpidr = read_mpidr();
	/* set the primary cpu */
	set_primary_cpu_mpidr(mpidr);
	/*
	 * Get information about the Secure Payload (BL32) image. Its
	 * absence is a critical failure.
	 */
	tee_entry_point = bl31_plat_get_next_image_ep_info(SECURE);
	cm_init_my_context(tee_entry_point);

#ifdef BOOT_BL32_FROM_OTHER_EXCEPTION
	/* set el3 fiq bit for tee init */
	cpu_context_t *ctx = NULL;
	el3_state_t *state = NULL;
	uint32_t scr_el3;
	ctx = cm_get_context(GET_SECURITY_STATE(tee_entry_point->h.attr));
	state = get_el3state_ctx(ctx);
	scr_el3 = read_ctx_reg(state, CTX_SCR_EL3);
	scr_el3 &= ~SCR_FIQ_BIT;
	write_ctx_reg(state, CTX_SCR_EL3, scr_el3);

	/* save nosecure context and disable interrupt during init */
	cm_el1_sysregs_context_save(NON_SECURE);
	fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
#endif
	/*
	 * Arrange for an entry into the test secure payload. It will be
	 * returned via TEE_ENTRY_DONE case
	 */
	rc = teed_synchronous_sp_entry(tee_ctx);
	assert(rc != 0);
	return rc;
}

/*
 * Secure Payload Dispatcher setup. The SPD finds out the SP entrypoint and type
 * (aarch32/aarch64) if not already known and initialises the context for entry
 * into the SP for its initialisation.
 */
static int32_t teed_setup(void)
{
	entry_point_info_t *image_info = NULL;
	uint32_t linear_id;

	linear_id = plat_my_core_pos();
	NOTICE("teed setup start!\n");
	/*
	 * Get information about the Secure Payload (BL32) image. Its
	 * absence is a critical failure.
	 * conditionally include the SPD service
	 */
	image_info = bl31_plat_get_next_image_ep_info(SECURE);
	if (image_info == NULL) {
		WARN("No TEE provided by BL2 boot loader, Booting device"
			" without TEE initialization. SMC`s destined for TEE"
			" will return SMC_UNK\n");
		return TEE_SETUP_FAIL;
	}
	assert(image_info != NULL);
	/*
	 * If there's no valid entry point for SP, we return a non-zero value
	 * signalling failure initializing the service. We bail out without
	 * registering any handlers
	 */
	if (image_info->pc == INVALID_PC_ADDR)
		return TEE_SETUP_FAIL;

	/*
	 * We could inspect the SP image and determine its execution
	 * state i.e whether AArch32 or AArch64. Assuming it's AArch64
	 * for the time being.
	 */
	tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
	teed_init_tee_ep_state(image_info,
					 TEE_AARCH64,
					 image_info->pc,
					 tee_ctx);

	/*
	 * All TEED initialization done. Now register our init function
	 * with BL31 for deferred invocation
	 */
	bl31_register_bl32_init(&teed_init);
	return 0;
}

/*
 * This function ID is used only by the tee to indicate that it has
 * finished handling a S-EL1 interrupt or was preempted by a higher
 * priority pending EL3 interrupt. Execution should resume
 * in the normal world.
 * TEE_HANDLED_S_EL1_INTR:
 * TEE_HANDLED_S_EL1_FIQ_AARCH32:
 */
static uintptr_t smc_handle_s_el1(tee_context_t *tee_ctx,
				  void *handle, uint32_t ns)
{
	if (ns != SECURE_WORLD_FLAG)
		SMC_RET1((uintptr_t)handle, SMC_UNK);

	assert(handle == cm_get_context(SECURE));
	assert(tee_ctx != NULL);
	cpu_context_t *ns_cpu_context = NULL;
	/*
	 * Restore the relevant EL3 state which saved to service
	 * this SMC.
	 */
	if (get_yield_smc_active_flag(tee_ctx->state) != SMC_INACTIVE) {
		SMC_SET_EL3(&tee_ctx->cpu_context,
			    CTX_SPSR_EL3,
			    tee_ctx->spsr_el3);
		SMC_SET_EL3(&tee_ctx->cpu_context,
			    CTX_ELR_EL3,
			    tee_ctx->elr_el3);
	}

	/* Get a reference to the non-secure context */
	ns_cpu_context = cm_get_context(NON_SECURE);
	assert(ns_cpu_context != NULL);

	/*
	 * Restore non-secure state. There is no need to save the
	 * secure system register context since the tee was supposed
	 * to preserve it during S-EL1 interrupt handling.
	 */
	cm_el1_sysregs_context_restore(NON_SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	cm_set_next_eret_context(NON_SECURE);
	SMC_RET0((uintptr_t)ns_cpu_context);
}

/*
 * This function ID is used only by the SP to indicate it has
 * finished initialising itself after a cold boot
 * TEE_ENTRY_DONE:
 * TEE_ENTRY_DONE_AARCH32:
 */
static void smc_handle_entry_done(tee_context_t *tee_ctx,
				  u_register_t x1, u_register_t *flags)
{
	/*
	 * Stash the SP entry points information. This is done
	 * only once on the primary cpu
	 */
	uint64_t rc;
	tee_vectors_t* tee_vectors_tmp = (tee_vectors_t *)(uintptr_t)x1;
	set_tee_vectors_t(tee_vectors_tmp);
	if (tee_vectors_tmp != NULL) {
		set_tee_pstate(tee_ctx->state, TEE_PSTATE_ON);
		/*
		 * tee has been successfully initialized. Register
		 * power managemnt hooks with PSCI
		 */
		const spd_pm_ops_t *teed_pm_tmp = get_teed_pm();
		psci_register_spd_pm_hook(teed_pm_tmp);

		/*
		 * Register an interrupt handler for S-EL1 interrupts
		 * when generated during code executing in the
		 * non-secure state.
		 */
		*flags = 0;
		set_interrupt_rm_flag(*flags, NON_SECURE);
		rc = register_interrupt_type_handler(INTR_TYPE_S_EL1,
						     teed_sel1_interrupt_handler,
						     *flags);
		if (rc != 0)
			panic();
	}

	/*
	 * SP reports completion. The SPD must have initiated
	 * the original request through a synchronous entry
	 * into the SP. Jump back to the original C runtime
	 * context.
	 */
	teed_synchronous_sp_exit(tee_ctx, x1);
}

/*
 * This function ID is used only by the SP to indicate it has finished
 * aborting a preempted Yielding SMC Call.
 * case TEE_ABORT_DONE:
 * *********
 * These function IDs are used only by the SP to indicate it has
 * finished:
 * 1. turning itself on in response to an earlier psci
 *    cpu_on request
 * 2. resuming itself after an earlier psci cpu_suspend
 *    request.
 * TEE_ON_DONE:
 * TEE_ON_DONE_AARCH32:
 * TEE_RESUME_DONE:
 * TEE_RESUME_DONE_AARCH32:
 * ****
 * These function IDs are used only by the SP to indicate it has
 * finished:
 * 1. suspending itself after an earlier psci cpu_suspend
 *    request.
 * 2. turning itself off in response to an earlier psci
 *    cpu_off request.
 * TEE_OFF_DONE:
 * TEE_SUSPEND_DONE:
 * TEE_SUSPEND_DONE_AARCH32:
 * TEE_SYSTEM_OFF_DONE:
 * TEE_SYSTEM_RESET_DONE:
 */
static void smc_handle_abort_on_resume(const tee_context_t *tee_ctx, u_register_t x1)
{
	/*
	 * SP reports completion. The SPD must have initiated the
	 * original request through a synchronous entry into the SP.
	 * Jump back to the original C runtime context, and pass x1 as
	 * return value to the caller
	 */
	teed_synchronous_sp_exit(tee_ctx, x1);
}

static uintptr_t smc_handle_std_request(tee_context_t *tee_ctx,
					smc_registers_t registers_t,
					const void *handle, uint32_t smc_fid,
					uint32_t ns)
{
	if (ns == SECURE_WORLD_FLAG)
		SMC_RET1((uintptr_t)handle, SMC_UNK);
	assert(handle == cm_get_context(NON_SECURE));
	cm_el1_sysregs_context_save(NON_SECURE);
	fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	assert(&tee_ctx->cpu_context == cm_get_context(SECURE));
	/*
	 * Restore the correct state considering if the
	 * OS has been active.
	 */
	tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();
	assert(tee_vectors_tmp != NULL);
	if (get_yield_smc_active_flag(tee_ctx->state) != SMC_INACTIVE) {
		cm_set_elr_spsr_el3(SECURE,
				    (uintptr_t)&tee_vectors_tmp->irq_return_entry,
				    SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
	} else {
		cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->yield_smc_entry,
				    SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
	}

	cm_el1_sysregs_context_restore(SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(SECURE)));
	cm_set_next_eret_context(SECURE);

	if (get_yield_smc_active_flag(tee_ctx->state) != SMC_INACTIVE) {
		SMC_RET0((uintptr_t)&tee_ctx->cpu_context);
	} else {
		set_yield_smc_active_flag(tee_ctx->state);
		SMC_RET5((uintptr_t)&tee_ctx->cpu_context, smc_fid, registers_t.x1,
			 registers_t.x2, registers_t.x3, registers_t.x4);
	}
}

static uintptr_t smc_handle_std_ree_siq(uint32_t smc_fid,
					tee_context_t *tee_ctx,
					u_register_t x1, void *handle,
					uint32_t ns)
{
	if (ns == SECURE_WORLD_FLAG)
		SMC_RET1((uintptr_t)handle, SMC_UNK);

	assert(handle == cm_get_context(NON_SECURE));

	cm_el1_sysregs_context_save(NON_SECURE);
	fpregs_context_save(get_fpregs_ctx(cm_get_context(NON_SECURE)));

	assert(&tee_ctx->cpu_context == cm_get_context(SECURE));

	tee_ctx->spsr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
					     CTX_SPSR_EL3);
	tee_ctx->elr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
					    CTX_ELR_EL3);
	tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();
	assert(tee_vectors_tmp != NULL);
	cm_set_elr_spsr_el3(SECURE,
			    (uintptr_t)&tee_vectors_tmp->fast_smc_entry,
			    SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));

	write_ctx_reg(get_gpregs_ctx(&tee_ctx->cpu_context), CTX_GPREG_X1, x1);
	(void)teed_synchronous_sp_entry(tee_ctx);
	/* Restore non-secure state */
	cm_el1_sysregs_context_restore(NON_SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	cm_set_next_eret_context(NON_SECURE);
	SMC_RET1((uintptr_t)handle, smc_fid);
}

static uintptr_t smc_handle_std_response(uint32_t smc_fid,
					 tee_context_t *tee_ctx,
					 smc_registers_t registers_t,
					 const void *handle, uint32_t ns)
{
	if (ns != SECURE_WORLD_FLAG)
		SMC_RET1((uintptr_t)handle, SMC_UNK);
	/* Forward secure responses to NS */
	cpu_context_t *ns_cpu_context = NULL;

	assert(handle == cm_get_context(SECURE));
	cm_el1_sysregs_context_save(SECURE);
	fpregs_context_save(get_fpregs_ctx(cm_get_context(SECURE)));

	/* Get a reference to the non-secure context */
	ns_cpu_context = cm_get_context(NON_SECURE);
	assert(ns_cpu_context != NULL);

	/* Restore non-secure state */
	cm_el1_sysregs_context_restore(NON_SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	cm_set_next_eret_context(NON_SECURE);
	clr_yield_smc_active_flag(tee_ctx->state);
	SMC_RET4((uintptr_t)ns_cpu_context, smc_fid, registers_t.x1,
		 registers_t.x2, registers_t.x3);
}

static uintptr_t smc_handle_std_crash(tee_context_t *tee_ctx,
				      smc_registers_t registers_t, const void *handle,
				      uint32_t ns)
{
	if (ns != SECURE_WORLD_FLAG)
		SMC_RET1((uintptr_t)handle, SMC_UNK);
	NOTICE("notify teeos has crashed\n");
	/* Secure OS has crashed, set the flag and return to ns */
	cpu_context_t *ns_cpu_context = NULL;
	assert(handle == cm_get_context(SECURE));

	set_std_crash_flag(tee_ctx->state);

	/* Get a reference to the non-secure context */
	ns_cpu_context = cm_get_context(NON_SECURE);
	assert(ns_cpu_context != NULL);

	/* Restore non-secure state */
	cm_el1_sysregs_context_restore(NON_SECURE);
	fpregs_context_restore(get_fpregs_ctx(cm_get_context(NON_SECURE)));
	cm_set_next_eret_context(NON_SECURE);
	SMC_RET4((uintptr_t)ns_cpu_context, TEE_STD_CRASH, registers_t.x1,
		 registers_t.x2, registers_t.x3);
}

/*
 * This function is responsible for handling all SMCs in the Trusted OS/App
 * range from the non-secure state as defined in the SMC Calling Convention
 * Document. It is also responsible for communicating with the Secure payload
 * to delegate work and return results back to the non-secure state. Lastly it
 * will also return any information that the secure payload needs to do the
 * work assigned to it.
 */

static uintptr_t teed_smc_handler(uint32_t smc_fid, u_register_t x1,
				       u_register_t x2, u_register_t x3,
				       u_register_t x4, void *cookie,
				       void *handle, u_register_t flags)
{
	uint32_t linear_id = plat_my_core_pos();
	/* Determine which security state this SMC originated from */
	uint32_t ns = is_caller_non_secure(flags);
	tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
	smc_registers_t registers_t = { x1, x2, x3, x4 };
	/*
	 * For calls comming from non-secure side after the OS signals
	 * it has crashed just return to NS side, no more forwarding
	 */
	assert(tee_ctx != NULL);
	if (ns != SECURE_WORLD_FLAG &&
	    get_std_crash_flag(tee_ctx->state) != STD_NO_CRASH_FLAG)
		SMC_RET1((uintptr_t)handle, TEE_STD_CRASH);

	switch (smc_fid) {
	/*
	 * This function ID is used only by the tee to indicate that it has
	 * finished handling a S-EL1 interrupt or was preempted by a higher
	 * priority pending EL3 interrupt. Execution should resume
	 * in the normal world.
	 */
	case TEE_HANDLED_S_EL1_INTR:
	case TEE_HANDLED_S_EL1_FIQ_AARCH32:
		return smc_handle_s_el1(tee_ctx, handle, ns);
	/*
	 * This function ID is used only by the SP to indicate it has
	 * finished initialising itself after a cold boot
	 */
	case TEE_ENTRY_DONE:
	case TEE_ENTRY_DONE_AARCH32:
		if (ns == SECURE_WORLD_FLAG)
			smc_handle_entry_done(tee_ctx, x1, &flags);
		break;
	/*
	 * This function ID is used only by the SP to indicate it has finished
	 * aborting a preempted Yielding SMC Call.
	 */
	case TEE_ABORT_DONE:
	case TEE_ON_DONE:
	case TEE_ON_DONE_AARCH32:
	case TEE_RESUME_DONE:
	case TEE_RESUME_DONE_AARCH32:
	/*
	 * These function IDs are used only by the SP to indicate it has
	 * finished:
	 * 1. suspending itself after an earlier psci cpu_suspend
	 *    request.
	 * 2. turning itself off in response to an earlier psci
	 *    cpu_off request.
	 */
	case TEE_SUSPEND_DONE:
	case TEE_SUSPEND_DONE_AARCH32:
		if (ns != SECURE_WORLD_FLAG)
			SMC_RET1((uintptr_t)handle, SMC_UNK);

		smc_handle_abort_on_resume(tee_ctx, x1);
		break;
	case TEE_STD_REQUEST:
		return smc_handle_std_request(tee_ctx, registers_t, handle, smc_fid, ns);
	case TEE_STD_REE_SIQ:
		return smc_handle_std_ree_siq(smc_fid, tee_ctx, x1, handle, ns);
	case TEE_STD_RESPONSE:
		return smc_handle_std_response(smc_fid, tee_ctx, registers_t, handle, ns);
	case TEE_STD_CRASH:
		return smc_handle_std_crash(tee_ctx, registers_t, handle, ns);
	default:
		break;
	}

	SMC_RET1((uintptr_t)handle, SMC_UNK);
}

/* Define a SPD runtime service descriptor for fast SMC calls */
DECLARE_RT_SVC(
	teed_fast,
	OEN_TOS_START,
	OEN_TOS_END,
	SMC_TYPE_FAST,
	teed_setup,
	teed_smc_handler
);

/* Define a SPD runtime service descriptor for Yielding SMC Calls */
DECLARE_RT_SVC(
	teed_std,
	OEN_TOS_START,
	OEN_TOS_END,
	SMC_TYPE_YIELD,
	NULL,
	teed_smc_handler
);

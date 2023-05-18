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

#include "teed_common.h"

#include <string.h>
#include <assert.h>
#include <arch_helpers.h>
#include <context_mgmt.h>
#include "teed_private.h"
#include "teed_helpers.h"
/*
 * Given a secure payload entrypoint info pointer, entry point PC, register
 * width, cpu id & pointer to a context data structure, this function will
 * initialize tee context and entry point info for the secure payload
 */
void teed_init_tee_ep_state(struct entry_point_info *ep,
                      uint32_t rw,
                      uintptr_t pc,
                      tee_context_t *tee_ctx)
{
    uint32_t ep_attr;
    uint32_t ee;
    uint32_t daif;
    /* Passing a NULL context is a critical programming error */
    assert(tee_ctx != NULL);
    assert(ep != NULL);
    assert(pc != INVALID_PC_ADDR);

    /*
     * We support AArch64 TEE for now.
     * Associate this context with the cpu specified
     */
    ee = (uint32_t)SPSR_E_LITTLE;
    tee_ctx->mpidr = read_mpidr_el1();
    tee_ctx->state = (uint32_t)TEE_PSTATE_OFF;
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_OFF);
    clr_yield_smc_active_flag(tee_ctx->state);

    cm_set_context(&tee_ctx->cpu_context, SECURE);

    /* initialise an entrypoint to set up the CPU context */
    ep_attr = SECURE | EP_ST_ENABLE;
    bool ee_bit_flag = (read_sctlr_el3() & SCTLR_EE_BIT) == 0 ? false : true;
    if (ee_bit_flag) {
        ep_attr |= EP_EE_BIG;
        ee = SPSR_E_BIG;
    }
    SET_PARAM_HEAD(ep, PARAM_EP, VERSION_1, ep_attr);
    ep->pc = pc;
    if (rw == TEE_AARCH64) {
        ep->spsr = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
    } else {
        daif = DAIF_ABT_BIT | DAIF_IRQ_BIT | DAIF_FIQ_BIT;
        ep->spsr = SPSR_MODE32(MODE32_svc, pc & SPSR_T_MASK, ee, daif);
    }

    memset(&ep->args, 0, sizeof(ep->args));
}

/*
 * This function takes an SP context pointer and:
 * 1. Applies the S-EL1 system register context from tee_ctx->cpu_context.
 * 2. Saves the current C runtime state (callee saved registers) on the stack
 *    frame and saves a reference to this state.
 * 3. Calls el3_exit() so that the EL3 system and general purpose registers
 *    from the tee_ctx->cpu_context are used to enter the secure payload image.
 */
uint64_t teed_synchronous_sp_entry(tee_context_t *tee_ctx)
{
    uint64_t rc;
    assert(tee_ctx != NULL);
    assert(tee_ctx->rt_context == INVALID_C_RT_CTX);

    /* Apply the Secure EL1 system register context and switch to it */
    assert(cm_get_context(SECURE) == &tee_ctx->cpu_context);

    cm_el1_sysregs_context_restore(SECURE);
    cm_set_next_eret_context(SECURE);
    rc = teed_enter_sp(&tee_ctx->rt_context);
#if ENABLE_ASSERTIONS
    tee_ctx->rt_context = INVALID_C_RT_CTX;
#endif

    return rc;
}

/*
 * This function takes an SP context pointer and:
 * 1. Saves the S-EL1 system register context tp tee_ctx->cpu_context.
 * 2. Restores the current C runtime state (callee saved registers) from the
 *    stack frame using the reference to this state saved in teed_enter_sp().
 * 3. It does not need to save any general purpose or EL3 system register state
 *    as the generic smc entry routine should have saved those.
 */
void teed_synchronous_sp_exit(const tee_context_t *tee_ctx, uint64_t ret)
{
    assert(tee_ctx != NULL);
    /* Save the Secure EL1 system register context */
    assert(cm_get_context(SECURE) == &tee_ctx->cpu_context);
    cm_el1_sysregs_context_save(SECURE);
    int64_t init_context_saved = get_tee_init_context_saved();

    tee_context_t *tee_context_tmp = get_teed_sp_init_context();
    assert(tee_context_tmp != NULL);
    if (init_context_saved == INIT_CONTEXT_NOT_SAVED) {
        memcpy(tee_context_tmp, tee_ctx, sizeof(*tee_context_tmp));
        set_tee_init_context_saved(INIT_CONTEXT_SAVED);
    }
    assert(tee_ctx->rt_context != INVALID_C_RT_CTX);
    teed_exit_sp(tee_ctx->rt_context, ret);
    printf("sp exit: Should never reach here\n");
    assert(0);
}

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

#include <assert.h>
#include <bl_common.h>
#include <context_mgmt.h>
#include <arch_helpers.h>
#include <platform.h>
#include <runtime_svc.h>
#include <string.h>
#include <context.h>
#include <spinlock.h>
#include "teed_common.h"
#include "teed_private.h"

static uint32_t g_cpu_initialized[TEED_CORE_COUNT];

/* need to be implemented */
static int32_t is_system_suspend(void)
{
    return 1;
}

/*
 * The target cpu is being turned on. Allow the TEED/TEE to perform any actions
 * needed. Nothing at the moment.
 */
static void teed_cpu_on_handler(u_register_t target_cpu)
{
    (void)target_cpu;
}

/*
 * This cpu is being turned off. Allow the TEED/TEE to perform
 * any actions needed
 */
static int32_t teed_cpu_off_handler(u_register_t unused)
{
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    assert(tee_ctx != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_ON);
    /*
     * Abort any preempted SMC request before overwriting the SECURE
     * context.
     */
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_OFF);

    return 0;
}

/*
 * This cpu is being suspended. S-EL1 state must have been saved in the
 * resident cpu (mpidr format) if it is a UP/UP migratable TEE.
 */
static void teed_cpu_suspend_handler(u_register_t max_off_pwrlvl)
{
    int32_t rc;
    uint64_t power_state;
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    assert(tee_ctx != NULL);

    tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();
    (void)max_off_pwrlvl;
    assert(tee_vectors_tmp != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_ON);
    /*
     * Abort any preempted SMC request before overwriting the SECURE
     * context.
     */
    if (is_system_suspend() != 0)
        power_state = CPU_IDLE_STATE; /* stand for cpu idle */
    else
        power_state = CPU_SUSPEND_STATE; /* stand for cpu suspend */

    /* Program the entry point and enter the TEE */
    write_ctx_reg(get_gpregs_ctx(&tee_ctx->cpu_context),
              CTX_GPREG_X0,
              power_state);
    tee_ctx->spsr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
                         CTX_SPSR_EL3);
    tee_ctx->elr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
                        CTX_ELR_EL3);
    cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->cpu_suspend_entry,
                SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
    rc = teed_synchronous_sp_entry(tee_ctx);
    /*
     * Read the response from the TEE. A non-zero return means that
     * something went wrong while communicating with the TEE.
     */
    if (rc != 0)
        panic();
    /* Update its context to reflect the state the TEE is in */
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_SUSPEND);
}

/*
 * This cpu has been turned on. Enter the TEE to initialise S-EL1 and other bits
 * before passing control back to the Secure Monitor. Entry in S-EL1 is done
 * after initialising minimal architectural state that guarantees safe
 * execution.
 */
static void teed_cpu_on_finish_handler(u_register_t unused)
{
    int32_t rc;
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    assert(tee_ctx != NULL);
    entry_point_info_t tee_on_entrypoint;
    el3_state_t *state = NULL;

    tee_vectors_t *tee_vectors_tmp = get_tee_vectors_t();
    assert(tee_vectors_tmp != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_OFF);
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_ON);

    uint64_t mpidr = read_mpidr();
    uint64_t primary_cpu_mpidr_tmp = get_primary_cpu_mpidr();
    if (linear_id >= TEED_CORE_COUNT)
        return;

    bool condition = (g_cpu_initialized[linear_id] == CPU_INIT_DONE ||
        mpidr == primary_cpu_mpidr_tmp);
    if (!condition) {
        tee_context_t *teed_sp_init_context = get_teed_sp_init_context();
        assert(teed_sp_init_context != NULL);
        (void)memcpy(&tee_ctx->cpu_context, &(teed_sp_init_context->cpu_context), sizeof(cpu_context_t));
        (void)memset(&tee_on_entrypoint, 0, sizeof(tee_on_entrypoint));
        /* Initialise this cpu's secure context */
        teed_init_tee_ep_state(&tee_on_entrypoint,
                         TEE_AARCH64,
                         (uintptr_t)&tee_vectors_tmp->cpu_on_entry,
                         tee_ctx);
        state = get_el3state_ctx(&tee_ctx->cpu_context);
        write_ctx_reg(state, CTX_ELR_EL3, tee_on_entrypoint.pc);
        write_ctx_reg(state, CTX_SPSR_EL3, tee_on_entrypoint.spsr);
    }
    /* Enter the TEE */
    rc = teed_synchronous_sp_entry(tee_ctx);
    g_cpu_initialized[linear_id] = CPU_INIT_DONE;
    /*
     * Read the response from the TEE. A non-zero return means that
     * something went wrong while communicating with the SP.
     */
    if (rc != 0)
        panic();
    /* Update its context to reflect the state the SP is in */
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_ON);
}

/*
 * This cpu has resumed from suspend. The SPD saved the TEE context when it
 * completed the preceding suspend call. Use that context to program an entry
 * into the TEE to allow it to do any remaining book keeping
 */
static void teed_cpu_suspend_finish_handler(u_register_t max_off_pwrlvl)
{
    int32_t rc;
    uint64_t power_state;
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    assert(tee_ctx != NULL);

    (void)max_off_pwrlvl;
    tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();
    assert(tee_vectors_tmp != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_SUSPEND);

    if (is_system_suspend() != 0)
        power_state = CPU_IDLE_STATE; /* stand for cpu idle */
    else
        power_state = CPU_SUSPEND_STATE; /* stand for cpu suspend */

    /* Program the entry point, max_off_pwrlvl and enter the SP */
    write_ctx_reg(get_gpregs_ctx(&tee_ctx->cpu_context),
              CTX_GPREG_X0,
              power_state);
    tee_ctx->spsr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
                         CTX_SPSR_EL3);
    tee_ctx->elr_el3 = SMC_GET_EL3(&tee_ctx->cpu_context,
                        CTX_ELR_EL3);
    cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->cpu_resume_entry,
                SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
    rc = teed_synchronous_sp_entry(tee_ctx);
    /*
     * Read the response from the TEE. A non-zero return means that
     * something went wrong while communicating with the TEE.
     */
    if (rc != 0)
        panic();
    /* Update its context to reflect the state the SP is in */
    set_tee_pstate(tee_ctx->state, TEE_PSTATE_ON);
}

/*
 * Return the type of TEE the TEED is dealing with. Report the current resident
 * cpu (mpidr format) if it is a UP/UP migratable TEE.
 */
static int32_t teed_cpu_migrate_info(u_register_t *resident_cpu)
{
    (void)resident_cpu;
    return TEE_MIGRATE_INFO;
}

/*
 * System is about to be switched off. Allow the TEED/TEE to perform
 * any actions needed.
 */
static void teed_system_off(void)
{
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    tee_vectors_t* tee_vectors_tmp = get_tee_vectors_t();

    assert(tee_vectors_tmp != NULL);
    assert(tee_ctx != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_ON);

    /* Program the entry point */
    cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->system_off_entry,
                SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
    /*
     * Enter the TEE. We do not care about the return value because we
     * must continue the shutdown anyway
     */
    NOTICE("teed system off\n");
    (void)teed_synchronous_sp_entry(tee_ctx);
}

/*
 * System is about to be reset. Allow the TEED/TEE to perform
 * any actions needed.
 */
static void teed_system_reset(void)
{
    uint32_t linear_id = plat_my_core_pos();
    tee_context_t *tee_ctx = get_teed_sp_context(linear_id);
    tee_vectors_t *tee_vectors_tmp = get_tee_vectors_t();

    assert(tee_vectors_tmp != NULL);
    assert(tee_ctx != NULL);
    assert(get_tee_pstate(tee_ctx->state) == TEE_PSTATE_ON);
    /*
     * Abort any preempted SMC request before overwriting the SECURE
     * context.
     * Program the entry point
     */
    cm_set_elr_spsr_el3(SECURE, (uintptr_t)&tee_vectors_tmp->system_reset_entry,
                SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS));
    /*
     * Enter the TEE. We do not care about the return value because we
     * must continue the reset anyway
     */
    NOTICE("teed system reset\n");
    (void)teed_synchronous_sp_entry(tee_ctx);
}

/*
 * Structure populated by the TEE Dispatcher to be given a chance to perform any
 * TEE bookkeeping before PSCI executes a power management operation.
 */
static const spd_pm_ops_t g_teed_pm = {
    .svc_on = teed_cpu_on_handler,
    .svc_off = teed_cpu_off_handler,
    .svc_suspend = teed_cpu_suspend_handler,
    .svc_on_finish = teed_cpu_on_finish_handler,
    .svc_suspend_finish = teed_cpu_suspend_finish_handler,
    .svc_migrate = NULL,
    .svc_migrate_info = teed_cpu_migrate_info,
    .svc_system_off = teed_system_off,
    .svc_system_reset = teed_system_reset
};

const spd_pm_ops_t *get_teed_pm()
{
    return &g_teed_pm;
}

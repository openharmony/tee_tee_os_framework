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

#include <teed_private.h>

/* Array to keep track of per-cpu Secure Payload state */
tee_context_t g_teed_sp_context[TEED_CORE_COUNT];
tee_context_t g_teed_sp_init_context;
int64_t g_tee_init_context_saved;

#define PRIMARY_CPU_DEFAULT 0xff

/* primary_cpu: which core bring up the teeos */
uint64_t g_primary_cpu_mpidr = PRIMARY_CPU_DEFAULT;

tee_vectors_t *g_tee_vectors = NULL;

tee_context_t *get_teed_sp_context(const uint32_t linear_id)
{
    if (linear_id >= TEED_CORE_COUNT)
        return NULL;

    return &g_teed_sp_context[linear_id];
}

uint64_t get_teed_sp_context_size(void)
{
    return sizeof(g_teed_sp_context);
}

tee_context_t *get_teed_sp_context_ptr(void)
{
    return g_teed_sp_context;
}

tee_context_t *get_teed_sp_init_context(void)
{
    return &g_teed_sp_init_context;
}

int64_t get_tee_init_context_saved(void)
{
    return g_tee_init_context_saved;
}

void set_tee_init_context_saved(const int64_t tee_init_context_saved)
{
    g_tee_init_context_saved = tee_init_context_saved;
}

uint64_t get_primary_cpu_mpidr(void)
{
    return g_primary_cpu_mpidr;
}

void set_primary_cpu_mpidr(const uint64_t primary_cpu_mpidr_in)
{
    g_primary_cpu_mpidr = primary_cpu_mpidr_in;
}

tee_vectors_t *get_tee_vectors_t(void)
{
    return g_tee_vectors;
}

void set_tee_vectors_t(tee_vectors_t *const tee_vectors_tmp)
{
    g_tee_vectors = tee_vectors_tmp;
}

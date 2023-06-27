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

#include <stddef.h>
#include <string.h>
#include <mem_ops.h>
#include <sys/mman.h>
#include <dlist.h>
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "mem_manager.h"
#include "tee_common.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "gtask_config_hal.h"
#include "mem_page_ops.h"
#include "securec.h"

#include "gtask_adapt.h"
#include "tee_ta2ta.h" /* for smc_operation */
#include "gtask_para_config.h"

#define ADDR_MAX                0xffffffffffffffff /* UINT64_MAX */
#define CA_TA_CMD_VALUE_INDEX   1
#define CA_TA_CMD_PUBKEY_INDEX  2
#define CA_TA_CMD_PKGNAME_INDEX 3

#define RESERVED_MEM_SECURE        0x1001     /* cmd id for setting reserved memory secure */
#define RESERVED_MEM_NONSECURE     0x1000     /* cmd id for setting reserved memory non-secure */
#define PG_SIZE_4K                 4096
#define PG_SIZE_64K                65536
#define MAX_MEM_SIZE_1G            1073741824

extern struct session_struct *g_cur_session;
extern struct service_struct *g_cur_service;

static TEE_Result task_add_mem_region(uint32_t event_nr, uint32_t task_pid, uint64_t addr, uint32_t size, bool ta2ta);
static TEE_Result check_operation_params_in_mailbox_range(const tee_operation_gtask *operation);

// for map to ns
struct mem_region_ns {
    uint64_t addr;
    uint32_t size;
    uint32_t event_nr;
    uint32_t task_id;
    bool ta2ta;
    struct dlist_node list;
};

struct mempool_state {
    bool init;
    paddr_t start;
    uint32_t size;
    uintptr_t va;
};

static struct dlist_node g_mem_ns;
static struct mempool_state g_mb_state;
static struct pam_node *g_gt_pam_node = NULL;
static tee_operation_gtask *g_gt_oper_addr = NULL;

static uint32_t get_index_value_a(const struct pam_node *node, uint32_t index)
{
    if (node->param_type) {
        tee_param_64 *param_64 = node->p_for_ta;
        return param_64[index].value.a;
    } else {
        tee_param_32 *param_32 = node->p_for_ta;
        return param_32[index].value.a;
    }
}

static uint32_t get_index_value_b(const struct pam_node *node, uint32_t index)
{
    if (node->param_type) {
        tee_param_64 *param_64 = node->p_for_ta;
        return param_64[index].value.b;
    } else {
        tee_param_32 *param_32 = node->p_for_ta;
        return param_32[index].value.b;
    }
}

static uint32_t get_index_memref_size(const struct pam_node *node, uint32_t index)
{
    if (node->param_type) {
        tee_param_64 *param_64 = node->p_for_ta;
        return (uint32_t)(param_64[index].memref.size);
    } else {
        tee_param_32 *param_32 = node->p_for_ta;
        return param_32[index].memref.size;
    }
}

static void set_index_value_a(const struct pam_node *node, uint32_t index, uint32_t a)
{
    if (node->param_type) {
        tee_param_64 *param_64  = node->p_for_ta;
        param_64[index].value.a = a;
    } else {
        tee_param_32 *param_32  = node->p_for_ta;
        param_32[index].value.a = a;
    }
}

static void set_index_value_b(const struct pam_node *node, uint32_t index, uint32_t b)
{
    if (node->param_type) {
        tee_param_64 *param_64  = node->p_for_ta;
        param_64[index].value.b = b;
    } else {
        tee_param_32 *param_32  = node->p_for_ta;
        param_32[index].value.b = b;
    }
}

static void set_index_memref_size(const struct pam_node *node, uint32_t index, uint32_t size)
{
    if (node->param_type) {
        tee_param_64 *param_64      = node->p_for_ta;
        param_64[index].memref.size = size;
    } else {
        tee_param_32 *param_32      = node->p_for_ta;
        param_32[index].memref.size = size;
    }
}

static void set_index_memref_buffer(const struct pam_node *node, uint32_t index, uint64_t buf)
{
    if (node->param_type) {
        tee_param_64 *param_64        = node->p_for_ta;
        param_64[index].memref.buffer = buf;
    } else {
        tee_param_32 *param_32        = node->p_for_ta;
        param_32[index].memref.buffer = (uint32_t)buf;
    }
}
static void free_tee_mem(const void *addr, uint32_t size)
{
    if (addr == NULL)
        return;
    free_sharemem((void *)addr, size);
}

static TEE_Result copy_from_src(uint32_t task_id, void **tee_addr, void *ree_addr, uint32_t size, uint32_t type)
{
    (void)type;
    if (tee_addr == NULL || ree_addr == NULL || size == 0) {
        tloge("copy_from_src invalid input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_UUID ta_uuid = {0};
    int32_t ret = get_ta_info(task_id, NULL, &ta_uuid);
    if (ret != 0) {
        tloge("get ta uuid failed\n");
        return TEE_ERROR_GENERIC;
    }
    *tee_addr = alloc_sharemem_aux(&ta_uuid, size + 1);
    if (*tee_addr == NULL) {
        tloge("copy tee mem alloc failed, size=0x%x.\n", size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s(*tee_addr, size + 1, ree_addr, size) != EOK) {
        free_tee_mem(*tee_addr, size + 1);
        return TEE_ERROR_GENERIC;
    }

    ((char *)(*tee_addr))[size] = 0;

    return TEE_SUCCESS;
}

static TEE_Result copy_to_src(void *ree_addr, uint32_t ree_size, const void *tee_addr, uint32_t tee_size)
{
    /* this condition should never hanppen */
    if (tee_addr == NULL) {
        tloge("tee_addr is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* this condition should never hanppen */
    if (ree_addr == NULL) {
        tloge("ree_addr is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ree_size == 0) {
        tloge("ree_size is 0\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* this condition is valid */
    if (tee_size == 0) {
        tlogd("tee_size is 0\n");
        return TEE_SUCCESS;
    }

    if (ree_size < tee_size) {
        tloge("invalid tee_size:%u\n", tee_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(ree_addr, ree_size, tee_addr, tee_size) != EOK)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static struct pam_node *alloc_pam_node(void)
{
    return TEE_Malloc(sizeof(*g_gt_pam_node), 0);
}

void release_pam_node(struct pam_node *node)
{
    uint32_t i;
    uint32_t size;

    if (node == NULL)
        return;
    /* free param's memref tee mem */
    for (i = 0; i < TEE_PARAM_NUM; i++) {
        uint32_t type = TEE_PARAM_TYPE_GET(node->op.p_type, i);
        switch (type) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            /* in order to adopt  copy_from_src funtionc(add + 1) */
            (void)memset_s(node->p_vaddr_gt_tee[i], node->op.p[i].memref.size + 1, 0, node->op.p[i].memref.size + 1);
            free_tee_mem(node->p_vaddr_gt_tee[i], node->op.p[i].memref.size + 1);
            break;
        default:
            break;
        }
    }

    size = get_tee_param_len(node->param_type) * TEE_PARAM_NUM;
    free_tee_mem(node->p_for_ta, size);
    /* free pam node itself */
    TEE_Free(node);
}

static TEE_Result copy_pam_from_src(const void *operation, uint32_t operation_size, struct pam_node **pam_node)
{
    if (operation == NULL || pam_node == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /* copy the ns shared mem into tee */
    struct pam_node *n_tee = alloc_pam_node();
    if (n_tee == NULL) {
        tloge("operation in use mem alloc failed.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* back up the mem size of input params using n_tee->op.p */
    if (memcpy_s(n_tee, sizeof(*n_tee), operation, operation_size) != EOK) {
        TEE_Free(n_tee);
        return TEE_ERROR_GENERIC;
    }

    /* alloc mem later */
    n_tee->p_for_ta = NULL;

    *pam_node = n_tee;

    return TEE_SUCCESS;
}

static TEE_Result copy_params_back_to_ree(const struct pam_node *n_tee, tee_operation_gtask *p_ree)
{
    TEE_Result ret = TEE_SUCCESS;
    TEE_Result e_ret;
    uint32_t i;

    for (i = 0; i < TEE_PARAM_NUM; i++) {
        uint32_t type = TEE_PARAM_TYPE_GET(n_tee->op.p_type, i);
        switch (type) {
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            p_ree->p[i].value.a = get_index_value_a(n_tee, i);
            p_ree->p[i].value.b = get_index_value_b(n_tee, i);
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            /* this condition should not happen */
            if (n_tee->op.p[i].memref.size != p_ree->p[i].memref.size) {
                tloge("ERROR:memref size is wrong:%u %u %u\n", n_tee->op.p[i].memref.size, p_ree->p[i].memref.size,
                      get_index_memref_size(n_tee, i));
                ret = TEE_ERROR_BAD_PARAMETERS;
                return ret;
            }

            /*
             * for tee size > ree size condition,no buffer copy,
             * just return tee size and short buffer error
             */
            if (n_tee->op.p[i].memref.size < get_index_memref_size(n_tee, i)) {
                tloge("ERROR:short memref size:%u/%u\n", n_tee->op.p[i].memref.size, get_index_memref_size(n_tee, i));
                p_ree->p[i].memref.size = get_index_memref_size(n_tee, i);
                ret                     = TEE_ERROR_SHORT_BUFFER;
                break;
            }

            /* tee memref buffer -> ree memref buffer */
            e_ret = copy_to_src(n_tee->p_vaddr_gt_ree[i], p_ree->p[i].memref.size, n_tee->p_vaddr_gt_tee[i],
                                get_index_memref_size(n_tee, i));
            if (e_ret != TEE_SUCCESS) {
                tloge("copy to ree p_%u failed:0x%x\n", i, e_ret);
                return e_ret;
            }

            /* tee memref size -> ree memref size */
            p_ree->p[i].memref.size = get_index_memref_size(n_tee, i);
            break;
        default:
            break;
        }
    }

    return ret;
}

TEE_Result copy_pam_to_src(uint32_t cmd_id, bool ta2ta)
{
    TEE_Result ret;

    bool is_global             = false;
    struct pam_node *n_tee     = NULL;
    tee_operation_gtask *p_ree = NULL;
    if (g_cur_session == NULL)
        is_global = true;

    /* global handled cmds */
    if (is_global == true) {
        n_tee = g_gt_pam_node;
        p_ree = g_gt_oper_addr;
        /* ta handled cmds */
    } else {
        n_tee = g_cur_session->pam_node;
        p_ree = g_cur_session->oper_addr;
    }

    /* some cases there is no params input */
    if (n_tee == NULL || p_ree == NULL) {
        tlogd("n_tee or p_ree is null\n");
        return TEE_SUCCESS;
    }

    /* special case for load TA cmd */
    if (is_global == true && !ta2ta && cmd_id == GLOBAL_CMD_ID_LOAD_SECURE_APP) {
        p_ree->p[CA_TA_CMD_VALUE_INDEX].value.a = get_index_value_a(n_tee, CA_TA_CMD_VALUE_INDEX);
        p_ree->p[CA_TA_CMD_VALUE_INDEX].value.b = get_index_value_b(n_tee, CA_TA_CMD_VALUE_INDEX);

        if (p_ree->p[CA_TA_CMD_PUBKEY_INDEX].memref.size == get_index_memref_size(n_tee, CA_TA_CMD_PUBKEY_INDEX))
            copy_to_src(n_tee->p_vaddr_gt_ree[CA_TA_CMD_PUBKEY_INDEX],
                        p_ree->p[CA_TA_CMD_PUBKEY_INDEX].memref.size,
                        n_tee->p_vaddr_gt_tee[CA_TA_CMD_PUBKEY_INDEX],
                        get_index_memref_size(n_tee, CA_TA_CMD_PUBKEY_INDEX));

        release_pam_node(n_tee);
        g_gt_pam_node  = NULL;
        g_gt_oper_addr = NULL;
        return TEE_SUCCESS;
    }

    /* copy params back to ree */
    ret = copy_params_back_to_ree(n_tee, p_ree);

    release_pam_node(n_tee);
    if (is_global == true) {
        g_gt_pam_node  = NULL;
        g_gt_oper_addr = NULL;
    } else {
        g_cur_session->pam_node  = NULL;
        g_cur_session->oper_addr = NULL;
    }

    return ret;
}

void mem_manager_init(void)
{
    dlist_init(&g_mem_ns);
}

TEE_Result store_s_cmd(const smc_cmd_t *cmd)
{
    if (g_cur_session != NULL && cmd != NULL) {
        if (memcpy_s(&g_cur_session->cmd_in, sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t)) != EOK) {
            tloge("memcpy_s cmd_in failed\n");
            return TEE_ERROR_GENERIC;
        }
        g_cur_session->cmd = &g_cur_session->cmd_in;
    } else {
        tloge("ta2ta target ta agent request error: g_cur_session or cmd is null\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/*
 * task_id=0, params are copy to gtask -- 32 bit
 * no need to change
 */
TEE_Result cmd_global_ns_get_params(const smc_cmd_t *cmd, uint32_t *param_type, TEE_Param **params)
{
    TEE_Result ret;
    uint64_t gtask_param = 0;

    if (cmd == NULL || param_type == NULL || params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret     = cmd_ns_get_params(0, cmd, param_type, &gtask_param);
    *params = (TEE_Param *)(uintptr_t)gtask_param;

    return ret;
}

bool is_opensession_cmd(const smc_cmd_t *cmd)
{
    if (cmd == NULL)
        return false;

    return ((cmd->cmd_type == CMD_TYPE_GLOBAL) && (cmd->cmd_id == GLOBAL_CMD_ID_OPEN_SESSION));
}

static TEE_Result map_memref_for_gtask(bool ta2ta, const smc_cmd_t *cmd, tee_param_32 p,
                                       paddr_t buffer_h_addr, uint32_t type, void **ree_addr)
{
    (void)type;
    if (ta2ta) {
        uint64_t tmp_addr;
        if (map_sharemem(cmd->uid, (uint32_t)p.memref.buffer | (buffer_h_addr << SHIFT_OFFSET),
                             p.memref.size, &tmp_addr) != 0) {
            tloge("ta2ta map smc cmd operation failed\n");
            return TEE_ERROR_GENERIC;
        }

        /* gtask is 32bit */
        *ree_addr = (void *)(uintptr_t)tmp_addr;
        TEE_Result ret = task_add_mem_region(cmd->event_nr, 0, (uint64_t)(uintptr_t)(*ree_addr),
                                             p.memref.size, ta2ta);
        if (ret != TEE_SUCCESS) {
            tloge("failed to refcount the memory\n");
            if (munmap(*ree_addr, p.memref.size) != 0)
                tloge("munmap ree_addr failed\n");
            return ret;
        }
    } else {
        paddr_t tmp_addr = (paddr_t)p.memref.buffer | (buffer_h_addr << SHIFT_OFFSET);
        *ree_addr = mailbox_phys_to_virt(tmp_addr);
        if (*ree_addr == NULL) {
            tloge("buffer addr value invalid\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result params_map_for_ta_memref(uint32_t i, struct pam_node *node, uint32_t task_id,
                                           const smc_cmd_t *cmd, bool ta2ta, uint32_t type)
{
    void *ree_addr          = NULL;
    void *tee_addr          = NULL;
    uint32_t *buffer_h_addr = node->op.p_h_addr;
    tee_param_32 *p         = node->op.p;

    set_index_memref_size(node, i, (unsigned int)p[i].memref.size);
    /*
     * copy memref from ree to tee
     * 1.first map memref for global_task
     */
    if (map_memref_for_gtask(ta2ta, cmd, p[i], (paddr_t)buffer_h_addr[i], type, &ree_addr) != TEE_SUCCESS) {
        tloge("%u map memref failed\n", task_id);
        return TEE_ERROR_GENERIC;
    }

    /* skip the ta_load cmd, because it will do copy itself */
    bool is_ta_load = ((cmd->cmd_id == GLOBAL_CMD_ID_LOAD_SECURE_APP) && (task_id == 0) && (!ta2ta) && (i == 0));
    if (is_ta_load) {
        set_index_memref_buffer(node, i, (uint64_t)(uintptr_t)ree_addr);
        return TEE_SUCCESS;
    }

    /*
     * 2.copy param memref ree->tee, if type is reserved memory,
     * we do not copy, just set tee addr same to ree addr.
     */
    TEE_Result ret = copy_from_src(task_id, &tee_addr, ree_addr, p[i].memref.size, type);
    if (ret != TEE_SUCCESS) {
        tloge("p[%u] copy from ree failed:0x%x and cmdid=%x\n", i, ret, cmd->cmd_id);
        return ret;
    }

    /* 3.save the params member's virt addr */
    node->p_vaddr_gt_tee[i] = tee_addr;
    node->p_vaddr_gt_ree[i] = ree_addr;

    /* 4.map tee mem addr for target ta */
    if (task_id == 0) {
        /* for global_task use tee_addr directly */
        set_index_memref_buffer(node, i, (uint64_t)(uintptr_t)tee_addr);
        return TEE_SUCCESS;
    }

    set_index_memref_buffer(node, i, (uint64_t)(uintptr_t)tee_addr);
    return TEE_SUCCESS;
}

static TEE_Result set_params_for_ta(uint32_t task_id, const smc_cmd_t *cmd, struct pam_node *node,
                                    bool ta2ta, uint32_t index)
{
    TEE_Result ret = TEE_SUCCESS;
    tee_param_32 *p = node->op.p;
    uint32_t type = TEE_PARAM_TYPE_GET(node->op.p_type, index);

    switch (type) {
    case TEE_PARAM_TYPE_NONE:
        break;
    case TEE_PARAM_TYPE_VALUE_INPUT:
    case TEE_PARAM_TYPE_VALUE_OUTPUT:
    case TEE_PARAM_TYPE_VALUE_INOUT:
        set_index_value_a(node, index, p[index].value.a);
        set_index_value_b(node, index, p[index].value.b);
        break;
    case TEE_PARAM_TYPE_MEMREF_INPUT:
    case TEE_PARAM_TYPE_MEMREF_OUTPUT:
    case TEE_PARAM_TYPE_MEMREF_INOUT:
        ret = params_map_for_ta_memref(index, node, task_id, cmd, ta2ta, type);
        break;
    default:
        tloge("invalid param type %u\n", type);
        ret = TEE_ERROR_GENERIC;
    }

    return ret;
}

static TEE_Result params_map_for_ta(uint32_t task_id, const smc_cmd_t *cmd, struct pam_node *node, bool ta2ta)
{
    TEE_Result ret = alloc_tee_param_for_ta(task_id, node);
    if (ret != TEE_SUCCESS)
        return ret;

    /* map ns smc cmd operation buffer to secure os */
    for (uint32_t i = 0; i < TEE_PARAM_NUM; i++) {
        ret = set_params_for_ta(task_id, cmd, node, ta2ta, i);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    return TEE_SUCCESS;
}

static void *__operation_map_for_gt(paddr_t phys, uint32_t size, bool *mapped)
{
    void *operation = NULL;
    uint64_t op_vaddr;

    if (g_mb_state.init == true)
        return mailbox_phys_to_virt(phys);

    /* Before mailbox initialized, we still need map the operation. */
    if (task_map_ns_phy_mem(0, (uint64_t)phys, size, &op_vaddr)) {
        tloge("2map smc cmd operation failed\n");
        return NULL;
    }
    *mapped   = true;
    operation = (void *)(uintptr_t)op_vaddr;
    return operation;
}

static TEE_Result map_cmd_to_operation(bool ta2ta, uint32_t *operation_size, const smc_cmd_t *cmd,
                                       void **operation)
{
    TEE_Result ret;
    bool mapped = false;

    if (ta2ta) {
        uint64_t tmp_operation;

        *operation_size = sizeof(struct smc_operation);
        if (map_sharemem(cmd->uid, cmd->operation_phys | ((paddr_t)cmd->operation_h_phys << SHIFT_OFFSET),
                             *operation_size, &tmp_operation) != 0) {
            tloge("ta2ta mode map smc cmd operation failed\n");
            return TEE_ERROR_GENERIC;
        }

        *operation = (void *)(uintptr_t)tmp_operation;
        mapped     = true;
    } else {
        paddr_t tmp_addr = cmd->operation_phys | ((paddr_t)cmd->operation_h_phys << SHIFT_OFFSET);

        *operation_size = sizeof(uint32_t) * PARAM_CNT + TEE_PARAM_NUM * sizeof(tee_param_32);
        *operation      = __operation_map_for_gt(tmp_addr, *operation_size, &mapped);
        if (*operation == NULL) {
            tloge("operation map for gt failed\n");
            return TEE_ERROR_GENERIC;
        }
    }

    if (mapped) {
        ret = task_add_mem_region(cmd->event_nr, 0, (uint64_t)(uintptr_t)(*operation), *operation_size, ta2ta);
        if (ret != TEE_SUCCESS) {
            if (munmap(*operation, *operation_size) != 0)
                tloge("unmap operation failed\n");
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result operation_map_for_gt(uint32_t task_id, const smc_cmd_t *cmd, uint32_t *param_type, uint64_t *params,
                                       bool ta2ta)
{
    TEE_Result ret;
    void *operation           = NULL;
    struct pam_node *pam_node = NULL;
    uint32_t operation_size;

    ret = map_cmd_to_operation(ta2ta, &operation_size, cmd, &operation);
    if (ret != TEE_SUCCESS)
        return ret;

    /* copy the ns shared mem into tee */
    ret = copy_pam_from_src(operation, operation_size, &pam_node);
    if (ret != 0) {
        tloge("copy pam from ree failed.\n");
        return ret;
    }

    if (!ta2ta) {
        ret = check_operation_params_in_mailbox_range(&(pam_node->op));
        if (ret != 0) {
            tloge("operation buffer is not in mailbox\n");
            release_pam_node(pam_node);
            return ret;
        }
    }

    ret = params_map_for_ta(task_id, cmd, pam_node, ta2ta);
    if (ret != 0) {
        tloge("operation map for ta failed:%x\n", ret);
        release_pam_node(pam_node);
        return ret;
    }

    if (task_id == 0) {
        bool reset_flag = false;

        *params = (uintptr_t)pam_node->p_for_ta;

        reset_flag = (g_gt_pam_node != NULL || g_gt_oper_addr != NULL);
        if (reset_flag)
            tloge("ERROR: g_gt_pam_node is not null\n");

        g_gt_pam_node  = pam_node;
        g_gt_oper_addr = operation;
    } else {
        /* map virt addr of param for task_id */
        *params = (uint64_t)(uintptr_t)pam_node->p_for_ta;

        g_cur_session->pam_node  = pam_node;
        g_cur_session->oper_addr = operation;
    }

    *param_type = pam_node->op.p_type;
    return ret;
}

TEE_Result cmd_ns_get_params(uint32_t task_id, const smc_cmd_t *cmd, uint32_t *param_type, uint64_t *params)
{
    TEE_Result ret;
    paddr_t tmp_operation_addr;

    if (cmd == NULL || param_type == NULL || params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tmp_operation_addr = cmd->operation_phys | (((paddr_t)cmd->operation_h_phys) << SHIFT_OFFSET);

    *param_type = 0;
    if (tmp_operation_addr != 0) {
        ret = operation_map_for_gt(task_id, cmd, param_type, params, false);
        if (ret != 0) {
            tloge("operation ns map for gt failed:%x\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result cmd_secure_get_params(uint32_t task_id, const smc_cmd_t *cmd, uint32_t *param_type, uint64_t *params)
{
    TEE_Result ret;
    paddr_t tmp_operation_addr;

    if (cmd == NULL || param_type == NULL || params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cmd->uid == task_id)
        return TEE_SUCCESS; /* Nothing to do, no need to remap */

    tmp_operation_addr = cmd->operation_phys | (((paddr_t)cmd->operation_h_phys) << SHIFT_OFFSET);
    *param_type        = 0;
    *params            = 0;
    if (tmp_operation_addr != 0) {
        ret = operation_map_for_gt(task_id, cmd, param_type, params, true);
        if (ret != 0) {
            tloge("operation ns map for gt failed:%x\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result task_add_mem_region(uint32_t event_nr, uint32_t task_pid, uint64_t addr, uint32_t size, bool ta2ta)
{
    struct mem_region_ns *mem = NULL;

    mem = (struct mem_region_ns *)TEE_Malloc(sizeof(struct mem_region_ns), 0);
    if (mem == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    mem->task_id  = task_pid;
    mem->addr     = addr;
    mem->size     = size;
    mem->event_nr = event_nr;
    mem->ta2ta    = ta2ta;

    if (g_cur_session != NULL) {
        dlist_insert_tail(&mem->list, &(g_cur_session->map_mem));
    } else {
        dlist_insert_tail(&mem->list, &g_mem_ns);
    }

    return TEE_SUCCESS;
}

void task_del_mem_region(struct dlist_node *mem_list, bool is_service_dead)
{
    struct mem_region_ns *mem = NULL;
    struct mem_region_ns *tmp = NULL;

    dlist_for_each_entry_safe(mem, tmp, mem_list, struct mem_region_ns, list) {
        if (!is_service_dead && task_unmap(mem->task_id, mem->addr, mem->size) != 0)
            tloge("unmap mem addr failed, id=0x%x\n", mem->task_id);
        dlist_delete(&mem->list);
        TEE_Free(mem);
        mem = NULL;
    }
}

void *map_ns_cmd(paddr_t cmd_phy)
{
    uint64_t cmd_virt;
    /* map ns smc cmd to secure os */
    if (task_map_ns_phy_mem(0, (uint64_t)cmd_phy, GT_SHARED_CMD_QUEUES_SIZE, &cmd_virt)) {
        tloge("map smc cmd failed\n");
        return NULL;
    }

    return (void *)(uintptr_t)(cmd_virt);
}

TEE_Result map_secure_operation(uint64_t tacmd, smc_cmd_t *out_cmd, uint32_t task_id)
{
    smc_cmd_t *cmd = NULL;
    TEE_Result ret = TEE_SUCCESS;
    uint64_t tmp_cmd;

    if (out_cmd == NULL) {
        tloge("map smc cmd failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* 1. do cmd copy */
    if (map_sharemem(task_id, tacmd, sizeof(smc_cmd_t), &tmp_cmd) != 0) {
        tloge("map smc cmd failed\n");
        return TEE_ERROR_GENERIC;
    }

    cmd      = (smc_cmd_t *)(uintptr_t)tmp_cmd;
    cmd->uid = task_id;

    if (memcpy_s(out_cmd, sizeof(*out_cmd), cmd, sizeof(*cmd)) != EOK) {
        tloge("copy ta2ta out cmd failed\n");
        ret = TEE_ERROR_GENERIC;
    }

    if (munmap(cmd, sizeof(smc_cmd_t)) != 0)
        tloge("unmap cmd failed\n");
    return ret;
}

TEE_Result unmap_secure_operation(const smc_cmd_t *cmd)
{
    struct mem_region_ns *mem = NULL;
    struct mem_region_ns *tmp = NULL;

    if (cmd == NULL) {
        tloge("map smc cmd failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (g_cur_session == NULL) {
        tlogd("g_cur_session is null\n");
        return TEE_SUCCESS;
    }

    dlist_for_each_entry_safe(mem, tmp, &(g_cur_session->map_mem), struct mem_region_ns, list) {
        if (cmd->event_nr == mem->event_nr && mem->ta2ta) {
            if (task_unmap(mem->task_id, mem->addr, mem->size) != 0)
                tloge("s unmap failed\n");
            dlist_delete(&mem->list);
            TEE_Free(mem);
            mem = NULL;
        }
    }
    g_cur_session->cmd = NULL;

    return TEE_SUCCESS;
}

/* Unmap all NS memory related to the smc_cmd */
TEE_Result unmap_ns_operation(smc_cmd_t *cmd)
{
    struct mem_region_ns *mem = NULL;
    struct mem_region_ns *tmp = NULL;
    uint32_t error_flag   = 0;
    struct dlist_node *mem_list = NULL;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tlogd("unmap_ns_operation: cmd->event_nr is %x\n", cmd->event_nr);

    if (g_cur_session != NULL) {
        mem_list = &(g_cur_session->map_mem);
    } else {
        mem_list = &g_mem_ns;
    }
    dlist_for_each_entry_safe(mem, tmp, mem_list, struct mem_region_ns, list) {
        if (cmd->event_nr == mem->event_nr && !mem->ta2ta) {
            if (task_unmap(mem->task_id, mem->addr, mem->size) != 0) {
                tloge("ns unmap mem addr failed\n");
                error_flag = 1;
            }
            dlist_delete(&mem->list);
            TEE_Free(mem);
            mem = NULL;
        }
    }

    cmd->operation_phys   = 0x0;
    cmd->operation_h_phys = 0x0;

    if (error_flag != 0)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static TEE_Result register_mempool(const smc_cmd_t *cmd, struct mempool_state *state, uint32_t pool_size)
{
    uint32_t param_type = 0;
    TEE_Param *param    = NULL;
    uint64_t vaddr;

    if (state->init) {
        tloge("mem pool has registered\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cmd_global_ns_get_params(cmd, &param_type, &param) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    /* check params types */
    if ((TEE_PARAM_TYPE_GET(param_type, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_type, 1) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* this condition should never happen here */
    if (param == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    state->start = (paddr_t)(param[0].value.a | ((paddr_t)param[0].value.b << SHIFT_OFFSET));
    state->size  = param[1].value.a;
    if (state->start > ADDR_MAX - state->size || state->size != pool_size) {
        tloge("mem pool addr is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (task_map_ns_phy_mem(0, (uint64_t)state->start, state->size, &vaddr)) {
        tloge("map mem pool failed\n");
        return TEE_ERROR_GENERIC;
    }

    state->va   = (uintptr_t)vaddr;
    state->init = true;
    return TEE_SUCCESS;
}

TEE_Result register_mailbox(const smc_cmd_t *cmd)
{
    uint32_t pool_size = get_mailbox_size();
    return register_mempool(cmd, &g_mb_state, pool_size);
}

bool in_mailbox_range(paddr_t addr, uint32_t size)
{
    if (g_mb_state.init == false) {
        tlogd("mailbox is not initialized\n");
        return true;
    }

    if (addr > ADDR_MAX - size || (addr < g_mb_state.start || addr >= (g_mb_state.start + g_mb_state.size)) ||
        ((addr + size) < g_mb_state.start || (addr + size) > (g_mb_state.start + g_mb_state.size))) {
        tloge("ns addr is illegal\n");
        return false;
    }

    return true;
}

void *mailbox_phys_to_virt(paddr_t phys)
{
    /* Before call this function to derive mailbox virtual address of mailbox in
     * gtask, non-zero phys is always checed by 'in_mailbox_range'. So we needn't
     * check physical address is legal again except 0.
     */
    if (phys == 0 || g_mb_state.init == false)
        return NULL;
    return (void *)(g_mb_state.va + (uintptr_t)(phys - g_mb_state.start));
}

static TEE_Result check_operation_params_in_mailbox_range(const tee_operation_gtask *operation)
{
    TEE_Result ret = TEE_SUCCESS;
    paddr_t buffer_addr;

    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (uint32_t i = 0; i < TEE_PARAM_NUM; i++) {
        uint32_t type = TEE_PARAM_TYPE_GET(operation->p_type, i);
        switch (type) {
        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            buffer_addr = (paddr_t)((uint32_t)operation->p[i].memref.buffer |
                                    ((paddr_t)operation->p_h_addr[i] << SHIFT_OFFSET));
            if (buffer_addr && !in_mailbox_range(buffer_addr, operation->p[i].memref.size)) {
                tloge("buffer[%u] is not in mailbox\n", i);
                ret = TEE_ERROR_BAD_PARAMETERS;
            }
            break;
        default:
            tloge("invalid param type %u operation->p_type : %x\n", type, operation->p_type);
            break;
        }
    }

    return ret;
}

TEE_Result check_cmd_in_mailbox_range(const smc_cmd_t *cmd)
{
    paddr_t operation_addr, login_data_addr;

    if (cmd == NULL) {
        tloge("cmd is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (g_mb_state.init == false)
        return TEE_SUCCESS;

    operation_addr = (paddr_t)(cmd->operation_phys | ((paddr_t)cmd->operation_h_phys << SHIFT_OFFSET));
    if (operation_addr != 0 &&
        !in_mailbox_range(operation_addr, sizeof(uint32_t) * PARAM_CNT + TEE_PARAM_NUM * sizeof(TEE_Param))) {
        tloge("operation is not in mailbox\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    login_data_addr = (paddr_t)(cmd->login_data_phy | ((paddr_t)cmd->login_data_h_phy << SHIFT_OFFSET));
    if (login_data_addr != 0 && !in_mailbox_range(login_data_addr, cmd->login_data_len)) {
        tloge("login data is not in mailbox\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_param_stat(uint32_t param_types, const TEE_Param *tee_param)
{
    if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_VALUE_INPUT) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (tee_param == NULL) {
        tloge("Something wrong happen, tee_param is wrong.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (tee_param[0].memref.size < sizeof(struct stat_mem_info)) {
        tloge("Bad size \n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result dump_statmeminfo(const smc_cmd_t *cmd)
{
    TEE_Param *tee_param = NULL;
    uint32_t param_types = 0;
    TEE_Result ret;
    int dump_stat;
    int print_history;

    if (cmd == NULL) {
        tloge("CAUTION!!! invalid cmd, please check.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (cmd_global_ns_get_params(cmd, &param_types, &tee_param) != TEE_SUCCESS) {
        tloge("failed to map operation!\n");
        return TEE_ERROR_GENERIC;
    }

    ret = check_param_stat(param_types, tee_param);
    if (ret != TEE_SUCCESS) {
        tloge("Bad expected parameter types.\n");
        return ret;
    }

    print_history = (int32_t)tee_param[1].value.b;
    if (tee_param[1].value.a == 0) {
        struct stat_mem_info *meminfo = (struct stat_mem_info *)tee_param[0].memref.buffer;
        dump_stat                     = dump_mem_info(meminfo, print_history);
        if (meminfo != NULL && dump_stat == 0) {
            tlogd("total=%u,pmem=%u,free=%u,lowest=%u\n", meminfo->total_mem, meminfo->mem, meminfo->free_mem,
                  meminfo->free_mem_min);
            for (uint32_t i = 0; i < meminfo->proc_num; i++)
                tlogd("i=%u,name=%s,mem=%u,memmax=%u,memlimit=%u\n", i, meminfo->proc_mem[i].name,
                      meminfo->proc_mem[i].mem, meminfo->proc_mem[i].mem_max, meminfo->proc_mem[i].mem_limit);
        } else {
            tlogd("meminfo is NULL or dump mem info failed.\n");
        }
    } else {
        dump_stat = dump_mem_info(NULL, print_history);
    }
    if (dump_stat == 0)
        return TEE_SUCCESS;
    else
        return TEE_ERROR_GENERIC;
}

bool check_short_buffer(void)
{
    struct pam_node *n_tee = NULL;
    uint32_t i;

    if (g_cur_session == NULL) {
        tloge("cur session is NULL, this never happen\n");
        return false;
    }

    n_tee = g_cur_session->pam_node;
    if (n_tee == NULL) {
        tlogd("no pam node\n");
        return false;
    }

    for (i = 0; i < TEE_PARAM_NUM; i++) {
        uint32_t type = TEE_PARAM_TYPE_GET(n_tee->op.p_type, i);
        if (type != TEE_PARAM_TYPE_MEMREF_OUTPUT &&
            type != TEE_PARAM_TYPE_MEMREF_INOUT)
            continue;
        /* size changed by ta is bigger than size given by ca */
        if (n_tee->op.p[i].memref.size < get_index_memref_size(n_tee, i)) {
            tloge("short buffer happen\n");
            return true;
        }
    }
    return false;
}

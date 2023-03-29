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
#ifndef GTASK_MEM_MANAGER_H
#define GTASK_MEM_MANAGER_H

#include <dlist.h>
#include "gtask_core.h"

TEE_Result cmd_ns_get_params(uint32_t task_id, const smc_cmd_t *cmd, uint32_t *param_type, uint64_t *params);
TEE_Result cmd_secure_get_params(uint32_t task_id, const smc_cmd_t *cmd, uint32_t *param_type, uint64_t *params);
TEE_Result cmd_global_ns_get_params(const smc_cmd_t *cmd, uint32_t *param_type, TEE_Param **params);
TEE_Result map_ns_operation(const smc_cmd_t *cmd);
TEE_Result unmap_ns_operation(smc_cmd_t *cmd);
void *map_ns_cmd(paddr_t cmd_phy);
TEE_Result map_secure_operation(uint64_t tacmd, smc_cmd_t *out_cmd, uint32_t task_id);
TEE_Result unmap_secure_operation(const smc_cmd_t *cmd);
void mem_manager_init(void);
TEE_Result store_s_cmd(const smc_cmd_t *cmd);
TEE_Result copy_pam_to_src(uint32_t cmd_id, bool ta2ta);
TEE_Result register_mailbox(const smc_cmd_t *cmd);
bool in_mailbox_range(paddr_t addr, uint32_t size);
TEE_Result check_cmd_in_mailbox_range(const smc_cmd_t *cmd);
void *mailbox_phys_to_virt(paddr_t phys);
TEE_Result register_res_mem(const smc_cmd_t *cmd);
bool in_res_mem_range(paddr_t addr, uint64_t size);
void *res_mem_phys_to_virt(paddr_t phys);
TEE_Result dump_statmeminfo(const smc_cmd_t *cmd);
void task_del_mem_region(struct dlist_node *mem_list, bool is_service_dead);

bool is_opensession_cmd(const smc_cmd_t *cmd);
void release_pam_node(struct pam_node *node);
bool check_short_buffer(void);

#endif /* GTASK_MEM_MANAGER_H */

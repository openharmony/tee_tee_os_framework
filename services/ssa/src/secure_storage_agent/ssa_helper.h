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
#ifndef __SSA_HELPER_H_
#define __SSA_HELPER_H_

#include <tee_defines.h>
#include "sfs.h"
#include "tee_ss_agent_api.h"
#include "sfs_internal.h"

TEE_Result ssa_internal_fcreate(const char *file_name, const TEE_UUID *uuid, struct sfd_t **sfd);
TEE_Result ssa_internal_fopen(const char *file_name, const TEE_UUID *uuid, struct sfd_t **sfd);
uint32_t ssa_internal_fwrite(struct sfd_t *sfd, const uint8_t *in_buff, uint32_t len);
void ssa_internal_fclose(struct sfd_t *sfd);
void ssa_internal_fremove(struct sfd_t *sfd);
TEE_Result create_param_mapping(const union ssa_agent_msg *msg, uint32_t sndr, mem_map_info_t *obj_id_info,
                                mem_map_info_t *attributes_info, mem_map_info_t *initial_data);
void create_param_unmapping(const mem_map_info_t *obj_id_info, const mem_map_info_t *attributes_info,
                            const mem_map_info_t *initial_data);
void create_object_proc(const struct create_obj_msg_t *create_obj, uint32_t sndr,
                        const TEE_UUID *uuid, struct ssa_agent_rsp *rsp);
TEE_Result open_param_mapping(const union ssa_agent_msg *msg, uint32_t sndr, mem_map_info_t *obj_id_info,
                              mem_map_info_t *attributes_info);
void open_param_unmapping(const mem_map_info_t *obj_id_info, const mem_map_info_t *attributes_info);
#endif

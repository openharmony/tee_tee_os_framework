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
#ifndef __SSA_ENUMERATOR
#define __SSA_ENUMERATOR

#include "tee_ss_agent_api.h"

#define ENUM_FILE_NAME_PREFIX     "enum_file_"
/* "enum_file_" and "sec_storage_data/" */
#define ENUM_FILE_NAME_PREFIX_LEN 27
#define UUID_SIZE                 16
/* add '-' num */
#define UUID_STR_LEN              (UUID_SIZE + 4)
#define ENUM_FILE_NAME_LEN        (ENUM_FILE_NAME_PREFIX_LEN + UUID_STR_LEN + 1)

enum operation_flag {
    ENUM_INVALID_OPER = 0,
    ENUM_CREATE       = 1,
    ENUM_OPEN         = 2,
};

TEE_Result add_objinfo_into_enum_file(const struct create_obj_msg_t *create_obj, uint32_t data_size, uint32_t sndr);
TEE_Result update_objinfo_in_enum_file(const uint8_t *object_id, uint32_t object_id_len,
                                       uint32_t new_size, uint32_t new_pos, uint32_t sndr);
TEE_Result rename_obj_in_enum_file(const uint8_t *origin_obj_id, const uint8_t *new_obj_id, uint32_t new_obj_id_len,
                                   uint32_t sndr);
TEE_Result delete_obj_in_enum_file(const uint8_t *object_id, uint32_t object_id_len, uint32_t sndr);
void ssa_get_enum_file_size(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_start_enumerator(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
#endif

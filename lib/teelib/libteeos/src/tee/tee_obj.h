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
#ifndef TEE_OBJ_H
#define TEE_OBJ_H

#include <pthread.h>

#include "tee_defines.h"

TEE_Result tee_obj_setname(TEE_ObjectHandle object, const uint8_t *name, uint32_t len);
TEE_Result tee_obj_new(TEE_ObjectHandle *object);
TEE_Result tee_obj_free(TEE_ObjectHandle *object);
TEE_Result tee_obj_init(void);
void tee_memory_dump(const uint8_t *data, uint32_t count);
void dump_object(void);
TEE_Result check_object(const TEE_ObjectHandle object);
TEE_Result add_object(TEE_ObjectHandle object);
TEE_Result delete_object(const TEE_ObjectHandle object);
TEE_Result check_permission(const char *object_id, size_t object_id_len, uint32_t flags);
int mutex_lock_ops(pthread_mutex_t *mutex);
TEE_Result check_enum_object_in_list(const TEE_ObjectEnumHandle object);
TEE_Result add_enum_object_in_list(const TEE_ObjectEnumHandle object);
void delete_enum_object_in_list(const TEE_ObjectEnumHandle object);
#endif

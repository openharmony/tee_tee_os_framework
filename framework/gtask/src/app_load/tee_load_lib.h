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

#ifndef GTASK_TEE_LOAD_LIB_H
#define GTASK_TEE_LOAD_LIB_H
#include "gtask_core.h"

extern struct service_struct *g_cur_service;
extern struct session_struct *g_cur_session;

#define CHECK_ERROR    (-1)
#define LIB_LOADED     1
#define LIB_NOT_LOADED 0

TEE_Result process_close_session_entry(struct service_struct **service, struct session_struct **session);
void tee_delete_all_libinfo(struct service_struct *service);
TEE_Result tee_add_libinfo(struct service_struct *service, const char *name, size_t name_size,
                           tee_img_type_t type);
int is_lib_loaded(const struct service_struct *service, const char *name, size_t name_size);
void do_age_timeout_lib(struct service_struct *service);
int32_t handle_unlink_dynamic_drv(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);
#endif

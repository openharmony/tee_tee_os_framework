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
#ifndef GTASK_SESSION_MANAGER_H
#define GTASK_SESSION_MANAGER_H

#include "gtask_core.h"

void reset_ta_context(void);
void set_tee_return_origin(smc_cmd_t *cmd, TEE_Result ret_origin);
void set_tee_return(smc_cmd_t *cmd, TEE_Result ret_val);
void set_tee_processed(bool processed);
TEE_Result proceed_return_code(smc_cmd_t *cmd);
bool is_command_processed(void);
TEE_Result start_ta_task(const smc_cmd_t *cmd, uint32_t cmd_type);
TEE_Result init_ta_context(const smc_cmd_t *cmd);
TEE_Result init_ta2ta_agent_context(smc_cmd_t *cmd);
TEE_Result init_ta2ta_context(smc_cmd_t *cmd, uint64_t ta_cmd, uint32_t task_id);
TEE_Result init_session_context(uint32_t task_id,
    struct service_struct **service, struct session_struct **session);
TEE_Result open_session(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t caller_id,
                        const struct ta2ta_info_t *ta2ta_info);
TEE_Result close_session(const smc_cmd_t *cmd, uint32_t cmd_type, bool *sync);
TEE_Result async_call_ta_entry(const smc_cmd_t *cmd, uint32_t cmd_type, uint32_t cmd_id);
TEE_Result process_open_session(const smc_cmd_t *cmd, uint32_t cmd_type);
void process_open_session_error(void);
TEE_Result process_close_session(void);
void session_set_cancelable(bool cancelable);
bool process_init_session(void);
void set_session_context(smc_cmd_t *cmd, uint32_t service_index, uint32_t session_id);
int32_t get_session_id(void);

int32_t find_service(const TEE_UUID *uuid, uint32_t service_index, struct service_struct **entry);
struct service_struct *find_service_by_task_id(uint32_t task_id);
int join_session_task_name(const char *service_name, struct session_struct *session);
struct session_struct *find_session_with_dev_file_id(uint32_t session_id, uint32_t dev_file_id,
    const struct service_struct *srv);
struct session_struct *get_cur_session(void);
struct service_struct *get_cur_service(void);
TEE_Result add_new_session_into_list(struct session_struct **session, uint32_t *session_id,
                                     uint32_t ta2ta_level);
int32_t release_session(struct service_struct *service, struct session_struct *session);
TEE_Result close_session_async(struct session_struct *sess);

#endif /* GTASK_SESSION_MANAGER_H */

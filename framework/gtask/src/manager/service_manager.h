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
#ifndef GTASK_SERVICE_MANAGER_H
#define GTASK_SERVICE_MANAGER_H

#include <dlist.h>
#include <ipclib.h>

#define INVALID_SERVICE_INDEX  (-1)
#define SERVICE_INDEX_MAX 2048

bool dynamic_service_exist(const TEE_UUID *uuid, bool build_in);
TEE_Result register_service(const char *name, const TEE_UUID *uuid, bool dyn_conf_registed,
                            const struct service_attr *service_attr);
TEE_Result ta_framework_init(void);
void init_service_property(const TEE_UUID *uuid, uint32_t stack, uint32_t heap,
                           bool single_instance, bool multi_session, bool keep_alive,
                           bool ssa_enum_enable, bool mem_page_align, const char *other_buff,
                           uint32_t other_len);
bool need_load_srv(const TEE_UUID *uuid);
TEE_Result start_internal_task(const TEE_UUID *uuid, uint16_t task_prio, const char *task_name, uint32_t *task_id);
bool is_gtask_by_uuid(const TEE_UUID *task_uuid);
struct dlist_node *get_service_head_ptr(void);
#ifdef CONFIG_ENABLE_DUMP_SRV_SESS
TEE_Result dump_service_session_info(const smc_cmd_t *cmd);
#endif

struct service_struct *find_service_dead(const TEE_UUID *uuid, uint32_t service_index);
bool find_task(uint32_t task_id, struct service_struct **service, struct session_struct **session);
bool find_task_dead(uint32_t task_id, struct service_struct **service, struct session_struct **session);
bool is_system_service(const struct service_struct *service);
void process_release_service(struct service_struct *service, uint32_t if_reuse_elf);
void recycle_srvc_thread(struct service_struct *service);
TEE_Result age_service(void);
void decr_ref_cnt(struct service_struct *service);
void get_interval(const TEE_Time *cur, const TEE_Time *base, uint64_t *interval);
void age_timeout_lib(void);

#endif /* GTASK_SERVICE_MANAGER_H */

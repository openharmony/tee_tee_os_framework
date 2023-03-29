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
#include <dlist.h>
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "gtask_config_hal.h"
#include "mem_page_ops.h" // PAGE_ALIGN_UP
#include "securec.h"
#include "tee_load_lib.h"
#include "gtask_core.h" /* for find_service */
#include "dynload.h"
#include "tee_bitmap.h"
#include "gtask_inner.h"
#include "service_manager.h"
#include "session_manager.h"
#include "mem_manager.h"
#include "agent_manager.h"
#include <signal.h>
#include "ipclib.h"
#include "tee_task.h"
#include "tee_time_api.h"
#include "task_adaptor_pub.h"
#include "sys_timer.h"
#include "tee_load_lib.h"
#include "tee_drv_internal.h"
#include "drvcall_dyn_conf_builder.h"

#define SERVICE_AGED_TIME_LIMIT  2000U /* unit: millis */

/* defined in trustedcore/TEE_ext/tee_config.c */
extern struct service_struct *g_cur_service;
extern struct session_struct *g_cur_session;

#define INDEX_MAP_LEN     (SERVICE_INDEX_MAX / 8)
#define FIRST_INDEX       1
static uint32_t g_cur_index = FIRST_INDEX;
static uint8_t g_service_index_map[INDEX_MAP_LEN] = {0};

/* service list head */
struct dlist_node g_service_head;
bool find_task(uint32_t task_id, struct service_struct **service, struct session_struct **session);

struct dlist_node *get_service_head_ptr(void)
{
    return &g_service_head;
}

bool is_gtask_by_uuid(const TEE_UUID *task_uuid)
{
    TEE_UUID uuid = TEE_SERVICE_GLOBAL;

    if (TEE_MemCompare(&uuid, task_uuid, sizeof(TEE_UUID)) == 0)
        return true;

    return false;
}

int32_t find_service(const TEE_UUID *uuid, uint32_t service_index, struct service_struct **entry)
{
    struct service_struct *service_entry = NULL;
    int32_t index                        = -1;

    if (uuid == NULL || entry == NULL)
        return -1;

    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        tlogd("iterate service %s \n", service_entry->name);
        if ((TEE_MemCompare(&service_entry->property.uuid, uuid, sizeof(TEE_UUID)) == 0) &&
            !service_entry->is_service_dead) {
            tlogd("call service : %s\n", service_entry->name);
            if (service_index == 0 || service_index == service_entry->index) {
                index  = (int32_t)service_entry->index;
                *entry = service_entry;
                break;
            } else {
                tloge("service(%s) uuid match but service_index miss match:0x%x <--> 0x%x\n", service_entry->name,
                      service_index, service_entry->index);
            }
        }
    }
    return index;
}

struct service_struct *find_service_dead(const TEE_UUID *uuid, uint32_t service_index)
{
    struct service_struct *service_entry = NULL;

    if (uuid == NULL || service_index == 0)
        return NULL;

    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        if ((TEE_MemCompare(&service_entry->property.uuid, uuid, sizeof(TEE_UUID)) == 0) &&
            service_entry->is_service_dead) {
            if (service_index == service_entry->index)
                return service_entry;
            else
                tloge("service(%s) uuid match but service_index miss match:0x%x <--> 0x%x\n", service_entry->name,
                      service_index, service_entry->index);
        }
    }
    return NULL;
}

struct service_struct *find_service_by_task_id(uint32_t task_id)
{
    struct service_struct *service_entry = NULL;

    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        if ((taskid_to_pid(service_entry->service_thread) == taskid_to_pid(task_id)) &&
            !service_entry->is_service_dead)
            return service_entry;
    }
    return NULL;
}

bool dynamic_service_exist(const TEE_UUID *uuid, bool build_in)
{
    struct service_struct *tmp_service = NULL;

    if (uuid == NULL)
        return false;

    if (build_in == false || !is_build_in_service(uuid)) {
        if (find_service(uuid, 0, &tmp_service) != -1 && tmp_service->elf_state == ELF_EXIST) {
            tlogi("dynamic service already exist, no need load elf again!\n");
            return true;
        }
    }
    return false;
}

static int32_t get_service_index(void)
{
    int32_t cnt = 0;

    while (1) {
        if (cnt == SERVICE_INDEX_MAX)
            return -1;

        if (g_cur_index >= SERVICE_INDEX_MAX)
            g_cur_index = FIRST_INDEX;

        if (!is_bit_seted(g_service_index_map, SERVICE_INDEX_MAX, g_cur_index)) {
            set_bitmap(g_service_index_map, SERVICE_INDEX_MAX, g_cur_index);
            break;
        }
        g_cur_index++;
        cnt++;
    }
    return (int32_t)(g_cur_index++);
}

static TEE_Result add_to_service_list(struct service_struct *service, const char *name, const TEE_UUID *uuid)
{
    int32_t index = get_service_index();
    if (index < 0) {
        tloge("get service index fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    service->index      = (uint32_t)index;
    service->init_build = 0;
    if (strlen(name) < SERVICE_NAME_MAX) {
        if (memmove_s(service->name, sizeof(service->name), (const void *)name, strlen(name)) != TEE_SUCCESS) {
            tloge("memmove service name failed\n");
            return TEE_ERROR_GENERIC;
        }
    } else {
        if (memmove_s(service->name, sizeof(service->name),
            (const void *)name, sizeof(service->name) - 1) != TEE_SUCCESS) {
            tloge("memmove service name failed\n");
            return TEE_ERROR_GENERIC;
        }
    }
    if (memmove_s(&service->property.uuid, sizeof(service->property.uuid), uuid, sizeof(*uuid)) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    dlist_init(&service->session_head);

    dlist_insert_tail(&service->service_list, &g_service_head);
    return TEE_SUCCESS;
}

TEE_Result register_service(const char *name, const TEE_UUID *uuid, bool dyn_conf_registed,
                            const struct service_attr *service_attr)
{
    struct service_struct *service     = NULL;
    struct service_struct *tmp_service = NULL;

    if (name == NULL || uuid == NULL || service_attr == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tlogd("register_service : %s\n", name);
    /* build in service can't be register after boot */
    if (!service_attr->build_in && is_build_in_service(uuid))
        return TEE_ERROR_REGISTER_EXIST_SERVICE;

    /* have registered service but elf have been deleted, only need load elf */
    if (find_service(uuid, 0, &tmp_service) != INVALID_SERVICE_INDEX) {
        tmp_service->elf_state = ELF_EXIST;
        return TEE_SUCCESS;
    }

    service = TEE_Malloc(sizeof(*service), 0);
    if (service == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;
    service->elf_state    = ELF_EXIST;
    service->ta_64bit     = service_attr->ta_64bit;
    service->first_open   = true;
    service->lib_list_head.next = NULL;
    service->is_service_dead = false;
    service->is_dyn_conf_registed = dyn_conf_registed;
    service->img_type = service_attr->img_type;
    /* we record load elf time for all service */
    TEE_GetSystemTime(&service->load_elf_time);

    if (!service_attr->build_in)
        service->ref_cnt = 1;

    TEE_Result ret = add_to_service_list(service, name, uuid);
    if (ret != TEE_SUCCESS) {
        TEE_Free(service);
        return ret;
    }

    tlogd("register_service %s, index=%u ref_cnt=%d\n", name, service->index, service->ref_cnt);
    return TEE_SUCCESS;
}

TEE_Result service_manager_init(void)
{
    TEE_UUID uuid_global             = TEE_SERVICE_GLOBAL;
    struct service_attr service_attr = { 0 };

    service_attr.build_in     = true;
#ifdef __aarch64__
    service_attr.ta_64bit     = true;
#else
    service_attr.ta_64bit     = false;
#endif

    dlist_init(&g_service_head);
    return register_service("global_task", &uuid_global, false, &service_attr);
}

/*
 * init global data and install built-in services
 */
TEE_Result ta_framework_init(void)
{
    TEE_Result ret;
    ret = service_manager_init();
    if (ret != 0) {
        tloge("service manager init failed:%u\n", ret);
        return ret;
    }

    agent_manager_init();
    mem_manager_init();

    return TEE_SUCCESS;
}

/*
 * If page align is true, it means we shoud multiply 4K for size,
 * or we use origin size by 4k align up. The page align is declared
 * in manifext.
 */
static uint64_t get_heap_stack_size(bool page_align, uint32_t size)
{
    if (!page_align)
        return PAGE_ALIGN_UP(size);
    uint64_t mem_size = (uint64_t)size * PAGE_SIZE;
    tlogd("page aligned so multi page size, %llu,%u", mem_size, size);
    return mem_size;
}

void init_service_property(const TEE_UUID *uuid, uint32_t stack, uint32_t heap,
                           bool single_instance, bool multi_session, bool keep_alive,
                           bool ssa_enum_enable, bool mem_page_align, const char *other_buff,
                           uint32_t other_len)
{
    struct service_struct *service_entry = NULL;

    if (uuid == NULL)
        return;

    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        if (!TEE_MemCompare(&service_entry->property.uuid, uuid, sizeof(TEE_UUID)) &&
            !service_entry->is_service_dead) {
            service_entry->property.stack_size      = get_heap_stack_size(mem_page_align, stack);
            service_entry->property.heap_size       = get_heap_stack_size(mem_page_align, heap);
            service_entry->property.single_instance = single_instance;
            service_entry->property.multi_session   = multi_session;
            service_entry->property.keep_alive      = keep_alive;
            service_entry->property.ssa_enum_enable = ssa_enum_enable;

            if (other_buff != NULL && other_len != 0) {
                service_entry->property.other_buff = (char *)TEE_Malloc(other_len, 0);
                if (service_entry->property.other_buff != NULL) {
                    if (memmove_s(service_entry->property.other_buff, other_len,
                        (void *)other_buff, other_len) != TEE_SUCCESS) {
                        TEE_Free(service_entry->property.other_buff);
                        service_entry->property.other_buff = NULL;
                    } else
                        service_entry->property.other_len = other_len;
                } else {
                    tloge("failed to allocate for service_entry->property.other_buff, other_len is %u\n", other_len);
                }
            }
            break;
        }
    }
}

static bool do_find_task(uint32_t task_id, bool dead_status,
    struct service_struct **entry, struct session_struct **session)
{
    struct session_struct *sess_context  = NULL;
    struct service_struct *service_entry = NULL;

    if (entry == NULL || session == NULL)
        return false;

    /* Go through all the services and all sessions */
    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        if (service_entry->is_service_dead != dead_status)
            continue;
        dlist_for_each_entry(sess_context, &service_entry->session_head, struct session_struct, session_list) {
            if (sess_context->task_id == task_id) {
                *entry   = service_entry;
                *session = sess_context;
                return true;
            }
        }
    }

    return false;
}

bool find_task(uint32_t task_id, struct service_struct **service, struct session_struct **session)
{
    return do_find_task(task_id, false, service, session);
}

bool find_task_dead(uint32_t task_id, struct service_struct **service, struct session_struct **session)
{
    return do_find_task(task_id, true, service, session);
}

bool is_system_service(const struct service_struct *service)
{
    TEE_UUID reet_uuid      = TEE_SERVICE_REET;
    TEE_UUID gtask_uuid     = TEE_SERVICE_GLOBAL;

    if (service == NULL)
        return false;

    if ((TEE_MemCompare(&reet_uuid, &service->property.uuid, sizeof(TEE_UUID)) == 0) ||
        (TEE_MemCompare(&gtask_uuid, &service->property.uuid, sizeof(TEE_UUID)) == 0) ||
        is_internal_task_by_uuid(&service->property.uuid))
        return true;
    return false;
}

static void incr_ref_cnt(struct service_struct *service)
{
    if (service == NULL)
        return;

    /* in case of overflow */
    if ((service->ref_cnt + 1) < 0) {
        tloge("invalid ref cnt when incr\n");
        return;
    }

    service->ref_cnt++;
}

void decr_ref_cnt(struct service_struct *service)
{
    if (service == NULL)
        return;

    /* in case of overflow */
    if (service->ref_cnt <= 0) {
        tloge("invalid ref cnt when decr\n");
        return;
    }

    service->ref_cnt--;
}

bool need_load_srv(const TEE_UUID *uuid)
{
    struct service_struct *service = NULL;

    if (uuid == NULL)
        return false;

    if (is_build_in_service(uuid))
        return false;

    if (find_service(uuid, 0, &service) == INVALID_SERVICE_INDEX)
        return true;

    if (!service->property.single_instance) {
        tloge("only support singleInstance as true\n");
        return false;
    }
    incr_ref_cnt(service);

    TEE_GetSystemTime(&service->load_elf_time);
    tlogd("service %s, session count is %d ref_cnt++ is %d\n", service->name, service->session_count, service->ref_cnt);

    return false;
}

#define S_TO_MILLIS 1000U

void get_interval(const TEE_Time *cur, const TEE_Time *base, uint64_t *interval)
{
    if (cur == NULL || base == NULL || interval == NULL)
        return;

    *interval = 0;
    if (cur->seconds < base->seconds) {
        tloge("error: incorrect time\n");
        return;
    }
    /*
     * 0xffffffffffffffff millis is more than 650000 year,
     * interval will never overflow when seconds multiplicate 1000
     */
    *interval = ((uint64_t)cur->seconds - (uint64_t)base->seconds) * S_TO_MILLIS;

    if (cur->millis >= base->millis)
        *interval += (uint64_t)cur->millis - (uint64_t)base->millis;
    else
        *interval -= (uint64_t)base->millis - (uint64_t)cur->millis;
}

static bool is_aged_service(const struct service_struct *service)
{
    TEE_Time current = { 0, 0 };
    uint64_t interval;

    if (service == NULL) {
        tloge("invalid param\n");
        return false;
    }

    TEE_GetSystemTime(&current);

    get_interval(&current, &service->load_elf_time, &interval);
    if (interval > SERVICE_AGED_TIME_LIMIT) {
        tlogi("aged service: uuid is 0x%x, and seconds interval =%llu, max interval = %u\n",
              service->property.uuid.timeLow, (unsigned long long)interval, SERVICE_AGED_TIME_LIMIT);
        return true;
    }
    return false;
}

static void do_age_service(struct service_struct *service_entry)
{
    if (is_aged_service(service_entry)) {
        tlogi("uuid 0x%x is aged, ref_cnt: %d\n", service_entry->property.uuid.timeLow, service_entry->ref_cnt);
        process_release_service(service_entry, TA_REGION_RELEASE);
    }
    return;
}

void age_timeout_lib(void)
{
    struct service_struct *service_entry = NULL;

    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        if (service_entry->lib_list_head.next == NULL)
            continue;

        do_age_timeout_lib(service_entry);
    }
}

TEE_Result age_service(void)
{
    struct service_struct *service_entry     = NULL;
    struct service_struct *service_entry_tmp = NULL;

    dlist_for_each_entry_safe(service_entry, service_entry_tmp, &g_service_head, struct service_struct, service_list) {
        if (service_entry->is_service_dead)
            continue;
        // builtin TA no need to age
        if (is_build_in_service(&service_entry->property.uuid))
            continue;

        // non keepalive, session count is 0; keepalive, session count is 0, first_open is true; we age it
        if (service_entry->session_count == 0 &&
            (!service_entry->property.keep_alive || service_entry->first_open))
                do_age_service(service_entry);
    }

    return TEE_SUCCESS;
}

void recycle_srvc_thread(struct service_struct *service)
{
    if (service == NULL) {
        tloge("service is null!\n");
        return;
    }

    if (service->service_thread != 0) {
        /*
         * gtask directly set TA process as zombie,
         * in case of service thread of TA is blocked and won't exit by itself
         */
        if (kill((int)taskid_to_pid(service->service_thread), 0) == 0)
            gt_wait_process(service->service_thread);
        service->service_thread = 0;
        /* send msg to internal service */
        task_adapt_ta_release(&service->property.uuid);
    }
}

void process_release_service(struct service_struct *service, uint32_t if_reuse_elf)
{
    if (service == NULL) {
        tloge("service is null!\n");
        return;
    }

    // for non-builtin TA, elf has be released when open session success.
    if (service->elf_state == ELF_EXIST) {
        if (sre_release_dynamic_region(&service->property.uuid, if_reuse_elf) != 0)
            tloge("release elf failed\n");
    }

    /* if TA's dyn conf has been registed, we should unregist that */
    if (service->is_dyn_conf_registed) {
        unregister_conf(uninstall_drvcall_permission, &service->property.uuid, sizeof(service->property.uuid));
        service->is_dyn_conf_registed = false;
    }

    release_timer_event(&service->property.uuid);
    recycle_srvc_thread(service);
    tee_delete_all_libinfo(service);
    dlist_delete(&service->service_list);
    clear_bitmap(g_service_index_map, SERVICE_INDEX_MAX, service->index);
    tlogd("release service: %s, service index is %d\n", service->name, service->index);
    if (service->property.other_buff != NULL) {
        TEE_Free(service->property.other_buff);
        service->property.other_buff = NULL;
    }
    TEE_Free(service);
}

/* for internal service, such as SSA, we only release session node */
static void create_internal_task_fail(void)
{
    if (g_cur_session != NULL) {
        if (g_cur_service != NULL) {
            CLR_BIT(g_cur_service->session_bitmap[get_index_by_uint32(g_cur_session->session_id - 1)],
                    get_bit_by_uint32(g_cur_session->session_id - 1));
            g_cur_service->session_count--;
        }
        release_pam_node(g_cur_session->pam_node);
        dlist_delete(&g_cur_session->session_list);
        TEE_Free(g_cur_session);
        g_cur_session = NULL;
    }
}

/* init this secure call's context and set the cmd and cmd_type to the current session */
TEE_Result start_internal_task(const TEE_UUID *uuid, uint16_t task_prio, const char *task_name, uint32_t *task_id)
{
    TEE_Result ret;
    struct session_struct *session = (struct session_struct *)NULL;
    uint32_t session_id;
    int32_t index;
    struct tsk_init_param task_param;

    if (task_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    index = find_service(uuid, 0, &g_cur_service);
    tlogd(" SS Agent handle = %d\n", index);
    if (index <= 0) {
        tloge("Service not found!\n");
        return TEE_ERROR_GENERIC;
    }

    ret = add_new_session_into_list(&session, &session_id, 0);
    if (ret != TEE_SUCCESS)
        return ret;

    g_cur_service->session_count++;

    /* Init task parameters */
    task_param.task_prior = task_prio;
    task_param.task_name  = task_name;
    task_param.que_num    = DEFAULT_MSG_QUEUE_NUM;

    if (memcpy_s(&task_param.uuid, sizeof(task_param.uuid), &(g_cur_service->property.uuid), sizeof(TEE_UUID)) != EOK) {
        tloge("copy uuid failed\n");
        ret = TEE_ERROR_GENERIC;
        goto create_task_fail;
    }

    /* Create task */
    int sre_ret = sre_task_create(&task_param, task_id);
    if (sre_ret != 0) {
        tloge("create task fail : errorno = 0x%x\n", sre_ret);
        ret = TEE_ERROR_GENERIC;
        goto create_task_fail;
    }

    session->task_id  = *task_id;

    session->cmd_type = CMD_TYPE_SECURE_TO_SECURE;
    return ret;

create_task_fail:
    create_internal_task_fail();
    return ret;
}

TEE_Result release_ion_empty_service(const TEE_UUID *uuid)
{
    struct service_struct *service_context = NULL;
    if (uuid == NULL) {
        tloge("uuid is null\n");
        return TEE_ERROR_GENERIC;
    }
    if (find_service(uuid, 0, &service_context) == -1)
        return TEE_SUCCESS;

    if (service_context->session_count == 0 && service_context->ref_cnt == 0) {
        if (!is_build_in_service(uuid)) {
            if (!service_context->property.keep_alive) {
                process_release_service(service_context, TA_REGION_RELEASE);
                service_context = NULL;
                tlogi("release third party ta success\n");
            }
        }
    } else {
        tloge("UUID: %x session count =%u, ref cnt=%d\n", uuid->timeLow,
              service_context->session_count, service_context->ref_cnt);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

#ifdef CONFIG_ENABLE_DUMP_SRV_SESS
static void dump_agent_info(const struct agent_control *agent, const char *prefix_str)
{
    struct session_struct *sess_context = NULL;

    tlogi("%s    agent id: 0x%x, locked: %u, size: %u\n",
        prefix_str, agent->id, (uint32_t)agent->locked, agent->size);
    tlogi("%s    waiting_sessions: %s\n", prefix_str, (dlist_empty(&agent->waiting_sessions) ? "(empty)" : ""));
    dlist_for_each_entry(sess_context, &agent->waiting_sessions, struct session_struct, waiting_agent)
        tlogi("%s        session name: %s, id: 0x%x, task_id: 0x%x\n", prefix_str,
            sess_context->name, sess_context->session_id, sess_context->task_id);
}

#define MAX_PREFIX 12
#define PREFIX_PER_DEPTH 4
static void dump_session_info(const struct session_struct *sess_context, int depth)
{
    struct session_struct *child_sess = NULL;
    struct agent_control *agent = NULL;

    /* base session infos */
    int prefix_len = depth * PREFIX_PER_DEPTH;
    if (prefix_len > MAX_PREFIX)
        return;
    char prefix_str[MAX_PREFIX + 1] = "            ";
    prefix_str[prefix_len] = '\0';
    tlogi("%ssession name: %s, sess_id: 0x%x, task_id: 0x%x, login_method: 0x%x,\n", prefix_str,
        sess_context->name, sess_context->session_id, sess_context->task_id,
        sess_context->login_method);
    tlogi("%sta2ta_from_taskid: 0x%x, cancelable: %u, agent_pending: 0x%x, ta2ta_level: %u, cmd_type: %u,\n",
        prefix_str, sess_context->ta2ta_from_taskid, (uint32_t)sess_context->cancelable,
        (uint32_t)sess_context->agent_pending, sess_context->ta2ta_level, sess_context->cmd_type);
    tlogi("%swait_ta_back_msg: 0x%x, session_status: 0x%x\n", prefix_str,
        (uint32_t)sess_context->wait_ta_back_msg, sess_context->session_status);

    /* agents */
    tlogi("%slocked_agents: %s\n", prefix_str, (dlist_empty(&sess_context->locked_agents) ? "(empty)" : ""));
    dlist_for_each_entry(agent, &sess_context->locked_agents, struct agent_control, session_list)
        dump_agent_info(agent, prefix_str);

    /* child session info */
    tlogi("%schild sessions: %s\n", prefix_str, (dlist_empty(&sess_context->child_ta_sess_head) ? "(empty)" : ""));
    dlist_for_each_entry(child_sess, &sess_context->child_ta_sess_head, struct session_struct, child_ta_sess_list)
        dump_session_info(child_sess, depth + 1);
}

TEE_Result dump_service_session_info(const smc_cmd_t *cmd)
{
    TEE_Result ret = TEE_SUCCESS;
    struct service_struct *service_entry = NULL;
    struct lib_info *libinfo = NULL;
    struct session_struct *sess_context  = NULL;
    (void)cmd;

    tlogi("dump all services:\n");
    dlist_for_each_entry(service_entry, &g_service_head, struct service_struct, service_list) {
        /* base info */
        tlogi("service index: %u, name: %s\n", service_entry->index, service_entry->name);
        tlogi("ref_cnt: %d, init_build: %u, first_open: %d, ta_64bit: %d, is_dead: %d, elf_state: 0x%x,",
            service_entry->ref_cnt, service_entry->init_build, (int32_t)service_entry->first_open,
            (int32_t)service_entry->ta_64bit,
            (int32_t)service_entry->is_service_dead, service_entry->elf_state);
        tlogi("service_thread: 0x%x, load elf time: %u.%us\n", service_entry->service_thread,
            service_entry->load_elf_time.seconds, service_entry->load_elf_time.millis);

        /* lib info */
        libinfo = service_entry->lib_list_head.next;
        tlogi("libs : %s\n", (libinfo == NULL ? "(empty)" : ""));
        while (libinfo != NULL) {
            tlogi("    libname: %s, load_elf_time: %u.%us, type: 0x%x\n", libinfo->name, libinfo->load_elf_time.seconds,
                libinfo->load_elf_time.millis, (uint32_t)libinfo->type);
            libinfo = libinfo->next;
        }

        /* session info */
        tlogi("session count: %u \n", service_entry->session_count);
        dlist_for_each_entry(sess_context, &service_entry->session_head, struct session_struct, session_list)
            dump_session_info(sess_context, 1);
        tlogi("\n");
    }

    return ret;
}
#endif

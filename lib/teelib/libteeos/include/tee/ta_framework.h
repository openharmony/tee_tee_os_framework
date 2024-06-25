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

#ifndef __TA_FRAMWORK_H_
#define __TA_FRAMWORK_H_

#include <mem_page_ops.h>

#include "tee_defines.h"
#include "tee_common.h"
#include "tee_time_api.h"
#include "tee_core_api.h"
#include "ipclib.h"

#define TA_SESSION_MAX 8 /* concurrent opened session count */
#define TA_STACK_MAX 5   /* we limit ta memory to heap_size + stack_size * 5 to compatible with the old version */

#define TASK_INVALID_HANDLE ((uint32_t)0xffffffff)

#define GLOBAL_SERVICE_NAME "TEEGlobalTask"
#define GLOBAL_HANDLE 0U

#define SSA_SERVICE_NAME "task_ssa"

#define PERM_SERVICE_NAME "task_permservice"
#define BIO_TASK_NAME "task_bioservice"
#define ROT_TASK_NAME "task_rotservice"
#define ART_TASK_NAME "task_artservice"
#define SE_TASK_NAME "task_seservice"
#define HSM_TASK_NAME "task_hsmservice"
#define SEM_TASK_NAME "sem_task"
#define VLTMMSRV_TASK_NAME "task_vltmm_service"
#define HUK_TASK_NAME "task_hukservice"
#define CRYPTO_AGENT_TASK_NAME "task_cryptoagent_service"
#define TEST_SERVICE_TASK_NAME "test_service"
#define TEST_SERVICE_TASK_NAME_A64 "test_service_a64"

#define TEE_PARAM_NUM 4 /* TA input param nums: TEE_Param[4] */

/* add for gtask send msg to service thread begin */
/* sizeof 'struct remove_thread_msg' should smaller than NOTIFY_MAX_LEN */
#define HANDLE_MAX ((NOTIFY_MAX_LEN - 3 * sizeof(uint32_t)) / sizeof(int))
struct remove_thread_msg {
    uint32_t tid;
    uint32_t session_id;
};

#define compile_time_assert(cond, msg) typedef char assert_##msg[(cond) ? 1 : -1]

compile_time_assert(sizeof(struct remove_thread_msg) <= NOTIFY_MAX_LEN, size_of_remove_thread_msg_too_large);

struct create_thread_msg {
    uint64_t stack_size;
};

struct global_to_service_thread_msg {
    union {
        struct remove_thread_msg remove_msg;
        struct create_thread_msg create_msg;
    };
};

enum smc_cmd_type {
    CMD_TYPE_GLOBAL,
    CMD_TYPE_TA,
    CMD_TYPE_TA_AGENT,
    CMD_TYPE_TA2TA_AGENT, /* compatible with TA2TA2TA->AGENT etc. */
    CMD_TYPE_BUILDIN_AGENT,
};

/* add for gtask send msg to service thread end */
typedef struct {
    uint8_t uuid[sizeof(TEE_UUID)];
    unsigned int cmd_type; /* refer to smc_cmd_type */
    unsigned int cmd_id;
    unsigned int dev_file_id;
    unsigned int context; /* high_16bits is service_index, low16_bits is session_id */
    unsigned int agent_id;
    unsigned int operation_phys;
    unsigned int operation_h_phys;
    unsigned int login_method;
    unsigned int login_data_phy;
    unsigned int login_data_h_phy;
    unsigned int login_data_len;
    unsigned int err_origin;
    unsigned int ret_val;
    unsigned int event_nr;
    unsigned int uid;
    unsigned int ca_pid;
    unsigned int pid;
    unsigned int eventindex;
    bool started;
} __attribute__((__packed__)) smc_cmd_t;

#define SERVICE_NAME_MAX 100

#define AGENT_BUFF_SIZE (4 * 1024)
// agent id
#define TEE_FS_AGENT_ID 0x46536673      /* FSfs */
#define TEE_MISC_AGENT_ID 0x4d495343    /* MISC */
#define TEE_SOCKET_AGENT_ID 0x69e85664  /* socket */
#define TEE_SECLOAD_AGENT_ID 0x4c4f4144 /* SECFILE-LOAD-AGENT */
#define TEE_VLTMM_AGENT_ID 0x564c544d   /* agent for vltmm service */

struct ta_property {
    TEE_UUID uuid;
    uint32_t stack_size;
    uint32_t heap_size;
    bool single_instance;
    bool multi_session;
    bool keep_alive;
    bool ssa_enum_enable;
    char *other_buff;   // TA's non-std property
    uint32_t other_len; // non-std propery buff len
};


// data for async call
struct notify_context_timer {
    uint32_t dev_id;
    TEE_UUID uuid;
    uint32_t session_id;
    TEE_timer_property property;
    uint32_t expire_time;
};

struct notify_context_wakeup {
    uint32_t ca_thread_id;
};

struct notify_context_shadow {
    uint64_t target_tcb;
};

struct notify_context_shadow_exit {
    uint32_t ca_thread_exit;
};

struct notify_context_meta {
    uint32_t send_s;
    uint32_t recv_s;
    uint32_t send_w;
    uint32_t recv_w;
    uint32_t missed; /* type of missed notifications */
};

union notify_context {
    struct notify_context_timer timer;
    struct notify_context_wakeup wakeup;
    struct notify_context_shadow shadow;
    struct notify_context_shadow_exit shadow_exit;
    struct notify_context_meta meta;
};

struct notify_data_entry {
    uint32_t entry_type : 31;
    uint32_t filled : 1;
    union notify_context context;
};

#define NOTIFY_DATA_ENTRY_COUNT ((PAGE_SIZE / sizeof(struct notify_data_entry)) - 1)

struct notify_data_struct {
    struct notify_data_entry entry[NOTIFY_DATA_ENTRY_COUNT];
    struct notify_data_entry meta;
};

enum notify_data_type {
    NOTIFY_DATA_ENTRY_UNUSED,
    NOTIFY_DATA_ENTRY_TIMER,
    NOTIFY_DATA_ENTRY_RTC,
    NOTIFY_DATA_ENTRY_WAKEUP,
    NOTIFY_DATA_ENTRY_SHADOW,
    NOTIFY_DATA_ENTRY_FIQSHD,
    NOTIFY_DATA_ENTRY_SHADOW_EXIT,
    NOTIFY_DATA_ENTRY_MAX,
};

enum TA_VERSION {
    TA_SIGN_VERSION = 1,    /* first version */
    TA_RSA2048_VERSION = 2, /* use rsa 2048, and use right crypt mode */
    CIPHER_LAYER_VERSION = 3,
    TA_THIRD_VERSION = 9,
    TA_SIGN_VERSION_MAX
};

// global call TA entrypoit cmd
#define CALL_TA_DEFAULT_CMD 0x0
#define CALL_TA_OPEN_SESSION 0x11
#define CALL_TA_INVOKE_CMD 0x12
#define CALL_TA_CLOSE_SESSION 0x13
#define CALL_TA_OPEN_SESSION_INIT 0x17
#define CALL_TA_OPEN_SESSION_PROP 0x18
#define CALL_TA_CREATE_THREAD 0x19
#define CALL_TA_REMOVE_THREAD 0x22
#define CALL_TA_STHREAD_EXIT 0x23

#define TA2TA_CALL 0x41
#define MSG_ABORT_VALUE 0xf0
#define TEE_PANIC_VALUE 0xf1
#define MSG_SRE_AUDIT_TRIGER 0xf2
#define TA_GET_AGENT_BUFFER 0x20
#define TA_CALL_AGENT 0x21
#define TA_LOCK_AGENT 0x22
#define TA_UNLOCK_AGENT 0x23
#define TA_GET_REEINFO 0x24
#define TA_GET_CALLERINFO 0x25

#define TA_LOCK_ACK 0x29
#define BINDER_SERVICE 0x2d
#define UNBINDER_SERVICE 0x2e
#define TEE_SERVICE_ACK 0x2f
#define TEE_SEC_NEED_LOAD 0x30
#define TEE_UNLINK_LIB 0x31
#define TEE_UNLINK_DYNAMIC_DRV 0x32
#define TEE_UNREGISTER_SERVICE 0x2007

#define REGISTER_ELF_REQ 0x3E

#define TEE_MAX_API_LEVEL_CONFIG ((CIPHER_LAYER_VERSION << 16) | API_LEVEL1_2)

struct global_to_ta_msg {
    uint32_t session_id;
    uint32_t session_type;
    uint32_t cmd_id;
    uint32_t param_type;
    TEE_Param *params;
    void *session_context;
    uint32_t dev_id;
    char first_session;
    char last_session;
    bool started;
    uint32_t stack_size;
    TEE_Result ret;
};

struct ta_to_global_msg {
    TEE_Result ret;
    uint32_t agent_id;
    void *session_context;
    uint32_t ta2ta_from_taskid;
};

struct global_to_ta_for_uid {
    uint32_t userid;
    uint32_t appid;
    uint32_t cmd_id;
    uint32_t reserved;
};

struct ta_init_msg {
    void *fs_mem;   /* fs agent share mem */
    void *misc_mem; /* misc agent share mem */
    struct ta_property prop;
    uint32_t login_method;
    void *time_data;
    TEE_Time sys_time;
    uint32_t rtc_time;
};

struct ta2ta_ret_msg {
    TEE_Result ret;
    uint32_t origin;
    TEE_TASessionHandle session;
    smc_cmd_t cmd;
};

struct ta2ta_msg {
    TEE_Result ret;
    TEE_TASessionHandle handle;
    uint64_t session_context; /* no use */
    uint64_t cmd;             /* this correspond to the pointer of smc_cmd_t cmd */
    bool is_load_worked;      /* indicate if sec file agent has worked */
};

#define MAX_NAME_LEN 31
struct tee_srvc_send_msg {
    char srvc_name[MAX_NAME_LEN + 1];
};
#endif

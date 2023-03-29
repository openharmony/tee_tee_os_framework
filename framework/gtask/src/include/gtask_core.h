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
#ifndef __GTASK_CORE_H_
#define __GTASK_CORE_H_

#include <dlist.h>
#include <ta_lib_img_unpack.h>
#include "gtask_msg.h"
#include <tee_secfile_load_agent.h>

#define MAX_STACK_SIZE (8 * 1024 * 1024)

#define MAX_TA2TA_LEVEL      1
#define UINT32_BIT_NUM       32

#define get_index_by_uint32(n) ((n) / (UINT32_BIT_NUM))
#define get_bit_by_uint32(n)   ((n) - ((get_index_by_uint32(n)) * (UINT32_BIT_NUM)))

typedef union {
    struct {
        unsigned int buffer;
        unsigned int size;
    } memref;
    struct {
        unsigned int a;
        unsigned int b;
    } value;
    struct {
        unsigned int buffer;
        unsigned int size;
    } sharedmem;
} tee_param_32;

typedef union {
    struct {
        uint64_t buffer;
        uint64_t size;
    } memref;
    struct {
        unsigned int a;
        unsigned int b;
    } value;
    struct {
        uint64_t buffer;
        uint64_t size;
    } sharedmem;
} tee_param_64;

struct tee_operation_g32 {
    uint32_t p_type;
    tee_param_32 p[TEE_PARAM_NUM];
    uint32_t p_h_addr[TEE_PARAM_NUM];
};

typedef struct tee_operation_g32 tee_operation_gtask;

union tee_param_gt {
    tee_param_32 *param_32;
    tee_param_64 *param_64;
};

struct pam_node {
    tee_operation_gtask op;
    bool param_type;                     /* indicate gtask mapped to TA's type: true--64bit false--32bit */
    void *p_for_ta;                      /* gtask malloc it */
    void *p_vaddr_gt_tee[TEE_PARAM_NUM]; /* virt tee mem addr of param mems mapping for gt */
    void *p_vaddr_gt_ree[TEE_PARAM_NUM]; /* virt ree mem addr of param mems mapping for gt */
};

enum secfile_type_t {
    LOAD_TA = 0,
    LOAD_SERVICE,
    LOAD_LIB,
    LOAD_DYNAMIC_DRV,
    LOAD_PATCH,
    LOAD_TYPE_MAX,
};

struct lib_info {
    char name[LIB_NAME_MAX];
    struct lib_info *next;
    TEE_Time load_elf_time;
    tee_img_type_t type;
};

#define SESSION_ID_LEN 8
struct session_struct {
    struct dlist_node session_list;
    uint32_t task_id;
    uint32_t session_id;
    uint64_t session_context;
    uint32_t login_method;
    char name[SERVICE_NAME_MAX + SESSION_ID_LEN]; /* for task name = "service_name + session_id" */
    uint32_t ta2ta_from_taskid;                   /* creator of internal session when TA call TA */
    bool cancelable;                              /* dedicate if this session is calling cacnelable func(TEE_Wait) */
    bool agent_pending;
    /* A list of locks of agents */
    struct dlist_node locked_agents;
    /* Place on waiting list for the agent */
    struct dlist_node waiting_agent;
    uint32_t cmd_type; /* Cmd type, n->s or s->s */
    smc_cmd_t *cmd;    /* Pointer to cmd that will be contain the answer */
    smc_cmd_t cmd_in;  /* Incomming smc cmd copy */
    void *oper_addr;         /* virt addr of ns op's mem */
    struct pam_node *pam_node;     /* pam node corresponding to one ns op */
    struct dlist_node map_mem;     /* map mem, ns->gtask or gtask -> TA */
    uint32_t ta2ta_level;    /* indicate while level in ta2ta */
    int ta2ta_handle;        /* ta2ta_handle in tee_core_api.c */
    bool wait_ta_back_msg; /* filter duplicate msg from ta */
    int32_t session_status;
    struct dlist_node child_ta_sess_head;
    struct dlist_node child_ta_sess_list;
};

#define ELF_NOT_EXIST 0
#define ELF_EXIST     1

struct service_struct {
    struct dlist_node service_list;
    char name[SERVICE_NAME_MAX];
    struct ta_property property; /* other_buff is malloced by gtask */
    uint32_t index;
    struct dlist_node session_head;
    int ref_cnt; /* indicate the number of ca or ta which lock this service */
    uint32_t session_count;
    /* if we use more than 32 sessions , we should use more u32 bitmap */
    uint32_t session_bitmap[TA_SESSION_MAX / UINT32_BIT_NUM + 1];
    uint32_t init_build;     /* for call cinit00 1 service 1 time */
    uint32_t elf_state;      /* indicating if elf is exist */
    uint32_t service_thread; /* service thread task_id */
    smc_cmd_t cmd_in;        /* Incomming smc cmd copy, it will be only used by gtask */
    bool ta_64bit;           /* true: TA is 64bit; false: TA is 32bit */
    bool first_open;         /* indicate if it's the first time for this serivice to open session */
    struct lib_info lib_list_head;
    TEE_Time load_elf_time;
    bool is_service_dead;    /* true: TA has exception */
    bool is_dyn_conf_registed; /* true: dyn conf has been registed */
    tee_img_type_t img_type;
};

struct aescbc_info {
    uint8_t *in;
    uint32_t in_len;
    uint8_t *out;
    uint32_t out_len;
    uint8_t *key;
};

struct pagelist_info {
    uint64_t page_num;
    uint64_t page_size;
    uint64_t sharedmem_offset;
    uint64_t sharedmem_size;
};

struct session_struct *find_session_by_ca_pid(uint32_t ca_pid, struct service_struct **service,
                                              struct session_struct **session);
void process_release_service_for_reuse(struct service_struct *service);
void gt_wait_process(uint32_t task_id);
#endif

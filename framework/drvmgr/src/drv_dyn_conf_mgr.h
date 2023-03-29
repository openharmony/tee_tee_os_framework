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

#ifndef DRVMGR_DRV_DYN_CONF_MGR_H
#define DRVMGR_DRV_DYN_CONF_MGR_H

#include <pthread.h>
#include <dlist.h>
#include <tee_defines.h>
#include <tee_drv_internal.h>
#include "dyn_conf_common.h"
#include "task_mgr.h"

struct task_node;

#define MAX_UUID_SIZE 36
#define MAX_CMD_SIZE 40
#define CMD_SET_FLAG 1

enum drv_receive_list_tag {
    RECEIVE_IO_MAP_LIST = 1,
    RECEIVE_IRQ_LIST,
    RECEIVE_MAP_SECURE_LIST,
    RECEIVE_MAP_NOSECURE_LIST,
    RECEIVE_MAC_INFO_LIST,
    RECEIVE_CMD_PERM_LIST,
    RECEIVE_MAX_TAG
};

struct addr_region_t {
    uint64_t start;
    uint64_t end;
};

struct drv_basic_info_t {
    uint32_t thread_limit;
    bool upgrade;
    bool virt2phys;
    uint8_t exception_mode;
};

struct drv_map_secure_t {
    struct tee_uuid uuid;
    struct addr_region_t region;
};

struct drv_map_nosecure_t {
    struct tee_uuid uuid;
};

struct drv_mac_info_t {
    struct tee_uuid uuid;
    uint64_t perm;
};

struct drv_conf_t {
    struct drv_mani_t mani;
    struct drv_basic_info_t drv_basic_info;
    union {
        struct addr_region_t *io_map_list;
        uint64_t tmp_io_map;
    };
    union {
        uint64_t *irq_list;
        uint64_t tmp_irq;
    };
    union {
        struct drv_map_secure_t *map_secure_list;
        uint64_t tmp_map_secure;
    };
    union {
        struct drv_map_nosecure_t *map_nosecure_list;
        uint64_t tmp_nosecure;
    };
    union {
        struct drv_mac_info_t *mac_info_list;
        uint64_t tmp_mac_info;
    };
    union {
        struct drv_cmd_perm_info_t *cmd_perm_list;
        uint64_t tmp_cmd_perm;
    };
    uint16_t io_map_list_size;
    uint16_t io_map_list_index;
    uint16_t irq_list_size;
    uint16_t irq_list_index;
    uint16_t map_secure_list_size;
    uint16_t map_nosecure_list_size;
    uint16_t map_nosecure_list_index;
    uint16_t mac_info_list_size;
    uint16_t mac_info_list_index; /* the index of the newest ava mac */
    uint16_t cmd_perm_list_size;
    uint16_t cmd_perm_list_index; /* the index of the newest cmd perm */
};

struct drv_conf_list_t {
    struct dlist_node list;
    pthread_mutex_t lock;
};

struct drv_tlv {
    struct tee_uuid uuid;
    struct drvcall_perm_apply_t drvcall_perm_apply;
    struct drv_conf_t drv_conf;
};

enum drv_error {
    DRV_FAIL = -1,
    DRV_SUCC = 0,
    DRV_NEED_SPAWN,
    DRV_WAIT,
};

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
void dump_drv_conf(const struct drv_conf_t *drv_conf);
#endif

void broadcast_drv_state(struct task_node *node, bool spawn_succ);
int32_t check_drv_node_state(struct task_node *node);
int32_t do_receive_drv_conf(struct drv_conf_t *drv_conf);
void free_drv_conf_list(struct drv_conf_t *drv_conf, uint32_t receive_flag);

#endif

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
#ifndef DYN_CONF_MGR_DYN_CONF_DISPATCH_INF_H
#define DYN_CONF_MGR_DYN_CONF_DISPATCH_INF_H

#include <stdint.h>
#include <dlist.h>
#include <tee_defines.h>

#define MAX_IMAGE_LEN 0x800000
/* tag(DYN_CONF_TAG_LEN) | type(DYN_CONF_TYPE_LEN) | len(DYN_CONF_LEN_LEN) | value */
#define DYN_CONF_TAG_LEN  3
#define DYN_CONF_TYPE_LEN 1
#define DYN_CONF_LEN_LEN  4
#define DYN_CONF_TAG_MAX  0xffffffff
#define DYN_CONF_TYPE_MAX 0xffffffff
/* dyn conf must start with gpd.ta.dynConf */
#define DYN_CONF_START    "gpd.ta.dynConf"
/* the types dyn conf support */
#define TYPE_CLASS 0
#define TYPE_BOOL 1
#define TYPE_INT 2
#define TYPE_CHAR 3
/* use to parse str special sym */
#define LEN_OF_HEX_TRIM   2 /* the length of 0x */
#define BIT_NUM_OF_UINT64 64
#define BASE_OF_TEN       10
#define BASE_OF_HEX       16
#define MAX_UINT64_LEN    20 /* the max length of an uint64 num str */
#define MAX_UINT32_LEN    10 /* the max length of an uint32 num str */

#define MAX_UINT64_HEX_LEN 16 /* the max length of an uint64 hex num str */

#define THREAD_LIMIT_MAX      8
#define DRV_CMD_MAX           0xffffffff
#define IRQ_MIN               32

#define MAX_UUID_SIZE 36

#define UUID_TIMELOW_LEN 8
#define UUID_TIMEMID_LEN 4
#define UUID_HIVERSION_LEN 4
#define UUID_SEQ_LEN 2

#define UUID_STRUCT_LEN 11
#define TIMELOW_MAX     0xFFFFFFFF
#define TIMEMID_MAX     0xFFFF
#define TIMESEQ_MAX     0xFF
#define UUID_SEQ_SIZE   8
#define TLV_TRUE        '1'

enum dyn_conf_exception_modes {
    DYN_CONF_SYSCRASH_TAG = 0,
    DYN_CONF_RESTART_TAG,
    DYN_CONF_DDOS_TAG,
};

enum dyn_conf_data_nums {
    DATA_TIMELOW_IDX = 0,
    DATA_TIMEMID_IDX,
    DATA_HVER_IDX,
};

/* the struct we use in queue */
struct conf_node_t {
    struct dlist_node head;
    uint32_t tag;
    uint32_t type;
    uint32_t size;
    const char *value;
};

struct conf_queue_t {
    struct dlist_node queue;
};

/* load the dyn conf from mani_ext section in sec file */
struct dyn_conf_t {
    uint32_t dyn_conf_size;
    char *dyn_conf_buffer;
};

typedef int32_t (*handler_conf_to_obj)(struct dlist_node **, const struct conf_node_t *, void *, uint32_t);
typedef int32_t (*handler_install_obj)(void *, uint32_t, const struct conf_queue_t *);
typedef void (*handler_uninstall_obj)(const void *, uint32_t);
typedef int32_t (*handler_check_obj)(const void *);

int32_t register_conf(const struct dyn_conf_t *dyn_conf, handler_install_obj handle, void *obj, uint32_t obj_size);
void unregister_conf(handler_uninstall_obj uninstall_obj_func, void *obj, uint32_t obj_size);
uint16_t get_num_of_tag(const struct conf_queue_t *conf_queue, uint32_t tag);
int32_t handle_conf_node_to_obj(struct dlist_node **pos, handler_conf_to_obj handle, void *obj, uint32_t obj_size);
int32_t trans_str_to_int(const char *buff, uint32_t len, uint32_t base, uint64_t *num);
int32_t check_item_chip_type(const struct dlist_node *now, uint32_t chip_type_tag);
int32_t tlv_to_uuid(const char *uuid_buff, uint32_t size, struct tee_uuid *uuid);

struct dyn_conf_build_func {
    uint32_t tag;
    handler_conf_to_obj handle;
    handler_check_obj checker;
};
#endif

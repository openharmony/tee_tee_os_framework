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
#ifndef TEE_CONFIG_H
#define TEE_CONFIG_H

#include <ta_framework.h>

#define DEFAULT_STACK_SIZE    0x4000
#define DEFAULT_HEAP_SIZE     0x10000

#define DEFAULT_HIVCODEC_STACK_SIZE 0x800
#define DEFAULT_HIVCODEC_HEAP_SIZE 0x800

#define INVALID_DIE_ID_SIZE   0U
#define OTHER_DIE_ID_SIZE     20U
#define M_DIE_ID_SIZE       32U
#define DV_DIE_ID_SIZE    32U
#define DIE_ID_SIZE_MAX       32U /* This value should be equal to the largest DIE_ID_SIZE above */

struct dynamic_mem_uuid_item {
    uint32_t configid;
    uint32_t size;
    TEE_UUID uuid;
    uint32_t ddr_sec_region;
};

enum static_mem_tag {
    MEM_TAG_MIN    = 0,
    PP_MEM_TAG     = 1,   /* general memory */
    PRI_PP_MEM_TAG = 2,   /* private memory of ta */
    PT_MEM_TAG     = 3,   /* private page table of ta */
    MEM_TAG_MAX,
};

struct rsv_mem_pool_uuid_item {
    uint64_t paddr;
    uint32_t size;
    TEE_UUID uuid;
    uint32_t type;
};

typedef struct rsv_pt_mem_uuid_item rsv_pp_mem_uuid_item;

#define PATH_NAME_MAX (SERVICE_NAME_MAX + 5)
struct task_info_st {
    TEE_UUID uuid;
    char name[SERVICE_NAME_MAX];
    char path[PATH_NAME_MAX];
    int priority;
    bool ta_64bit;
};

#define MAX_LIB_NAME_LEN   32
struct drvlib_load_caller_info {
    TEE_UUID uuid;
    char name[MAX_LIB_NAME_LEN];
};

struct drv_frame_info {
    const char *drv_name;
    uint64_t sid;
    uint32_t pid;
    size_t stack_size;
    size_t heap_size;
    struct tee_uuid uuid;
    bool is_elf;
};

uint32_t get_product_service_property_num(void);
const struct ta_property *get_product_service_property_config(void);

uint32_t get_product_dynamic_ta_num(void);

uint32_t get_drv_frame_nums(void);
struct drv_frame_info *get_drv_frame_infos(void);

#endif

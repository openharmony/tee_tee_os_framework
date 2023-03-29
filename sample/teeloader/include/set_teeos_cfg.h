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

#ifndef TEE_LOADER_SET_TEEOS_CFG_H
#define TEE_LOADER_SET_TEEOS_CFG_H

#include <stdint.h>
#include <stdbool.h>

#define teelog(fmt, args...)

typedef struct p_reg {
    uint64_t start;
    uint64_t end;
} p_region_t;

#ifndef  PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define MAX_CONFIG_LENGTH 0x1000

#define GIC_V3_VERSION              3
#define GIC_V2_VERSION              2
#define MAX_PROTECTED_REGIONS       16
#define GICR_MAX_NUM    8
#define PLAT_ENABLE_PAN (1ull << 60)
#define PL011_TYPE         0x101
#define PL011_GENERAL_TYPE 0x102
#define PL011_V500_TYPE    0x103
#define UART_LPC_TYPE      0x201
#define UART_INVALID_TYPE  0xFFFF
#define UART_TYPE_MASK     (32U)

#define UART_ENABLE_FLAG   ((uint64_t)(0x54524155U) << UART_TYPE_MASK)
#define UART_DISABLE_FLAG  ((uint64_t)(0x1234U) << UART_TYPE_MASK)

struct gic_config_t {
    char version;
    union {
        struct v2_t {
            p_region_t dist;
            p_region_t contr;
        } v2;
        struct v3_t {
            p_region_t dist;
            uint32_t redist_num;
            uint32_t redist_stride;
            p_region_t redist[GICR_MAX_NUM];
        } v3;
    };
};

int32_t set_teeos_mem(uintptr_t teeos_base_addr, uint64_t size);
void set_teeos_uart(uint64_t uart_addr, uint64_t uart_type);
bool set_protected_regions(p_region_t *protected_regions, uint32_t regions_num);
void set_sharedmem_size(uint64_t shmem_size);
bool set_random(uint64_t random_data);
void set_gic(struct gic_config_t gic_config);
void set_spi_num(uint32_t spi_num);
void set_plat_features(uint64_t plat_features);
bool copy_extend_datas(void *extend_datas, uint64_t extend_length);
bool copy_teeos_cfg(void);

uint64_t get_teeos_start(void);
uint64_t get_teeos_code_start(void);
uint64_t get_teeos_size(void);
uint64_t get_sharedmem_start(void);
uint64_t get_sharedmem_size(void);

#endif

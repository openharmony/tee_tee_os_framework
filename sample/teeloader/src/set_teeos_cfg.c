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

#include <set_teeos_cfg.h>

#include <securec.h>

#include <teeos_uuid.h>
#include <tlv_sharedmem.h>

#define TEEOS_TEXT_OFFSET (0x8000)
#define ALIGN_SIZE_2M    (0x200000)

struct platform_info {
    uint64_t plat_cfg_size;
    uint64_t phys_region_size;
    uint64_t phys_region_start;
    uint64_t uart_addr;
    uint64_t uart_type;
    p_region_t protected_regions[MAX_PROTECTED_REGIONS];
    uint64_t reserved;
    uint64_t shmem_size;
    uint32_t random_seed;
    struct gic_config_t gic_config;
    uint32_t spi_num_for_notify;
    uint64_t plat_features;
    struct extend_datas_t {
        uint64_t extend_length;
        char extend_paras[0];
    } extend_datas;
};

static struct platform_info g_teeos_cfg;

static uintptr_t g_teeos_base_addr = 0;

int32_t set_teeos_mem(uintptr_t teeos_base_addr, uint64_t size)
{
    g_teeos_base_addr = teeos_base_addr;
    g_teeos_cfg.phys_region_size = size;
    if ((uint64_t)teeos_base_addr % ALIGN_SIZE_2M != 0)
        return -1;

    g_teeos_cfg.phys_region_start = (uint64_t)teeos_base_addr;

    return 0;
}

void set_teeos_uart(uint64_t uart_addr, uint64_t uart_type)
{
    g_teeos_cfg.uart_addr = uart_addr;
    g_teeos_cfg.uart_type = uart_type;
}

bool set_protected_regions(p_region_t *protected_regions, uint32_t regions_num)
{
    if (regions_num > MAX_PROTECTED_REGIONS)
        return false;

    if (protected_regions == NULL)
        return false;

    if (memcpy_s(g_teeos_cfg.protected_regions, sizeof(p_region_t) * regions_num,
                 protected_regions, sizeof(p_region_t) * regions_num) != EOK)
        return false;

    return true;
}

void set_sharedmem_size(uint64_t shmem_size)
{
    g_teeos_cfg.shmem_size   = shmem_size;
}

bool set_random(uint64_t random_data)
{
    if (random_data == 0)
        return false;

    g_teeos_cfg.random_seed = random_data;

    return true;
}

void set_gic(struct gic_config_t gic_config)
{
    g_teeos_cfg.gic_config = gic_config;
}

void set_spi_num(uint32_t spi_num)
{
    g_teeos_cfg.spi_num_for_notify = spi_num;
}

void set_plat_features(uint64_t plat_features)
{
    g_teeos_cfg.plat_features = plat_features;
}

bool copy_extend_datas(void *extend_datas, uint64_t extend_length)
{
    if (extend_datas == NULL)
        return false;

    if (sizeof(struct platform_info) + extend_length > MAX_CONFIG_LENGTH)
        return false;

    g_teeos_cfg.extend_datas.extend_length = extend_length;
    char *dst = (char *)(uintptr_t)(g_teeos_cfg.phys_region_start + sizeof(g_teeos_cfg));

    if (memcpy_s(dst, MAX_CONFIG_LENGTH - sizeof(g_teeos_cfg),
                 extend_datas, extend_length) != EOK)
        return false;

    return true;
}

bool copy_teeos_cfg(void)
{
    if (g_teeos_cfg.phys_region_start == 0)
        return false;

    g_teeos_cfg.plat_cfg_size = sizeof(struct platform_info) + g_teeos_cfg.extend_datas.extend_length;
    char *dst = (void *)(uintptr_t)g_teeos_cfg.phys_region_start;

    if (memcpy_s(dst, sizeof(g_teeos_cfg),
                 (char *)&g_teeos_cfg, g_teeos_cfg.plat_cfg_size - sizeof(uint64_t)) != EOK)
        return false;

    return true;
}

uint64_t get_teeos_start(void)
{
    return g_teeos_cfg.phys_region_start;
}

uint64_t get_teeos_code_start(void)
{
    return g_teeos_cfg.phys_region_start + TEEOS_TEXT_OFFSET;
}

uint64_t get_teeos_size(void)
{
    return g_teeos_cfg.phys_region_size;
}

uint64_t get_sharedmem_start(void)
{
    return g_teeos_cfg.phys_region_start + g_teeos_cfg.phys_region_size - g_teeos_cfg.shmem_size;
}

uint64_t get_sharedmem_size(void)
{
    return g_teeos_cfg.shmem_size;
}

#define CHIP_TYPE_TAG "chip_type"
#define CHIP_TYPE_LEN_MAX 32
int32_t set_chip_type_info(char *chip_type, uint32_t size)
{
    TEE_UUID all_service = TEE_SERVICE_ALL;
    struct tlv_item_data tlv_item_data;
    char chip_type_tmp[CHIP_TYPE_LEN_MAX] = {0};

    if (memcpy_s(chip_type_tmp, CHIP_TYPE_LEN_MAX,
                 chip_type, (size > CHIP_TYPE_LEN_MAX) ? CHIP_TYPE_LEN_MAX : size) != EOK ) {
        teelog("copy to chip_type_tmp failed\n");
        return -1;
    }

    tlv_item_data.type = CHIP_TYPE_TAG;
    tlv_item_data.type_size = strlen(CHIP_TYPE_TAG);
    tlv_item_data.owner_list = (void *)&all_service;
    tlv_item_data.owner_len = sizeof(TEE_UUID);
    tlv_item_data.value = chip_type;
    tlv_item_data.value_len = size;

    if (put_tlv_shared_mem(tlv_item_data) != 0) {
        teelog("put chip_type info failed\n");
        return -1;
    }

    return 0;
}

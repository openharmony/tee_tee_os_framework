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
#ifndef DRIVERS_BOOT_SHAREDMEM_H
#define DRIVERS_BOOT_SHAREDMEM_H

#define TEEOS_SHAREDMEM_MODULE_SIZE_256    256
#define TEEOS_SHAREDMEM_MODULE_SIZE_512    512
#define TEEOS_SHAREDMEM_MODULE_SIZE_4K     0x1000
#define TEEOS_SHAREDMEM_MODULE_SIZE_128K   0x20000

#define TEEOS_SHAREDMEM_OFFSET_MODEM         0x0F00
#define TEEOS_SHAREDMEM_OFFSET_FINGERPRINT   0x0E00
#define TEEOS_SHAREDMEM_OFFSET_ROOTSTATUS    0x0D00
#define TEEOS_SHAREDMEM_OFFSET_ESE           0x0C00
#define TEEOS_SHAREDMEM_OFFSET_COLORLOCK     0x0A00
#define TEEOS_SHAREDMEM_OFFSET_DSS           0x0900
#define TEEOS_SHAREDMEM_OFFSET_MAILBOX       0x0800
#define TEEOS_SHAREDMEM_OFFSET_SKYTONE       0x0700
#define TEEOS_SHAREDMEM_OFFSET_NOMAP         0x0600
#define TEEOS_SHAREDMEM_OFFSET_TBIMGINFO     0x0400
#define TEEOS_SHAREDMEM_OFFSET_ES_CS         0x0300
#define TEEOS_SHAREDMEM_OFFSET_SECFLASH      0x0200
#define TEEOS_SHAREDMEM_OFFSET_SPI_DMA_BUF   0x0100
#define TEEOS_SHAREDMEM_OFFSET_CERTKEY       0x1000
#define TEEOS_SHAREDMEM_OFFSET_MEMORY_SGLIST 0x21000
enum sharedmem_types {
    TEEOS_SHARED_MEM_SECBOOT = 0,
    TEEOS_SHARED_MEM_FINGERPRINT = 1,
    TEEOS_SHARED_MEM_ROOT_STATUS = 2,
    TEEOS_SHARED_MEM_ESE = 3,
    TEEOS_SHARED_MEM_COLORLOCK = 4,
    TEEOS_SHARED_MEM_DSS = 5,
    TEEOS_SHARED_MEM_MAILBOX = 6,
    TEEOS_SHARED_MEM_SKYTONE = 7,
    TEEOS_SHARED_MEM_NOMAP = 8,
    TEEOS_SHARED_MEM_TBIMGINFO = 9,
    TEEOS_SHARED_MEM_ES_CS = 10,
    TEEOS_SHARED_MEM_SECFLASH = 11,
    TEEOS_SHARED_MEM_SPI_DMA_BUF = 12,
    TEEOS_SHARED_MEM_CERTKEY = 13,
    TEEOS_SHARED_MEM_MEMORY_SGLIST = 14,
    TEEOS_SHARED_MEM_MAX,
};

struct shared_buffer_args {
    uint64_t type_buffer;
    uint32_t type_size;
    uint64_t buffer;
    uint32_t buffer_size;
    bool clear_flag;
};

struct oemkey_buffer_args {
    uint64_t oemkey_buffer;
    uint32_t key_size;
};
#define IOCTRL_GET_OEM_KEY 0x11
#define IOCTRL_GET_TLV_SHARED_MEM 0x10

#define GET_SHAREDMEM_TYPE_STATIC   0u
#define GET_SHAREDMEM_TYPE_DYNAMIC  1u

int32_t get_sharedmem_addr(uintptr_t *sharedmem_vaddr, bool *sharedmem_flag, uint32_t *sharedmem_size);
/* get sharedmem from platdrv */
int32_t get_shared_mem_info(enum sharedmem_types type, unsigned int *buffer, uint32_t size);

int32_t get_tlv_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag);

int32_t get_tlv_shared_mem_drv(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag);

/* get sharedmem outside of platdrv */
int32_t sre_get_shared_mem_info(enum sharedmem_types type, uint32_t *buffer, uint32_t size);

#endif

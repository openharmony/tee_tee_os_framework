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


#include "img_load.h"

#include <securec.h>
#include "set_teeos_cfg.h"

uintptr_t get_buf_addr(const char *part_name);
int32_t storage_read(const char *part_name, uint32_t part_size, uintptr_t buf_addr);
int32_t verify_sign(uintptr_t buf_addr);
int32_t rsa_decrypt(uintptr_t buf_addr);

static uintptr_t read_teeos(const char *part_name, uint32_t part_size)
{
    int32_t ret;
    uintptr_t buf_addr = get_buf_addr(part_name);

    ret = storage_read(part_name, part_size, buf_addr);
    if (ret != 0)
        return 0;

    return buf_addr;
}

static int32_t verify_teeos(uintptr_t buf_addr)
{
    int32_t ret;
    ret = verify_sign(buf_addr);

    return ret;
}

static int32_t decrypt_teeos(uintptr_t buf_addr)
{
    int32_t ret;

    ret = rsa_decrypt(buf_addr);

    return ret;
}

static int32_t copy_teeos(uintptr_t buf_addr, uint64_t dst_addr)
{
    struct secure_img_header *img_header = (struct secure_img_header*)buf_addr;
    void *src_ptr = (void *)(uintptr_t)((uint64_t)(uintptr_t)img_header + img_header->kernel_offset);
    uint32_t size = img_header->kernel_size;

    if (memcpy_s((void *)(uintptr_t)dst_addr, size, src_ptr, size) != EOK)
        return -1;

    return 0;
}

int32_t load_teeos(const char *part_name, uint32_t part_size, ...)
{
    /* 1st step: copy teeos to ram from flash */
    uintptr_t buf_addr = read_teeos(part_name, part_size);
    if (buf_addr == 0) {
        teelog("read teeos failed\n");
        return -1;
    }

    /* 2nd step: verify teeos */
    if (verify_teeos(buf_addr) != 0) {
        teelog("verify teeos failed\n");
        return -1;
    }

    /* 3rd step: decrypt teeos */
    if (decrypt_teeos(buf_addr) != 0) {
        teelog("decrypt teeos failed\n");
        return -1;
    }

    /* 4th step: copy teeos to destination */
    uint64_t teeos_boot_addr = get_teeos_code_start();
    if (teeos_boot_addr == 0) {
        teelog("get teeos start addr error\n");
        return -1;
    }

    if (copy_teeos(buf_addr, teeos_boot_addr) != 0) {
        teelog("copy to teeos failed\n");
        return -1;
    }

    (void)part_name;
    (void)part_size;

    return 0;
}

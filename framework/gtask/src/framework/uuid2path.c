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

#include <stdio.h>
#include <tee_log.h>
#include <fileio.h>
#include <securec.h>
#include "gtask_core.h"

/* uuid need 32, '/' and '-' need 6 */
#define MIN_PATH_NAME_LEN (int)(32 + 6 + sizeof(TAFS_MOUNTPOINT))
/* uuid need 32, '/' need 2, '-' need 4, ".so" need 3, tafs need 4,'\0' need 1, libname max 18,(ta_framework.h) */
#define MIN_LIB_NAME_LEN (int)(32 + 10 + sizeof(TAFS_MOUNTPOINT))

int uuid_to_fname(const TEE_UUID *uuid, char *name, int name_len)
{
    int ret;
    bool check_value = (uuid == NULL || name == NULL || name_len < MIN_PATH_NAME_LEN);
    if (check_value) {
        tloge("param is error\n");
        return -1;
    }

    ret = snprintf_s(name, (unsigned int)name_len, (unsigned int)(name_len - 1),
                     "%s/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", TAFS_MOUNTPOINT, uuid->timeLow,
                     uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
                     uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3], uuid->clockSeqAndNode[4],
                     uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);
    if (ret < 0)
        return -1;
    tlogd("after uuid_to_fname, write %d, fname is %s\n", ret, name);
    return 0;
}

int uuid_to_libname(const TEE_UUID *uuid, char *name, int name_len, const char *lib_name, tee_img_type_t type)
{
    int ret = -1;
    bool check_value = (uuid == NULL || name == NULL || lib_name == NULL || name_len < MIN_LIB_NAME_LEN ||
        name_len > LIB_NAME_MAX);
    if (check_value) {
        tloge("param is error\n");
        return -1;
    }

    TEE_UUID global_uuid = TEE_SERVICE_GLOBAL;
    if (TEE_MemCompare(&global_uuid, uuid, sizeof(*uuid)) != 0) {
        tlogd("ta dynamic library\n");
        ret = snprintf_s(name, (unsigned int)name_len, (unsigned int)(name_len - 1),
            "%s/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x%s.so", TAFS_MOUNTPOINT, uuid->timeLow,
            uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
            uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3], uuid->clockSeqAndNode[4],
            uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7], lib_name);
    } else if (type == IMG_TYPE_DYNAMIC_DRV) {
        tlogd("new driver framework elf\n");
        ret = snprintf_s(name, (unsigned int)name_len, (unsigned int)(name_len - 1),
            "%s/%s.elf", TAFS_MOUNTPOINT, lib_name);
    } else if (type == IMG_TYPE_CRYPTO_DRV) {
        tlogd("new crypto driver framework so\n");
        ret = snprintf_s(name, (unsigned int)name_len, (unsigned int)(name_len - 1),
            "%s/%s.so", TAFS_MOUNTPOINT, "libhardware_crypto_drv");
    }

    if (ret < 0)
        return -1;

    return 0;
}

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
#include "perm_srv_file_op.h"
#include <string.h>
#include <tee_log.h>
#include <tee_defines.h>
#include <tee_trusted_storage_api.h>


int32_t perm_srv_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    if (ops == NULL)
        return -1;

    return ops->write(filename, buf, len);
}

int32_t perm_srv_file_read(const char *filename, uint8_t *buf, size_t len)
{
    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    if (ops == NULL)
        return -1;

    return ops->read(filename, buf, len);
}

int32_t perm_srv_file_size(const char *filename)
{
    if (filename == NULL)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    if (ops == NULL)
        return -1;

    return ops->filesize(filename);
}

int32_t perm_srv_file_remove(const char *filename)
{
    if (filename == NULL)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    if (ops == NULL)
        return -1;

    return ops->remove(filename);
}

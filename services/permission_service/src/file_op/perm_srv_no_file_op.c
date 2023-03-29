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

const struct file_operations *perm_srv_file_op_init(void)
{
    return NULL;
}

int32_t perm_srv_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    (void)filename;
    (void)buf;
    (void)len;
    return 0;
}

int32_t perm_srv_file_read(const char *filename, uint8_t *buf, size_t len)
{
    (void)filename;
    (void)buf;
    (void)len;
    return 0;
}

int32_t perm_srv_file_size(const char *filename)
{
    (void)filename;
    return 0;
}

int32_t perm_srv_file_remove(const char *filename)
{
    (void)filename;
    return 0;
}
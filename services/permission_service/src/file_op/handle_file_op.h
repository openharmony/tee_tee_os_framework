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
#ifndef HANDLE_FILE_OP_H
#define HANDLE_FILE_OP_H
#include <tee_defines.h>

int32_t do_file_truncate(TEE_ObjectHandle *handle);

int32_t do_file_sync(TEE_ObjectHandle *handle, uint32_t mode);

int32_t do_file_open(uint32_t storage_id, TEE_ObjectHandle *handle, const char *filename, uint32_t mode);

int32_t do_file_close(TEE_ObjectHandle *handle, uint32_t mode);

int32_t do_file_read(uint32_t storage_id, const char *filename, uint8_t *buf, size_t len);

int32_t do_file_write(uint32_t storage_id, const char *filename, const uint8_t *buf, size_t len);

int32_t do_file_size(uint32_t storage_id, const char *filename);

int32_t do_file_remove(uint32_t storage_id, const char *filename);

#endif
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
#include "handle_file_op.h"
#include <string.h>
#include <tee_log.h>
#include <tee_defines.h>
#include <tee_trusted_storage_api.h>

int32_t do_file_open(uint32_t storage_id, TEE_ObjectHandle *handle, const char *filename, uint32_t mode)
{
    TEE_Result ret;

    if (filename == NULL || handle == NULL || mode == 0)
        return -1;

    if (mode & TEE_DATA_FLAG_CREATE) {
        ret = TEE_CreatePersistentObject(storage_id, filename, strlen(filename), mode,
                                         TEE_HANDLE_NULL, NULL, 0, handle);
        if (ret != TEE_SUCCESS) {
            tloge("file create failed: 0x%x %s\n", ret, filename);
            return -1;
        }
        tlogd("file create successfully: %s, ret %x\n", filename, ret);

        if (do_file_truncate(handle) < 0)
            return -1;
    } else {
        ret = TEE_OpenPersistentObject(storage_id, filename, strlen(filename), mode, handle);
        if (ret != TEE_SUCCESS) {
            if (ret == TEE_ERROR_ITEM_NOT_FOUND)
                return 1;
            tloge("file open failed: 0x%x and %s\n", ret, filename);
            return -1;
        }
    }

    return 0;
}

int32_t do_file_close(TEE_ObjectHandle *handle, uint32_t mode)
{
    if (handle == NULL)
        return -1;

    if (do_file_sync(handle, mode) < 0)
        return -1;

    TEE_CloseObject(*handle);
    return 0;
}

int32_t do_file_read(uint32_t storage_id, const char *filename, uint8_t *buf, size_t len)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ;
    uint32_t read_size = 0;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    int32_t ret;
    TEE_Result tee_ret;

    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    ret = do_file_open(storage_id, &handle, filename, mode);
    if (ret < 0) {
        tloge("file open error\n");
        return -1;
    }

    if (ret > 0) {
        tloge("file doesn't exist\n");
        return 0;
    }

    tee_ret = TEE_ReadObjectData(handle, buf, len, &read_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("file read error 0x%x\n", ret);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = do_file_close(&handle, (uint32_t)mode);
    if (ret != 0) {
        tloge("file close error\n");
        return -1;
    }

    return (int32_t)read_size;
}

int32_t do_file_write(uint32_t storage_id, const char *filename, const uint8_t *buf, size_t len)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result tee_ret;
    int32_t ret;

    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    tlogd("file write into:%s\n", filename);
    ret = do_file_open(storage_id, &handle, filename, mode);
    if (ret < 0) {
        tloge("file open error\n");
        return ret;
    }

    tee_ret = TEE_WriteObjectData(handle, buf, len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("file write failed: 0x%x and %s\n", tee_ret, filename);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = do_file_close(&handle, (uint32_t)mode);
    if (ret < 0) {
        tloge("file close error\n");
        return ret;
    }

    tlogd("file write success\n");
    return ret;
}

int32_t do_file_size(uint32_t storage_id, const char *filename)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result tee_ret;
    uint32_t len = 0;
    uint32_t pos = 0;
    int32_t ret;

    if (filename == NULL)
        return -1;

    ret = do_file_open(storage_id, &handle, filename, mode);
    if (ret < 0) {
        tloge("file open error\n");
        return -1;
    } else if (ret > 0) {
        return 0;
    }

    tee_ret = TEE_InfoObjectData(handle, &pos, &len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("file get info failed: 0x%x and %s\n", tee_ret, filename);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = do_file_close(&handle, (uint32_t)mode);
    if (ret < 0) {
        tloge("file close error\n");
        return ret;
    }
    tlogd("file get info success\n");
    return (int32_t)len;
}

int32_t do_file_remove(uint32_t storage_id, const char *filename)
{
    TEE_Result ret;

    if (filename == NULL)
        return -1;

    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_ObjectHandle handle = NULL;
    ret = TEE_OpenPersistentObject(storage_id, filename, strlen(filename), mode, (&handle));
    if (ret != TEE_SUCCESS) {
        tloge("file remove failed: 0x%x and %s\n", ret, filename);
        return -1;
    }

    TEE_CloseAndDeletePersistentObject(handle);
    return 0;
}

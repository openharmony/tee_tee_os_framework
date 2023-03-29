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
#include "handle_file_op.h"

int32_t do_file_truncate(TEE_ObjectHandle *handle)
{
    TEE_Result ret;

    if (handle == NULL)
        return -1;
    ret = TEE_TruncateObjectData(*handle, 0);
    if (ret != TEE_SUCCESS) {
        tloge("file truncate failed: 0x%x\n", ret);
        TEE_CloseObject(*handle);
        return -1;
    }
    return 0;
}

int32_t do_file_sync(TEE_ObjectHandle *handle, uint32_t mode)
{
    TEE_Result ret;

    if (handle == NULL)
        return -1;
    if ((mode & TEE_DATA_FLAG_ACCESS_WRITE) != 0) {
        ret = TEE_SyncPersistentObject(*handle);
        if (ret != TEE_SUCCESS) {
            tloge("file sync error: 0x%x\n", ret);
            return -1;
        }
    }
    return 0;
}

static int32_t do_sfs_file_read(const char *filename, uint8_t *buf, size_t len)
{
    return do_file_read(TEE_OBJECT_STORAGE_PRIVATE, filename, buf, len);
}

static int32_t do_sfs_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    return do_file_write(TEE_OBJECT_STORAGE_PRIVATE, filename, buf, len);
}

static int32_t do_sfs_file_size(const char *filename)
{
    return do_file_size(TEE_OBJECT_STORAGE_PRIVATE, filename);
}

static int32_t do_sfs_file_remove(const char *filename)
{
    return do_file_remove(TEE_OBJECT_STORAGE_PRIVATE, filename);
}

static const struct file_operations g_sfs_ops = {
    .read     = do_sfs_file_read,
    .write    = do_sfs_file_write,
    .filesize = do_sfs_file_size,
    .remove   = do_sfs_file_remove,
    .fs_using = STORE_SFS,
};

static const struct file_operations *g_ops = NULL;
const struct file_operations *perm_srv_file_op_init(void)
{
    if (g_ops != NULL)
        return g_ops;

    bool enable_rpmb = false;
    /* use sfs */
    if (!enable_rpmb) {
        tlogd("use sfs to operate data\n");
        g_ops = &g_sfs_ops;
    }

    return g_ops;
}
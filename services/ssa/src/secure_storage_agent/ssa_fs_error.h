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
#ifndef __SSA_FS_ERRDEF_H
#define __SSA_FS_ERRDEF_H

#include "tee_defines.h"

#define EPERM        1
#define ENOENT       2
#define EINTR        4
#define EIO          5
#define EBADF        9
#define EAGAIN       11
#define ENOMEM       12
#define EACCES       13
#define ENOTDIR      20
#define EISDIR       21
#define EINVAL       22
#define ENFILE       23
#define EMFILE       24
#define EFBIG        27
#define ENOSPC       28
#define EROFS        30
#define ENAMETOOLONG 36
#define EOVERFLOW    75
#define ESTORAGEDEAD 200
#define EFCORRUPT    201

struct errno_map_type {
    uint32_t ns_errno;
    TEE_Result s_errno;
    const char *msg;
};

static const struct errno_map_type g_fs_error_strings[] = {
    { 0,  TEE_SUCCESS, "Success" },
    { EPERM,  TEE_ERROR_ACCESS_DENIED, "Operation not permitted" },
    { ENOENT,  TEE_ERROR_ITEM_NOT_FOUND, "No such file or directory" },
    { EINTR,  TEE_ERROR_EXTERNAL_CANCEL, "Interrupted system call" },
    { EIO,  TEE_ERROR_STORAGE_EIO, "I/O error" },
    { EBADF,  TEE_ERROR_BAD_PARAMETERS, "Bad file number" },
    { EAGAIN,  TEE_ERROR_STORAGE_EAGAIN, "Try again" },
    { ENOMEM,  TEE_ERROR_OUT_OF_MEMORY, "Out of memory" },
    { EACCES,  TEE_ERROR_ACCESS_DENIED, "Permission denied" },
    { ENOTDIR,  TEE_ERROR_STORAGE_ENOTDIR, "Not a directory" },
    { EISDIR,  TEE_ERROR_STORAGE_EISDIR, "Is a directory" },
    { EINVAL,  TEE_ERROR_BAD_PARAMETERS, "Invalid argument" },
    { ENFILE,  TEE_ERROR_STORAGE_ENFILE, "File table overflow" },
    { EMFILE,  TEE_ERROR_STORAGE_EMFILE, "Too many open files" },
    { EFBIG,  TEE_ERROR_OVERFLOW, "File too large" },
    { ENOSPC,  TEE_ERROR_STORAGE_NO_SPACE, "No space left on device" },
    { EROFS,  TEE_ERROR_STORAGE_EROFS, "Read-only file system" },
    { ENAMETOOLONG,  TEE_ERROR_BAD_PARAMETERS, "File name too long" },
    { EOVERFLOW,  TEE_ERROR_OVERFLOW, "Value too large for defined data type" },
    { ESTORAGEDEAD,  TEE_ERROR_STORAGE_NOT_AVAILABLE, "Secure storage died" },
    { EFCORRUPT,  TEE_ERROR_CORRUPT_OBJECT, "Object corruptted" },
    { 0,  TEE_SUCCESS, NULL },
};
#endif

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
#ifndef __TEE_FS_H
#define __TEE_FS_H

#include "tee_defines.h"

/* Macros for access() */
#define R_OK 4 // Read
#define W_OK 2 // Write
#define F_OK 0 // Existence

#define HASH_LEN        32
/* DIR_LEN is for mutiple sec storage partition and dir,e.g. sec_storage/dirA/file1.txt */
#define DIR_LEN                         64
#define NEW_DIR_LEN                     128

#ifndef CONFIG_SPEC_STORAGE_PATH /* for router */
#define HASH_NAME_BUFF_LEN              (2 * HASH_LEN + 1 + DIR_LEN)
#define MAX_FILE_ID_LEN                 HASH_NAME_BUFF_LEN
#define SFS_PARTITION_PERSISTENT        "sec_storage/"
#define SFS_PARTITION_TRANSIENT         "sec_storage_data/"
#else
#define HASH_NAME_BUFF_LEN              (2 * HASH_LEN + 1 + DIR_LEN)
#define MAX_FILE_ID_LEN                 256
#define SFS_PARTITION_PERSISTENT        "cert/"
#define SFS_PARTITION_TRANSIENT         "tee/"
#endif

#define MAX_FILE_SIZE                   (4 * 1024 * 1024)
#define SFS_PERSO                       "_perso/"
#define SFS_PRIVATE                     "_private/"
#define SFS_PARTITION_TRANSIENT_PRIVATE SFS_PARTITION_TRANSIENT SFS_PRIVATE
#define SFS_PARTITION_TRANSIENT_PERSO   SFS_PARTITION_TRANSIENT SFS_PERSO
#define MAX_TRUNCATE_SIZE               (4 * 1024 * 1024)

#define FILE_NAME_INVALID_STR "../" // file name path must not contain ../

TEE_Result check_file_name(const char *name);
TEE_Result check_name_by_storageid(const char *obj_id, uint32_t obj_len, uint32_t storage_id);
#endif

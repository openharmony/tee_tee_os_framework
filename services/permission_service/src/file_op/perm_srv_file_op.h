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
#ifndef PERM_SRV_FILE_OP_H
#define PERM_SRV_FILE_OP_H
#include <tee_defines.h>

#define STORE_RPMB 0
#define STORE_SFS  1
#define STORE_SEC_FLASH 2

struct file_operations {
    /*
     * Read data from file
     *
     * @para filename:  The path name of the file
     * @para buf:       The buffer used to store the content readed from the file
     * @len:            The size count in buffer trying to read from the file
     * @return  <0  read error
     *          >=0 real read length
     */
    int32_t (*read)(const char *filename, uint8_t *buf, size_t len);

    /*
     * Write data into file
     *
     * @para filename:  The path name of the file
     * @para buf:       The content which you want write into the file
     * @len:            The size of the content
     * @return  TEE_SUCCESS  ok
     *          others error
     */
    int32_t (*write)(const char *filename, const uint8_t *buf, size_t len);

    /*
     * Delete file
     *
     * @para filename:  The path name of the file
     * @return  TEE_SUCCESS  ok
     *          others error
     */
    int32_t (*remove)(const char *filename);

    /*
     * Get file size
     *
     * @para filename:  The path name of the file
     * @return  < 0 error
     *          >=0 The size of the file
     */
    int32_t (*filesize)(const char *filename);

    /* fs using */
    int32_t fs_using;
};

const struct file_operations *perm_srv_file_op_init(void);
int32_t perm_srv_file_write(const char *filename, const uint8_t *buf, size_t len);
int32_t perm_srv_file_read(const char *filename, uint8_t *buf, size_t len);
int32_t perm_srv_file_size(const char *filename);
int32_t perm_srv_file_remove(const char *filename);
#endif

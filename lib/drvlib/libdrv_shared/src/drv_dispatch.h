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
#ifndef DRVMGR_SRC_DRV_DISPATCH_H
#define DRVMGR_SRC_DRV_DISPATCH_H

#include <dlist.h>
#include <tee_defines.h>

struct fd_node {
    struct dlist_node data_list;
    int64_t fd;
    struct drv_node *drv;
    bool close_flag;
};

struct tee_drv_param {
    uint64_t args;
    uint64_t data;
    struct tee_uuid uuid;
    uint32_t caller_pid;
};

#endif

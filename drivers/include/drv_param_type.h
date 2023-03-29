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
#ifndef PLATDRV_INCLUDE_DRV_PARAM_TYPE_H
#define PLATDRV_INCLUDE_DRV_PARAM_TYPE_H

struct drv_param {
    uint64_t args; /* pointer to args addr */
    uint64_t data;
    uint64_t rdata;
    uint64_t rdata_len;
    uint32_t uid;
    uint32_t pid;
    uint64_t job_handler;
    uint32_t caller_pid;
};
#endif

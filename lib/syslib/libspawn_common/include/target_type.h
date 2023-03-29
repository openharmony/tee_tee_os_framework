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

#ifndef LIBSPAWN_COMMON_INCLUDE_TARGET_TYPE_H
#define LIBSPAWN_COMMON_INCLUDE_TARGET_TYPE_H

#include <stdint.h>

/* should match with target_type defined in manifest.txt */
enum target_type {
    TA_TARGET_TYPE = 0,
    DRV_TARGET_TYPE = 1,
    DYN_LIB_TARGET_TYPE = 2,
    SRV_TARGET_TYPE = 3,
    CLIENT_TARGET_TYPE = 4,
    MAX_TARGET_TYPE,
};

#endif

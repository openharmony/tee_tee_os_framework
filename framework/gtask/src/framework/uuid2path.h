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

#ifndef __UUID_TO_PATH_H_
#define __UUID_TO_PATH_H_
#include <tee_defines.h>
#include "gtask_core.h"

int uuid_to_fname(const TEE_UUID *uuid, char *name, int namelen);
int uuid_to_libname(const TEE_UUID *uuid, char *name, int namelen, const char *lib_name, tee_img_type_t type);

#endif

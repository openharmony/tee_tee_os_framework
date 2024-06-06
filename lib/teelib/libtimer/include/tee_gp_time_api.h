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

#ifndef SYS_LIBS_LIBTIMER_GP_TIME_API_H
#define SYS_LIBS_LIBTIMER_GP_TIME_API_H
#include <tee_defines.h>

void TEE_GetSystemTime(TEE_Time *time);
void TEE_GetREETime(TEE_Time *time);
TEE_Result TEE_Wait(uint32_t mill_second);
TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);
TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);
void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len);
#endif
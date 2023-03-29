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

#ifndef __DYN_LOAD_H_
#define __DYN_LOAD_H_
#include "gtask_core.h"

typedef struct {
    char *file_buffer;
    int file_size;
    char *lib_name;
    char *fname;
    uint32_t fname_size;
} load_elf_func_params;

#define LIB_EXIST      1
#define LOAD_SUCC      0
#define LOAD_FAIL      (-1)

bool get_dyn_client_name(bool is_64bit,  char *client, uint32_t size);
int dynamic_load_lib_elf(const load_elf_func_params *param, const struct service_struct *service,
                         const TEE_UUID *uuid, uint64_t memid, tee_img_type_t type);
uint32_t sre_release_dynamic_region(const TEE_UUID *uuid, uint32_t release);
TEE_Result load_elf_to_tee(const TEE_UUID *uuid, const char *task_name, bool buildin,
                           bool dyn_conf_registed, struct service_attr *service_attr);
int elf_param_check(uint32_t stack_size, uint32_t heap_size, uint32_t mani_ext_size);
TEE_Result varify_elf_arch(const char *elf, int file_size, bool *ta_64bit);
#endif

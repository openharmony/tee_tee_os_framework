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
#ifndef LIBSPAWN_COMMON_INCLUDE_GET_ELF_INFO_H
#define LIBSPAWN_COMMON_INCLUDE_GET_ELF_INFO_H

#include <stdio.h>
#include <elf.h>

#define ELF_NOT_SUPPORT (-1)
#define ELF_NATIVE      0
#define ELF_TALDR       1
#define ELF_TARUNNER    2
#define ELF_TARUNNER_A32 3

#define EH_SIZE sizeof(Elf64_Ehdr)

int32_t get_elf_class(const char *ehdr, uint32_t ehdr_size);
int32_t get_elf_type(const char *ehdr, uint32_t ehdr_size, int32_t elf_class);

#endif

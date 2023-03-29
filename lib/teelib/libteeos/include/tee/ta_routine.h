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
#ifndef LIBTEEOS_TA_ROUTINE_H
#define LIBTEEOS_TA_ROUTINE_H

#include <stdbool.h>
#include <stdint.h>

enum gp_function_index {
    CREATE_ENTRY_INDEX = 0,
    OPEN_SESSION_INDEX,
    INVOKE_COMMAND_INDEX,
    CLOSE_SESSION_INDEX,
    DESTROY_ENTRY_INDEX,
    BSS_START_INDEX,
    BSS_END_INDEX,
    INIT_ARRAY_START_INDEX,
    INIT_ARRAY_END_INDEX,
    TOTAL_SYM_NUM,
};

#define GP_SYMBOL_NUM BSS_START_INDEX

struct ta_routine_info {
    /* info store the address of GP function/bss_start/bss_end/init_array_start/init_array_end */
    void *info[TOTAL_SYM_NUM];
    bool addcaller_flag;
};

typedef void (*ta_entry_t)(uint32_t, const struct ta_routine_info *);
typedef void (*ta_entry_orig_t)(uint32_t);

typedef union {
    ta_entry_t ta_entry;
    ta_entry_orig_t ta_entry_orig;
} ta_entry_type;
#endif

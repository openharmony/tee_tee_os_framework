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

#ifndef TEED_COMMON_H
#define TEED_COMMON_H

#include <teed_private.h>

void teed_init_tee_ep_state(struct entry_point_info *tee_entry_point,
                            uint32_t rw,
                            uintptr_t pc,
                            tee_context_t *tee_ctx);

uint64_t teed_synchronous_sp_entry(tee_context_t *tee_ctx);

void __dead2 teed_synchronous_sp_exit(const tee_context_t *tee_ctx, uint64_t ret);

#endif

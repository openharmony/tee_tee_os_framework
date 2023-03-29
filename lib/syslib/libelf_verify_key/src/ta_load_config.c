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
#include "ta_load_config.h"
#include <stdbool.h>

#ifdef TEE_DISABLE_TA_SIGN_VERIFY
static const bool g_tee_disable_ta_signature = true;
#else
static const bool g_tee_disable_ta_signature = false;
#endif

bool get_ta_signature_ctrl(void)
{
    return g_tee_disable_ta_signature;
}

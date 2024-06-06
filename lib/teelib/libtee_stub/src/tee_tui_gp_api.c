/*
 * Copyright (C) 2024 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_tui_gp_api.h"

TEE_Result TEE_TUIInitSession(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUICloseSession(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUICheckTextFormat(const char *text, uint32_t *width, uint32_t *height, uint32_t *last_index)
{   
    (void)text;
    (void)width;
    (void)height;
    (void)last_index;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUIGetScreenInfo(TEE_TUIScreenOrientation screenOrientation,
                                uint32_t nbEntryFields,
                                TEE_TUIScreenInfo *screenInfo)
{
    (void)screenOrientation;
    (void)nbEntryFields;
    (void)screenInfo;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUIDisplayScreen(TEE_TUIScreenConfiguration *screenConfiguration,
                                bool closeTUISession,
                                TEE_TUIEntryField *entryFields,
                                uint32_t entryFieldCount,
                                TEE_TUIButtonType *selectedButton)
{
    (void)screenConfiguration;
    (void)closeTUISession;
    (void)entryFields;    
    (void)entryFieldCount;
    (void)selectedButton;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUINotify_fp(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUISetInfo(int32_t type)
{
    (void)type;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUISendEvent(int32_t type)
{
    (void)type;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_TUISetLabel(TEE_TUIScreenLabel *label, uint32_t len)
{
    (void)label;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}

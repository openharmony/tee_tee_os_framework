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

#ifndef __TEE_EXT_TRUSTED_STORAGE_API_LEGACY_H
#define __TEE_EXT_TRUSTED_STORAGE_API_LEGACY_H

#include "tee_defines.h"


TEE_Result TEE_Ext_CreatePersistentObject(TEE_UUID target, uint32_t storageID, const void *objectID, size_t objectIDLen,
                                          uint32_t flags, TEE_ObjectHandle attributes, const void *initialData,
                                          size_t initialDataLen, TEE_ObjectHandle *object);

TEE_Result TEE_Ext_OpenPersistentObject(TEE_UUID target, uint32_t storageID, const void *objectID, size_t objectIDLen,
                                        uint32_t flags, TEE_ObjectHandle *object);


TEE_Result TEE_Ext_DeleteAllObjects(TEE_UUID target);

#endif
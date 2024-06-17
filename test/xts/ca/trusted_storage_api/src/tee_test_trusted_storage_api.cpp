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

#include <common_test.h>

using namespace testing::ext;
/**
 * @testcase.name   : CaseCreatePersistentObjectAndDelete
 * @testcase.desc   : test GP interfaces
 *                      TEE_CreatePersistentObject, TEE_CloseAndDeletePersistentObject1,
 *                      TEE_WriteObjectData, TEE_ReadObjectData, TEE_SeekObjectData,
 *                      TEE_OpenPersistentObject, TEE_CloseObject, TEE_SyncPersistentObject
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CaseCreatePersistentObjectAndDelete);

/**
 * @testcase.name   : CaseRenameObjectAndGetInfo
 * @testcase.desc   : test GP interfaces
 *                      TEE_TruncateObjectData, TEE_RenamePersistentObject, TEE_GetObjectInfo1, TEE_InfoObjectData
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CaseRenameObjectAndGetInfo);

/**
 * @testcase.name   : CaseEnumerateDeleteAllObject
 * @testcase.desc   : test GP interfaces
 *                      TEE_AllocatePersistentObjectEnumerator, TEE_FreePersistentObjectEnumerator,
 *                      TEE_ResetPersistentObjectEnumerator, TEE_StartPersistentObjectEnumerator,
 *                      TEE_GetNextPersistentObject
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CaseEnumerateDeleteAllObject);

/**
 * @testcase.name   : CaseRestrictObjectUsage
 * @testcase.desc   : test GP interfaces
 *                      TEE_AllocateTransientObject, TEE_FreeTransientObject,
 *                      TEE_RestrictObjectUsage1, TEE_ResetTransientObject
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CaseRestrictObjectUsage);

/**
 * @testcase.name   : CasePopulateAndCopyObject
 * @testcase.desc   : test GP interfaces
 *                      TEE_InitRefAttribute, TEE_InitValueAttribute,
 *                      TEE_PopulateTransientObject, TEE_CopyObjectAttributes1,
 *                      TEE_GetObjectBufferAttribute, TEE_GetObjectValueAttribute
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CasePopulateAndCopyObject);

/**
 * @testcase.name   : CaseGenerateKey
 * @testcase.desc   : test GP interfaces TEE_GenerateKey
 * @testcase.expect : return TEEC_SUCCESS
 */
TRUSTED_STORAGE_TEST_EQ(CaseGenerateKey);

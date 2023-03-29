/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "test_trusted_storage_api_defines.h"
#include "monad.h"
#include "tee_log.h"

char object_id[] = "FCA6E042AD82303E489B80AEBBEAA7779C1E73E92690EF320A5EDBC44A979BB9";
char rename_object_id[] = "816C0DD90927C5A2062968420E5B3ADDFBEA1FDDC";

char object_init_data[] = "80D35C919E8BFAABE92DA7D8C309FC08623246FBC8DB61B77F58880EA932BD11";
char object_write_data[] = "FF89C286D5D9AE021FD96F2DECBD1501228B6D10A13FADA485EBD1C8B078564EFF89C286D5D9AE021FD96F2D";

char attr_buffer1[] = "FAABE92DA7D8C309FC08623246FB";
char attr_buffer2[] = "FAABE92DA7D8C309FC08623246FB";

int CaseCreatePersistentObjectAndDelete(void)
{
    TestVector tv = {
        .storageID = TEE_OBJECT_STORAGE_PRIVATE,
        .createObjectID = object_id,
        .createFlags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ,
        .attributes = TEE_HANDLE_NULL,
        .initialData = object_init_data,
        .openObjectID = object_id,
        .openFlags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ,
        .writeBuffer = object_write_data,
        .readBufferLen = sizeof(object_write_data),
        .seekOffset = 0,
        .whence = TEE_DATA_SEEK_SET,
        .actions = {
            IRSetUp,
            CreatePersistentObject,
            SeekObject,
            WriteObject,
            CloseObject,
            OpenPersistentObject,
            SeekObject,
            ReadObject, CheckReadBuffer,
            DeletePersistentObject,
            IRTearDown, },
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseCreatePersistentObjectAndDelete success\n", __func__);
    return 0;
}

int CaseRenameObjectAndGetInfo(void)
{
    TestVector tv = {
        .storageID = TEE_OBJECT_STORAGE_PRIVATE,
        .createObjectID = object_id,
        .createFlags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META,
        .attributes = TEE_HANDLE_NULL,
        .initialData = object_init_data,
        .resetSize = 0x100,
        .newObjectID = rename_object_id,
        .openObjectID = rename_object_id,
        .openFlags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ,
        .isTransientObject = false,
        .actions = {
            IRSetUp,
            CreatePersistentObject,
            TruncateObject,
            RenameObject,
            CloseObject,
            OpenPersistentObject,
            GetObjectInfo, CheckObjectSize,
            DeletePersistentObject,
            IRTearDown, },
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseRenameObjectAndGetInfo success\n", __func__);
    return 0;
}

int CaseEnumerateDeleteAllObject(void)
{
    TestVector tv = {
        .storageID = TEE_OBJECT_STORAGE_PRIVATE,
        .createObjectID = object_id,
        .createFlags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META,
        .attributes = TEE_HANDLE_NULL,
        .initialData = object_init_data,
        .createNum = 5,
        .openFlags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ,
        .actions = {
            IRSetUp,
            CreateMultiObject,
            AllocateEnumerator,
            ResetEnumerator,
            StartEnumerator,
            EnumerateAllObject,
            FreeEnumerator,
            IRTearDown, },
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseEnumerateDeleteAllObject success\n", __func__);
    return 0;
}

int CaseRestrictObjectUsage(void)
{
    TestVector tv = {
        .transientObjectNum = 1,
        .objectType = {TEE_TYPE_AES},
        .maxObjectSize = {256},
        .objectUsage = {0xFFFF0000, 0x0000FFFF},
        .isTransientObject = true,
        .actions = {
            IRSetUp,
            AllocateTransientObject,
            RestrictObjectUsage, GetObjectInfo, CheckObjectUsage,
            ResetObject,
            RestrictObjectUsage, GetObjectInfo, CheckObjectUsage,
            FreeTransientObject,
            IRTearDown, },
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseRestrictObjectUsage success\n", __func__);
    return 0;
}

int CasePopulateAndCopyObject(void)
{
    TestVector tv = {
        .transientObjectNum = 2,
        .objectType = {TEE_TYPE_ECDSA_PUBLIC_KEY, TEE_TYPE_ECDSA_PUBLIC_KEY},
        .maxObjectSize = {256, 256},
        .attrCount = 3,
        .attributeID = {TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_CURVE},
        .attrInitBuffer = {attr_buffer1, attr_buffer2},
        .attrInitA = {0x1234},
        .attrInitB = {0x5678},
        .getAttributeID = {TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_CURVE},
        .actions = {
            IRSetUp,
            AllocateTransientObject,
            InitRefAttr, InitRefAttr, InitValueAttr,
            PopulateTransientObject,
            CopyObjectAttr,
            GetObjectBufferAttr, GetObjectBufferAttr, GetObjectValueAttr,
            CheckAttr,
            FreeTransientObject,
            IRTearDown, },
        .expRet = ER_OK,
    };

    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CasePopulateAndCopyObject success\n", __func__);
    return 0;
}

int CaseGenerateKey(void)
{
    TestVector tv = {
        .transientObjectNum = 1,
        .objectType = {TEE_TYPE_AES},
        .maxObjectSize = {256},
        .generateKeySize = 256,
        .actions = {
            IRSetUp,
            AllocateTransientObject,
            GenerateKey,
            FreeTransientObject,
            IRTearDown, },
        .expRet = ER_OK,
    };
    int ret = MonadRun2(&tv);
    if (ret != 0) {
        tloge("[%s]:MonadRun2 failed\n", __func__);
        return -1;
    }
    tlogi("[%s]:MonadRun2 success\n", __func__);
    tlogi("[%s]:--------------CaseGenerateKey success\n", __func__);
    return 0;
}
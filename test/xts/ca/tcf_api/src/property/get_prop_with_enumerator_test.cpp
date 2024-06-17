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

#include <common_test.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_defines.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;

struct unIntMapping {
    char *name;
    uint32_t cmd;
    ALL_PROP_SETS propSet;
    char *expectResult;
    uint32_t expectLen;
};

struct intMapping {
    char *name;
    uint32_t cmd;
    ALL_PROP_SETS propSet;
    uint64_t expectResult;
};

struct unIntMapping g_unIntMap[] = {
    // bool
    { (char*)GPD_TA_INSTANCEKEEPALIVE, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_CURRENT_TA,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TA_MULTISESSION, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_CURRENT_TA,
      (char*)VALUE_PREDEFINED_BOOLEAN, sizeof(VALUE_PREDEFINED_BOOLEAN) },
    { (char*)GPD_TA_SINGLEINSTANCE, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_CURRENT_TA,
      (char*)VALUE_PREDEFINED_BOOLEAN, sizeof(VALUE_PREDEFINED_BOOLEAN) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_ECC, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_NIST, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_BSI_R, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_BSI_T, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_IETF, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },
    { (char*)GPD_TEE_CRYPTOGRAPHY_OCTA, CMD_TEE_GetPropertyAsBool, TEE_PROPSET_IMPLEMENTATION,
      (char*)VALUE_PREDEFINED_FALSE, sizeof(VALUE_PREDEFINED_FALSE) },

    // binaryblock
    { (char*)SMC_TA_TESTBINARYBLOCK, CMD_TEE_GetPropertyAsBinaryBlock, TEE_PROPSET_CURRENT_TA,
      (char*)VALUE_PREDEFINED_BINARY_BLOCK, sizeof(VALUE_PREDEFINED_BINARY_BLOCK) },

    // uuid
    { (char*)GPD_TA_APPID, CMD_TEE_GetPropertyAsUUID, TEE_PROPSET_CURRENT_TA, NULL, 0 },
    // do not test GPD_TEE_DEVICEID
    { (char*)GPD_TEE_DEVICEID, CMD_TEE_GetPropertyAsUUID, TEE_PROPSET_IMPLEMENTATION, NULL, 0 },

    // string
    // this only test get uuid as string
    { (char*)GPD_TA_APPID, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_CURRENT_TA, (char*)VALUE_PREDEFINED_UUID, BIG_SIZE },
    { (char*)GPD_CLIENT_IDENTITY, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_CURRENT_CLIENT, (char*)VALUE_PREDEFINED_CLIENT_IDENTITY, BIG_SIZE },
    { (char*)GPD_TA_VERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_CURRENT_TA, (char*)VALUE_PREDEFINED_TA_VERSION, BIG_SIZE },
    { (char*)GPD_TA_DESCRIPTION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_CURRENT_TA, (char*)VALUE_PREDEFINED_TA_DESCRIPTION, BIG_SIZE },
    { (char*)GPD_TEE_APIVERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_API_VERSION, BIG_SIZE },
    { (char*)GPD_TEE_DESCRIPTION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_BUILD_VER, BIG_SIZE },
    { (char*)GPD_TEE_TRUSTEDOS_IMP_VERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_IMP_VERSION, BIG_SIZE },
    { (char*)GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_IMP_VERSION, BIG_SIZE },
    { (char*)GPD_TEE_FIRMWARE_IMP_VERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_FIRMWARE_IMP_VERSION, BIG_SIZE },
    { (char*)GPD_TEE_FIRMWARE_IMP_BINARYVERSION, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_FIRMWARE_IMP_VERSION, BIG_SIZE },
    { (char*)GPD_TEE_TRUSTEDOS_MANUFACTURER, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_MANUFACTURER, BIG_SIZE },
    { (char*)GPD_TEE_FIRMWARE_MANUFACTURER, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_FIRMWARE_MANUFACTURER, BIG_SIZE },
    { (char*)GPD_TEE_DEVICEID, CMD_TEE_GetPropertyAsString,
      TEE_PROPSET_IMPLEMENTATION, (char*)TEE_FIRMWARE_MANUFACTURER, BIG_SIZE },
};

struct intMapping g_intMap[] = {
    // int32
    { (char*)GPD_TA_DATASIZE, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_CURRENT_TA, VALUE_PREDEFINED_DATASIZE },
    { (char*)GPD_TA_STACKSIZE, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_CURRENT_TA, VALUE_PREDEFINED_STACKSIZE },
    { (char*)GPD_TA_ENDIAN, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_CURRENT_TA, 0 },
    { (char*)GPD_CLIENT_ENDIAN, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_CURRENT_CLIENT, VALUE_PREDEFINED_CLIENT_ENDIAN },
    { (char*)GPD_TEE_INTERNALCORE_VERSION, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, TEE_INTERNAL_CORE_VERSION },
    { (char*)GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, TEE_TIME_PROTECT_LEVEL },
    { (char*)GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, TA_TIME_PROTECT_LEVEL },
    { (char*)GPD_TEE_ARITH_MAXBIGINTSIZE, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, MAX_BIG_INT_SIZE },
    { (char*)GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, 0 },
    { (char*)GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, 0 },
    { (char*)GPD_TEE_EVENT_MAXSOURCES, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, 0 },
    { (char*)GPD_TEE_API_LEVEL, CMD_TEE_GetPropertyAsU32,
      TEE_PROPSET_IMPLEMENTATION, TEE_MAX_API_LEVEL_CONFIG },
    // int64
    { (char*)SMC_TA_TESTU64, CMD_TEE_GetPropertyAsU64,
      TEE_PROPSET_CURRENT_TA, VALUE_PREDEFINED_U64 },
};

TEEC_Result GetPropertyFromUnIntMap(TEEC_Context *context, TEEC_Session *session, TestData *val, int *flag)
{
    TEEC_Result result;
    int i;

    for (i = 0; i < (sizeof(g_unIntMap) / sizeof(g_unIntMap[0])); i++) {
        if (strncmp(val->inBuffer, g_unIntMap[i].name, val->inBufferLen) == 0) {
            *flag = 1;
            val->cmd = g_unIntMap[i].cmd;
            result = Invoke_GetPropertyAsX(context, session, val);
            if (result != TEEC_SUCCESS || val->origin != TEEC_ORIGIN_TRUSTED_APP) {
                TEST_PRINT_ERROR("getProperty from Enumerator with %s is fail! result = 0x%x\n", val->inBuffer, result);
                return result;
            }
            if (val->cmd != CMD_TEE_GetPropertyAsUUID) {
                if (val->outBufferLen != g_unIntMap[i].expectLen ||
                    (strncmp(val->outBuffer, g_unIntMap[i].expectResult, g_unIntMap[i].expectLen) != 0)) {
                    TEST_PRINT_ERROR("getProperty from Enumerator with %s is fail! outlen=0x%x, expect outlen=0x%x\n",
                        val->inBuffer, val->outBufferLen, g_unIntMap[i].expectLen);
                    TEST_PRINT_ERROR("outbuffer=%s, expect outbuffer=%s\n", val->outBuffer, g_unIntMap[i].expectResult);
                    return TEEC_ERROR_GENERIC;
                }
            }
            return result;
        }
    }
    return TEEC_SUCCESS;
}

TEEC_Result GetPropertyFromIntMap(TEEC_Context *context, TEEC_Session *session, TestData *val, int *flag)
{
    TEEC_Result result;
    int i;

    for (i = 0; i < (sizeof(g_intMap) / sizeof(g_intMap[0])); i++) {
        if (strncmp(val->inBuffer, g_intMap[i].name, val->inBufferLen) == 0) {
            *flag = 1;
            val->cmd = g_intMap[i].cmd;
            result = Invoke_GetPropertyAsX(context, session, val);
            if (result != TEEC_SUCCESS || val->origin != TEEC_ORIGIN_TRUSTED_APP) {
                TEST_PRINT_ERROR("getProperty from Enumerator with %s is fail! result = 0x%x\n", val->inBuffer, result);
                return result;
            }
            if (val->cmd == CMD_TEE_GetPropertyAsU32) {
                if (atoi(val->outBuffer) != (uint32_t)g_intMap[i].expectResult) {
                    TEST_PRINT_ERROR("getProperty from Enumerator with %s is fail! out=0x%x, expect out=0x%x\n",
                        val->inBuffer, atoi(val->outBuffer), (uint32_t)g_intMap[i].expectResult);
                    return TEEC_ERROR_GENERIC;
                }
            } else {
                if (atoll(val->outBuffer) != g_intMap[i].expectResult) {
                    TEST_PRINT_ERROR("getProperty from Enumerator with %s is fail! out=0x%llx, expect out=0x%llu\n",
                        val->inBuffer, atoll(val->outBuffer), g_intMap[i].expectResult);
                    return TEEC_ERROR_GENERIC;
                }
            }
            return result;
        }
    }
    return TEEC_SUCCESS;
}

/**
 * @testcase.name      : TEE_GetProperty_WithEnum_TEE_PROPSET_CURRENT_TA
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator, TEE_StartPropertyEnumerator, TEE_GetPropertyName,
 * TEE_GetNextProperty and TEE_GetPropertyAsX API to get all kinds of property from Enumerator for
 * TEE_PROPSET_CURRENT_TA
 * @testcase.expect    : process success
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetProperty_WithEnum_TEE_PROPSET_CURRENT_TA, Function | MediumTest | Level0)
{
    TEEC_Result result, ret;
    int rc, count = 0, findFlag = 0;

    // start PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_StartPropertyEnumerator;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    do {
        value.cmd = CMD_TEE_GetPropertyNameEnumerator;
        value.outBufferLen = BIG_SIZE;
        result = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        if ((count != 0) && (result == TEEC_ERROR_ITEM_NOT_FOUND))
            break;
        ASSERT_EQ(result, TEEC_SUCCESS);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
        rc = memcpy_s(value.inBuffer, BIG_SIZE, value.outBuffer, value.outBufferLen);
        value.inBufferLen = value.outBufferLen;
        ASSERT_EQ(rc, 0);
        count++;

        ret = GetPropertyFromUnIntMap(GetContext(), GetSession(), &value, &findFlag);
        ASSERT_EQ(ret, TEEC_SUCCESS);

        if (findFlag != 1) {
            ret = GetPropertyFromIntMap(GetContext(), GetSession(), &value, &findFlag);
            ASSERT_EQ(ret, TEEC_SUCCESS);
        }

        if (findFlag == 0) {
            TEST_PRINT_ERROR("get PropertyName from Enumerator is undefined!\n");
            ASSERT_FALSE(1);
        }

        value.cmd = CMD_TEE_GetNextPropertyEnumerator;
        Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        findFlag = 0;
    } while (result != TEEC_ERROR_ITEM_NOT_FOUND);
}

/**
 * @testcase.name      : TEE_GetProperty_WithEnum_TEE_PROPSET_CURRENT_CLIENT
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator, TEE_StartPropertyEnumerator, TEE_GetPropertyName,
 * TEE_GetNextProperty and TEE_GetPropertyAsX API to get all kinds of property from Enumerator for
 * TEE_PROPSET_CURRENT_CLIENT
 * @testcase.expect    : process success
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetProperty_WithEnum_TEE_PROPSET_CURRENT_CLIENT, Function | MediumTest | Level0)
{
    TEEC_Result result, ret;
    int rc, count = 0, findFlag = 0;

    // start PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_StartPropertyEnumerator;
    value.propSet = TEE_PROPSET_CURRENT_CLIENT;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    do {
        value.cmd = CMD_TEE_GetPropertyNameEnumerator;
        value.outBufferLen = BIG_SIZE;
        result = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        if ((count != 0) && (result == TEEC_ERROR_ITEM_NOT_FOUND))
            break;
        ASSERT_EQ(result, TEEC_SUCCESS);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
        rc = memcpy_s(value.inBuffer, BIG_SIZE, value.outBuffer, value.outBufferLen);
        value.inBufferLen = value.outBufferLen;
        ASSERT_EQ(rc, 0);
        count++;

        ret = GetPropertyFromUnIntMap(GetContext(), GetSession(), &value, &findFlag);
        ASSERT_EQ(ret, TEEC_SUCCESS);

        if (findFlag != 1) {
            ret = GetPropertyFromIntMap(GetContext(), GetSession(), &value, &findFlag);
            ASSERT_EQ(ret, TEEC_SUCCESS);
        }

        if (findFlag == 0) {
            TEST_PRINT_ERROR("get PropertyName from Enumerator is undefined!\n");
            ASSERT_FALSE(1);
        }

        value.cmd = CMD_TEE_GetNextPropertyEnumerator;
        Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        findFlag = 0;
    } while (result != TEEC_ERROR_ITEM_NOT_FOUND);
}

/**
 * @testcase.name      : TEE_GetProperty_WithEnum_TEE_PROPSET_IMPLEMENTATION
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator, TEE_StartPropertyEnumerator, TEE_GetPropertyName,
 * TEE_GetNextProperty and TEE_GetPropertyAsX API to get all kinds of property from Enumerator for
 * TEE_PROPSET_IMPLEMENTATION
 * @testcase.expect    : process success
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetProperty_WithEnum_TEE_PROPSET_IMPLEMENTATION, Function | MediumTest | Level0)
{
    TEEC_Result result, ret;
    int rc, count = 0, findFlag = 0;

    // start PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_StartPropertyEnumerator;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    do {
        value.cmd = CMD_TEE_GetPropertyNameEnumerator;
        value.outBufferLen = BIG_SIZE;
        result = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        if ((count != 0) && (result == TEEC_ERROR_ITEM_NOT_FOUND))
            break;
        ASSERT_EQ(result, TEEC_SUCCESS);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
        rc = memcpy_s(value.inBuffer, BIG_SIZE, value.outBuffer, value.outBufferLen);
        value.inBufferLen = value.outBufferLen;
        ASSERT_EQ(rc, 0);
        count++;

        ret = GetPropertyFromUnIntMap(GetContext(), GetSession(), &value, &findFlag);
        ASSERT_EQ(ret, TEEC_SUCCESS);

        if (findFlag != 1) {
            ret = GetPropertyFromIntMap(GetContext(), GetSession(), &value, &findFlag);
            ASSERT_EQ(ret, TEEC_SUCCESS);
        }

        if (findFlag == 0) {
            TEST_PRINT_ERROR("get PropertyName from Enumerator is undefined!\n");
            ASSERT_FALSE(1);
        }

        value.cmd = CMD_TEE_GetNextPropertyEnumerator;
        Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        findFlag = 0;
    } while (result != TEEC_ERROR_ITEM_NOT_FOUND);
}

/**
 * @testcase.name      : TEE_GetProperty_WithEnum_WithResetEnum
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator , TEE_StartPropertyEnumerator,
 * TEE_ResetPropertyEnumerator, TEE_GetPropertyName, TEE_GetNextProperty and TEE_GetPropertyAsX
 * API to get all kinds of property from Enumerator for TEE_PROPSET_CURRENT_CLIENT
 * @testcase.expect    : process success
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetProperty_WithEnum_WithResetEnum, Function | MediumTest | Level0)
{
    TEEC_Result result, ret;
    int rc, count = 0, findFlag = 0;

    // start PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_StartPropertyEnumerator;
    value.propSet = TEE_PROPSET_CURRENT_CLIENT;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    do {
        value.cmd = CMD_TEE_GetPropertyNameEnumerator;
        value.outBufferLen = BIG_SIZE;
        result = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        if ((count != 0) && (result == TEEC_ERROR_ITEM_NOT_FOUND))
            break;
        ASSERT_EQ(result, TEEC_SUCCESS);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
        rc = memcpy_s(value.inBuffer, BIG_SIZE, value.outBuffer, value.outBufferLen);
        value.inBufferLen = value.outBufferLen;
        ASSERT_EQ(rc, 0);
        count++;

        ret = GetPropertyFromUnIntMap(GetContext(), GetSession(), &value, &findFlag);
        ASSERT_EQ(ret, TEEC_SUCCESS);

        if (findFlag != 1) {
            ret = GetPropertyFromIntMap(GetContext(), GetSession(), &value, &findFlag);
            ASSERT_EQ(ret, TEEC_SUCCESS);
        }

        if (findFlag == 0) {
            TEST_PRINT_ERROR("get PropertyName from Enumerator is undefined!\n");
            ASSERT_FALSE(1);
        }

        value.cmd = CMD_TEE_GetNextPropertyEnumerator;
        Invoke_Operate_PropertyEnumerator(GetSession(), &value);
        findFlag = 0;
    } while (result != TEEC_ERROR_ITEM_NOT_FOUND);

    // reset PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_ResetPropertyEnumerator;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    // get PropertyEnumerator after reset
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.outBufferLen = BIG_SIZE;
    result = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(result, TEEC_ERROR_ITEM_NOT_FOUND);
}

/**
 * @testcase.name      : TEE_AllocatePropertyEnumerator_EnumIsNull
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator while Enumerator is NULL
 * property from TEE_PROPSET_CURRENT_TA
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TCF1Test, TEE_AllocatePropertyEnumerator_EnumIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };
    value.cmd = CMD_TEE_AllocatePropertyEnumerator;
    value.caseId = OUTPUT_ISNULL;
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_AllocatePropertyEnumerator_MaxEnum
 * @testcase.desc      : test TA call TEE_AllocatePropertyEnumerator alloc PropertyEnumerator reach max numbers limit
 * property from TEE_PROPSET_CURRENT_TA
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF1Test, TEE_AllocatePropertyEnumerator_MaxEnum, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };
    value.cmd = CMD_TEE_AllocatePropertyEnumerator;

    for (int i = 1; i <= MAX_ENUMERATOR; i++) {
        ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
        ASSERT_EQ(ret, TEEC_SUCCESS);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    }

    // then alloc 1024th Enumerator,should fail
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.enumerator, 0);

    // intend to free enumerator which NO is MAX_ENUMERATOR
    value.enumerator = MAX_ENUMERATOR;
    value.cmd = CMD_TEE_FreePropertyEnumerator;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    value.cmd = CMD_TEE_AllocatePropertyEnumerator;
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.enumerator, MAX_ENUMERATOR);
}

/**
 * @testcase.name      : TEE_GetPropertyName_BufferIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyName while output buffer is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetPropertyName_BufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    // get Property from Enumerator
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.caseId = OUTPUT_ISNULL;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyName_BufferSizeIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyName while output buffer size is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetPropertyName_BufferSizeIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    // get Property from Enumerator
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.caseId = OUTPUTBUFFERSIZE_ISNULL;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyName_BufferSizeTooShort
 * @testcase.desc      : test TA call TEE_GetPropertyName while output buffer size too short
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TCF1ENUM_Test, TEE_GetPropertyName_BufferSizeTooShort, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    // start PropertyEnumerator this api has no return value
    value.cmd = CMD_TEE_StartPropertyEnumerator;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);

    // get Property from Enumerator
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.caseId = OUTPUTBUFFERSIZE_TOOSHORT;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyName_EnumeratorNotAlloc
 * @testcase.desc      : test TA call TEE_GetPropertyName while Enumerator is not alloc
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyName_EnumeratorNotAlloc, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };

    // get Property from Enumerator
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.enumerator = ENUMERATOR1;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    EXPECT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyName_EnumeratorNotStart
 * @testcase.desc      : test TA call TEE_GetPropertyName while Enumerator is not start
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyName_EnumeratorNotStart, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };

    // alloc PropertyEnumerator
    value.cmd = CMD_TEE_AllocatePropertyEnumerator;
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(value.enumerator, ENUMERATOR1);

    // get Property from Enumerator
    value.cmd = CMD_TEE_GetPropertyNameEnumerator;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    EXPECT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);

    value.cmd = CMD_TEE_FreePropertyEnumerator;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);
}

/**
 * @testcase.name      : TEE_GetNextProperty_EnumeratorNotAlloc
 * @testcase.desc      : test TA call TEE_GetPropertyName while Enumerator is not alloc
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetNextProperty_EnumeratorNotAlloc, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };

    // get next Property from Enumerator
    value.cmd = CMD_TEE_GetNextPropertyEnumerator;
    value.enumerator = ENUMERATOR1;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    EXPECT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetNextProperty_EnumeratorNotStart
 * @testcase.desc      : test TA call TEE_GetPropertyName while Enumerator is not start
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetNextProperty_EnumeratorNotStart, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestData value = { 0 };

    // alloc PropertyEnumerator
    value.cmd = CMD_TEE_AllocatePropertyEnumerator;
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(value.enumerator, ENUMERATOR1);

    // get next Property from Enumerator
    value.cmd = CMD_TEE_GetNextPropertyEnumerator;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_Operate_PropertyEnumerator(GetSession(), &value);
    EXPECT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    EXPECT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);

    value.cmd = CMD_TEE_FreePropertyEnumerator;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);
}

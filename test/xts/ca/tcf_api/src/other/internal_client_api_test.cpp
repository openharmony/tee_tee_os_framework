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
#include <session_mgr/client_session_mgr.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_defines.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;

static char g_teeOutput[] = "TEEMEM_OUTPUT";
static char g_teeInout[] = "the param is TEEMEM_INOUT";
static uint32_t g_teeOutputLen;
static uint32_t g_teeInoutLen;

/**
 * @testcase.name      : TEE_OpenTASession_With_Success
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_Success, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = 0;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    g_teeInoutLen = strlen(g_teeInout) + 1;

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    ASSERT_STREQ(value.inBuffer, g_teeInout);
    ASSERT_EQ(value.inBufferLen, g_teeInoutLen);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_UUIDIsNULL
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while uuid is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_UUIDIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = INPUT_ISNULL;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_OriginIsNULL
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while origin is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_OriginIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = RETURNORIGIN_ISNULL;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_NE(ta2taSession, 0);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_SessionIsNULL
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while session is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_SessionIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = OUTPUT_ISNULL;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_NoAvailableSession
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while session is null
 * @testcase.expect    : return TEEC_ERROR_ACCESS_CONFLICT
 */
TEE_TEST(TeeTCF1Test, TEE_OpenTASession_With_NoAvailableSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = 0;

    value.uuid = TCF_API_UUID_2; // this uuid is for ta2, this is a single session ta
    ClientSessionMgr sess;
    ret = sess.Start(&value.uuid);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    sess.Destroy();
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_CONFLICT);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_MaxSession
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA to reach max session
 * @testcase.expect    : return TEEC_ERROR_SESSION_MAXIMUM
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_MaxSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession[8] = { 0 };
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = 0;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    int i;
    value.inBufferLen = BIG_SIZE;

    for (i = 0; i <= 6; i++) {
        ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[i], &value, &origin);
        ASSERT_EQ(ret, TEEC_SUCCESS);
        ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
        ASSERT_NE(ta2taSession[i], 0);
        if (i >= 1)
            ASSERT_NE(ta2taSession[i], ta2taSession[i - 1]);
    }

    // ta2 has reach max session,so this time will open session fail
    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[i], &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_SESSION_MAXIMUM);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(ta2taSession[i], 0);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_UUIDIsNotExist
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while uuid is not exist
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_UUIDIsNotExist, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = 0;
    value.uuid = UUID_TA_NOT_EXIST; // this uuid is for ta2

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_OpenTASession_With_TA2Crash
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while ta2 is crashed
 * @testcase.expect    : return TEEC_ERROR_TARGET_DEAD
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_TA2Crash, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.caseId = TA_CRASH_FLAG;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2

    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_TARGET_DEAD);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
#else
    ASSERT_EQ(ret, TEEC_SUCCESS);
#endif
}

/**
 * @testcase.name      : TEE_OpenTASession_With_BufferNoFillNoShare
 * @testcase.desc      : test TA call TEE_OpenTASession to call other TA while buffer hint is
 * TEE_MALLOC_NO_FILL|TEE_MALLOC_NO_SHARE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_OpenTASession_With_BufferNoFillNoShare, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    g_teeInoutLen = strlen(g_teeInout) + 1;

    value.caseId = BUFFER_NOFILLNOSHARE;
    value.inBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    ASSERT_STREQ(value.inBuffer, g_teeInout);
    ASSERT_EQ(value.inBufferLen, g_teeInoutLen);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CloseTASession_With_MaxSession
 * @testcase.desc      : test TA call TEE_CloseTASession when TA to reach max session, then can open new session to ta2
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_CloseTASession_With_MaxSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession[8] = { 0 };
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    int i;
    value.inBufferLen = BIG_SIZE;

    for (i = 0; i <= 6; i++) {
        ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[i], &value, &origin);
        ASSERT_EQ(ret, TEEC_SUCCESS);
        ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
        ASSERT_NE(ta2taSession[i], 0);
        if (i >= 1)
            ASSERT_NE(ta2taSession[i], ta2taSession[i - 1]);
    }

    // ta2 has reach max session,so this time will open session fail
    value.inBufferLen = BIG_SIZE;
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[7], &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_SESSION_MAXIMUM);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(ta2taSession[7], 0);

    // close one session of ta2
    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession[6], &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    // ta2 has close one session, so this time will open session success
    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[6], &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession[6], 0);
}

/**
 * @testcase.name      : TEE_InvokeTACommand_With_PARAM_TYPE_MEMREF
 * @testcase.desc      : test TA call TEE_InvokeTACommand to pass memref params to other TA
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_PARAM_TYPE_MEMREF, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    (void)memset_s(value.inBuffer, BIG_SIZE, 0x41, BIG_SIZE);

    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);

    ASSERT_STREQ(value.inBuffer, g_teeInout);
    ASSERT_EQ(value.inBufferLen, g_teeInoutLen);
    ASSERT_STREQ(value.outBuffer, g_teeOutput);
    ASSERT_EQ(value.outBufferLen, g_teeOutputLen);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_InvokeTACommand_With_SessionIsNull
 * @testcase.desc      : test TA call TEE_InvokeTACommand to other TA while session is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_SessionIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    value.caseId = INPUT_ISNULL;
    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_InvokeTACommand_With_OriginIsNull
 * @testcase.desc      : test TA call TEE_InvokeTACommand to other TA while origin is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_OriginIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    value.caseId = OUTPUT_ISNULL;
    (void)memset_s(value.inBuffer, BIG_SIZE, 0x41, BIG_SIZE);
    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ASSERT_STREQ(value.inBuffer, g_teeInout);
    ASSERT_EQ(value.inBufferLen, g_teeInoutLen);
    ASSERT_STREQ(value.outBuffer, g_teeOutput);
    ASSERT_EQ(value.outBufferLen, g_teeOutputLen);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_InvokeTACommand_With_TA2Crash
 * @testcase.desc      : test TA call TEE_InvokeTACommand to other TA while ta2 is crash
 * @testcase.expect    : return TEEC_ERROR_TARGET_DEAD
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_TA2Crash, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    value.caseId = TA_CRASH_FLAG;
    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_TARGET_DEAD);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
#else
    ASSERT_EQ(ret, TEEC_SUCCESS);
#endif

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

#ifdef TEST_BLOCK
/**
 * @testcase.name      : TEE_InvokeTACommand_With_MaxShareBufferSize
 * @testcase.desc      : test TA call TEE_InvokeTACommand to pass memref to other TA while buffer size is MAX_SHARE_SIZE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_MaxShareBufferSize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    value.caseId = BUFFERSIZE_ISTOOBIG;
    value.outBufferLen = BIG_SIZE;
    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}
#endif
/**
 * @testcase.name      : TEE_InvokeTACommand_With_BufferNoFillNoShare
 * @testcase.desc      : test TA call TEE_InvokeTACommand to pass memref to TA2 while buffer hint is
 * TEE_MALLOC_NO_FILL|TEE_MALLOC_NO_SHARE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_BufferNoFillNoShare, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    value.caseId = BUFFER_NOFILLNOSHARE;
    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);

    ASSERT_STREQ(value.inBuffer, g_teeInout);
    ASSERT_EQ(value.inBufferLen, g_teeInoutLen);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

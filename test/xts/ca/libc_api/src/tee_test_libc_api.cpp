/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>
#include <public_test.h>
#include <test_log.h>
#include <securec.h>
#include <common_test.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <session_mgr/client_session_mgr.h>

using namespace testing::ext;

/**
 * @testcase.name      : CasePthreadAttr
 * @testcase.desc      : run case CasePthreadAttr
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CasePthreadAttr, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PTHREAD_ATTR, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CasePthreadBaseFunc
 * @testcase.desc      : run case CasePthreadBaseFunc
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CasePthreadBaseFunc, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PTHREAD_BASE_FUNC, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CasePthreadMutexLock
 * @testcase.desc      : run case CasePthreadMutexLock
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CasePthreadMutexLock, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PTHREAD_MUTEX_LOCK, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CasePthreadSpinLock
 * @testcase.desc      : run case CasePthreadSpinLock
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CasePthreadSpinLock, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PTHREAD_SPIN_LOCK, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CasePthreadCond
 * @testcase.desc      : run case CasePthreadCond
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CasePthreadCond, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PTHREAD_COND, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseSem
 * @testcase.desc      : run case CaseSem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseSem, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_SEM, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseApplyAndFreeMem
 * @testcase.desc      : run case CaseApplyAndFreeMem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseApplyAndFreeMem, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_APPLY_AND_FREE_MEM, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseMmapAndMunmap
 * @testcase.desc      : run case CaseMmapAndMunmap
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseMmapAndMunmap, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_MMAP_AND_MUNMAP, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcMath
 * @testcase.desc      : run case CaseLibcMath
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcMath, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_MATH, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcStdlib
 * @testcase.desc      : run case CaseLibcStdlib
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcStdlib, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_STDLIB, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcCtype
 * @testcase.desc      : run case CaseLibcCtype
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcCtype, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_CTYPE, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcTime
 * @testcase.desc      : run case CaseLibcTime
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_TIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcStdio
 * @testcase.desc      : run case CaseLibcStdio
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcStdio, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_STDIO, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcError
 * @testcase.desc      : run case CaseLibcError
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcError, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_ERROR, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcUnistd
 * @testcase.desc      : run case CaseLibcUnistd
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcUnistd, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_UNISTD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcLocale
 * @testcase.desc      : run case CaseLibcLocale
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcLocale, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_LOCALE, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcMultiByte
 * @testcase.desc      : run case CaseLibcMultiByte
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcMultiByte, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_MULTIBYTE, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcPrng
 * @testcase.desc      : run case CaseLibcPrng
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcPrng, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_PRNG, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : CaseLibcString
 * @testcase.desc      : run case CaseLibcString
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, CaseLibcString, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = LIBC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_LIBC_STRING, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}
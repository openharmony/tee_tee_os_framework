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
 * @testcase.name      : BigInt_ComputeFMM
 * @testcase.desc      : test TEE_BigIntComputeFMM api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ComputeFMM, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_COMPUTE_FMM, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_InitFMMContext
 * @testcase.desc      : test initialize context for FMM
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_InitFMMContext, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_INIT_FMM_CONTEXT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ConverterBetweenBigIntAndFMM
 * @testcase.desc      : test converter between big int and FMM
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ConverterBetweenBigIntAndFMM, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_FMM, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ComputeExpMod
 * @testcase.desc      : test TEE_BigIntExpMod api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ComputeExpMod, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_EXP_MOD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ConverterBetweenBigIntAndOctetString
 * @testcase.desc      : test converter between big int and octet string
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ConverterBetweenBigIntAndOctetString, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_OCTET_STRING, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ComputeExpMod
 * @testcase.desc      : test converter between big int and shortVal
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ConverterBetweenBigIntAndShortVal, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_S32, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_AddAndSubMod
 * @testcase.desc      : test compute add and sub mod
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_AddAndSubMod, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_ADD_AND_SUB_MOD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_MulAndInvMod
 * @testcase.desc      : test compute mul, square and inv mod
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_MulAndInvMod, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_MUL_AND_INV_MOD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_InitMod
 * @testcase.desc      : test TEE_BigIntMod api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_InitMod, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_MOD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_AddAndSub
 * @testcase.desc      : test add and sub
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_AddAndSub, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_ADD_AND_SUB, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_Neg
 * @testcase.desc      : test negate
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_Neg, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_NEG, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_MulAndSquare
 * @testcase.desc      : test mul and square
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_MulAndSquare, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_MUL_AND_SQUARE, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_div
 * @testcase.desc      : test div
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_div, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_DIV, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ShiftRight
 * @testcase.desc      : test shift right
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ShiftRight, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_SHIFT_RIGHT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_GetBit
 * @testcase.desc      : test get bit
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_GetBit, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_GET_BIT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_GetBitCount
 * @testcase.desc      : test get bit counts
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_GetBitCount, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_GET_BIT_COUNT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_SetBit
 * @testcase.desc      : test set bit
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_SetBit, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_SET_BIT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_AssignSrcToDest
 * @testcase.desc      : test TEE_BigIntAssign api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_AssignSrcToDest, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_ASSIGN, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_Abs
 * @testcase.desc      : test abs
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_Abs, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_ABS, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_RelativePrime
 * @testcase.desc      : test Relative Prime
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_RelativePrime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_RELATIVE_PRIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ComputeExtendedGcd
 * @testcase.desc      : test compute extended gcd
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ComputeExtendedGcd, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_COMPUTE_EXTENTED_GCD, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_ProbabilisticPrimality
 * @testcase.desc      : test probabilistic primality
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_ProbabilisticPrimality, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_IS_PROBABLE_PRIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_Compare
 * @testcase.desc      : test comparison
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_Compare, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_CMP, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_CompareWithShortVal
 * @testcase.desc      : test comparison with shortVal
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_CompareWithShortVal, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_CMP_S32, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_InitializeFMM
 * @testcase.desc      : test initialize bigIntFMM
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_InitializeFMM, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_INIT_FMM, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : BigInt_InitializeBigInt
 * @testcase.desc      : test initialize bigInt
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, BigInt_InitializeBigInt, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_BIG_INT_INIT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}
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
 * @testcase.name      : Test_SEAPI
 * @testcase.desc      : test TEE_SEServiceOpen, TEE_SEServiceClose, TEE_SEServiceGetReaders, TEE_SEReaderGetProperties,
 *                       TEE_SEReaderGetName, TEE_SEReaderOpenSession, TEE_SEReaderCloseSessions, TEE_SESessionGetATR,
 *                       TEE_SESessionIsClosed, TEE_SESessionClose, TEE_SESessionCloseChannels, 
 *                       TEE_SESessionOpenBasicChannel, TEE_SESessionOpenLogicalChannel, TEE_SEChannelClose,
 *                       TEE_SEChannelGetSelectResponse, TEE_SEChannelTransmit, TEE_SEChannelGetID API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_SEAPI, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_SE_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : Test_SEChannelSelectNext
 * @testcase.desc      : test TEE_SEChannelSelectNext API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_SEChannelSelectNext, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_SECHANNELSELECTNEXT_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : Test_SESECURECHANNELOPENCLOSE
 * @testcase.desc      : test TEE_SESecureChannelOpen, TEE_SESecureChannelClose API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_SESECURECHANNELOPENCLOSE, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_SESECURECHANNELOPENCLOSE_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : Test_TUIAPI
 * @testcase.desc      : test TEE_TUIInitSession, TEE_TUICloseSession, TEE_TUICheckTextFormat, TEE_TUIGetScreenInfo,
 *                       TEE_TUIDisplayScreen, TEE_TUINotify_fp, TEE_TUISetInfo, TEE_TUISendEvent, TEE_TUISetLabel API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_TUIAPI, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_TUI_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : Test_RPMBAPI
 * @testcase.desc      : test TEE_RPMB_FS_Init, TEE_RPMB_FS_Format, TEE_RPMB_FS_Write, TEE_RPMB_FS_Read,
 *                       TEE_RPMB_FS_Rename, TEE_RPMB_FS_Rm, TEE_RPMB_FS_Stat, TEE_RPMB_FS_StatDisk, 
 *                       TEE_RPMB_FS_SetAttr, TEE_RPMB_FS_Erase, TEE_RPMB_KEY_Status, 
 *                       tee_ext_rpmb_driver_write, tee_ext_rpmb_driver_read, tee_ext_rpmb_driver_remove API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_RPMBAPI, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_RPMB_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : Test_HUKAPI
 * @testcase.desc      : test tee_hal_get_provision_key, tee_ext_get_device_unique_id, tee_ext_derive_key_iter,
 *                       tee_ext_derive_key_iter_by_huk2, TEE_EXT_DeriveTARootKey, tee_ext_derive_ta_root_key_by_huk2, 
 *                       tee_ext_root_derive_key2_by_huk2, tee_ext_root_uuid_derive_key_by_huk2 API
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, Test_HUKAPI, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = DEVICE_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_HUK_API, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}
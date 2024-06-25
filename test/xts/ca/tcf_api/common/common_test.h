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

#ifndef __TCF_COMMON_TEST_H__
#define __TCF_COMMON_TEST_H__

#include <gtest/gtest.h>
#include <stdint.h>
#include <tee_client_type.h>

#define TESTSIZE 16
#define BIG_SIZE 1024
#define MAX_SHARE_SIZE 0x100000

#define ENUMERATOR1 1
#define MAX_ENUMERATOR 1023

#define EXPECTBUFFER_ZERO ""
#define EXPECTBUFFER_A "AAAAAAAAAAAAAAAA"
#define EXPECTBUFFER_A_LESS "AAAAAAAAAAAAAAA"
#define EXPECTBUFFER_B "BBBBBBBBBBBBBBBB"
#define EXPECTBUFFER_OVERLAP "AAAAAAAAABBBBBBB"

// ALL_PROPERTY_NAMES
#define GPD_CLIENT_IDENTITY "gpd.client.identity"
#define GPD_CLIENT_ENDIAN "gpd.client.endian"
#define GPD_TA_APPID "gpd.ta.appID"
#define GPD_TA_SERVICENAME "gpd.ta.service_name"
#define GPD_TA_DATASIZE "gpd.ta.dataSize"
#define GPD_TA_INSTANCEKEEPALIVE "gpd.ta.instanceKeepAlive"
#define GPD_TA_MULTISESSION "gpd.ta.multiSession"
#define GPD_TA_SINGLEINSTANCE "gpd.ta.singleInstance"
#define GPD_TA_STACKSIZE "gpd.ta.stackSize"
#define GPD_TA_VERSION "gpd.ta.version"
#define GPD_TA_DESCRIPTION "gpd.ta.description"
#define GPD_TA_ENDIAN "gpd.ta.endian"
#define GPD_TEE_ARITH_MAXBIGINTSIZE "gpd.tee.arith.maxBigIntSize"
#define GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL "gpd.tee.systemTime.protectionLevel"
#define GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL "gpd.tee.TAPersistentTime.protectionLevel"
#define GPD_TEE_APIVERSION "gpd.tee.apiversion"
#define GPD_TEE_INTERNALCORE_VERSION "gpd.tee.internalCore.version"
#define GPD_TEE_DESCRIPTION "gpd.tee.description"
#define GPD_TEE_DEVICEID "gpd.tee.deviceID"
#define GPD_TEE_CRYPTOGRAPHY_ECC "gpd.tee.cryptography.ecc"
#define GPD_TEE_CRYPTOGRAPHY_NIST "gpd.tee.cryptography.nist"
#define GPD_TEE_CRYPTOGRAPHY_BSI_R "gpd.tee.cryptography.bsi-r"
#define GPD_TEE_CRYPTOGRAPHY_BSI_T "gpd.tee.cryptography.bsi-t"
#define GPD_TEE_CRYPTOGRAPHY_IETF "gpd.tee.cryptography.ietf"
#define GPD_TEE_CRYPTOGRAPHY_OCTA "gpd.tee.cryptography.octa"
#define GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL "gpd.tee.trustedStorage.antiRollback.protectionLevel"
#define GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL "gpd.tee.trustedStorage.rollbackDetection.protectionLevel"
#define GPD_TEE_TRUSTEDOS_IMP_VERSION "gpd.tee.trustedos.implementation.version"
#define GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION "gpd.tee.trustedos.implementation.binaryversion"
#define GPD_TEE_TRUSTEDOS_MANUFACTURER "gpd.tee.trustedos.manufacturer"
#define GPD_TEE_FIRMWARE_IMP_VERSION "gpd.tee.firmware.implementation.version"
#define GPD_TEE_FIRMWARE_IMP_BINARYVERSION "gpd.tee.firmware.implementation.binaryversion"
#define GPD_TEE_FIRMWARE_MANUFACTURER "gpd.tee.firmware.manufacturer"
#define GPD_TEE_EVENT_MAXSOURCES "gpd.tee.event.maxSources"
#define GPD_TEE_API_LEVEL "gpd.tee.api_level"
#define PROPERTY_NAME_UNKNOWN "unknown"
#define SMC_TA_TESTBINARYBLOCK "smc.ta.testbinaryblock"
#define SMC_TA_TESTIDENTITY "smc.ta.identity"
#define SMC_TA_TESTU64 "smc.ta.testu64"

// ALL_PROPERTY_VALUES
#define VALUE_PREDEFINED_BINARY_BLOCK "VGhpcy"
#define VALUE_PREDEFINED_SERVICENAME "TCF_test"
#define VALUE_PREDEFINED_BOOLEAN "true"
#define VALUE_PREDEFINED_FALSE "false"
#define VALUE_PREDEFINED_DATASIZE 819200
#define VALUE_PREDEFINED_STACKSIZE 81920
#define VALUE_PREDEFINED_TA_VERSION "0"
#define VALUE_PREDEFINED_TA_DESCRIPTION "test ta"
#define VALUE_PREDEFINED_CLIENT_IDENTITY "identity:0:00000000-0000-0000-6100-000000000000"
#define VALUE_PREDEFINED_CLIENT_ENDIAN 0
#define VALUE_PREDEFINED_STRING "test string"
#define VALUE_PREDEFINED_U64 5147483647
#define VALUE_PREDEFINED_UUID "534d4152-542d-4353-4c54-d3016a171f01"

#define TEE_INTERNAL_CORE_MAJOR_VERSION 1
#define TEE_INTERNAL_CORE_MINOR_VERSION 2
#define TEE_INTERNAL_CORE_MAINTENANCE_VERSION 0
#define TEE_INTERNAL_CORE_RESERVED_VERSION 0
// TEE_API_VERSION should match with TEE_INTERNAL_CORE_VERSION
#define TEE_API_VERSION "v1.2.0"
#define TEE_INTERNAL_CORE_VERSION                                                        \
    ((TEE_INTERNAL_CORE_MAJOR_VERSION << 24) | (TEE_INTERNAL_CORE_MINOR_VERSION << 16) | \
        (TEE_INTERNAL_CORE_MAINTENANCE_VERSION << 8) | TEE_INTERNAL_CORE_RESERVED_VERSION)
#define TEE_BUILD_VER "B309"
#define TEE_IMP_VERSION "TEE-1.0.0"
#define TEE_MANUFACTURER "TEE"
#define TEE_FIRMWARE_IMP_VERSION "TEE-1.0."
#define TEE_FIRMWARE_MANUFACTURER "TEE"
#define TEE_TIME_PROTECT_LEVEL 100
#define TA_TIME_PROTECT_LEVEL 100
#define MAX_BIG_INT_SIZE 32
#define API_LEVEL1_2 3
#define CIPHER_LAYER_VERSION 3
#define TEE_MAX_API_LEVEL_CONFIG ((CIPHER_LAYER_VERSION << 16) | API_LEVEL1_2)

#define SESSION_FROM_UNKNOWN 0xff

typedef enum {
    TEE_PROPSET_CURRENT_CLIENT = 0xFFFFFFFE,
    TEE_PROPSET_CURRENT_TA = 0xFFFFFFFF,
    TEE_PROPSET_IMPLEMENTATION = 0xFFFFFFFD,
    TEE_PROPSET_ZERO = 0x0,
} ALL_PROP_SETS;

typedef struct {
    uint32_t login;
    TEEC_UUID uuid;
} TEEC_Identity;

#define TCF_API_UUID_1                                     \
    {                                                      \
        0x534d4152, 0x542d, 0x4353,                        \
        {                                                  \
            0x4c, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x01 \
        }                                                  \
    }

#define TCF_API_UUID_2                                     \
    {                                                      \
        0x534D4152, 0x542D, 0x4353,                        \
        {                                                  \
            0x4C, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x02 \
        }                                                  \
    }

#define UUID_TA_NOT_EXIST                                  \
    {                                                      \
        0x534D4152, 0x542D, 0x4353,                        \
        {                                                  \
            0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x5B \
        }                                                  \
    }

struct TestData {
    uint32_t cmd;
    uint32_t caseId;
    ALL_PROP_SETS propSet;
    uint32_t enumerator;
    uint32_t origin;
    char inBuffer[BIG_SIZE];
    uint32_t inBufferLen;
    char outBuffer[BIG_SIZE];
    uint32_t outBufferLen;
    TEEC_UUID uuid;
};
typedef struct TestData TestData;

struct TestMemData {
    size_t oldSize;
    size_t newSize;
    uint32_t oldAddr;
    uint32_t newAddr;
    uint32_t caseId;
    uint32_t origin;
    uint32_t accessFlags;
    size_t inMemSize;
    uint32_t inHint;
    char *testBuffer;
};
typedef struct TestMemData TestMemData;

typedef enum {
    HINT_RESERVE = 0x80000000,
    TEE_MALLOC_FILL_ZERO = 0,
    TEE_MALLOC_NO_FILL = 1,
    TEE_MALLOC_NO_SHARE = 2,
} ALL_MEMORY_HINTS;

#define TEE_MEMORY_ACCESS_READ 0x00000001
#define TEE_MEMORY_ACCESS_WRITE 0x00000002
#define TEE_MEMORY_ACCESS_ANY_OWNER 0x00000004

class TCF1Test : public ::testing::Test {
private:
    static TEEC_Context context;
    static TEEC_Session session;

public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    TEEC_Context *GetContext()
    {
        return &TCF1Test::context;
    }
    TEEC_Session *GetSession()
    {
        return &TCF1Test::session;
    }
    void SetUp();
    void TearDown();
};

class TCF2Test : public ::testing::Test {
private:
    static TEEC_Context context;
    static TEEC_Session session;

public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    TEEC_Context *GetContext()
    {
        return &TCF2Test::context;
    }
    TEEC_Session *GetSession()
    {
        return &TCF2Test::session;
    }
    void SetUp();
    void TearDown();
};

class TCF2TA2TATest : public ::testing::Test {
private:
    static TEEC_Context context;
    static TEEC_Session session;
    static TEEC_Session session2;

public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    TEEC_Context *GetContext()
    {
        return &TCF2TA2TATest::context;
    }
    TEEC_Session *GetSession()
    {
        return &TCF2TA2TATest::session;
    }
    TEEC_Session *GetSession2()
    {
        return &TCF2TA2TATest::session2;
    }
    void SetUp();
    void TearDown();
};

class TCF1ENUM_Test : public ::testing::Test {
private:
    static TEEC_Context context;
    static TEEC_Session session;

public:
    TestData value = { 0 };
    static void SetUpTestCase();
    static void TearDownTestCase();

    TEEC_Context *GetContext()
    {
        return &TCF1ENUM_Test::context;
    }
    TEEC_Session *GetSession()
    {
        return &TCF1ENUM_Test::session;
    }

    void SetUp();
    void TearDown();
};

TEEC_Result Invoke_GetPropertyAsX(TEEC_Context *context, TEEC_Session *session, TestData *testData);
TEEC_Result Invoke_AllocatePropertyEnumerator(TEEC_Session *session, TestData *testData);
TEEC_Result Invoke_Operate_PropertyEnumerator(TEEC_Session *session, TestData *testData);
TEEC_Result Invoke_Malloc(TEEC_Session *session, uint32_t commandID, TestMemData *testData, uint32_t *origin);
TEEC_Result Invoke_Realloc(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *output);
TEEC_Result Invoke_MemMove_Or_Fill(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *output);
TEEC_Result Invoke_Free(TEEC_Session *session, uint32_t commandID, uint32_t caseNum, uint32_t *origin);
TEEC_Result Invoke_MemCompare(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *buffer1,
    char *buffer2);
TEEC_Result Invoke_CheckMemoryAccessRights(TEEC_Session *session, uint32_t commandID, TestMemData *testData);
TEEC_Result Invoke_SetInstanceData(TEEC_Session *session, uint32_t commandID, char *buffer, uint32_t caseNum,
    uint32_t *origin);
TEEC_Result Invoke_GetInstanceData(TEEC_Session *session, uint32_t commandID, char *buffer, uint32_t *bufSize,
    uint32_t *origin);
TEEC_Result Invoke_OpenTASession(TEEC_Session *session, uint32_t commandID, uint32_t *ta2taSession,
    TestData *testData, uint32_t *origin);
TEEC_Result Invoke_CloseTASession(TEEC_Session *session, uint32_t commandID, uint32_t ta2taSession,
    uint32_t *origin);
TEEC_Result Invoke_InvokeTACommand(TEEC_Session *session, uint32_t commandID, uint32_t ta2taSession,
    TestData *testData, uint32_t *origin);
TEEC_Result Invoke_Panic(TEEC_Session *session, uint32_t commandID, TEEC_Result panicCode, uint32_t *origin);
uint32_t get_ta_data_size(TEEC_Context *context, TEEC_Session *session);
uint32_t get_ta_stack_size(TEEC_Context *context, TEEC_Session *session);
#endif

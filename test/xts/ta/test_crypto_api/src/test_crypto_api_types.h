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

#ifndef TEST_CRYPTO_API_TYPES_H
#define TEST_CRYPTO_API_TYPES_H
#include "tee_trusted_storage_api.h"
#include "stddef.h"
#include "tee_crypto_api.h"
#include "tee_log.h"

enum {
    DATA_MODE_WHOLE  = 0,
    DATA_MODE_SLICE = 1,
};

#define DATA_EXPAND_SIZE 1024
#define AE_TAG_MAX_SIZE 64
#define MAX_STRING_NAME_LEN 100

typedef struct {
    uint32_t dataMode;
    void *data;
    size_t dataMallocSize;
    size_t dataSize;
    size_t dataUsed;
    size_t sliceSize;
    uint8_t aeTag[AE_TAG_MAX_SIZE];
    size_t aeTagSize;
} ProcessInOutData;

struct _IntermediateReprestation;
typedef int (*ActionEntryType)(struct _IntermediateReprestation *ir);
#define MAX_ACTIONS_SIZE 100
typedef struct {
    // common test vector
    char algName[MAX_STRING_NAME_LEN];                // ae, asymEn, asymSg, derive, digest, symEn, mac,
    size_t operaMaxKeySize;                           // ae, asymEn, asymSg, derive,         symEn, mac,
    size_t keySize;                                   // ae, asymEn, asymSg, derive,         symEn, mac,
    char fwdKeyTypeName[MAX_STRING_NAME_LEN];         // ae, asymEn, asymSg, derive,         symEn, mac,
    char bckKeyTypeName[MAX_STRING_NAME_LEN];         //     asymEn, asymSg, derive,                mac,
    uint32_t fwdEngine;                               // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t bckEngine;                               // ae, asymEn, asymSg, derive, digest, symEn, mac,
    size_t dataSize;                                  // ae, asymEn, asymSg, derive, digest, symEn, mac,
    size_t sliceSize;                                 // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t expRet;                                  // ae, asymEn, asymSg, derive, digest, symEn, mac,
    size_t ivLen;                                     //                                     symEn, mac,

    // ae test vector
    size_t aeTagLen;                                  // ae,
    size_t aeTagOSize;                                // ae,
    size_t aeNonceLen;                                // ae,
    uint8_t nonceByte;                                // ae,
    size_t aeAadLenInit;                              // aes-ccm,
    size_t aeAadLen;                                  // ae,
    uint8_t aadByte;                                  // ae,

    // asym encrypt test vector
    uint32_t rsaEnMgf1Hash;                           //     asymEn,

    // asym sign test vector
    uint32_t rsaSgPssLen;                             //             asymSg,

    // ecc key gen nist
    uint32_t ecKeyCurve;                              //     asymEn, asymSg, derive,
    // rsa key gen pub exp id
    uint32_t rsaGenPubExpId;                          //     asymEn, asymSg,
    // dh key gen base prime xbits
    uint32_t dhGenKeySize;                           //                     derive,
    // common action sequence
    ActionEntryType actions[MAX_ACTIONS_SIZE];        // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t actionsSize;                             // ae, asymEn, asymSg, derive, digest, symEn, mac,
} TestVector;

enum {
    ER_OK = 0,
    ER_JF = 1,
};

#define MAX_ACT_SEQ_LIST_SIZE  100

typedef struct {
    char algName[MAX_STRING_NAME_LEN];
    uint32_t algValue;
    uint32_t fwdMode;
    uint32_t bckMode;
    uint32_t operaKeyCount;
    uint32_t needKeyCount;
    uint32_t isSwitchFwdBckOperaKey;
    char algOperaClassName[MAX_STRING_NAME_LEN];
    uint32_t algOperaClassValue;
} AlgMapInfo;
enum {
    NEED_NO_GEN_PARAMS = 0,
    NEED_GEN_ECC_CURVE = 1,
    NEED_DH_BASE_PRIME_XBITS = 2,
    NEED_RSA_EXP_MAYBE = 3,
};
typedef struct {
    uint8_t  keyTypeName[MAX_STRING_NAME_LEN];
    uint32_t keyType;
    uint32_t keyGenType;
    uint32_t needGenParams;
} KeyTypeMapInfo;

enum {
    XTS_KEY_COUNT_TWO = 2,
};

enum {
    GROUP_BALANCED = 0,
    GRUPP_NOT_BALANCED = 1,
};
typedef struct {
    char *elementName;
    ActionEntryType element;
    char *inverseElementName;
    ActionEntryType inverseElement;
    uint32_t isBalanced;
} MonadReversibilityProperty;
#define MONAD_REVERSE_PROP_LIST_SIZE 100
#define AE_NONCE_BUFFER_SIZE 32
#define AE_TAG_BUFFER_SIZE 32
#define MAX_KEY_OBJECT_HANDLE_LIST_SIZE 2
#define MAX_TEST_KEY_ITEM_LIST_SIZE 100
typedef struct {
    uint32_t keyType;
    uint32_t keySize;
    TEE_ObjectHandle keyObjList[MAX_KEY_OBJECT_HANDLE_LIST_SIZE];
    size_t keyObjListSize;
} TestKeyItem;

typedef struct _IntermediateReprestation {
    // input factor space
    TestVector *tv;  // ae, asymEn, asymSg, derive, digest, symEn, mac,

    // inner state factor space
    AlgMapInfo *algMap;     // ae, asymEn, asymSg, derive, digest, symEn, mac,
    KeyTypeMapInfo *fwdKeyMap; // ae, asymEn, asymSg, derive,         symEn, mac,
    KeyTypeMapInfo *bckKeyMap; // ae, asymEn, asymSg, derive,         symEn, mac,

    // common factor
    uint32_t algValue;      // ae, asymEn, asymSg, derive, digest, symEn, mac,

    uint32_t algOperaClassValue;  // ae, asymEn, asymSg, derive, digest, symEn, mac,

    uint32_t fwdMode;  // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t bckMode;  // ae, asymEn, asymSg, derive, digest, symEn, mac,

    uint32_t operaKeyCount;            // ae, asymEn, asymSg, derive,         symEn, mac,
    uint32_t needKeyCount;             // ae, asymEn, asymSg, derive,         symEn, mac,
    uint32_t isSwitchFwdBckOperaKey;   // ae, asymEn, asymSg, derive,         symEn, mac,

    size_t operaMaxKeySize;            // ae, asymEn, asymSg, derive,         symEn, mac,
    size_t keySize;                    // ae, asymEn, asymSg, derive,         symEn, mac,

    uint32_t fwdKeyType;               // ae, asymEn, asymSg, derive,         symEn, mac,
    uint32_t bckKeyType;               // ae, asymEn, asymSg, derive,         symEn, mac,
    uint32_t genKeyType;               // ae, asymEn, asymSg, derive,         symEn, mac,

    uint32_t dataSize;                 // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t sliceSize;                // ae, asymEn, asymSg, derive, digest, symEn, mac,

    size_t ivLen;                      //                             digest, symEn, mac,

    size_t aeNonceLen;                 // ae,
    uint8_t nonceByte;                 // ae,
    uint8_t nonce[AE_NONCE_BUFFER_SIZE];  // ae,
    size_t aeTagLen;                      // ae,
    size_t aeTagOSize;                     // ae,
    uint8_t aeTag[AE_TAG_BUFFER_SIZE];    // ae,
    size_t aeAadLenInit;                      // aes-ccm,
    size_t aeAadLen;                      // ae,
    uint8_t aadByte;                      // ae,
    uint8_t *pAad;                        // ae,

    size_t rsaEnMgf1Hash;              //     asymEn,
    size_t rsaSgPssLen;                //             asymSg,

    uint32_t fwdEngine;                // ae, asymEn, asymSg, derive, digest, symEn, mac,
    uint32_t bckEngine;                // ae, asymEn, asymSg, derive, digest, symEn, mac,

    uint32_t tvExpRet;                 // ae, asymEn, asymSg, derive, digest, symEn, mac,

    ProcessInOutData plainData;        // ae, asymEn, asymSg, derive, digest, symEn, mac,
    ProcessInOutData cipherData;       // ae, asymEn, asymSg, derive, digest, symEn, mac,
    ProcessInOutData decryptedData;    // ae, asymEn, asymSg, derive, digest, symEn, mac,

    TEE_OperationHandle fwdOperaHandle; // ae, asymEn, asymSg, derive, digest, symEn, mac,
    TEE_OperationHandle bckOperaHandle; // ae, asymEn, asymSg, derive, digest, symEn, mac,

    TestKeyItem *tki;                   //                     derive,
    // ecc key gen nist
    uint32_t ecKeyCurve;                //     asymEn, asymSg, derive,
    // rsa key gen pub exp id
    uint32_t rsaGenPubExpId;            //     asymEn, asymSg,
    // dh key gen base prime xbits
    uint32_t dhGenKeySize;             //                     derive,

    MonadReversibilityProperty mrpl[MONAD_REVERSE_PROP_LIST_SIZE];
    uint32_t mrplSize;
} IntermediateReprestation;

enum {
    ERROR_OK = 0,
};

enum {
    USE_DX = 0, // 使用DX引擎
    USE_SW = 1, // 使用SW软引擎
    USE_EP = 2, // 使用EPS引擎
    USE_SE = 3, // 使用SEC引擎
    USE_DF = 4, // 使用默认引擎
};

typedef enum {
    RSA_ENCRYPT_MGF_DEF = 0,
    RSA_ENCYPT_MGF_SHA1 = 1,      // TEE_DH_HASH_SHA1_mode = 0
    RSA_ENCYPT_MGF_SHA224 = 2,    // TEE_DH_HASH_SHA224_mode = 1,
    RSA_ENCYPT_MGF_SHA256 = 3,    // TEE_DH_HASH_SHA256_mode = 2,
    RSA_ENCYPT_MGF_SHA384 = 4,    // TEE_DH_HASH_SHA384_mode = 3,
    RSA_ENCYPT_MGF_SHA512 = 5,    // TEE_DH_HASH_SHA512_mode = 4,
    RSA_ENCYPT_MGF_COUNT,
} RsaEncryptMgfType;

typedef enum {
    TST_ECC_CURVE_NIST_NONE = 0,
    TST_ECC_CURVE_NIST_P192 = 1,
    TST_ECC_CURVE_NIST_P224 = 2,
    TST_ECC_CURVE_NIST_P256 = 3,
    TST_ECC_CURVE_NIST_P384 = 4,
    TST_ECC_CURVE_NIST_P521 = 5,
    TST_ECC_CURVE_SM2 = 6,
    TST_ECC_CURVE_25519 = 7,
    TST_ECC_CURVE_COUNT = 8,
} EccKeyGenCurve;

enum {
    TST_RSA_KEYGEN_PUB_EXP_ID_NULL = 0,
    TST_RSA_KEYGEN_PUB_EXP_ID_0 = 1,
    TST_RSA_KEYGEN_PUB_EXP_ID_1 = 2,
    TST_RSA_KEYGEN_PUB_EXP_ID_2 = 3,
    TST_RSA_KEYGEN_PUB_EXP_ID_3 = 4,
    TST_RSA_KEYGEN_PUB_EXP_ID_4 = 5,
};

#endif // end TEST_CRYPTO_API_TYPES_H

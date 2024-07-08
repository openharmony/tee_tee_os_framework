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

#include "test_crypto_api_types.h"
#include "tee_crypto_hal.h"
#include "tee_log.h"

TestKeyItem g_testKeyItemList[MAX_TEST_KEY_ITEM_LIST_SIZE];
size_t g_testKeyItemListSize = 0;

static int FindKeyItem(IntermediateReprestation *ir)
{
    uint32_t keyType = ir->fwdKeyType;
    uint32_t keySize = ir->keySize;
    size_t i;
    for (i = 0; i < g_testKeyItemListSize; i++) {
        if (g_testKeyItemList[i].keyType == keyType && g_testKeyItemList[i].keySize == keySize) {
            tlogi("[%s]:find key item at %u\n", __func__, i);
            ir->tki = &(g_testKeyItemList[i]);
            return 0;
        }
    }
    tlogi("[%s]:could not find key item, g_testKeyItemListSize = %u\n", __func__, g_testKeyItemListSize);
    return -1;
}

/*
 * DH算法Base和Prime参数定义
 */
static uint8_t g_base512[] = {
    0xd4, 0x07, 0xa9, 0x80, 0xaf, 0xc2, 0x7a, 0x5b, 0x61, 0x22, 0x76, 0x29, 0x1d, 0x65, 0x52, 0x59,
    0x7f, 0x4f, 0x17, 0x7a, 0xa1, 0xea, 0x04, 0x02, 0x8c, 0x8b, 0x01, 0x11, 0x72, 0x2b, 0x4d, 0xc3,
    0x78, 0xc0, 0x08, 0x11, 0x01, 0xcd, 0x45, 0xab, 0xb3, 0x05, 0x56, 0xcd, 0x72, 0x52, 0x16, 0x7c,
    0x74, 0xf1, 0x00, 0x77, 0xa4, 0xf3, 0x31, 0x83, 0x50, 0xc3, 0xed, 0x3b, 0xb5, 0xb5, 0x5d, 0x43
};
static uint8_t g_prime512[] = {
    0xfc, 0xf6, 0xd3, 0x9e, 0x31, 0x88, 0x25, 0x66, 0x30, 0x74, 0x1c, 0x03, 0x85, 0x6e, 0xbd, 0xea,
    0x02, 0x01, 0x0b, 0x77, 0x43, 0x35, 0xfe, 0x57, 0x9c, 0x60, 0xd5, 0x24, 0x22, 0xbe, 0x99, 0xeb,
    0x4f, 0x8f, 0x95, 0x77, 0xdc, 0x47, 0x6a, 0x5e, 0x31, 0x21, 0x6e, 0x9c, 0x00, 0x1b, 0x55, 0xa7,
    0xed, 0xc4, 0xcd, 0xf2, 0x31, 0xd2, 0x44, 0x60, 0x10, 0xd4, 0xb2, 0x6c, 0xb6, 0xf4, 0xb3, 0x73
};
static uint8_t g_base1024[] = {
    0xc4, 0x3b, 0x36, 0xc8, 0xe7, 0xa9, 0x60, 0xea, 0x35, 0x80, 0x6a, 0x02, 0x6a, 0x02, 0x02, 0xcb,
    0x21, 0x24, 0x3d, 0xb8, 0x3d, 0x01, 0x76, 0x63, 0x8a, 0xee, 0x95, 0x50, 0x94, 0x1d, 0x6f, 0x0c,
    0x6f, 0x84, 0x17, 0x16, 0x24, 0x00, 0x27, 0xe2, 0x01, 0x8a, 0xa8, 0xa4, 0xdf, 0x7e, 0xde, 0xb4,
    0x49, 0x20, 0x2c, 0x8f, 0x34, 0x3b, 0xa1, 0x4e, 0x6b, 0x02, 0x23, 0x11, 0x42, 0x9a, 0x9c, 0xba,
    0x22, 0x15, 0x06, 0x1c, 0x26, 0x39, 0x1c, 0xdb, 0x43, 0xd3, 0x2c, 0x75, 0x96, 0xaf, 0x97, 0xcf,
    0xa9, 0x32, 0xa1, 0xa7, 0x3f, 0x90, 0xa9, 0xa8, 0x1d, 0xb8, 0x48, 0xcc, 0x2e, 0x68, 0xc1, 0xf1,
    0x71, 0xd2, 0xfb, 0x4f, 0xda, 0x9c, 0x89, 0x02, 0xea, 0x89, 0x9b, 0xa2, 0xe9, 0x33, 0xc4, 0xfe,
    0x7a, 0x31, 0x39, 0x71, 0x12, 0x18, 0xb9, 0xbe, 0x33, 0x10, 0xcf, 0x1b, 0x65, 0xcb, 0xc1, 0x73
};
static uint8_t g_prime1024[] = {
    0xc4, 0xac, 0x0a, 0xd9, 0x6a, 0xf5, 0xb1, 0x93, 0x46, 0x43, 0xac, 0x5b, 0x2e, 0x45, 0x38, 0x29,
    0x4e, 0x24, 0xde, 0x8f, 0x80, 0x28, 0x6c, 0x4a, 0xef, 0xcb, 0xc2, 0x07, 0xe5, 0xae, 0xec, 0x4f,
    0x9a, 0x1b, 0x1b, 0x61, 0x35, 0xdb, 0xf9, 0x88, 0x83, 0x61, 0x4e, 0xca, 0x8e, 0x82, 0x43, 0xf9,
    0x56, 0x9f, 0x4c, 0xb0, 0x28, 0xbc, 0xa9, 0x9a, 0x23, 0x05, 0xbd, 0x08, 0x7d, 0xc6, 0x3b, 0x62,
    0x8f, 0x2a, 0x96, 0x30, 0xcf, 0x29, 0x6f, 0x1c, 0x18, 0x54, 0x57, 0x9f, 0xcb, 0xf3, 0xb0, 0x85,
    0xb9, 0xce, 0xea, 0xce, 0x71, 0x7a, 0x16, 0x05, 0xb3, 0xeb, 0xf4, 0xf6, 0x99, 0xd2, 0x7c, 0xe8,
    0x0e, 0x36, 0x01, 0x3f, 0x87, 0x6c, 0x4a, 0xfc, 0x45, 0x67, 0x09, 0x5c, 0xcb, 0x09, 0x9a, 0x5b,
    0x96, 0x61, 0xd3, 0x35, 0x1a, 0x04, 0x07, 0xa8, 0x68, 0xe4, 0xc4, 0xb1, 0x3b, 0x11, 0xd7, 0xa3
};
static uint8_t g_base2048[] = {
    0xc9, 0x16, 0xa6, 0x54, 0x91, 0xa7, 0x1c, 0xdf, 0x9b, 0xf9, 0x59, 0x07, 0x95, 0x06, 0x4f, 0xfa,
    0x95, 0x79, 0xc5, 0x20, 0x47, 0xa4, 0x75, 0xce, 0x49, 0xb5, 0x3c, 0xfa, 0x91, 0xd4, 0xd2, 0xb5,
    0xe5, 0x6b, 0x36, 0x24, 0x5f, 0x90, 0x8e, 0xfb, 0x7a, 0x1b, 0x41, 0xf7, 0x18, 0x41, 0xfc, 0x7b,
    0xa5, 0xb4, 0xc3, 0xe1, 0x71, 0xb4, 0x66, 0x54, 0x02, 0x0a, 0xd3, 0xd9, 0xd2, 0x9d, 0xe6, 0x18,
    0x6d, 0x2a, 0xb7, 0xdb, 0x45, 0xbe, 0xc1, 0x83, 0x7f, 0x94, 0x5b, 0xd7, 0xd8, 0x98, 0xd2, 0xcf,
    0x54, 0x38, 0x39, 0xda, 0x90, 0x86, 0xcc, 0xab, 0x0f, 0x15, 0xf8, 0xb8, 0xbf, 0xde, 0x50, 0x07,
    0x74, 0x45, 0x84, 0x4c, 0x2f, 0x08, 0xb1, 0x2f, 0x40, 0x49, 0x9c, 0xaf, 0xb6, 0xd1, 0x6c, 0xe3,
    0x45, 0xbf, 0xf1, 0x63, 0xcc, 0x77, 0x66, 0x5d, 0x45, 0x35, 0xb9, 0x0a, 0xac, 0x74, 0x14, 0x91,
    0x64, 0x1b, 0x34, 0x50, 0xb4, 0xa0, 0x1e, 0xd9, 0xa9, 0x62, 0x56, 0x57, 0xcb, 0x73, 0x3c, 0x96,
    0x5f, 0x86, 0x7f, 0xc3, 0x66, 0xbf, 0xac, 0x79, 0x21, 0x51, 0x14, 0x3f, 0x37, 0x29, 0xbe, 0x96,
    0xc8, 0xee, 0xf1, 0xaf, 0x4e, 0xc7, 0x9f, 0x83, 0x20, 0xe7, 0xb5, 0xb2, 0x52, 0x57, 0xcc, 0xa8,
    0xb0, 0xf2, 0x4d, 0x88, 0x3e, 0x71, 0xfb, 0xd7, 0x45, 0x4d, 0x96, 0x0b, 0xcb, 0x24, 0x0a, 0x88,
    0x4f, 0xaf, 0xe8, 0x96, 0x79, 0x87, 0x14, 0xf8, 0x1e, 0x3d, 0xf7, 0x2c, 0x48, 0xf7, 0x0e, 0x52,
    0x4e, 0x3d, 0xcb, 0xeb, 0x57, 0x54, 0xb9, 0x90, 0xe1, 0x14, 0x5c, 0x36, 0x7d, 0xc0, 0xa3, 0x5f,
    0xf4, 0xfd, 0xf6, 0x33, 0x23, 0x7e, 0xf2, 0xd0, 0xff, 0x0d, 0xe0, 0xe2, 0xa3, 0xcc, 0x81, 0x86,
    0xbc, 0xde, 0x67, 0x83, 0x03, 0xd6, 0xfa, 0x5b, 0x42, 0xd3, 0x1f, 0xfe, 0xd2, 0x0f, 0x2b, 0x1b
};
static uint8_t g_prime2048[] = {
    0xce, 0xd3, 0x02, 0x09, 0x7d, 0xe5, 0x34, 0xf5, 0x3f, 0x14, 0x2e, 0x7b, 0x3e, 0x15, 0x4c, 0x66,
    0x2c, 0xe1, 0xf0, 0xb7, 0x40, 0x72, 0x68, 0xfa, 0xad, 0xa6, 0xd5, 0xd9, 0x55, 0x1e, 0x7e, 0xfd,
    0x06, 0xbc, 0x4f, 0xb8, 0x27, 0xe9, 0x22, 0x3d, 0x17, 0xfa, 0x4d, 0x8c, 0x8b, 0x8e, 0xce, 0xf6,
    0xc9, 0x49, 0x38, 0x74, 0xa2, 0x77, 0x3b, 0x9a, 0xe1, 0xc0, 0xa7, 0xc8, 0x83, 0xf9, 0xdc, 0xa7,
    0x9a, 0x12, 0xc5, 0x19, 0x5c, 0xfb, 0x40, 0x0c, 0x08, 0x57, 0xa1, 0xf7, 0x8d, 0xf2, 0x10, 0x83,
    0xe8, 0xe7, 0x8a, 0xc1, 0x0c, 0x59, 0xa1, 0xa3, 0x77, 0xb1, 0x9f, 0x0d, 0x0f, 0xf8, 0x27, 0xdd,
    0xdc, 0xed, 0xbf, 0x04, 0x91, 0xa3, 0x00, 0x19, 0x08, 0x2d, 0x7c, 0xc9, 0xda, 0xfb, 0x05, 0x31,
    0xf5, 0x34, 0x0d, 0xaa, 0xd3, 0xbb, 0xc0, 0x5b, 0xfb, 0xad, 0x32, 0x6b, 0x98, 0x00, 0x17, 0x01,
    0x39, 0x61, 0x0e, 0x03, 0x2e, 0xf6, 0x60, 0x30, 0x7b, 0xb9, 0xeb, 0x39, 0x60, 0x1b, 0xc4, 0x7f,
    0xe5, 0xcb, 0x5f, 0xc3, 0xb0, 0x79, 0xdb, 0x04, 0xd2, 0x9a, 0x11, 0x95, 0x3e, 0xa4, 0x33, 0x61,
    0x8e, 0x94, 0x22, 0x9b, 0x0a, 0xd0, 0xfb, 0xda, 0x07, 0xc7, 0x34, 0xfb, 0xa9, 0x94, 0xc8, 0x31,
    0x03, 0xe1, 0x92, 0xac, 0x86, 0xfc, 0x45, 0xe3, 0x79, 0x0b, 0x9e, 0x29, 0x63, 0xe8, 0xcf, 0x26,
    0x05, 0xb3, 0x6e, 0xa9, 0xae, 0x9d, 0xe3, 0xdc, 0x03, 0x43, 0x26, 0xdf, 0x7e, 0x8b, 0xae, 0xcb,
    0xe8, 0x09, 0x04, 0x25, 0xdd, 0x42, 0xb8, 0x59, 0x44, 0xec, 0xc1, 0xc7, 0xbf, 0x78, 0x50, 0x31,
    0xec, 0x6e, 0xa5, 0x5f, 0xe4, 0x4f, 0x79, 0x7b, 0xf3, 0xbf, 0x03, 0xd3, 0xa9, 0x7b, 0x7c, 0x70,
    0xa2, 0x5f, 0xdb, 0x86, 0x96, 0xfa, 0xd1, 0x3f, 0x43, 0xc5, 0xd2, 0x2a, 0xf8, 0xf3, 0x3c, 0x7b
};

// ecc curve value
static TEE_Attribute g_eccCurveAttrNistP192 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_NIST_P192,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttrNistP224 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_NIST_P224,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttrNistP256 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_NIST_P256,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttrNistP384 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_NIST_P384,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttrNistP521 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_NIST_P521,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttrSM2 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_SM2,
            .b = 0,
        },
    },
};
static TEE_Attribute g_eccCurveAttr25519 = {
    .attributeID = TEE_ATTR_ECC_CURVE,
    .content = {
        .value = {
            .a = TEE_ECC_CURVE_25519,
            .b = 0,
        },
    },
};
// dh gen params
#define DH_GEN_PARAMS_CNT 3
static TEE_Attribute g_dhGenParams512[DH_GEN_PARAMS_CNT] = {
    {
        .attributeID = TEE_ATTR_DH_BASE,
        .content = {
            .ref = {
                .buffer = g_base512,
                .length = sizeof(g_base512)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_PRIME,
        .content = {
            .ref = {
                .buffer = g_prime512,
                .length = sizeof(g_prime512)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_X_BITS,
        .content = {
            .value = {
                .a = 512,
                .b = 0,
            },
        },
    },
};
static TEE_Attribute g_dhGenParams1024[DH_GEN_PARAMS_CNT] = {
    {
        .attributeID = TEE_ATTR_DH_BASE,
        .content = {
            .ref = {
                .buffer = g_base1024,
                .length = sizeof(g_base1024)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_PRIME,
        .content = {
            .ref = {
                .buffer = g_prime1024,
                .length = sizeof(g_prime1024)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_X_BITS,
        .content = {
            .value = {
                .a = 1024,
                .b = 0,
            },
        },
    },
};
static TEE_Attribute g_dhGenParams2048[DH_GEN_PARAMS_CNT] = {
    {
        .attributeID = TEE_ATTR_DH_BASE,
        .content = {
            .ref = {
                .buffer = g_base2048,
                .length = sizeof(g_base2048)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_PRIME,
        .content = {
            .ref = {
                .buffer = g_prime2048,
                .length = sizeof(g_prime2048)
            },
        },
    },
    {
        .attributeID = TEE_ATTR_DH_X_BITS,
        .content = {
            .value = {
                .a = 2048,
                .b = 0,
            },
        },
    },
};
// rsa gen pulibc_exponent params
static uint8_t g_e0[] = {0x01, 0x00, 0x01};
static uint8_t g_e1[] = {0x0D, 0xBA, 0xA9};
static uint8_t g_e2[] = {0x01, 0x1A, 0x73};
static uint8_t g_e3[] = {0x01, 0x25, 0xA1};
static uint8_t g_e4[] = {0x89, 0x95, 0x19};
static TEE_Attribute g_rsaPubExpAttr0 = {
    .attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT,
    .content = {
        .ref = {
            .buffer = g_e0,
            .length = sizeof(g_e0)
        },
    },
};
static TEE_Attribute g_rsaPubExpAttr1 = {
    .attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT,
    .content = {
        .ref = {
            .buffer = g_e1,
            .length = sizeof(g_e1)
        },
    },
};
static TEE_Attribute g_rsaPubExpAttr2 = {
    .attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT,
    .content = {
        .ref = {
            .buffer = g_e2,
            .length = sizeof(g_e2)
        },
    },
};
static TEE_Attribute g_rsaPubExpAttr3 = {
    .attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT,
    .content = {
        .ref = {
            .buffer = g_e3,
            .length = sizeof(g_e3)
        },
    },
};
static TEE_Attribute g_rsaPubExpAttr4 = {
    .attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT,
    .content = {
        .ref = {
            .buffer = g_e4,
            .length = sizeof(g_e4)
        },
    },
};
typedef struct {
    char name[MAX_STRING_NAME_LEN];
    uint32_t needParamsType;
    TEE_Attribute *params;
    uint32_t paramCount;
    uint32_t dhKeySize;
    uint32_t ecCurve;
    uint32_t rsaPubExpId;
} KeyGenParamsMap;
static KeyGenParamsMap g_keyGenParamsMap[] = {
    // NEED_RSA_EXP_MAYBE
    {
        .name = {"default null params"},
        .needParamsType = NEED_NO_GEN_PARAMS,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = 0,

        .params = NULL,
        .paramCount = 0,
    },
    // NEED_DH_BASE_PRIME_XBITS
    {
        .name = {"dh bash prime xbits 512"},
        .needParamsType = NEED_DH_BASE_PRIME_XBITS,
        .dhKeySize = 512,
        .ecCurve = 0,
        .rsaPubExpId = 0,

        .params = &(g_dhGenParams512[0]),
        .paramCount = 3,
    },
    {
        .name = {"dh bash prime xbits 1024"},
        .needParamsType = NEED_DH_BASE_PRIME_XBITS,
        .dhKeySize = 1024,
        .ecCurve = 0,
        .rsaPubExpId = 0,

        .params = &(g_dhGenParams1024[0]),
        .paramCount = 3,
    },
    {
        .name = {"dh bash prime xbits 2048"},
        .needParamsType = NEED_DH_BASE_PRIME_XBITS,
        .dhKeySize = 2048,
        .ecCurve = 0,
        .rsaPubExpId = 0,

        .params = &(g_dhGenParams2048[0]),
        .paramCount = 3,
    },
    // NEED_GEN_ECC_CURVE
    {
        .name = {"ecc curve nist p192"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_NIST_P192,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrNistP192,
        .paramCount = 1,

    },
    {
        .name = {"ecc curve nist p224"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_NIST_P224,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrNistP224,
        .paramCount = 1,

    },
    {
        .name = {"ecc curve nist p256"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_NIST_P256,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrNistP256,
        .paramCount = 1,
    },
    {
        .name = {"ecc curve nist p384"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_NIST_P384,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrNistP384,
        .paramCount = 1,
    },
    {
        .name = {"ecc curve nist p521"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_NIST_P521,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrNistP521,
        .paramCount = 1,

    },
    {
        .name = {"ecc curve sm2"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_SM2,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttrSM2,
        .paramCount = 1,
    },
    {
        .name = {"ecc curve 25519"},
        .needParamsType = NEED_GEN_ECC_CURVE,
        .dhKeySize = 0,
        .ecCurve = TEE_ECC_CURVE_25519,
        .rsaPubExpId = 0,

        .params = &g_eccCurveAttr25519,
        .paramCount = 1,
    },
    // NEED_RSA_EXP_MAYBE
    {
        .name = {"rsa key gen params null"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = 0,

        .params = NULL,
        .paramCount = 0,
    },
    {
        .name = {"rsa key gen params attr0"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = TST_RSA_KEYGEN_PUB_EXP_ID_0,

        .params = &g_rsaPubExpAttr0,
        .paramCount = 1,
    },
    {
        .name = {"rsa key gen params attr1"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = TST_RSA_KEYGEN_PUB_EXP_ID_1,

        .params = &g_rsaPubExpAttr1,
        .paramCount = 1,
    },
    {
        .name = {"rsa key gen params attr2"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = TST_RSA_KEYGEN_PUB_EXP_ID_2,

        .params = &g_rsaPubExpAttr2,
        .paramCount = 1,
    },
    {
        .name = {"rsa key gen params attr3"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = TST_RSA_KEYGEN_PUB_EXP_ID_3,

        .params = &g_rsaPubExpAttr3,
        .paramCount = 1,
    },
    {
        .name = {"rsa key gen params attr4"},
        .needParamsType = NEED_RSA_EXP_MAYBE,
        .dhKeySize = 0,
        .ecCurve = 0,
        .rsaPubExpId = TST_RSA_KEYGEN_PUB_EXP_ID_4,

        .params = &g_rsaPubExpAttr4,
        .paramCount = 1,
    },
};
size_t g_keyGenParamsMapSize = sizeof(g_keyGenParamsMap) / sizeof(g_keyGenParamsMap[0]);

static int SetGenKeyParams(IntermediateReprestation *ir, TEE_Attribute **params, uint32_t *paramCount)
{
    uint32_t needParamsType = ir->fwdKeyMap->needGenParams;
    uint32_t dhKeySize = ir->dhGenKeySize;
    uint32_t ecCurve = ir->ecKeyCurve;
    uint32_t rsaPubExpId = ir->rsaGenPubExpId;

    uint32_t i;
    for (i = 0; i < g_keyGenParamsMapSize; i++) {
        if (g_keyGenParamsMap[i].needParamsType == needParamsType &&
            g_keyGenParamsMap[i].dhKeySize == dhKeySize &&
            g_keyGenParamsMap[i].ecCurve == ecCurve &&
            g_keyGenParamsMap[i].rsaPubExpId == rsaPubExpId) {
            tlogi("[%s]:find key gen params map:%s\n", __func__, g_keyGenParamsMap[i].name);
            *params = g_keyGenParamsMap[i].params;
            *paramCount = g_keyGenParamsMap[i].paramCount;
            return 0;
        }
    }
    tloge("[%s]:cound not find key gen params\n", __func__);
    return -1;
}
static int GenerateKeyItem(IntermediateReprestation *ir)
{
    uint32_t keyType = ir->genKeyType;
    uint32_t keySize = ir->keySize;
    tlogi("[%s]:keyType[0x%x].keySize[0x%x]\n",  __func__, keyType, keySize);
    int ret = TEE_AllocateTransientObject(keyType, keySize,
        &(g_testKeyItemList[g_testKeyItemListSize].keyObjList[0]));
    if (ret != TEE_SUCCESS) {
        tloge("[%s]:allocate key object0 failed\n", __func__);
        return -1;
    }
    ret = TEE_AllocateTransientObject(keyType, keySize,
        &(g_testKeyItemList[g_testKeyItemListSize].keyObjList[1]));
    if (ret != TEE_SUCCESS) {
        tloge("[%s]:allocate key object1 failed\n", __func__);
        TEE_FreeTransientObject(g_testKeyItemList[g_testKeyItemListSize].keyObjList[0]);
        return -1;
    }

    TEE_SetObjectFlag(g_testKeyItemList[g_testKeyItemListSize].keyObjList[0], SOFT_CRYPTO);
    TEE_SetObjectFlag(g_testKeyItemList[g_testKeyItemListSize].keyObjList[1], SOFT_CRYPTO);

    TEE_Attribute *params     = NULL;
    uint32_t       paramCount = 0;
    int ret0 = SetGenKeyParams(ir, &params, &paramCount);
    int ret1 = TEE_GenerateKey(g_testKeyItemList[g_testKeyItemListSize].keyObjList[0],
        keySize, params, paramCount);
    int ret2 = TEE_GenerateKey(g_testKeyItemList[g_testKeyItemListSize].keyObjList[1],
        keySize, params, paramCount);
    if (ret0 != 0 || ret1 != 0 || ret2 != 0) {
        tloge("[%s]:generte key failed, ret0 = 0x%x, ret2 = 0x%x, ret3 = 0x%x\n", __func__,
            ret0, ret1, ret2);
        ret = -1;
        goto error1;
    }
    tlogi("[%s]:generte key success\n", __func__);

    ir->tki = &(g_testKeyItemList[g_testKeyItemListSize]);

    g_testKeyItemListSize++;
    tlogi("[%s]:GenerateKeyItem success\n", __func__);
    return 0;

error1:
    ir->tki = NULL;
    TEE_FreeTransientObject(g_testKeyItemList[g_testKeyItemListSize].keyObjList[0]);
    TEE_FreeTransientObject(g_testKeyItemList[g_testKeyItemListSize].keyObjList[1]);
    tloge("[%s]:generate test key item failed\n", __func__);
    return ret;
}

int GetOrGenIRTestKeys(IntermediateReprestation *ir)
{
    ir->tki = NULL;
    int ret = FindKeyItem(ir);
    if (ret == 0) {
        tlogi("[%s]:find exist test key item and  return\n", __func__);
        return 0;
    }
    tlogi("[%s]:could not find key, need to generate.\n", __func__);
    ret = GenerateKeyItem(ir);
    if (ret != 0) {
        tloge("[%s]:GenerateKeyItem failed\n", __func__);
        return -1;
    }
    return 0;
}


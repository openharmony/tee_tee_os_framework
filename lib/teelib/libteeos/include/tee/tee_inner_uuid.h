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
#ifndef TEE_INNER_UUID_H
#define TEE_INNER_UUID_H

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * Secure Global Serivce
 */
#define TEE_MISC_DRIVER                                    \
    {                                                      \
        0x5bb40be1, 0x6b49, 0x421c,                        \
        {                                                  \
            0x9d, 0xd5, 0x79, 0xf5, 0xcb, 0xde, 0x3f, 0xb3 \
        }                                                  \
    }

#define TEE_SERVICE_GLOBAL                                 \
    {                                                      \
        0x00000000, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

#define TEE_SMC_MGR                               \
    {                                                      \
        0x6e1ce639, 0x1e07, 0x4972,                        \
        {                                                  \
            0xa6, 0x63, 0xc0, 0x2c, 0xa4, 0xb4, 0xac, 0x47 \
        }                                                  \
    }

#define DRVMGR                                     \
    {                                                      \
        0x4b73448d, 0x3423, 0x4162,                        \
        {                                                  \
            0x82, 0xad, 0x29, 0x43, 0x6c, 0x68, 0x05, 0x8f \
        }                                                  \
    }

#define TEE_SERVICE_SSA                                    \
    {                                                      \
        0x999286b9, 0x54da, 0x4235,                        \
        {                                                  \
            0x9e, 0x77, 0x96, 0xe8, 0x1f, 0xea, 0x1e, 0xe4 \
        }                                                  \
    }

/* 1074b0ca-3efb-42c9-ab63-78711e542b1b */
#define TEE_SERVICE_PERM                                   \
    {                                                      \
        0x1074b0ca, 0x3efb, 0x42c9,                        \
        {                                                  \
            0xab, 0x63, 0x78, 0x71, 0x1e, 0x54, 0x2b, 0x1b \
        }                                                  \
    }

/* 91f0cf6b-bd4b-456e-862d-3fa61ab1a4ac */
#define TEE_SERVICE_SE                                     \
    {                                                      \
        0x91f0cf6b, 0xbd4b, 0x456e,                        \
        {                                                  \
            0x86, 0x2d, 0x3f, 0xa6, 0x1a, 0xb1, 0xa4, 0xac \
        }                                                  \
    }

/* 0db8b999-e0e1-42dd-b6fe-61629cec01fa */
#define TEE_SERVICE_CRLAGENT                               \
    {                                                      \
        0x0db8b999, 0xe0e1, 0x42dd,                        \
        {                                                  \
            0xb6, 0xfe, 0x61, 0x62, 0x9c, 0xec, 0x01, 0xfa \
        }                                                  \
    }

/* 9a5c802c-386f-4081-8c5d-de19bda0239b */
#define TEE_SERVICE_HUK                                    \
    {                                                      \
        0x9a5c802c, 0x386f, 0x4081,                        \
        {                                                  \
            0x8c, 0x5d, 0xde, 0x19, 0xbd, 0xa0, 0x23, 0x9b \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * Notification task
 */
#define TEE_SERVICE_REET                                   \
    {                                                      \
        0x0A0A0A0A, 0x0A0A, 0x0A0A,                        \
        {                                                  \
            0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A \
        }                                                  \
    }

/* 2427f879-4655-4367-8231-e58e2945c9b8 */
#define CRYPTOMGR                                     \
    {                                                      \
        0x2427f879, 0x4655, 0x4367,                        \
        {                                                  \
            0x82, 0x31, 0xe5, 0x8e, 0x29, 0x45, 0xc9, 0xb8 \
        }                                                  \
    }
#endif

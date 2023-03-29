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
#ifndef LIBTEEOS_SRE_TYPEDEF_H
#define LIBTEEOS_SRE_TYPEDEF_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#ifndef SRE_TYPE_DEF
#define SRE_TYPE_DEF

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef float FLOAT;
typedef double DOUBLE;
typedef char CHAR;

typedef unsigned int BOOL;
typedef uint64_t UINT64;
typedef int64_t INT64;
typedef unsigned int UINTPTR;
typedef signed int INTPTR;
typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

#ifndef VOID
#define VOID void
#endif

#endif /* end of #ifndef SRE_TYPE_DEF */

#ifndef FALSE
#define FALSE ((BOOL)0)
#endif

#ifndef TRUE
#define TRUE ((BOOL)1)
#endif

#ifndef NULL
#define NULL ((VOID *)0)
#endif

#ifndef SRE_OK
#define SRE_OK (0)
#endif

#define OS_ERROR     (UINT32)(-1)
#define OS_ERROR_A64 (UINT64)(-1)

#define SET_BIT(map, bit) (map |= (1UL << (bit)))
#define CLR_BIT(map, bit) (map &= (~(1UL << (bit))))

/* interrupt type id */
typedef UINT32 HWI_HANDLE_T;

/* interrupt prior */
typedef UINT16 HWI_PRIOR_T;

/* interrupt mode */
typedef UINT16 HWI_MODE_T;

/* interrupt agru type */
typedef UINT32 HWI_ARG_T;

/* Physical address in the system */
#ifndef PADDR_T_DEFINED
typedef uint64_t paddr_t;
#define PADDR_T_DEFINED
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif

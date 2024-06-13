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
#include "tee_mem_mgmt_api.h"

#include <malloc.h>
#include <securec.h>

#include <mem_ops.h>
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_property_inner.h"

#define COMPARE_SMALL (-1)
#define COMPARE_LARGE 1
#define COMPARE_EQUAL 0

#define ERR_INVALID 0xFFFFFFFFU
#define ERR_NO_MASK 0xFF

// overwrite GP standard interface, enable it only in GP certificate
#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

static void *g_instance_data = NULL;

static void *malloc_with_hint(size_t size, uint32_t hint)
{
    void *ptr = NULL;

    ptr = malloc(size);
    if (ptr == NULL) {
        tloge("apply buffer is failed 0x%x\n", size);
        return ptr;
    }

    if (hint == 0)
        (void)memset_s(ptr, size, 0x0, size);

    return ptr;
}

static void *malloc_with_hint_mask(size_t size, uint32_t hint)
{
    void *ptr = NULL;

    if (((hint & TEE_MALLOC_NO_FILL) != 0) && ((hint & TEE_MALLOC_NO_SHARE) == 0)) {
        tloge("invalid parameters\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return ptr;
    }

    ptr = malloc(size);
    if (ptr == NULL) {
        tloge("apply buffer is failed 0x%x\n", size);
        return ptr;
    }

    if ((hint == 0) || ((hint & TEE_MALLOC_NO_FILL) == 0))
        (void)memset_s(ptr, size, 0x0, size);

    return ptr;
}

static int32_t compare_each_byte(const void *buffer1, const void *buffer2, size_t size)
{
    const unsigned char *c1 = buffer1;
    const unsigned char *c2 = buffer2;
    size_t i;
    int32_t result = 0;

    for (i = 0; i < size; i++) {
        if ((*c1 != *c2) && (result == 0))
            result = (*c1 > *c2 ? COMPARE_LARGE : COMPARE_SMALL);

        c1++;
        c2++;
    }

    return result;
}

static int32_t buffer_full_compare(const void *buffer1, const void *buffer2, size_t size)
{
    // static function, called only by TEE_MemCompare, don't need to check param again
    const unsigned long *l1 = NULL;
    const unsigned long *l2 = NULL;

    uint32_t remainder;
    uint32_t step  = sizeof(*l1);
    int32_t result = 0;

    remainder = size % step;

    if (remainder != 0)
        result = compare_each_byte(buffer1, buffer2, remainder);

    l1 = buffer1 + remainder;
    l2 = buffer2 + remainder;
    size -= remainder;

    for (; size > 0; size -= step) {
        if ((*l1 != *l2) && (result == 0)) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            result = compare_each_byte(l1, l2, step);
#else
            result = ((*l1 > *l2) ? COMPARE_LARGE : COMPARE_SMALL);
#endif
        }

        l1++;
        l2++;
    }

    return result;
}

/*
 * below APIs are defined by Global Platform or Platform SDK released previously
 * for compatibility:
 * don't change function name / return value type / parameters types / parameters names
 */
void TEE_MemFill(void *buffer, uint32_t x, size_t size)
{
    unsigned char *p = NULL;

    if (buffer == NULL)
        return;

    p = buffer;

    while (size-- > 0)
        *p++ = (unsigned char)x;
}

void TEE_MemMove(void *dest, const void *src, size_t size)
{
    char *dst_ptr = NULL;
    const char *src_ptr = NULL;

    bool invalid = (size == 0) || (size > SECUREC_MEM_MAX_LEN) || (dest == NULL) || (src == NULL);
    if (invalid)
        return;

    if (dest == src)
        return;

    src_ptr = src;
    dst_ptr = dest;
    if (src_ptr < dst_ptr) {
        while (size-- != 0)
            dst_ptr[size] = src_ptr[size];
    } else {
        while (size-- != 0)
            *dst_ptr++ = *src_ptr++;
    }
}

void *TEE_Malloc(size_t size, uint32_t hint)
{
    uint32_t api_level;
    if (size == 0)
        return NULL;

    api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_2)
        return malloc_with_hint_mask(size, hint);
    else
        return malloc_with_hint(size, hint);
}

void TEE_Free(void *buffer)
{
    if (buffer == NULL)
        return;

    free(buffer);
}

void *TEE_Realloc(void *buffer, size_t new_size)
{
    if (new_size == 0)
        return NULL;

    return realloc(buffer, new_size);
}

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, size_t size)
{
    if ((buffer1 != NULL) && (buffer2 != NULL))
        return buffer_full_compare(buffer1, buffer2, size);
    else if ((buffer1 == NULL) && (buffer2 != NULL))
        return COMPARE_SMALL;
    else if ((buffer1 != NULL) && (buffer2 == NULL))
        return COMPARE_LARGE;
    else
        return COMPARE_EQUAL;
}

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, const void *buffer, size_t size)
{
    (void)accessFlags;
    (void)buffer;
    (void)size;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SetInstanceData(void *instanceData)
{
    g_instance_data = instanceData;
}

void *TEE_GetInstanceData(void)
{
    return g_instance_data;
}

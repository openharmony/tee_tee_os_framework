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
#include "tee_arith_api.h"
#include <pthread.h>
#include <openssl/bn.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <ta_framework.h>

#define METADATA_SIZE_IN_U32 2
#define BN_DIGIT_OFFSET      METADATA_SIZE_IN_U32
#define BYTE_LEN_PADD        3
#define BYTE_LEN_U32S(a)     (((a) + BYTE_LEN_PADD) / sizeof(uint32_t))
#define BN_LEN(a)            ((a)[BIG_INT_BYTES_OFFSET] & 0xffff)
#define BN_SIGN(a)           ((a)[BIG_INT_BYTES_OFFSET] >> 16)
#define BIGINT_MEM_POOL_SIZE 12
#define SYMBOL_BIT           16
#define BYTE_SIZE            8
#define BYTE_SHIFT           7
#define TRIAL_DIVISION       1

#define BIG_INT_ERROR         (-1)
#define BIG_INT_SUCCESS       0
#define BIG_INT_ALLOC_OFFSET  0
#define BIG_INT_BYTES_OFFSET  1
#define BIG_INT_POSITIVE_FLAG 0
#define BIG_INT_NEGITIVE_FLAG 1
#define BIG_INT_INIT_SIZE     0
#define BIG_INT_INIT_VALUE    1
#define BN_INVALID_LEN        (-1)
#define BN_SET_WORD_SUCC      1
#define BN_OP_SUCC            1

struct bn_mem_pool_t {
    BIGNUM *a;
    BIGNUM *b;
    BIGNUM *c;
    BIGNUM *d;
    BIGNUM *e;
    BN_CTX *ctx;
    BN_MONT_CTX *mont_ctx;
};

/* overwrite GP standard interface, enable it only in GP certificate */
#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

static void release_mem_pool(struct bn_mem_pool_t *pool);
static struct bn_mem_pool_t *reserve_mem_pool(void)
{
    struct bn_mem_pool_t *pool = TEE_Malloc(sizeof(*pool), 0);
    if (pool == NULL) {
        tloge("malloc mem pool failed!");
        return NULL;
    }
    pool->a        = BN_new();
    pool->b        = BN_new();
    pool->c        = BN_new();
    pool->d        = BN_new();
    pool->e        = BN_new();
    pool->ctx      = BN_CTX_new();
    pool->mont_ctx = BN_MONT_CTX_new();
    bool check = ((pool->a == NULL) || (pool->b == NULL) || (pool->c == NULL) || (pool->d == NULL) ||
        (pool->e == NULL) || (pool->ctx == NULL) || (pool->mont_ctx == NULL));
    if (check) {
        release_mem_pool(pool);
        return NULL;
    }
    return pool;
}

static void release_mem_pool(struct bn_mem_pool_t *pool)
{
    if (pool != NULL) {
        BN_free(pool->a);
        pool->a = NULL;
        BN_free(pool->b);
        pool->b = NULL;
        BN_free(pool->c);
        pool->c = NULL;
        BN_free(pool->d);
        pool->d = NULL;
        BN_free(pool->e);
        pool->e = NULL;
        BN_CTX_free(pool->ctx);
        pool->ctx = NULL;
        BN_MONT_CTX_free(pool->mont_ctx);
        pool->mont_ctx = NULL;
        TEE_Free(pool);
        pool = NULL;
    }
}

static bool invalid_big_int_len(size_t len)
{
    bool check = ((len < METADATA_SIZE_IN_U32) || ((len - METADATA_SIZE_IN_U32) > (UINT32_MAX / sizeof(uint32_t))));
    if (check)
        return true;

    return false;
}

static int32_t big_int_to_bn(BIGNUM *bn, const TEE_BigInt *big_int, uint32_t len)
{
    bool check = ((bn == NULL) || (big_int == NULL) || (len <= METADATA_SIZE_IN_U32));
    if (check)
        return BIG_INT_ERROR;

    if (BN_bin2bn((uint8_t *)&big_int[BN_DIGIT_OFFSET], BN_LEN(big_int), bn) == NULL)
        return BIG_INT_ERROR;

    if (BN_SIGN(big_int) != BIG_INT_POSITIVE_FLAG)
        BN_set_negative(bn, BIG_INT_NEGITIVE_FLAG);

    return BIG_INT_SUCCESS;
}

static int32_t bn_to_big_int(TEE_BigInt *big_int, uint32_t len, const BIGNUM *bn)
{
    uint32_t blen;

    bool check = ((bn == NULL) || (big_int == NULL) || (len <= METADATA_SIZE_IN_U32) ||
        invalid_big_int_len((size_t)big_int[BIG_INT_ALLOC_OFFSET]));
    if (check)
        return BIG_INT_ERROR;

    /* check that bn fits into bigInt */
    blen = BN_num_bytes(bn);
    if (blen > (sizeof(uint32_t) * (big_int[BIG_INT_ALLOC_OFFSET] - METADATA_SIZE_IN_U32)))
        return BIG_INT_ERROR;

    if (BN_bn2bin(bn, (uint8_t *)&big_int[BN_DIGIT_OFFSET]) == BN_INVALID_LEN)
        return BIG_INT_ERROR;

    big_int[BIG_INT_BYTES_OFFSET] = blen;
    if (BN_is_negative(bn))
        big_int[BIG_INT_BYTES_OFFSET] |= ((uint32_t)BIG_INT_NEGITIVE_FLAG << SYMBOL_BIT);

    return BIG_INT_SUCCESS;
}

/*
 * below APIs are defined by Global Platform, need to follow Global Platform code style
 * don't change function name / return value type / parameters types / parameters names
 */
/*
 * TEE_BigInt representation is following: a0, a1, a2, ..., an, where
 * a0 is number of allocated uint32s
 * a1 the a1&0xffff is number of bytes for bigint-> a1>>16 is sign of bigint if a1>>16 = 0 then number is positive
 * othervice negative
 * a2,...,an contains digits in bytes (Note: this a1 has number in uint32s)
 */
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
    bool check = ((bigInt == NULL) || invalid_big_int_len(len));
    if (check) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }
    bigInt[BIG_INT_ALLOC_OFFSET] = len;
    bigInt[BIG_INT_BYTES_OFFSET] = BIG_INT_INIT_SIZE;
    return;
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len)
{
    TEE_BigIntInit(bigIntFMM, len);
}

TEE_Result TEE_BigIntInitFMMContext1(TEE_BigIntFMMContext *context, size_t len, const TEE_BigInt *modulus)
{
    errno_t ret;
    uint32_t modlen;

    bool check = ((context == NULL) || (modulus == NULL) || invalid_big_int_len(len));
    if (check) {
        tloge("parameters is invalid!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    modlen = BN_LEN(modulus);
    if (((len - METADATA_SIZE_IN_U32) * sizeof(uint32_t)) < modlen) {
        TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    context[BIG_INT_ALLOC_OFFSET] = len - METADATA_SIZE_IN_U32;
    context[BIG_INT_BYTES_OFFSET] = modulus[BIG_INT_BYTES_OFFSET];
    ret = memcpy_s(&context[BN_DIGIT_OFFSET], (len - METADATA_SIZE_IN_U32) * sizeof(uint32_t),
                   &modulus[BN_DIGIT_OFFSET], modlen);
    if (ret != EOK) {
        tloge("copy data failed\n");
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len, const TEE_BigInt *modulus)
{
    if (TEE_BigIntInitFMMContext1(context, len, modulus) != TEE_SUCCESS)
        tloge("init big int context failed\n");
}

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits)
{
    return TEE_BigIntSizeInU32(modulusSizeInBits);
}

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits)
{
    return TEE_BigIntSizeInU32(modulusSizeInBits);
}

TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest, const uint8_t *buffer, size_t bufferLen, int32_t sign)
{
    size_t len;
    errno_t rc;

    bool check = ((dest == NULL) || (buffer == NULL) || invalid_big_int_len((size_t)dest[BIG_INT_ALLOC_OFFSET]));
    if (check) {
        tloge("parameters is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    while ((bufferLen > 0) && (buffer[BIG_INT_ALLOC_OFFSET] == 0)) {
        buffer++;
        bufferLen--;
    }

    len = (dest[BIG_INT_ALLOC_OFFSET] - METADATA_SIZE_IN_U32) * sizeof(uint32_t);
    if (len < bufferLen) {
        tloge("buffer over flow, bigInt len %zu, bufferLen %zu\n", len, bufferLen);
        return TEE_ERROR_OVERFLOW;
    }

    /*
     * dest[BIG_INT_ALLOC_OFFSET] tells length of 1) number and 2) METADATA in UINT32s. The from &dest[2] there is
     * available space 4 * (dest[BIG_INT_ALLOC_OFFSET] - METADATA_SIZE_IN_U32) bytes
     */
    rc = memcpy_s(&dest[BN_DIGIT_OFFSET], len, buffer, bufferLen);
    if (rc != EOK) {
        tloge("copy data failed\n");
        return TEE_ERROR_SECURITY;
    }
    dest[BIG_INT_BYTES_OFFSET] = bufferLen;
    if (sign < BIG_INT_POSITIVE_FLAG)
        dest[BIG_INT_BYTES_OFFSET] |= ((uint32_t)BIG_INT_NEGITIVE_FLAG << SYMBOL_BIT);
    return TEE_SUCCESS;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer, size_t *bufferLen, const TEE_BigInt *bigInt)
{
    errno_t ret;
    bool check = ((buffer == NULL) || (bufferLen == NULL) || (bigInt == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*bufferLen < BN_LEN(bigInt)) {
        tloge("bufferLen too short, dest len %zu, bigInt len %u\n", *bufferLen, BN_LEN(bigInt));
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* *bufferLen is INPUT and OUTPUT, it tells how much buffer has memory and BN_LEN(bigInt) will be written */
    ret = memcpy_s(buffer, *bufferLen, &bigInt[BN_DIGIT_OFFSET], BN_LEN(bigInt));
    if (ret != EOK) {
        tloge("copy data failed\n");
        return TEE_ERROR_SECURITY;
    }
    *bufferLen = BN_LEN(bigInt);

    return TEE_SUCCESS;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
    struct bn_mem_pool_t *pool = NULL;
    if (dest == NULL) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for convert s32 is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    if (shortVal < BIG_INT_POSITIVE_FLAG) {
        if ((BN_set_word(pool->a, -shortVal) != BN_SET_WORD_SUCC) ||
            (bn_to_big_int(dest, *dest, pool->a) != BIG_INT_SUCCESS))
            goto end;
        TEE_BigIntNeg(dest, dest);
    } else {
        if ((BN_set_word(pool->a, shortVal) != BN_SET_WORD_SUCC) ||
            (bn_to_big_int(dest, *dest, pool->a) != BIG_INT_SUCCESS))
            goto end;
    }
end:
    release_mem_pool(pool);
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src)
{
    uint8_t *tmp = NULL;
    uint32_t i;
    int32_t tmp2 = 0;
    uint32_t blen;
    bool check = ((dest == NULL) || (src == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    blen = BN_LEN(src);
    if (blen > sizeof(uint32_t))
        return TEE_ERROR_OVERFLOW;

    if (blen == 0)
        *dest = 0;

    tmp = (uint8_t *)&src[BN_DIGIT_OFFSET];

    if ((blen == sizeof(uint32_t)) && (tmp[BIG_INT_ALLOC_OFFSET] >> BYTE_SHIFT))
        return TEE_ERROR_OVERFLOW;

    for (i = 0; i < blen; i++)
        tmp2 += (tmp[blen - 1 - i] << (BYTE_SIZE * i));

    if ((src[BIG_INT_BYTES_OFFSET] >> SYMBOL_BIT) != BIG_INT_POSITIVE_FLAG)
        *dest = -tmp2;
    else
        *dest = tmp2;

    return TEE_SUCCESS;
}

int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    int32_t ret;
    struct bn_mem_pool_t *pool = NULL;
    if ((op1 == NULL) || (op2 == NULL)) {
        tloge("parameters is invalid!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for cmp is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return (int32_t)TEE_ERROR_OUT_OF_MEMORY;
    }
    if ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS)) {
        release_mem_pool(pool);
        return BIG_INT_ERROR;
    }

    ret = BN_cmp(pool->a, pool->b);
    release_mem_pool(pool);

    return ret;
}

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal)
{
    TEE_BigInt *op2 = NULL;
    int32_t ret;

    if (op == NULL) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;
    }
    op2 = TEE_Malloc(TEE_BigIntSizeInU32(BIG_INT_INIT_VALUE) * sizeof(*op2), 0);
    if (op2 == NULL) {
        tloge("apply op2 buffer is failed!\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return (int32_t)TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_BigIntInit(op2, TEE_BigIntSizeInU32(BIG_INT_INIT_VALUE));
    TEE_BigIntConvertFromS32(op2, shortVal);

    ret = TEE_BigIntCmp(op, op2);
    TEE_Free(op2);
    return ret;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op, size_t bits)
{
    struct bn_mem_pool_t *pool = NULL;
    if ((dest == NULL) || (op == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for shift right is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    if ((big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) || (BN_rshift(pool->a, pool->a, bits) != BN_OP_SUCC))
        goto end;

    if (bn_to_big_int(dest, *dest, pool->a) != BIG_INT_SUCCESS)
        tloge("bn convert failed\n");
end:
    release_mem_pool(pool);
}

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex)
{
    struct bn_mem_pool_t *pool = NULL;
    if (src == NULL) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return false;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for get bit is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return false;
    }

    if (big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return false;
    }

    if ((uint32_t)BN_num_bits(pool->a) < bitIndex) {
        release_mem_pool(pool);
        return false;
    }

    if (big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return false;
    }

    bool ret = (bool)BN_is_bit_set(pool->a, bitIndex);
    release_mem_pool(pool);

    return ret;
}

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src)
{
    uint32_t ret;
    struct bn_mem_pool_t *pool = NULL;
    if (src == NULL) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return (uint32_t)TEE_ERROR_BAD_PARAMETERS;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for bit count is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return (uint32_t)TEE_ERROR_OUT_OF_MEMORY;
    }
    if (big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return (uint32_t)TEE_ERROR_GENERIC;
    }
    ret = (uint32_t)BN_num_bits(pool->a);
    release_mem_pool(pool);

    return ret;
}

TEE_Result TEE_BigIntSetBit(TEE_BigInt *op, uint32_t bitIndex, bool value)
{
    struct bn_mem_pool_t *pool = NULL;
    int32_t ret;

    if (op == NULL) {
        tloge("parameters is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for set bit is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return (uint32_t)TEE_ERROR_GENERIC;
    }

    if ((uint32_t)BN_num_bits(pool->a) < bitIndex) {
        release_mem_pool(pool);
        return TEE_ERROR_OVERFLOW;
    }

    if (value)
        ret = BN_set_bit(pool->a, bitIndex);
    else
        ret = BN_clear_bit(pool->a, bitIndex);

    if ((ret != BN_OP_SUCC) || (bn_to_big_int(op, *op, pool->a) != BIG_INT_SUCCESS)) {
        release_mem_pool(pool);
        return TEE_ERROR_GENERIC;
    }
    release_mem_pool(pool);
    return TEE_SUCCESS;
}

TEE_Result TEE_BigIntAssign(TEE_BigInt *dest, const TEE_BigInt *src)
{
    struct bn_mem_pool_t *pool = NULL;
    bool check                 = ((dest == NULL) || (src == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for assign is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (bn_to_big_int(dest, *dest, pool->a) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return TEE_ERROR_OVERFLOW;
    }

    release_mem_pool(pool);
    return TEE_SUCCESS;
}

TEE_Result TEE_BigIntAbs(TEE_BigInt *dest, const TEE_BigInt *src)
{
    bool check = ((dest == NULL) || (src == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (TEE_BigIntCmpS32(src, 0) < 0) {
        TEE_BigIntNeg(dest, src);
        return TEE_SUCCESS;
    }

    return TEE_BigIntAssign(dest, src);
}

void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL));
    if (check) {
        tloge("parameters is invalid for add\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for add is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) || (BN_add(pool->c, pool->a, pool->b) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL));
    if (check) {
        tloge("parameters is invalid for sub\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for sub is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) || (BN_sub(pool->c, pool->a, pool->b) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *src)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (src == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for neg failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    big_int_to_bn(pool->a, src, *src);

    if (BN_is_negative(pool->a))
        BN_set_negative(pool->a, BIG_INT_POSITIVE_FLAG);
    else
        BN_set_negative(pool->a, BIG_INT_NEGITIVE_FLAG);

    if (bn_to_big_int(dest, *dest, pool->a) != BIG_INT_SUCCESS)
        tloge("operation failed\n");

    release_mem_pool(pool);
}

void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL));
    if (check) {
        tloge("parameters is invalid for mul\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for mul is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) ||
        (BN_mul(pool->c, pool->a, pool->b, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (op == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for square is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check =
        ((big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) || (BN_sqr(pool->b, pool->a, pool->ctx) != BN_OP_SUCC) ||
         (bn_to_big_int(dest, *dest, pool->b) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r, const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest_q == NULL) || (dest_r == NULL) || (op1 == NULL) || (op2 == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for div is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) ||
        (BN_div(pool->d, pool->c, pool->a, pool->b, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(dest_q, *dest_q, pool->d) != BIG_INT_SUCCESS) ||
        (bn_to_big_int(dest_r, *dest_r, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid for int mod\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for int mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check =
        ((big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->b, n, *n) != BIG_INT_SUCCESS) ||
         (BN_mod(pool->c, pool->a, pool->b, pool->ctx) != BN_OP_SUCC) ||
         (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid for add mod\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for add mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }
    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
        (BN_mod_add(pool->d, pool->a, pool->b, pool->c, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->d) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid for sub mod\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for sub mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
        (BN_mod_sub(pool->d, pool->a, pool->b, pool->c, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->d) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, const TEE_BigInt *op1, const TEE_BigInt *op2, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;
    bool check = ((dest == NULL) || (op1 == NULL) || (op2 == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid for mul mod\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for mul mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
        (BN_mod_mul(pool->d, pool->a, pool->b, pool->c, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(dest, *dest, pool->d) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((dest == NULL) || (op == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid for square mod\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for square mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    check =
        ((big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->b, n, *n) != BIG_INT_SUCCESS) ||
         (BN_mod_sqr(pool->c, pool->a, pool->b, pool->ctx) != BN_OP_SUCC) ||
         (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (op == NULL) || (n == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for inv mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check =
        ((big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->b, n, *n) != BIG_INT_SUCCESS) ||
         (bn_to_big_int(dest, *dest, BN_mod_inverse(pool->c, pool->a, pool->b, pool->ctx)) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

bool EXT_TEE_BigIntExpMod(TEE_BigInt *out, TEE_BigInt *in, const TEE_BigInt *exp, const TEE_BigInt *n)
{
    struct bn_mem_pool_t *pool = NULL;

    bool check = ((out == NULL) || (in == NULL) || (exp == NULL) || (n == NULL));
    if (check) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return false;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for exp mod is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return false;
    }

    check = ((big_int_to_bn(pool->a, in, *in) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, exp, *exp) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
        (BN_mod_exp(pool->d, pool->a, pool->b, pool->c, pool->ctx) != BN_OP_SUCC) ||
        (bn_to_big_int(out, *out, pool->d) != BIG_INT_SUCCESS));
    if (check) {
        release_mem_pool(pool);
        return false;
    }

    release_mem_pool(pool);
    return true;
}
TEE_Result TEE_BigIntExpMod(TEE_BigInt *des, TEE_BigInt *op1, const TEE_BigInt *op2, const TEE_BigInt *n,
                            TEE_BigIntFMMContext *context)
{
    (void)context;

    if (!EXT_TEE_BigIntExpMod(des, op1, op2, n))
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;
    if ((op1 == NULL) || (op2 == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return false;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for relative prime is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return false;
    }

    if ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
        (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) ||
        (BN_gcd(pool->c, pool->a, pool->b, pool->ctx) != BN_OP_SUCC)) {
        release_mem_pool(pool);
        return false;
    }

    bool ret = (bool)BN_is_one(pool->c);
    release_mem_pool(pool);
    return ret;
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u, TEE_BigInt *v, const TEE_BigInt *op1,
                                  const TEE_BigInt *op2)
{
    struct bn_mem_pool_t *pool = NULL;
    if ((gcd == NULL) || (u == NULL) || (v == NULL) || (op1 == NULL) || (op2 == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for extended gcd is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
                  (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) ||
                  (BN_gcd(pool->d, pool->a, pool->b, pool->ctx) != BN_OP_SUCC) ||
                  (bn_to_big_int(gcd, *gcd, pool->d) != BIG_INT_SUCCESS) ||
                  (BN_div(pool->a, pool->e, pool->a, pool->d, pool->ctx) != BN_OP_SUCC) ||
                  (BN_div(pool->b, pool->e, pool->b, pool->d, pool->ctx) != BN_OP_SUCC) ||
                  (bn_to_big_int(u, *u, BN_mod_inverse(pool->c, pool->a, pool->b, pool->ctx)) != BIG_INT_SUCCESS) ||
                  (BN_mul(pool->e, pool->a, pool->c, pool->ctx) != BN_OP_SUCC) ||
                  (BN_set_word(pool->c, BIG_INT_INIT_VALUE) != BN_OP_SUCC) ||
                  (BN_sub(pool->e, pool->c, pool->e) != BN_OP_SUCC) ||
                  (BN_div(pool->e, pool->c, pool->e, pool->b, pool->ctx) != BN_OP_SUCC) ||
                  (bn_to_big_int(v, *v, pool->e) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op, uint32_t confidenceLevel)
{
    (void)confidenceLevel;

    int32_t ret;
    struct bn_mem_pool_t *pool = NULL;
    if (op == NULL) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for probable prime is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return (int32_t)TEE_ERROR_OUT_OF_MEMORY;
    }

    if (big_int_to_bn(pool->a, op, *op) != BIG_INT_SUCCESS) {
        release_mem_pool(pool);
        return BIG_INT_ERROR;
    }
    ret = BN_is_prime_fasttest_ex(pool->a, BN_prime_checks, pool->ctx, TRIAL_DIVISION, NULL);
    release_mem_pool(pool);
    return ret;
}

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, const TEE_BigInt *src, const TEE_BigInt *n,
                            const TEE_BigIntFMMContext *context)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (src == NULL) || (context == NULL) || (n == NULL)) {
        tloge("parameters is invalid for convert to fmm\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for convert to fmm is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check =
        ((big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
         (BN_MONT_CTX_set(pool->mont_ctx, pool->c, pool->ctx) != BN_OP_SUCC) ||
         (BN_to_montgomery(pool->b, pool->a, pool->mont_ctx, pool->ctx) != BN_OP_SUCC) ||
         (bn_to_big_int(dest, *dest, pool->b) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, const TEE_BigIntFMM *src, const TEE_BigInt *n,
                              const TEE_BigIntFMMContext *context)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (src == NULL) || (context == NULL) || (n == NULL)) {
        tloge("parameters is invalid for convert from fmm\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for convert from fmm is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check =
        ((big_int_to_bn(pool->a, src, *src) != BIG_INT_SUCCESS) || (big_int_to_bn(pool->c, n, *n) != BIG_INT_SUCCESS) ||
         (BN_MONT_CTX_set(pool->mont_ctx, pool->c, pool->ctx) != BN_OP_SUCC) ||
         (BN_from_montgomery(pool->b, pool->a, pool->mont_ctx, pool->ctx) != BN_OP_SUCC) ||
         (bn_to_big_int(dest, *dest, pool->b) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1, const TEE_BigIntFMM *op2, const TEE_BigInt *n,
                          const TEE_BigIntFMMContext *context)
{
    struct bn_mem_pool_t *pool = NULL;

    if ((dest == NULL) || (op1 == NULL) || (op2 == NULL) || (context == NULL) || (n == NULL)) {
        tloge("parameters is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    pool = reserve_mem_pool();
    if (pool == NULL) {
        tloge("reserve memory pool for compute fmm is failed\n");
        TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);
        return;
    }

    bool check = ((big_int_to_bn(pool->a, op1, *op1) != BIG_INT_SUCCESS) ||
                  (big_int_to_bn(pool->b, op2, *op2) != BIG_INT_SUCCESS) ||
                  (big_int_to_bn(pool->d, context, *context) != BIG_INT_SUCCESS) ||
                  (BN_MONT_CTX_set(pool->mont_ctx, pool->d, pool->ctx) != BN_OP_SUCC) ||
                  (BN_mod_mul_montgomery(pool->c, pool->a, pool->b, pool->mont_ctx, pool->ctx) != BN_OP_SUCC) ||
                  (bn_to_big_int(dest, *dest, pool->c) != BIG_INT_SUCCESS));
    if (check)
        tloge("big int operation error");

    release_mem_pool(pool);
}

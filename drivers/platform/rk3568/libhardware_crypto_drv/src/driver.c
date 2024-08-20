/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <crypto_driver_adaptor_ops.h>
#include <drv_io_share.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define BIT(x) (1 << (x))

#define TRNG_64_BIT_LEN (0 << 4)
#define TRNG_128_BIT_LEN (1 << 4)
#define TRNG_192_BIT_LEN (2 << 4)
#define TRNG_256_BIT_LEN (3 << 4)
#define TRNG_FATESY_SOC_RING (0 << 2)
#define TRNG_SLOWER_SOC_RING_0 (1 << 2)
#define TRNG_SLOWER_SOC_RING_1 (2 << 2)
#define TRNG_SLOWEST_SOC_RING (3 << 2)
#define TRNG_ENABLE BIT(1)
#define TRNG_START BIT(0)
#define TRNG_BASE (0xfe370000)
#define TRNG_SIZE (0x10000)
#define TRNG_RNG_CTL(addr) ((addr) + 0x0400)
#define TRNG_RST_CTL(addr) ((addr) + 0x0004)
#define TRNG_RNG_SAMPLE_CNT(addr) ((addr) + 0x0404)
#define TRNG_RNG_DOUT(addr, x) ((addr) + 0x0410 + 4 * (x))

static void put32(unsigned long addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static uint32_t get32(unsigned long addr)
{
    return *(volatile uint32_t *)addr;
}

static void set32(unsigned long addr, uint32_t set_mask)
{
    put32(addr, get32(addr) | set_mask);
}

static unsigned long s_trng_vaddr;

int32_t init(void)
{
    s_trng_vaddr = (unsigned long)ioremap((uintptr_t)TRNG_BASE, TRNG_SIZE, PROT_READ | PROT_WRITE);
    if ((void *)s_trng_vaddr == NULL)
        return -EFAULT;
    return 0;
}

uint64_t hw_rng(void)
{
    int reg = 0;
    uint64_t rnd;

    set32(TRNG_RNG_SAMPLE_CNT(s_trng_vaddr), 100);

    reg |= TRNG_64_BIT_LEN;
    reg |= TRNG_SLOWER_SOC_RING_0;
    reg |= TRNG_ENABLE;
    reg |= TRNG_START;

    put32(TRNG_RNG_CTL(s_trng_vaddr), ((0xffff) | (reg)) << 16 | (reg));

    set32(TRNG_RNG_CTL(s_trng_vaddr), 0b1);
    while (get32(TRNG_RNG_CTL(s_trng_vaddr)) & 1);
    
    rnd = ((uint64_t)get32(TRNG_RNG_DOUT(s_trng_vaddr, 0)) << 32) | (uint64_t)get32(TRNG_RNG_DOUT(s_trng_vaddr, 1));

    put32(TRNG_RNG_CTL(s_trng_vaddr), (0xffff) << 16);

    return rnd;
}

int32_t generate_random(void *buffer, size_t size)
{
    size_t i;
    int rnd;
    for (i = 0; i < size; i += sizeof(uint64_t)) {
        rnd = hw_rng();
        memcpy(buffer + i, &rnd, MIN(sizeof(uint64_t), size - i));
    }
    return 0;
}

__attribute__((visibility("default"))) const struct crypto_drv_ops_t g_crypto_drv_ops = {
    .init = init,
    .generate_random = generate_random,
};

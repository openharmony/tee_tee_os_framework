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
#ifndef DRIVERS_REGISTER_OPS_H
#define DRIVERS_REGISTER_OPS_H
#include <stdint.h>

#define ALIGN(addr, size) (((addr) + (size) - 1) & ~((size) - 1))
#define read32(addr) u32_read((volatile unsigned *)(uintptr_t)(addr))
#define read16(addr) u16_read((volatile unsigned short *)(uintptr_t)(addr))

#ifdef __aarch64__
static inline void u8_write(uint8_t val, volatile void  *addr)
{
    asm volatile("strb %w0, [%1]" : : "rZ" (val), "r" (addr));
}

static inline void u16_write(uint16_t val, volatile void  *addr)
{
    asm volatile("strh %w0, [%1]" : : "rZ" (val), "r" (addr));
}

static inline void u32_write(uint32_t val, volatile void  *addr)
{
    asm volatile("str %w0, [%1]" : : "rZ" (val), "r" (addr));
}

static inline void u64_write(uint64_t val, volatile void  *addr)
{
    asm volatile("str %x0, [%1]" : : "rZ" (val), "r" (addr));
}

static inline uint8_t u8_read(const volatile void  *addr)
{
    uint8_t val;
    asm volatile("ldrb %w0, [%1]" : "=r" (val) : "r" (addr));
    return val;
}

static inline uint16_t u16_read(const volatile void  *addr)
{
    uint16_t val;
    asm volatile("ldrh %w0, [%1]" : "=r" (val) : "r" (addr));
    return val;
}

static inline uint32_t u32_read(const volatile void *addr)
{
    uint32_t val;
    asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (addr));
    return val;
}

static inline uint64_t u64_read(const volatile void *addr)
{
    uint64_t val;
    asm volatile("ldr %0, [%1]" : "=r" (val) : "r" (addr));
    return val;
}

#else

static inline void u16_write(uint16_t val, volatile void *addr)
{
    asm volatile("strh %1, %0"
             : : "Q" (*(volatile uint16_t *)addr), "r" (val));
}

static inline uint16_t u16_read(const volatile void *addr)
{
    uint16_t val;
    asm volatile("ldrh %0, %1" : "=r" (val) : "Q" (*(volatile uint16_t *)addr));
    return val;
}

static inline void u8_write(uint8_t val, volatile void *addr)
{
    asm volatile("strb %1, %0"
             : : "Qo" (*(volatile uint8_t *)addr), "r" (val));
}

static inline void u32_write(uint32_t val, volatile void *addr)
{
    asm volatile("str %1, %0"
            : : "Qo" (*(volatile uint32_t *)addr), "r" (val));
}

static inline uint8_t u8_read(const volatile void *addr)
{
    uint8_t val;
    asm volatile("ldrb %0, %1" : "=r" (val) : "Qo" (*(volatile uint8_t *)addr));
    return val;
}

static inline uint32_t u32_read(const volatile void *addr)
{
    uint32_t val;
    asm volatile("ldr %0, %1" : "=r" (val) : "Qo" (*(volatile uint32_t *)addr));
    return val;
}

static inline void u64_write(uint64_t val, volatile void  *addr)
{
    asm volatile("strd %1, %0"
             : : "Qo" (*(volatile uint64_t *)addr), "r" (val));
}

static inline uint64_t u64_read(const volatile void *addr)
{
    uint64_t val;
    asm volatile("ldrd %0, %1" : "=r"(val) : "Qo" (*(volatile uint64_t *)addr));
    return val;
}

#endif

static inline void data_sync(void) /* drain write buffer */
{
    asm volatile("dsb sy");
}

static inline void write32(unsigned long addr, unsigned val)
{
    data_sync();
    u32_write(val, (volatile unsigned *)(uintptr_t)(addr));
    data_sync();
}

static inline void write16(unsigned long addr, unsigned val)
{
    data_sync();
    u16_write(val, (volatile unsigned short *)(uintptr_t)(addr));
    data_sync();
}

static inline void writel(unsigned val, unsigned long addr)
{
    data_sync();
    u32_write(val, (volatile unsigned *)(uintptr_t)(addr));
    data_sync();
}

static inline void writew(unsigned val, unsigned long addr)
{
    data_sync();
    u16_write(val, (volatile unsigned short *)(uintptr_t)(addr));
    data_sync();
}

static inline void writeb(unsigned val, unsigned long addr)
{
    data_sync();
    u8_write(val, (volatile unsigned char *)(uintptr_t)(addr));
    data_sync();
}

static inline unsigned readl(unsigned long addr)
{
    return u32_read((volatile unsigned *)(uintptr_t)(addr));
}

static inline unsigned readw(unsigned long addr)
{
    return u16_read((volatile unsigned short *)(uintptr_t)(addr));
}

static inline unsigned char readb(unsigned long addr)
{
    return u8_read((volatile unsigned char *)(uintptr_t)(addr));
}

static inline void writeq(uint64_t val, uint64_t addr)
{
    data_sync();
    u64_write(val, (volatile uint64_t *)(uintptr_t)addr);
    data_sync();
}

static inline uint64_t readq(uint64_t addr)
{
    return u64_read((volatile uint64_t *)(uintptr_t)addr);
}

#endif /* DRIVERS_REGISTER_OPS_H */

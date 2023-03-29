/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include "test_libc_func.h"

#define TEST_PAGE_SIZE 4096
#define FD_MMAP_PMEM  (-9)

static int do_zero_test(void *buf, size_t sz)
{
    size_t *p = buf;
    for (size_t i = 0; i < sz; i += sizeof(size_t), p++) {
        if (*p)
            return -1;
    }
    return 0;
}

#define TEST_MMAP_ITER 10
int test_mmap(void)
{
    int ret = 0;
    int i;
    char *ptr[TEST_MMAP_ITER];
    char *p;
    int k = 0;

    for (i = 0; i < TEST_MMAP_ITER; i++) {
        ptr[i] = mmap((char *)0, TEST_PAGE_SIZE * (i + 1),
                  PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS,
                  -1, 0);
        if (ptr[i] == MAP_FAILED) {
            printf("Failed to mmap at iteration %d.\n", i);
            k = i;
            goto err_reclaim;
        }

        printf("Mmap at iteration %d with %p[%p].\n",
            i, ptr[i], ptr[i] + (TEST_PAGE_SIZE * (i + 1)));

        if (do_zero_test(ptr[i], TEST_PAGE_SIZE * (i + 1))) {
            printf("Zero test failed at iteration %d\n", i);
            k = i + 1;
            goto err_reclaim;
        }
    }

    for (i = 0; i < TEST_MMAP_ITER; i++) {
        ret = munmap(ptr[i], TEST_PAGE_SIZE * (i + 1));
        if (ret != 0) {
            printf("Munmap failed at ptr[%d] = %p.\n", i, ptr[i]);
            return ret;
        }
    }

    // mmap with invalid prot.
    p = mmap((char *)0, TEST_PAGE_SIZE,
         PROT_WRITE,
         MAP_ANONYMOUS,
         -1, 0);
    if (p != MAP_FAILED) {
        munmap(p, TEST_PAGE_SIZE);
        printf("Mmap with PROT_WRITE should failed.\n");
        return -1;
    }

    // mmap physical with all PROT flags (incl PROT_CLEAR) and invalid paddr
    p = mmap(NULL, TEST_PAGE_SIZE, -1, MAP_FILE, FD_MMAP_PMEM, 0);
    if (p != MAP_FAILED) {
        printf("mmap physical failed\n");
        return -1;
    }
    if (munmap(p, TEST_PAGE_SIZE) == 0) {
        printf("munmap physical should failed, but success\n");
        return -1;
    }
    printf("test mmap & munmap success.\n");
    return 0;

err_reclaim:
    for (i = 0; i < k; i++) {
        ret = munmap(ptr[i], TEST_PAGE_SIZE * (i + 1));
        if (ret != 0)
            printf("Munmap failed at ptr[%d] = %p.\n", i, ptr[i]);
    }
    return -1;
}
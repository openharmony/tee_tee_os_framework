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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "test_libc_func.h"

#define BUFSIZE 128

#define FMT0 "test: %o %u %x %X\n"
#define AP0  99, 99, 99, 99

#define FMT1 "test: %d %i\n"
#define AP1  99, 99

#define FMT2 "test: %e %E\n"
#define AP2  99.99, 99.99

#define FMT3 "test: %f %F\n"
#define AP3  99.99, 99.99

#define FMT4 "test: %g %G\n"
#define AP4  99.99, 99.99

#define FMT5 "test: %c\n"
#define AP5  '9'

#define FMT6 "test: %s\n"
#define AP6  "9999"

#define FMT7 "test: %%\n"
#define AP7

#define FMT8 "test: %#x %#X\n"
#define AP8  99, 99

static int test(char *fmt, ...)
{
    va_list ap;
    int iret;
    char pszbuf[BUFSIZE];

    va_start(ap, fmt);
    iret = vsprintf(pszbuf, fmt, ap);
    va_end(ap);

    return iret;
}

int do_test_vsprintf(void)
{
    int iret;

    if ((iret = test(FMT0, AP0)) < 0) goto fail;
    if ((iret = test(FMT1, AP1)) < 0) goto fail;
    if ((iret = test(FMT2, AP2)) < 0) goto fail;
    if ((iret = test(FMT3, AP3)) < 0) goto fail;
    if ((iret = test(FMT4, AP4)) < 0) goto fail;
    if ((iret = test(FMT5, AP5)) < 0) goto fail;
    if ((iret = test(FMT6, AP6)) < 0) goto fail;
    if ((iret = test(FMT7)) < 0) goto fail;
    if ((iret = test(FMT8, AP8)) < 0) goto fail;

    printf("TEST PASSED\n");
    return 0;
fail:
    fprintf(stderr, "TEST FAULT %d\n", iret);
    return -1;
}

#define SIZE (70)
#define STR(x) #x

int do_test_sprintf(void)
{
    char buf[100];
    int result = 0;

    puts("sprintf test start");
    if (sprintf(buf, "%.0ls", L"foo") != 0
        || strlen(buf) != 0) {
        puts("sprintf (buf, \"%.0ls\", L\"foo\") produced some output");
        result = 1;
    }

    char *dst = malloc(SIZE + 1);

    if (dst == NULL) {
        puts("memory allocation failure");
        result = 1;
    } else {
        sprintf(dst, "%*s", SIZE, "");
        if (strnlen(dst, SIZE + 1) != SIZE) {
            puts("sprintf (dst, \"%*s\", " STR(SIZE)
                 ", \"\") did not produce enough output");
            result = 1;
        }
        free(dst);
    }

    if (sprintf(buf, "%1$d%3$.*2$s%4$d", 7, 67108863, "x", 8) != 3
        || strcmp(buf, "7x8") != 0) {
        printf("sprintf (buf, \"%%1$d%%3$.*2$s%%4$d\", 7, 67108863, \"x\", 8) produced `%s' output",
               buf);
        result = 1;
    }


    if (sprintf(buf, "%%67108863.16\"%d", 7) != 14
        || strcmp(buf, "%67108863.16\"7") != 0) {
        printf("sprintf (buf, \"%%67108863.16\\\"%%d\", 7) produced `%s' output", buf);
        result = 1;
    }

    if (sprintf(buf, "%%%d\"%d", 0x3ffffff, 7) != 11
        || strcmp(buf, "%67108863\"7") != 0) {
        printf("sprintf (buf, \"%%*\\\"%%d\", 0x3ffffff, 7) produced `%s' output", buf);
        result = 1;
    }
    printf("sprintf test result = %d\n", result);
    return result;
}

int do_test_fflush(void)
{
    int i;
    for (i = 0; i < 10; i++) {
        printf("fflush i=%d\n", i);
        fflush(stdout);
    }
    return 0;

}

int do_test_stdio(void)
{
    printf("=== test stdio begin ===\n");

    char ch1 = 'x', ch2;
    ungetc(ch1, stdin);
    ch2 = getc(stdin);
    if (ch1 != ch2) {
        printf("Failed: getc/ungetc failed, unget %c and get %c\n", ch1, ch2);
        return -1;
    }
    printf("Test putc, expect 'ok' ... ");
    putc('o', stdout);
    putc('k', stdout);
    printf("\n");
    wchar_t wc = L'x', wc2;
    ungetwc(wc, stdin);
    wc2 = getwc(stdin);
    if (wc != wc2) {
        printf("Failed: test getwc and ungetwc failed\n");
        return -1;
    }
    printf("Test putwc, expect 'ok' ... ");
    putwc(L'o', stdout);
    putwc(L'k', stdout);
    printf("\n");
    printf("=== test stdio end   ===\n\n");
    return 0;
}


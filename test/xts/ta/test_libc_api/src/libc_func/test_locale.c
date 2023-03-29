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

#include <ctype.h>
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include "test_libc_func.h"

struct ltest {
    const char *str;        /* Convert this.  */
    double expect;        /* To get this.  */
    char left;            /* With this left over.  */
    int err;            /* And this in errno.  */
};
static const struct ltest tests_g1[] = {
    { "12.345", 12.345, '\0', 0 },
    { "12.345e19", 12.345e19, '\0', 0 },
    { "-.1e+9", -.1e+9, '\0', 0 },
    { ".125", .125, '\0', 0 },
    { "1e20", 1e20, '\0', 0 },
    { "0e-19", 0, '\0', 0 },
    { "4\00012", 4.0, '\0', 0 },
    { "5.9e-76", 5.9e-76, '\0', 0 },
    { "0x1.4p+3", 10.0, '\0', 0 },
    { "0xAp0", 10.0, '\0', 0 },
    { "0x0Ap0", 10.0, '\0', 0 },
    { "0x0A", 10.0, '\0', 0 },
    { "0xA0", 160.0, '\0', 0 },
    { "0x0.A0p8", 160.0, '\0', 0 },
    { "0x0.50p9", 160.0, '\0', 0 },
    { "0x0.28p10", 160.0, '\0', 0 },
    { "0x0.14p11", 160.0, '\0', 0 },
    { "0x0.0A0p12", 160.0, '\0', 0 },
    { "0x0.050p13", 160.0, '\0', 0 },
    { "0x0.028p14", 160.0, '\0', 0 },
    { "0x0.014p15", 160.0, '\0', 0 },
    { "0x00.00A0p16", 160.0, '\0', 0 },
    { "0x00.0050p17", 160.0, '\0', 0 },
    { "0x00.0028p18", 160.0, '\0', 0 },
    { "0x00.0014p19", 160.0, '\0', 0 },
    { NULL, 0, '\0', 0 }
};

struct test {
    const char *str;
    double result;
    size_t offset;
} tests_g2[] = {
    { "0xy", 0.0, 1 },
    { "0x.y", 0.0, 1 },
    { "0x0.y", 0.0, 4 },
    { "0x.0y", 0.0, 4 },
    { ".y", 0.0, 0 },
    { "0.y", 0.0, 2 },
    { ".0y", 0.0, 2 }
};

static void expand(char *dst, register int c)
{
    if (isprint(c)) {
        dst[0] = c;
        dst[1] = '\0';
    } else
        (void) sprintf(dst, "%#.3o", (unsigned int) c);
}

int do_test_strtod1(void)
{
    char buf[100];
    register const struct ltest *lt;
    char *ep;
    int status = 0;
    int save_errno;

    for (lt = tests_g1; lt->str != NULL; ++lt) {
        double d;

        errno = 0;
        d = strtod(lt->str, &ep);
        save_errno = errno;
        printf("strtod (\"%s\") test %u",
               lt->str, (unsigned int)(lt - tests_g1));
        if (d == lt->expect && *ep == lt->left && save_errno == lt->err)
            puts("\tOK");
        else {
            puts("\tBAD");
            if (d != lt->expect)
                printf("  returns %.60g, expected %.60g\n", d, lt->expect);
            if (lt->left != *ep) {
                char exp1[5], exp2[5];
                expand(exp1, *ep);
                expand(exp2, lt->left);
                printf("  leaves '%s', expected '%s'\n", exp1, exp2);
            }
            if (save_errno != lt->err)
                printf("  errno %d (%s)  instead of %d (%s)\n",
                       save_errno, strerror(save_errno),
                       lt->err, strerror(lt->err));
            status = 1;
        }
    }

    sprintf(buf, "%f", strtod("-0.0", NULL));
    if (strcmp(buf, "-0.000000") != 0) {
        printf("  strtod (\"-0.0\", NULL) returns \"%s\"\n", buf);
        status = 1;
    }
    return status;
}

int do_test_strtod2(void)
{
    /* Regenerate this string using

       echo '(2^53-1)*2^(1024-53)' | bc | sed 's/\([^\]*\)\\*$/    "\1"/'

     */
    static const char longestdbl[] =
        "17976931348623157081452742373170435679807056752584499659891747680315"
        "72607800285387605895586327668781715404589535143824642343213268894641"
        "82768467546703537516986049910576551282076245490090389328944075868508"
        "45513394230458323690322294816580855933212334827479782620414472316873"
        "8177180919299881250404026184124858368";
    double d = strtod(longestdbl, NULL);

    printf("strtod (\"%s\", NULL) = %g\n", longestdbl, d);

    if (d != 179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.000000)
        return 1;

    return 0;
}

int do_test_strtod3(void)
{
    int status = 0;
    size_t i;
    for (i = 0; i < sizeof(tests_g2) / sizeof(tests_g2[0]); ++i) {
        char *ep;
        double r = strtod(tests_g2[i].str, &ep);
        if (r != tests_g2[i].result) {
            printf("test %zu r = %g, expect %g\n", i, r, tests_g2[i].result);
            status = 1;
        }
        if (ep != tests_g2[i].str + tests_g2[i].offset) {
            printf("test %zu strtod parsed %tu characters, expected %zu\n",
                   i, ep - tests_g2[i].str, tests_g2[i].offset);
            status = 1;
        }
    }
    return status;
}

int do_test_strcoll(void)
{
    const char t1[] = "0-0-0-0-0-0-0-0-0-0.COM";
    const char t2[] = "00000-00000.COM";
    int res1;
    int res2;

    res1 = strcoll(t1, t2);
    printf("strcoll (\"%s\", \"%s\") = %d\n", t1, t2, res1);
    res2 = strcoll(t2, t1);
    printf("strcoll (\"%s\", \"%s\") = %d\n", t2, t1, res2);

    return ((res1 == 0 && res2 != 0)
        || (res1 != 0 && res2 == 0)
        | (res1 < 0 && res2 < 0)
        || (res1 > 0 && res2 > 0));
}

int test_strxfrm(void)
{
    char dest[10], src[10];
    int len;
    if (strcmp("C.UTF-8", setlocale(1, NULL)) != 0) {
        printf("Failed: Test setlocale fail\n");
        return -1;
    }
    if (!(strcoll("ABC", "abc") < 0)) {
        printf("Failed: Test strcoll fail\n");
        return -1;
    }
    strcpy(src, "strxfrm");
    len = strxfrm(dest, src, 10);
    if (!(len == 7 && strcmp(dest, src) == 0)) {
        printf("Failed: Test strxfm fail, got len %d, str %s\n", len, dest);
        return -1;
    }
    return 0;
}


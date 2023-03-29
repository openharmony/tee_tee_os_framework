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
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>
#include <wchar.h>
#include "test_libc_func.h"

int do_test_ctype(void)
{
    printf("=== test ctype begin ===\n");
    if (isdigit('9') == 0) {
        printf("Failed: isdigit test failed\n");
        return -1;
    }
    if (isascii('a') == 0) {
        printf("Failed: isascii test failed\n");
        return -1;
    }
    if (islower('A') != 0) {
        printf("ERROR: islower test failed\n");
        return -1;
    }
    if (isspace(' ') == 0) {
        printf("ERROR: isspace test failed\n");
        return -1;
    }
    wchar_t wc = L'T';
    if (towlower(wc) != L't') {
        printf("ERROR: towlower test failed\n");
        return -1;
    }
    wint_t a = L'1';
    if (iswdigit(a) == 0) {
        printf("ERROR: iswdigit test failed\n");
        return -1;
    }
    // now, locale only support C or UTF-8, __ctype_get_mb_cur_max should be 1 or 4
    unsigned long nbytes = __ctype_get_mb_cur_max();
    if (nbytes != 4 && nbytes != 1) {
        printf("Failed: locale only support C or UTF-8, __ctype_get_mb_cur_max should return 1 or 4, but got %lu\n",
               nbytes);
        return -1;
    }
    printf("=== test ctype end   ===\n\n");
    return 0;
}


int do_test_wctype(void)
{
    int result = 0;
    wctype_t bit_alnum = wctype("alnum");
    wctype_t bit_alpha = wctype("alpha");
    wctype_t bit_cntrl = wctype("cntrl");
    wctype_t bit_digit = wctype("digit");
    wctype_t bit_graph = wctype("graph");
    wctype_t bit_lower = wctype("lower");
    wctype_t bit_print = wctype("print");
    wctype_t bit_punct = wctype("punct");
    wctype_t bit_space = wctype("space");
    wctype_t bit_upper = wctype("upper");
    wctype_t bit_xdigit = wctype("xdigit");
    int ch;

    if (wctype("does not exist") != 0) {
        puts("wctype return value != 0 for non existing property");
        result = 1;
    }

    for (ch = 0; ch < 256; ++ch) {
#define TEST(test) \
    do                                      \
    {                                      \
        if ((is##test (ch) == 0) != (iswctype (btowc(ch), bit_##test) == 0))          \
        {                                      \
            printf ("`iswctype' class `%s' test "                  \
                "for character \\%o failed\n", #test, ch);          \
            result = 1;                              \
        }                                      \
        if ((is##test (ch) == 0) != (isw##test (btowc(ch)) == 0))              \
        {                                      \
            printf ("`isw%s' test for character \\%o failed\n",          \
                #test, ch);                          \
            result = 1;                              \
        }                                      \
    }                                      \
    while (0)

        TEST(alnum);
        TEST(alpha);
        TEST(cntrl);
        TEST(digit);
        TEST(graph);
        TEST(lower);
        TEST(print);
        TEST(punct);
        TEST(space);
        TEST(upper);
        TEST(xdigit);
    }

    if (result == 0)
        puts("All test successful!");
    return result;
}

int do_test_towfun(void)
{
    int result = 0;
    wint_t ch;

    for (ch = 0; ch < 128; ++ch) {
        if (iswlower(ch)) {
            /* Get corresponding upper case character.  */
            wint_t up = towupper(ch);
            /* This should have no effect.  */
            wint_t low  = towlower(ch);

            if ((ch != low) || (up == ch) || (up == low)) {
                printf("iswlower/towupper/towlower for character \\%x failed\n", ch);
                result++;
            }
        }

        if (iswupper(ch)) {
            /* Get corresponding lower case character.  */
            wint_t low = towlower(ch);
            /* This should have no effect.  */
            wint_t up  = towupper(ch);

            if ((ch != up) || (low == ch) || (up == low)) {
                printf("iswupper/towlower/towupper for character \\%x failed\n", ch);
                result++;
            }
        }
    }

    /* Finally some specific tests.  */
    ch = L'A';
    if (!iswupper(ch) || iswlower(ch)) {
        printf("!iswupper/iswlower (L'A') failed\n");
        result++;
    }

    ch = L'a';
    if (iswupper(ch) || !iswlower(ch)) {
        printf("iswupper/!iswlower (L'a') failed\n");
        result++;
    }

    if (towlower(L'A') != L'a') {
        printf("towlower(L'A') failed\n");
        result++;
    }

    if (towupper(L'a') != L'A') {
        printf("towupper(L'a') failed\n");
        result++;
    }

    if (result == 0)
        puts("All test successful!");

    return result;
}

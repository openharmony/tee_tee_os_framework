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

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "test_libc_func.h"

static int check_ascii_mbrtowc(const char *locname)
{
    int c;
    int res = 0;

    printf("Testing locale \"%s\":\n", locname);

    for (c = 0; c <= 127; ++c) {
        char buf[MB_CUR_MAX];
        wchar_t wc = 0xffffffff;
        mbstate_t s;
        size_t n, i;

        for (i = 0; i < MB_CUR_MAX; ++i)
            buf[i] = c + i;

        memset(&s, '\0', sizeof(s));

        n = mbrtowc(&wc, buf, MB_CUR_MAX, &s);
        if (n == (size_t) -1) {
            printf("%s: '\\x%x': encoding error\n", locname, c);
            ++res;
        } else if (n == (size_t) -2) {
            printf("%s: '\\x%x': incomplete character\n", locname, c);
            ++res;
        } else if (n == 0 && c != 0) {
            printf("%s: '\\x%x': 0 returned\n", locname, c);
            ++res;
        } else if (n != 0 && c == 0) {
            printf("%s: '\\x%x': not 0 returned\n", locname, c);
            ++res;
        } else if (c != 0 && n != 1) {
            printf("%s: '\\x%x': not 1 returned\n", locname, c);
            ++res;
        } else if (wc != (wchar_t) c) {
            printf("%s: '\\x%x': wc != L'\\x%x'\n", locname, c, c);
            ++res;
        }
    }

    printf(res == 1 ? "%d mbrtowc error\n" : "%d errors mbrtowc pass\n", res);

    return res != 0;
}

int do_test_mbrtowc(void)
{
    int result = 0;

    /* Check mapping of ASCII range for some character sets which have
       ASCII as a subset.  For those the wide char generated must have
       the same value.  */
    setlocale(LC_ALL, "C");
    result |= check_ascii_mbrtowc(setlocale(LC_ALL, NULL));

    result |= check_ascii_mbrtowc(setlocale(LC_ALL, NULL));

    result |= check_ascii_mbrtowc(setlocale(LC_ALL, NULL));

    return result;
}

static int check_ascii_wcrtomb(const char *locname)
{
    wchar_t wc;
    int res = 0;

    printf("Testing locale \"%s\":\n", locname);

    for (wc = 0; wc <= 127; ++wc) {
        char buf[2 * MB_CUR_MAX];
        mbstate_t s;
        size_t n;

        memset(buf, '\xff', sizeof(buf));
        memset(&s, '\0', sizeof(s));

        n = wcrtomb(buf, wc, &s);
        if (n == (size_t) -1) {
            printf("%s: '\\x%x': encoding error\n", locname, (int) wc);
            ++res;
        } else if (n == 0) {
            printf("%s: '\\x%x': 0 returned\n", locname, (int) wc);
            ++res;
        } else if (n != 1) {
            printf("%s: '\\x%x': not 1 returned\n", locname, (int) wc);
            ++res;
        } else if (wc != (wchar_t) buf[0]) {
            printf("%s: L'\\x%x': buf[0] != '\\x%x'\n", locname, (int) wc,
                   (int) wc);
            ++res;
        }
    }

    printf(res == 1 ? "%d error\n" : "%d errors\n", res);

    return res != 0;
}

int do_test_wcrtomb(void)
{
    int result = 0;

    setlocale(LC_ALL, "C");
    result |= check_ascii_wcrtomb(setlocale(LC_ALL, NULL));

    setlocale(LC_ALL, "C.UTF-8");
    result |= check_ascii_wcrtomb(setlocale(LC_ALL, NULL));

    setlocale(LC_ALL, "en_US.UTF-8");
    result |= check_ascii_wcrtomb(setlocale(LC_ALL, NULL));

    setlocale(LC_ALL, "POSIX");
    result |= check_ascii_wcrtomb(setlocale(LC_ALL, NULL));

    return result;
}

int do_test_wctob(void)
{
    int     bChar = 0;
    wint_t  wChar = 0;
    int     result = 0;

    // Set the corresponding wide character to exactly one byte.
    wChar = (wint_t)'A';

    bChar = wctob(wChar);
    if ((unsigned int)bChar == WEOF) {
        printf("No corresponding multibyte character was found.\n");
        result = 1;
    } else {
        printf("wctob pass: Determined the corresponding multibyte character to be \"%c\".\n",
               bChar);
        result = 0;

    }
    return result;
}

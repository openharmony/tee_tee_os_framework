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
#include <string.h>
#include "test_libc_func.h"

#define STREQ(a, b)     (strcmp((a), (b)) == 0)

int test_rt = 0;
const char *it = "<UNSET>";

static void check(int thing, int number)
{
    if (!thing) {
        printf("%s %d test failed.\n", it, number);
        test_rt++;
    }
}

static void equal(const char *a, const char *b, int number)
{
    check(a != NULL && b != NULL && STREQ(a, b), number);
}

int do_test_memcmp(void)
{
    printf("start memcmp test printf\n");
    int cnt = 1;
    int i;
    char one[21];
    char two[21];

    it = "memcmp";
    test_rt = 0;

    check(memcmp("a", "a", 1) == 0, cnt++);       /* Identity. */
    check(memcmp("abc", "abc", 3) == 0, cnt++);   /* Multicharacter. */
    check(memcmp("abcd", "abcf", 4) < 0, cnt++);  /* Honestly unequal. */
    check(memcmp("abcf", "abcd", 4) > 0, cnt++);
    check(memcmp("alph", "cold", 4) < 0, cnt++);
    check(memcmp("a\203", "a\003", 2) > 0, cnt++);
    check(memcmp("a\003", "a\203", 2) < 0, cnt++);
    check(memcmp("a\003bc", "a\203bc", 2) < 0, cnt++);
    check(memcmp("abc\203", "abc\003", 4) > 0, cnt++);
    check(memcmp("abc\003", "abc\203", 4) < 0, cnt++);
    check(memcmp("abcf", "abcd", 3) == 0, cnt++); /* Count limited. */
    check(memcmp("abc", "def", 0) == 0, cnt++);   /* Zero count. */
    /* Comparisons with shifting 4-byte boundaries. */
    for (i = 0; i < 4; ++i) {
        char *a = one + i;
        char *b = two + i;
        strncpy(a, "--------11112222", 16);
        strncpy(b, "--------33334444", 16);
        check(memcmp(b, a, 16) > 0, cnt++);
        check(memcmp(a, b, 16) < 0, cnt++);
    }

    return test_rt;
}

int do_test_strcmp(void)
{
    it = "strcmp";
    test_rt = 0;

    check(strcmp("", "") == 0, 1);                /* Trivial case. */
    check(strcmp("a", "a") == 0, 2);              /* Identity. */
    check(strcmp("abc", "abc") == 0, 3);          /* Multicharacter. */
    check(strcmp("abc", "abcd") < 0, 4);          /* Length mismatches. */
    check(strcmp("abcd", "abc") > 0, 5);
    check(strcmp("abcd", "abce") < 0, 6);         /* Honest miscompares. */
    check(strcmp("abce", "abcd") > 0, 7);
    check(strcmp("a\203", "a") > 0, 8);           /* Tricky if char signed. */
    check(strcmp("a\203", "a\003") > 0, 9);

    char buf1[0x40], buf2[0x40];
    int i, j;
    for (i = 0; i < 0x10; i++) {
        for (j = 0; j < 0x10; j++) {
            int k;
            for (k = 0; k < 0x3f; k++) {
                buf1[k] = '0' ^ (k & 4);
                buf2[k] = '4' ^ (k & 4);
            }
            buf1[i] = buf1[0x3f] = 0;
            buf2[j] = buf2[0x3f] = 0;
            for (k = 0; k < 0xf; k++) {
                int cnum = 0x10 + 0x10 * k + 0x100 * j + 0x1000 * i;
                check(strcmp(buf1 + i, buf2 + j) == 0, cnum);
                buf1[i + k] = 'A' + i + k;
                buf1[i + k + 1] = 0;
                check(strcmp(buf1 + i, buf2 + j) > 0, cnum + 1);
                check(strcmp(buf2 + j, buf1 + i) < 0, cnum + 2);
                buf2[j + k] = 'B' + i + k;
                buf2[j + k + 1] = 0;
                check(strcmp(buf1 + i, buf2 + j) < 0, cnum + 3);
                check(strcmp(buf2 + j, buf1 + i) > 0, cnum + 4);
                buf2[j + k] = 'A' + i + k;
                buf1[i] = 'A' + i + 0x80;
                check(strcmp(buf2 + j, buf1 + i) < 0, cnum + 6);
                buf1[i] = 'A' + i;
            }
        }
    }
    return test_rt;
}

int do_test_strchr(void)
{
    it = "strchr";
    test_rt = 0;
    char one[50];

    check(strchr("abcd", 'z') == NULL, 1);        /* Not found. */
    (void) strcpy(one, "abcd");
    check(strchr(one, 'c') == one + 2, 2);        /* Basic test. */
    check(strchr(one, 'd') == one + 3, 3);        /* End of string. */
    check(strchr(one, 'a') == one, 4);            /* Beginning. */
    // check(strchr(one, '\0') == one + 4, 5);       /* Finding NUL. */
    (void) strcpy(one, "ababa");
    check(strchr(one, 'b') == one + 1, 6);        /* Finding first. */
    (void) strcpy(one, "");
    check(strchr(one, 'b') == NULL, 7);           /* Empty string. */
    // check(strchr(one, '\0') == one, 8);           /* NUL in empty string. */

    char buf[4096];
    int i;
    char *p;
    for (i = 0; i < 0x100; i++) {
        p = (char *)((unsigned long int)(buf + 0xff) & ~0xff) + i;
        strcpy(p, "OK");
        strcpy(p + 3, "BAD/WRONG");
        check(strchr(p, '/') == NULL, 9 + i);
    }
    return test_rt;
}

int do_test_strlen(void)
{
    it = "strlen";
    test_rt = 0;

    check(strlen("") == 0, 1);            /* Empty. */
    check(strlen("a") == 1, 2);           /* Single char. */
    check(strlen("abcd") == 4, 3);        /* Multiple chars. */
    char buf[4096];
    int i;
    char *p;
    for (i = 0; i < 0x100; i++) {
        p = (char *)((unsigned long int)(buf + 0xff) & ~0xff) + i;
        strcpy(p, "OK");
        strcpy(p + 3, "BAD/WRONG");
        check(strlen(p) == 2, 4 + i);
    }
    return test_rt;
}

int do_test_memset(void)
{
    int i;

    it = "memset";
    test_rt = 0;
    char one[50];
    (void) strcpy(one, "abcdefgh");
    check((char *)memset(one + 1, 'x', 3) == one + 1, 1); /* Return value. */
    equal(one, "axxxefgh", 2);            /* Basic test. */

    (void) memset(one + 5, 0, 1);
    equal(one, "axxxe", 4);                       /* Zero fill. */
    equal(one + 6, "gh", 5);                      /* And the leftover. */

    (void) memset(one + 2, 010045, 1);
    equal(one, "ax\045xe", 6);            /* Unsigned char convert. */

    /* Non-8bit fill character.  */
    memset(one, 0x101, sizeof(one));
    for (i = 0; i < (int) sizeof(one); ++i)
        check(one[i] == '\01', 7);

    /* Test for more complex versions of memset, for all alignments and
       lengths up to 256. This test takes a little while, perhaps it should
       be made weaker?  */
    char data[512];
    int j;
    int k;
    int c;

    for (i = 0; i < 512; i++)
        data[i] = 'x';
    for (c = 0; c <= 'y'; c += 'y')  /* check for memset(,0,) and
                        memset(,'y',) */
        for (j = 0; j < 256; j++)
            for (i = 0; i < 256; i++) {
                memset(data + i, c, j);
                for (k = 0; k < i; k++)
                    if (data[k] != 'x')
                        goto fail;
                for (k = i; k < i + j; k++) {
                    if (data[k] != c)
                        goto fail;
                    data[k] = 'x';
                }
                for (k = i + j; k < 512; k++)
                    if (data[k] != 'x')
                        goto fail;
                continue;

fail:
                check(0, 8 + i + j * 256 + (c != 0) * 256 * 256);
            }
    return test_rt;
}

int do_test_memmove(void)
{
    it = "memmove";
    test_rt = 0;
    char one[50];
    char two[50];

    check((char *)memmove(one, "abc", 4) == one, 1);      /* Returned value. */
    equal(one, "abc", 2);                 /* Did the copy go right? */

    (void) strcpy(one, "abcdefgh");
    (void) memmove(one + 1, "xyz", 2);
    equal(one, "axydefgh", 3);            /* Basic test. */

    (void) strcpy(one, "abc");
    (void) memmove(one, "xyz", 0);
    equal(one, "abc", 4);                 /* Zero-length copy. */

    (void) strcpy(one, "hi there");
    (void) strcpy(two, "foo");
    (void) memmove(two, one, 9);
    equal(two, "hi there", 5);            /* Just paranoia. */
    equal(one, "hi there", 6);            /* Stomped on source? */

    (void) strcpy(one, "abcdefgh");
    (void) memmove(one + 1, one, 9);
    equal(one, "aabcdefgh", 7);           /* Overlap, right-to-left. */

    (void) strcpy(one, "abcdefgh");
    (void) memmove(one + 1, one + 2, 7);
    equal(one, "acdefgh", 8);             /* Overlap, left-to-right. */

    (void) strcpy(one, "abcdefgh");
    (void) memmove(one, one, 9);
    equal(one, "abcdefgh", 9);            /* 100% overlap. */

    return test_rt;
}

int do_test_memcpy(void)
{
    int i;
    it = "memcpy";
    char one[50];
    char two[50];
    test_rt = 0;


    check((char *)memcpy(one, "abc", 4) == one, 1);       /* Returned value. */
    equal(one, "abc", 2);                 /* Did the copy go right? */

    (void) strcpy(one, "abcdefgh");
    (void) memcpy(one + 1, "xyz", 2);
    equal(one, "axydefgh", 3);            /* Basic test. */

    (void) strcpy(one, "abc");
    (void) memcpy(one, "xyz", 0);
    equal(one, "abc", 4);                 /* Zero-length copy. */

    (void) strcpy(one, "hi there");
    (void) strcpy(two, "foo");
    (void) memcpy(two, one, 9);
    equal(two, "hi there", 5);            /* Just paranoia. */
    equal(one, "hi there", 6);            /* Stomped on source? */

    for (i = 0; i < 16; i++) {
        const char *x = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        strcpy(one, x);
        check(memcpy(one + i, "hi there", 9) == one + i,
              7 + (i * 6));              /* Unaligned destination. */
        check(memcmp(one, x, i) == 0, 8 + (i * 6));    /* Wrote under? */
        equal(one + i, "hi there", 9 + (i * 6));
        check(one[i + 9] == 'x', 10 + (i * 6));        /* Wrote over? */
        check(memcpy(two, one + i, 9) == two,
              11 + (i * 6));             /* Unaligned source. */
        equal(two, "hi there", 12 + (i * 6));
    }

    return test_rt;
}

static int tst_wmemchr4(void)
{
    wchar_t s1[] = L"adbabcd";
    wchar_t s2[] = L"abca";
    wchar_t *sret;
    size_t isize = 4;
    int ret = -1;
    sret = wmemchr(s1, L'a', isize);
    ret = memcmp(s2, sret, strlen((char *)s2));
    return ret;
}

static int tst_wmemchr3(void)
{
    wchar_t s1[] = L"abcdefg";
    wchar_t *sret;
    sret = wmemchr(s1, L'h', 1);
    if (sret != NULL) return -1;
    return 0;
}

static int tst_wmemchr2(void)
{
    wchar_t s1[] = L"abcdefhhijklmnopqrstuvwxyz";
    wchar_t s2[] = L"abcd";
    wchar_t *sret;
    size_t isize = 4;
    int ret = -1;
    sret = wmemchr(s1, L'a', isize);
    ret = memcmp(s2, sret, strlen((char *)s2));
    return ret;
}

static int tst_wmemchr1(void)
{
    wchar_t s1[] = L"abcdefhhijklmnopqrstuvwxyz";
    wchar_t s2[] = L"abcdefhhijklmnopqrstuvwxyz";
    wchar_t *sret;
    size_t isize = 26;
    int ret;
    sret = wmemchr(s1, L'a', isize);
    ret = memcmp(s2, sret, strlen((char *)s2));
    return ret;
}

int do_test_wmemchr(void)
{
    int ret = 0;

    if ((ret = tst_wmemchr1()) != 0) return ret;
    if ((ret = tst_wmemchr2()) != 0) return ret;
    if ((ret = tst_wmemchr3()) != 0) return ret;
    if ((ret = tst_wmemchr4()) != 0) return ret;

    return ret;
}

int do_test_wcslen(void)
{
    if (wcslen(L"0123456789\nabcdefghijklmnopqrstuvwxyz") != 37) return -1;
    if (wcslen(L"0123测试abc") != 9) return -2;
    if (wcslen(L"\n") != 1) return -3;
    if (wcslen(L"\r") != 1) return -4;
    if (wcslen(L"") != 0) return -5;
    if (wcslen(L"测试") != 2) return -6;

    return 0;
}

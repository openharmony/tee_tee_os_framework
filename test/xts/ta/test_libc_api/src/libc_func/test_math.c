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
#include <math.h>
#include "test_libc_func.h"

int do_test_atan(void)
{
    double result;
    double x = 0.5;

    result = atan(x);
    printf("The arctangent of %lf is %lf\n", x, result);
    result = tan(x);
    printf("The tan of %lf is %lf\n", x, result);
    x = 100.98;
    result = atan(x);
    printf("The arctangent of %lf is %lf\n", x, result);
    result = tan(x);
    printf("The tan of %lf is %lf\n", x, result);

    return (0);
}

int do_test_ceil(void)
{
    double number = 123.45;
    double down, up;
    down = floor(number);
    up = ceil(number);
    printf("origina lnumber %5.2lf\n", number);
    printf("number rounded down%5.2lf\n", down);
    printf("number rounded up%5.2lf\n", up);

    return 0;
}

int do_test_ceilf(void)
{
    float number = 123.45;
    float down, up;
    down = floor(number);
    up = ceilf(number);
    printf("original number %5.2lf\n", number);
    printf("number rounded down%5.2lf\n", down);
    printf("number rounded up%5.2lf\n", up);

    return 0;
}

int do_test_exp(void)
{
    double result;
    double x = 4.0;
    result = exp(x);
    printf("'e'raised to the power of %lf(e^%lf)=%lf\n", x, x, result);
    return 0;
}

int do_test_fabs(void)
{
#define Delta 1.0E-6
    if (fabs(atan(1) - 0.785398) > Delta) {
        printf("Failed: atan(1) = %f, delta=%f\n", atan(1), fabs(atan(1) - 0.785398));
        return -1;
    }
    if (fabs(ceil(-1.1) - (-1.000000)) > Delta) {
        printf("Failed: ceil(-1.1) = %f, delta=%f\n", ceil(-1.1),
               fabs(ceil(-1.1) - (-1.00)));
        return -1;
    }
    if (fabs(floor(3.8) - 3.000000) > Delta) {
        printf("Failed: floor(3.8) = %f, delta=%f\n", floor(3.8),
               fabs(floor(3.8) - 3.000000));
        return -1;
    }
#undef Delta
    return 0;
}

static int float_eq(double a, double b)
{
    if (a > (b + 0.00000001)) {
        return 1;
    } else if (a < (b - 0.000000001)) {
        return -1;
    }
    return 0;
}

int do_test_floor(void)
{
    if (float_eq(floor(0.0), 0.0) != 0) return -1;
    if (float_eq(floor(1.9), 1.0) != 0) return -2;
    if (float_eq(floor(-1.9), -2.0) != 0) return -3;
    if (float_eq(floor(0.0f), 0.0) != 0) return -4;
    if (float_eq(floor(1.9f), 1.0) != 0) return -5;
    if (float_eq(floor(-1.9f), -2.0) != 0) return -6;
    if (float_eq(floor(1ll), 1) != 0) return -7;

    return 0;
}

int do_test_frexpl(void)
{
    float x;
    int exp;
    long double y;

    y = 130.12;
    x = frexpl(64.0, &exp);
    printf("LIBC TEST 64=%.2f*2^%d\n", x, exp);

    x = frexpl(y, &exp);
    printf("LIBC TEST %Lf=%f*2^%d\n", y, x, exp);
    return 0;
}

int do_test_log(void)
{
    double result;
    double x = 800.6872;
    double y = 1000.0;
    result = log(x);
    printf("LIBC TEST - The common log of %lf is %lf\n", x, result);
    result = log(y);
    printf("LIBC TEST - The common log of %lf is %lf\n", y, result);
    return 0;
}

int do_test_log2(void)
{
    double result;
    double x = 800.6872;
    result = log2(x);
    printf("The common log2 of %lf is %lf\n", x, result);
    return 0;
}

int do_test_pow(void)
{
    long total;
    int x = 2, y = 5;
    total = pow(x, y);
    printf("The pow test %d^%d=%ld", x, y, total);
    return 0;
}

int do_test_roundf(void)
{
    float num = 1.4999;
    printf("ceil(%f) is %f\n", num, ceil(num));
    printf("floor(%f) is %f\n", num, floor(num));
    printf("roundf(%f) is %f\n", num, roundf(num));
    return 0;
}

int do_test_sqrt(void)
{

    printf("sqrt (%lf) =  %lf\n", 4.0, sqrt(4.0));
    printf("sqrt (%lf) =  %lf\n", 5.0, sqrt(5.0));
    printf("sqrtf (%lf) =  %lf\n", 9.12, sqrtf(9.12));
    printf("sqrtf (%lf) =  %lf\n", 36.0, sqrtf(36.0));

    return (0);
}

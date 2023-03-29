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

#include <stdlib.h>
#include <stdio.h>
#include "test_libc_func.h"

const int degree = 128;        /* random number generator degree (should
                   be one of 8, 16, 32, 64, 128, 256) */
const int nseq = 3;        /* number of test sequences */
const int nrnd = 50;        /* length of each test sequence */
const unsigned int seed[3] = { 0x12344321U, 0xEE11DD22U, 0xFEDCBA98 };
static int errors = 0;

void fail(const char *msg, int s, int i)
{
    printf("\nTest FAILED: ");
    printf("%s (seq %d, pos %d).\n", msg, s, i);
    errors++;
}

int do_test_srandom(void)
{
    long int rnd[nseq][nrnd];    /* pseudorandom numbers */
    char *state[nseq];        /* state for PRNG */
    char *oldstate[nseq];        /* old PRNG state */
    int s;            /* sequence index */
    int i;            /* element index */

    printf("Begining random package test using %d sequences of length %d.\n",
           nseq, nrnd);

    /* 1. Generate and store the sequences.  */
    printf("Generating random sequences.\n");
    for (s = 0; s < nseq; ++s) {
        srandom(seed[s]);
        for (i = 0; i < nrnd; ++i)
            rnd[s][i] = random();
    }

    /* 2. Regenerate and check.  */
    printf("Regenerating and checking sequences.\n");
    for (s = 0; s < nseq; ++s) {
        srandom(seed[s]);
        for (i = 0; i < nrnd; ++i)
            if (rnd[s][i] != random())
                fail("first regenerate test", s, i);
    }

    /* 3. Create state vector, one for each sequence.
       First state is random's internal state; others are malloced.  */
    printf("Creating and checking state vector for each sequence.\n");
    srandom(seed[0]);            /* reseed with first seed */
    for (s = 1; s < nseq; ++s) {
        state[s] = (char *) malloc(degree);
        oldstate[s] = initstate(seed[s], state[s], degree);
    }
    state[0] = oldstate[1];

    /* Check returned values.  */
    for (s = 1; s < nseq - 1; ++s)
        if (state[s] != oldstate[s + 1])
            fail("bad initstate() return value", s, i);

    /* 4. Regenerate sequences interleaved and check.  */
    printf("Regenerating and checking sequences in interleaved order.\n");
    for (i = 0; i < nrnd; ++i) {
        for (s = 0; s < nseq; ++s) {
            char *oldstate = (char *) setstate(state[s]);
            if (oldstate != state[(s + nseq - 1) % nseq])
                fail("bad setstate() return value", s, i);
            if (rnd[s][i] != random())
                fail("bad value generated in interleave test", s, i);
        }
    }
    return errors;
}

int do_test_random(void)
{
    int pass;
    int ret = 0;
    long int r[2];

    for (pass = 0; pass < 2; pass++) {
        srandom(0x12344321);

        int j;
        for (j = 0; j < 3; ++j)
            random();
        if (pass == 1) {
            char state[128];
            char *ostate = initstate(0x34562101, state, 128);
            if (setstate(ostate) != state) {
                puts("setstate (ostate) != state");
                ret = 1;
            }
        }

        random();
        r[pass] = random();
    }

    if (r[0] != r[1]) {
        printf("%ld != %ld\n", r[0], r[1]);
        ret = 1;
    }
    return ret;
}


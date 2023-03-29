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
 #define API_LEVEL1_1_1 2
 #define API_LEVEL1_2 3

    .extern tee_get_ta_api_level
    .extern tee_digest_update100
    .extern tee_digest_update111
    .extern tee_mac_commare_final100
    .extern tee_mac_commare_final111

    .section .text
    .align   4
#**********************************************
#  Function:   TEE_DigestUpdate
#  ASM wrapper function of TEE_DigestUpdate for GP compatible
#***********************************************
    .global TEE_DigestUpdate
    .type TEE_DigestUpdate, %function
TEE_DigestUpdate:
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    bl      tee_get_ta_api_level
    cmp     x0, #2
    b.eq    digest_gp111
    cmp     x0, #3
    b.eq    digest_gp120
digest_gp100:
    ldp     x29, x30, [sp], #48
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
    b       tee_digest_update100
digest_gp111:
digest_gp120:
    ldp     x29, x30, [sp], #48
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
    b       tee_digest_update111


#**********************************************
#  Function:   TEE_MACCompareFinal
#  ASM wrapper function of TEE_MACCompareFinal for GP compatible
#***********************************************
    .global TEE_MACCompareFinal
    .type TEE_MACCompareFinal, %function
TEE_MACCompareFinal:
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    bl      tee_get_ta_api_level
    cmp     x0, #2
    b.eq    MacCompare_gp111
    cmp     x0, #3
    b.eq    MacCompare_gp120
MacCompare_gp100:
    ldp     x29, x30, [sp], #48
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
    b       tee_mac_commare_final100
MacCompare_gp111:
MacCompare_gp120:
    ldp     x29, x30, [sp], #48
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
    b       tee_mac_commare_final111


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


    .syntax unified

    .extern tee_get_ta_api_level
    .extern tee_digest_update100
    .extern tee_digest_update111
    .extern tee_mac_commare_final100
    .extern tee_mac_commare_final111

    .section .text
    .align   2
@  **********************************************
@  Function:   TEE_DigestUpdate
@  ASM wrapper function of TEE_DigestUpdate for GP compatible
@***********************************************
    .global TEE_DigestUpdate
    .type TEE_DigestUpdate, %function
TEE_DigestUpdate:
    push    {r0-r7, fp, lr}
    add     fp, sp, #36
    bl      tee_get_ta_api_level
    cmp     r0, #API_LEVEL1_1_1
    beq     digest_gp111
    cmp     r0, #API_LEVEL1_2
    beq     digest_gp120
digest_gp100:
    sub     sp, fp, #36
    pop     {r0-r7, fp, lr}
    b       tee_digest_update100
digest_gp111:
digest_gp120:
    sub     sp, fp, #36
    pop     {r0-r7, fp, lr}
    b       tee_digest_update111


@  **********************************************
@  Function:   TEE_MACCompareFinal
@  ASM wrapper function of TEE_MACCompareFinal for GP compatible
@***********************************************
    .global TEE_MACCompareFinal
    .type TEE_MACCompareFinal, %function
TEE_MACCompareFinal:
    push    {r0-r7, fp, lr}
    add     fp, sp, #36
    bl      tee_get_ta_api_level
    cmp     r0, #API_LEVEL1_1_1
    beq     MacCompare_gp111
    cmp     r0, #API_LEVEL1_2
    beq     MacCompare_gp120
MacCompare_gp100:
    sub     sp, fp, #36
    pop     {r0-r7, fp, lr}
    b       tee_mac_commare_final100
MacCompare_gp111:
MacCompare_gp120:
    sub     sp, fp, #36
    pop     {r0-r7, fp, lr}
    b       tee_mac_commare_final111


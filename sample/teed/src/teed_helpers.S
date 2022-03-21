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

#include <asm_macros.S>

#define __ASSEMBLY__

#include <teed_private.h>

	.global	teed_enter_sp
func teed_enter_sp
	/* Make space for the registers that we're going to save */
	mov	x3, sp
	str	x3, [x0, #0]
	sub	sp, sp, #TEED_C_RT_CTX_SIZE

	/* Save callee-saved registers on to the stack */
	stp	x19, x20, [sp, #TEED_C_RT_CTX_X19]
	stp	x21, x22, [sp, #TEED_C_RT_CTX_X21]
	stp	x23, x24, [sp, #TEED_C_RT_CTX_X23]
	stp	x25, x26, [sp, #TEED_C_RT_CTX_X25]
	stp	x27, x28, [sp, #TEED_C_RT_CTX_X27]
	stp	x29, x30, [sp, #TEED_C_RT_CTX_X29]

	/*
	 * el3_exit() will use the secure context to restore to the
	 * general purpose and EL3 system registers to ERET into the secure payload
	 */
	b	el3_exit
endfunc teed_enter_sp

	/*
	 * This function is called 'x0' pointing to a C
	 * runtime context saved in teed_enter_sp()
	 */
	.global teed_exit_sp
func teed_exit_sp
	/* Restore the previous stack */
	mov	sp, x0

	/* Restore callee-saved registers on to the stack */
	ldp	x19, x20, [x0, #(TEED_C_RT_CTX_X19 - TEED_C_RT_CTX_SIZE)]
	ldp	x21, x22, [x0, #(TEED_C_RT_CTX_X21 - TEED_C_RT_CTX_SIZE)]
	ldp	x23, x24, [x0, #(TEED_C_RT_CTX_X23 - TEED_C_RT_CTX_SIZE)]
	ldp	x25, x26, [x0, #(TEED_C_RT_CTX_X25 - TEED_C_RT_CTX_SIZE)]
	ldp	x27, x28, [x0, #(TEED_C_RT_CTX_X27 - TEED_C_RT_CTX_SIZE)]
	ldp	x29, x30, [x0, #(TEED_C_RT_CTX_X29 - TEED_C_RT_CTX_SIZE)]

	/*
	 * This should take us back to the instruction
	 * after the call to the last teed_enter_sp().
	 */
	mov	x0, x1
	ret
endfunc teed_exit_sp

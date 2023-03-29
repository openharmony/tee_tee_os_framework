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

#include <stdio.h>
#include "ui/ui_local.h"
#include "openssl/ossl_typ.h"
#include "crypto/evp.h"
#include "internal/dso.h"
#include "openssl/ossl_typ.h"
#include "arm_arch.h"

unsigned int OPENSSL_armcap_P = ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256 | ARMV7_NEON;
UI *UI_new(void)
{
    return NULL;
}

int UI_add_input_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize)
{
    return -1;
}

int UI_add_verify_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize,
    const char *test_buf)
{
    return -1;
}

int UI_process(UI *ui)
{
    return -1;
}

void UI_free(UI *ui)
{
}

void async_deinit(void)
{
}

void ossl_store_cleanup_int(void)
{
}

void async_delete_thread_state(void)
{
}

int async_init(void)
{
    return 1;
}

int DSO_free(DSO *dso)
{
    return 1;
}

void X448_public_from_private(uint8_t out_public_value[56],
                              const uint8_t private_key[56])
{
}

int ED448_public_from_private(uint8_t out_public_key[57],
                              const uint8_t private_key[57])
{
    return 1;
}

int X448(uint8_t out_shared_key[56], const uint8_t private_key[56],
         const uint8_t peer_public_value[56])
{
    return 1;
}

int ED448_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
               const uint8_t public_key[57], const uint8_t private_key[57],
               const uint8_t *context, size_t context_len)
{
    return 1;
}

int ED448_verify(const uint8_t *message, size_t message_len,
                 const uint8_t signature[114], const uint8_t public_key[57],
                 const uint8_t *context, size_t context_len)
{
    return 1;
}

int getuid(void)
{
    return 0;
}

int geteuid(void)
{
    return 0;
}

int getgid(void)
{
    return 0;
}

int getegid(void)
{
    return 0;
}

int getpid(void)
{
    return 0;
}

int openssl_config_int(const OPENSSL_INIT_SETTINGS *settings)
{
    return 1;
}

void openssl_no_config_int(void)
{
}

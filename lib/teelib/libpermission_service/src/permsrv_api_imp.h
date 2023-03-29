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
#ifndef __PERSRV_API_IMP_H__
#define __PERSRV_API_IMP_H__

#include "permission_service.h"

#define HASH_FILE_MAX_SIZE (64 * 1024)
#define PERMSRV_FILE_OPT "permsrv_file_operation"

int perm_srv_msg_call(const char *path, perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp);

void tee_perm_init_msg(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg);

TEE_Result rslot_file_msg_call(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg);

void permsrv_registerta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id, uint32_t opt_type);

TEE_Result tee_cert_import(const uint8_t *cert_buf, uint32_t cert_size, const uint8_t *pub_key, uint32_t pub_key_size);

void permsrv_notify_unload_ta(const TEE_UUID *uuid);

void permsrv_load_file(void);

TEE_Result permsrv_elf_verify(const void *verify_req, uint32_t len);

TEE_Result tee_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size);

#endif /* __PERSRV_API_IMP_H__ */

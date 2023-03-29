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
#ifndef PERM_SRV_ELF_VERIFY_CMD_H
#define PERM_SRV_ELF_VERIFY_CMD_H

#include <tee_defines.h>
#include "permission_service.h"

enum rpmb_status {
    PERMSRV_RPMB_UNKNOWN = 0,
    PERMSRV_RPMB_AGENT_REGTISTED,
    PERMSRV_RPMB_AGENT_NOT_REGISTED,
    PERMSRV_RPMB_ERR,
};

TEE_Result perm_srv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                               const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp);
#endif

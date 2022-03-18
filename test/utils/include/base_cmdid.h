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

#ifndef __BASE_CMDID_H__
#define __BASE_CMDID_H__

/**
 * the structure of cmdid
 * total: 32 bits
 * 31 30 ... 16 15 ... 1 0
 *
 * |----16----|----16----|
 * base_id    inner_id
 */

// other module can be defined in turn
#define BASEID_SAMPLE 0
#define BASEID_COMMUNICATION 1
#define BASEID_DRVTEST 2


#define GET_CMD_ID(base, inner) ((((uint32_t)(base)) << 16) | (inner))

#define GET_BASE_ID(cmd_id) (((uint32_t)(cmd_id)) >> 16)

#define GET_INNER_ID(cmd_id) (((uint32_t)(cmd_id)) & 0x0000ffff)

#endif

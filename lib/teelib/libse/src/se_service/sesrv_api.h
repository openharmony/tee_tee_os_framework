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
#ifndef SE_SERVICE_SESRV_API_H
#define SE_SERVICE_SESRV_API_H

#include "tee_defines.h"

struct se_transmit_info_t {
    uint32_t reader_id;
    uint8_t channel_id;
    uint8_t *data;
    uint32_t data_len;
    uint8_t *p_rsp;
    uint32_t rsp_len;
};

bool se_srv_exist(void);
int se_srv_get_ese_type(void);
TEE_Result se_srv_connect(uint32_t reader_id, uint8_t *p_atr, uint32_t *atr_len);
TEE_Result se_srv_disconnect(uint32_t reader_id);
TEE_Result tee_se_srv_transmit(struct se_transmit_info_t *transmit_info);
TEE_Result tee_se_srv_open_basic_channel(struct se_transmit_info_t *transmit_info);
TEE_Result tee_se_srv_open_logical_channel(struct se_transmit_info_t *transmit_info);
TEE_Result tee_se_srv_close_channel(const struct se_transmit_info_t *transmit_info);
TEE_Result tee_se_srv_select_channel(struct se_transmit_info_t *transmit_info);
bool se_srv_get_msp_status(void);
bool se_srv_get_sec_flash_status(void);
#endif

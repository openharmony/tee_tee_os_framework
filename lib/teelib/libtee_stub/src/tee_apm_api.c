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
#include <tee_apm_api.h>

TEE_Result tee_query_ta_measure_report(const TEE_UUID *uuid, struct ta_measure_report_t *report)
{   
    (void)uuid;
    (void)report;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_query_mspc_measure_report(struct mspc_metric_result_report_t *report)
{
    (void)report;
    return TEE_ERROR_NOT_SUPPORTED;
}
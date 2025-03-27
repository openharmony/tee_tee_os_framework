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

#ifndef TEE_APM_API_H
#define TEE_APM_API_H

#include "tee_defines.h"

/**
 * @addtogroup TeeTrusted
 * @{
 *
 * @brief TEE(Trusted Excution Environment) API.
 * Provides security capability APIs such as trusted storage, encryption and decryption,
 * and trusted time for trusted application development.
 *
 * @since 12
 */

/**
 * @file tee_apm_api.h
 *
 * @brief Provides the API about TA APM.
 *
 * @library NA
 * @kit TEEKit
 * @syscap SystemCapability.Tee.TeeClient
 * @since 12
 * @version 1.0
 */

#ifdef __cplusplus
extern "C" {
#endif

enum tee_measure_result_value {
    TEE_MEASURE_SUCCESS                            = 0x00000000,
    TEE_MEASURE_ERROR_GENERIC                      = 0x00000001,
    TEE_MEASURE_ERROR_TA_HASH_CHECK_FAILED         = 0x00000002,
    TEE_MEASURE_ERROR_TA_BASELINE_NOT_EXIST        = 0x00000003,
    TEE_MEASURE_ERROR_TA_MEMHASH_NOT_EXIST         = 0x00000004,
    TEE_MEASURE_ERROR_PERMISSION_DENY              = 0x00000005,
    TEE_MEASURE_ERROR_TA_HISTORY_MEASURE_NOT_EXIT  = 0x00000006,
    TEE_MEASURE_ERROR_MSPC_REPORT_QUERY_FAILED     = 0x00000007,
    TEE_MEASURE_ERROR_MSPC_NOT_SUPPORT             = 0x00000008,
    TEE_MEASURE_ERROR_REPORT_NOT_SUPPORT           = 0x00000009,
    TEE_MEASURE_ERROR_APM_NOT_SUPPORT              = 0x0000000a,
};

/**
 * @brief Record the recent measure errors.
 *
 * @since 12
 * @version 1.0
 */
#define MAX_HISTORY_MEASURE_RECORDS_NUM 10

struct history_measure_result_t {
    uint8_t error_num;
    /** measure error type */
    uint32_t error_type[MAX_HISTORY_MEASURE_RECORDS_NUM];
    /** measure error time */
    uint64_t error_time[MAX_HISTORY_MEASURE_RECORDS_NUM];
};

#define TA_HASH_SIZE 12

struct ta_measure_report_t {
    /** TA's UUID */
    TEE_UUID uuid;
    /** TA's measure result */
    uint32_t measure_result;
    /** TA's measure hash */
    uint8_t ta_measured[TA_HASH_SIZE];
    /** TA's baseline hash */
    uint8_t ta_baseline[TA_HASH_SIZE];
    /** history measurement errors. */
    struct history_measure_result_t history_result;
};

/**
 * @brief Query ta measure report.
 *
 * @param uuid The TA's UUID.
 * @param report The agent ID. 
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns other information otherwise.
  *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_query_ta_measure_report(const TEE_UUID *uuid, struct ta_measure_report_t *report);

struct mspc_metric_report_element_t {
    uint32_t baseline_status;
    uint32_t recent_error;
    uint32_t error_class;
    uint32_t error_time;
};

struct mspc_metirc_result_report_sub {
    struct mspc_metric_report_element_t global_result;
    struct mspc_metric_report_element_t bl2_result;
    struct mspc_metric_report_element_t bl31_result;
    struct mspc_metric_report_element_t tee_result;
};

struct mspc_metirc_result_report_passive {
    struct mspc_metric_report_element_t bl2_verify_result;
    struct mspc_metric_report_element_t tee_active_protect;
};

struct mspc_metirc_result_report_of_cmd_process {
    struct mspc_metric_report_element_t cmd_baseline;
    struct mspc_metric_report_element_t cmd_active_metric;
    struct mspc_metric_report_element_t cmd_passive_metric;
    struct mspc_metric_report_element_t cmd_query_result;
};

struct mspc_metric_result_report_t {
    uint32_t final_result;
    struct mspc_metirc_result_report_sub baseline_report;
    struct mspc_metirc_result_report_sub idel_metric_report;
    struct mspc_metirc_result_report_sub active_metric_report;
    struct mspc_metirc_result_report_passive passive_metric_report;
    struct mspc_metirc_result_report_of_cmd_process cmd_process_report;
};

/**
 * @brief Query mspc measure report.
 *
 * @param report The agent ID. 
 *
 * @return Returns {@code TEE_SUCCESS} if the operation is successful.
 *         Returns other information otherwise.
  *
 * @since 12
 * @version 1.0
 */
TEE_Result tee_query_mspc_measure_report(struct mspc_metric_result_report_t *report);

#ifdef __cplusplus
}
#endif
/** @} */
#endif
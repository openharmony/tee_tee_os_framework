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
#include "perm_srv_ta_cert.h"
#include <timer_export.h>
#include <crypto_wrapper.h>
#include <tee_log.h>

#define DECIMAL_UNIT_SIZE 10
#define DATE_TAIL_INDEX   12
#define CMP_YEAR_ACCURACY 100

#define ASN1_TO_INT(x)             ((x) - '0')

static TEE_Result asn1_bytes_to_tee_time(const uint8_t *asn1_time, size_t asn1_buff_size, TEE_Date_Time *tm)
{
    (void)asn1_buff_size;
    /* asn1_time is encoded in  format "YYMMDDHHMMSSZ" */
    if (asn1_time[DATE_TAIL_INDEX] != 'Z')
        return TEE_ERROR_BAD_PARAMETERS;

    tm->year    = ASN1_TO_INT(asn1_time[0]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[1]);
    tm->month   = ASN1_TO_INT(asn1_time[2]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[3]);
    tm->day     = ASN1_TO_INT(asn1_time[4]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[5]);
    tm->hour    = ASN1_TO_INT(asn1_time[6]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[7]);
    tm->min     = ASN1_TO_INT(asn1_time[8]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[9]);
    tm->seconds = ASN1_TO_INT(asn1_time[10]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[11]);

    return TEE_SUCCESS;
}

static int32_t value_cmp(int32_t value1, int32_t value2)
{
    if (value1 > value2)
        return 1;

    if (value1 < value2)
        return -1;

    return 0;
}

static inline TEE_Result result_value_check(int32_t result)
{
    return result > 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result perm_srv_cert_time_cmp(const TEE_Date_Time *time1, const TEE_Date_Time *time2)
{
    int32_t result;

    result = value_cmp(time1->year, time2->year);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->month, time2->month);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->day, time2->day);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->hour, time2->hour);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->min, time2->min);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->seconds, time2->seconds);
    if (result != 0)
        return result_value_check(result);

    return TEE_ERROR_GENERIC;
}

TEE_Result perm_srv_cert_expiration_date_check(const validity_period_t *valid_date)
{
    TEE_Date_Time current = { 0 };
    TEE_Date_Time start   = { 0 };
    TEE_Date_Time end     = { 0 };
    TEE_Result ret;

    if (valid_date == NULL) {
        tloge("cert date is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = asn1_bytes_to_tee_time(valid_date->start, sizeof(valid_date->start), &start);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get expiration start time from cert\n");
        return TEE_ERROR_GENERIC;
    }

    ret = asn1_bytes_to_tee_time(valid_date->end, sizeof(valid_date->end), &end);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get expiration end time from cert\n");
        return TEE_ERROR_GENERIC;
    }

    get_sys_date_time((tee_date_time_kernel *)&current);
    /* compare last two numbers of year */
    current.year = current.year % CMP_YEAR_ACCURACY;

    ret = perm_srv_cert_time_cmp(&current, &start);
    if (ret != TEE_SUCCESS) {
        tloge("cert expiration start date check failed\n");
        return ret;
    }

    ret = perm_srv_cert_time_cmp(&end, &current);
    if (ret != TEE_SUCCESS) {
        tloge("cert expiration end date check failed\n");
        return ret;
    }

    perm_srv_cert_expiration_alarm(&end, &current);
    return TEE_SUCCESS;
}
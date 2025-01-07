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
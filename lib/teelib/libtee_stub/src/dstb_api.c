#include <dstb_api.h>

TEE_Result tee_dstb_gen_sharekey(struct device_info *device_info, const uint8_t *salt, uint32_t salt_len,
    const uint8_t *info, uint32_t info_len, uint8_t *key, uint32_t key_len)
{   
    (void)device_info;
    (void)salt;
    (void)salt_len;
    (void)info;
    (void)info_len;
    (void)key;
    (void)key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_dstb_pre_attestation(struct device_info *device_info, uint32_t cond)
{
    (void)device_info;
    (void)cond;
    return TEE_ERROR_NOT_SUPPORTED;
}
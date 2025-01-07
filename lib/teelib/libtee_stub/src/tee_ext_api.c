#include <tee_ext_api.h>

TEE_Result tee_ext_derive_ta_platfrom_keys(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t params_count, const uint8_t *exinfo, uint32_t exinfo_size)
{   
    (void)object;
    (void)key_size;
    (void)params;
    (void)params_count;
    (void)exinfo;
    (void)exinfo_size;
    return TEE_ERROR_NOT_SUPPORTED;
}
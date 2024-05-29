#include "rpmb_driver_rw_api.h"

TEE_Result tee_ext_rpmb_protect_cfg_blk_write(uint8_t lun, struct rpmb_protect_cfg_blk_entry *entries, uint32_t len)
{
    (void)lun;
    (void)entries;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_protect_cfg_blk_read(uint8_t lun, struct rpmb_protect_cfg_blk_entry *entries, uint32_t *len)
{
    (void)lun;
    (void)entries;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_write(const uint8_t *buf, size_t size, uint32_t block, uint32_t offset)
{
    (void)buf;
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_read(uint8_t *buf, size_t size, uint32_t block, uint32_t offset)
{
    (void)buf;
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_remove(size_t size, uint32_t block, uint32_t offset)
{
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

#include "rpmb_fcntl.h"
#include "stdint.h"

TEE_Result TEE_RPMB_FS_Init(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Format(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Write(const char *filename, const uint8_t *buf, size_t size)
{
    (void)filename;
    (void)buf;
    (void)size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Read(const char *filename, uint8_t *buf, size_t size, uint32_t *count)
{
    (void)filename;
    (void)buf;
    (void)size;
    (void)count;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Rename(const char *old_name, const char *new_name)
{
    (void)old_name;
    (void)new_name;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Rm(const char *filename)
{
    (void)filename;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Stat(const char *filename, struct rpmb_fs_stat *stat)
{
    (void)filename;
    (void)stat;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_StatDisk(struct rpmb_fs_statdisk *stat)
{
    (void)stat;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_SetAttr(const char *filename, uint32_t fmode)
{
    (void)filename;
    (void)fmode;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_FS_Erase(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

uint32_t TEE_RPMB_KEY_Status(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_RPMB_TAVERSION_Process(uint32_t ta_version)
{
    (void)ta_version;
    return TEE_ERROR_NOT_SUPPORTED;
}

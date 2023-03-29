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
#include "tee_trusted_storage_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "sfs.h"
#include "ssa_fs.h"
#include "sfs_internal.h"
#include "securec.h"
#include "string.h"
#include "permsrv_api.h"
#include <tee_huk_derive_key.h>
#include <crypto_hal_derive_key.h>

void reset_meta(meta_data_t *meta)
{
    errno_t rc;

    if (meta == NULL)
        return;

    rc = memset_s(meta->ta_root_key, sizeof(meta->ta_root_key), 0, sizeof(meta->ta_root_key));
    if (rc != EOK)
        tloge("mem set takey failed\n");

    rc = memset_s(meta->file_key, sizeof(meta->file_key), 0, sizeof(meta->file_key));
    if (rc != EOK)
        tloge("mem set file_key failed\n");

    rc = memset_s(meta->xts_key1, sizeof(meta->xts_key1), 0, sizeof(meta->xts_key1));
    if (rc != EOK)
        tloge("mem set xts_key1 failed\n");

    rc = memset_s(meta->xts_key2, sizeof(meta->xts_key2), 0, sizeof(meta->xts_key2));
    if (rc != EOK)
        tloge("mem set xts_key2 failed\n");

    rc = memset_s(meta->hmac_key, sizeof(meta->hmac_key), 0, sizeof(meta->hmac_key));
    if (rc != EOK)
        tloge("mem set hmac_key failed\n");

    rc = memset_s(meta->file_id_key, sizeof(meta->file_id_key), 0, sizeof(meta->file_id_key));
    if (rc != EOK)
        tloge("mem set file_id_key failed\n");

    rc = memset_s(meta->master_hmac, sizeof(meta->master_hmac), 0, sizeof(meta->master_hmac));
    if (rc != EOK)
        tloge("mem set master_hmac failed\n");
}

static void tee_free_file_id(meta_data_t *meta)
{
    TEE_Free(meta->file_id);
    meta->file_id = NULL;

    TEE_Free(meta->joint_file_id);
    meta->joint_file_id = NULL;
}

static TEE_Result derive_file_id_po(meta_data_t *meta)
{
    (void)meta;
    return TEE_SUCCESS;
}

void free_meta_data(meta_data_t **ppmeta)
{
    if (ppmeta == NULL || *ppmeta == NULL)
        return;
    meta_data_t *meta = *ppmeta;

    TEE_Free(meta->file_id);
    meta->file_id = NULL;
    TEE_Free(meta->joint_file_id);
    meta->joint_file_id = NULL;
    TEE_Free(meta->encrypted_file_id);
    meta->encrypted_file_id = NULL;
    TEE_Free(meta->backup_file_id);
    meta->backup_file_id = NULL;

    reset_meta(meta);

    TEE_Free(meta);

    *ppmeta = NULL;
}

void set_meta_data_verion(meta_data_t *meta_data, uint32_t arch_version)
{
    if (meta_data == NULL)
        return;

    meta_data->arch_version = arch_version;

    switch (meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA:
        meta_data->cur_encrypted_file_id = meta_data->encrypted_file_id;
        meta_data->cur_backup_file_id    = meta_data->backup_file_id;
        meta_data->crypto_block_size     = CRYPT_BLOCK_SIZE_V3;
        break;
    default:
        tloge("invalid arch_version: %u\n", meta_data->arch_version);
        break;
    }
}

static int32_t joint_name(const char *file_name, uint32_t name_len, meta_data_t *meta_data, char *name_out,
                          uint32_t out_len)
{
    int32_t rc;
    (void)meta_data;

    rc = memcpy_s(name_out, out_len, file_name, name_len);
    if (rc != EOK) {
        tloge("get path failed!");
        return -1;
    }

    return 0;
}

static int32_t get_files_path_info(const meta_data_t *meta, const uint8_t *old_name,
    uint32_t *size, int32_t *path_lable)
{
    uint32_t size_temp;
    uint32_t i;
    uint32_t persistent;
    uint32_t transient;

    if (old_name == NULL) {
        tloge("old name is null\n");
        return -1;
    }

    size_temp = strlen((char *)(meta->joint_file_id));

    /*
     * Find the last '/', to support dir create and mutiple sec_storage partition
     * If there is no '/' then just store the file into sec_storage,compatible for GP TestSuite
     */
    for (i = size_temp - 1; i > 0; i--) {
        if (old_name[i] == '/') {
            *path_lable = (int32_t)i;
            break;
        }
    }
    if ((int32_t)(size_temp - 1) == *path_lable || *path_lable >= (int32_t)NEW_DIR_LEN) {
        tloge("invalid file path, the last '/' is name %d\n", *path_lable);
        return -1;
    }
    if (meta->storage_id != TEE_OBJECT_STORAGE_CE) {
        /* If there is no '/' then just store the file into sec_storage,compatible for GP TestSuite */
        persistent = size_temp >= strlen(SFS_PARTITION_PERSISTENT) ?
                                  strlen(SFS_PARTITION_PERSISTENT) : size_temp;
        transient  = size_temp >= strlen(SFS_PARTITION_TRANSIENT) ?
                                  strlen(SFS_PARTITION_TRANSIENT) : size_temp;
        if ((TEE_MemCompare((void *)SFS_PARTITION_PERSISTENT, (void *)old_name, persistent) != 0) &&
            (TEE_MemCompare((void *)SFS_PARTITION_TRANSIENT, (void *)old_name, transient) != 0))
            *path_lable = -1;
    }
    *size = size_temp;

    return 0;
}

/* caller should make sure new_name buffer is big enough */
int32_t file_name_transfer(meta_data_t *meta, char *hash_name, uint32_t hash_name_len, bool is_file_hash)
{
    uint8_t *old_name = NULL;
    uint32_t size;
    char *new_name     = NULL;
    int32_t path_lable = -1; /* If there is no '/' path_lable is set to -1 */
    uint32_t add_len = IDENTIFY_SIZE + (is_file_hash ? 1 : 0);
    errno_t rc;
    int32_t ret;

    if (meta == NULL || hash_name == NULL)
        return -1;

    old_name = meta->joint_file_id;

    ret = get_files_path_info(meta, old_name, &size, &path_lable);
    if (ret != 0)
        return ret;

    new_name = (char *)TEE_Malloc(size + 1 + add_len, 0);
    if (new_name == NULL) {
        tloge("malloc new name failed!\n");
        return -1;
    }

    /* fs_identify is for TAs storage isolation */
    rc = memmove_s(new_name, size, (void *)old_name, size);
    if (rc != EOK) {
        tloge("mem move new name failed!\n");
        TEE_Free(new_name);
        return -1;
    }
    rc = memmove_s(new_name + size, 1 + add_len, &meta->uuid, sizeof(meta->uuid));
    if (rc != EOK) {
        tloge("mem move uuid failed!\n");
        TEE_Free(new_name);
        return -1;
    }

    if (is_file_hash)
        *(new_name + size + add_len - 1) = HASH_FILE_MAGIC;
    *(new_name + size + add_len) = '\0';

    /* copy partition and dir info to hash_name */
    if (path_lable > 0) {
        if (memmove_s(hash_name, FILE_NAME_MAX_BUF, new_name, (size_t)(path_lable + 1)) != EOK) {
            TEE_Free(new_name);
            tloge("mem move hash name error!\n");
            return -1;
        }
    }
    /* get file name hash, keep the partiton and dir name. */
    if (get_hname(new_name + (path_lable + 1), (int32_t)(size + add_len - (path_lable + 1)),
                  hash_name + (path_lable + 1), hash_name_len - (path_lable + 1), meta)) {
        TEE_Free(new_name);
        tloge("get hash name failed\n");
        return -1;
    }

    TEE_Free(new_name);

    return 0;
}

#define TA_KEY_LEN  32
#define TA_SALT_LEN 32
#define KEY_DERIVE_TIMES 2
static TEE_Result derive_ta_key(uint8_t *ta_key, uint32_t ta_key_len, TEE_UUID *uuid, uint32_t flags)
{
    TEE_Result ret;
    uint8_t key_out[TA_KEY_LEN] = {0};
    uint8_t salt_buffer[TA_SALT_LEN] = {0};
    uint32_t i;
    errno_t rc;

    if (ta_key == NULL || uuid == NULL) {
        tloge("Bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = memmove_s(salt_buffer, sizeof(salt_buffer), uuid, sizeof(TEE_UUID));
    if (rc != EOK) {
        tloge("mem move secret buffer failed\n");
        ret = TEE_ERROR_SECURITY;
        return ret;
    }

    for (i = TA_SALT_LEN - 1; i >= sizeof(TEE_UUID); i--)
        salt_buffer[i] = salt_buffer[TA_SALT_LEN - 1 - i];

    if ((flags & TEE_DATA_FLAG_DERIVE_32BYTES_KEY_ONCE) == TEE_DATA_FLAG_DERIVE_32BYTES_KEY_ONCE) {
        ret = tee_internal_derive_key(salt_buffer, sizeof(salt_buffer), key_out, sizeof(key_out));
    } else {
        ret = tee_internal_derive_key(salt_buffer, TA_SALT_LEN/KEY_DERIVE_TIMES, key_out, TA_KEY_LEN/KEY_DERIVE_TIMES);
        if (ret == TEE_SUCCESS)
            ret = tee_internal_derive_key(salt_buffer + TA_SALT_LEN/KEY_DERIVE_TIMES, TA_SALT_LEN/KEY_DERIVE_TIMES,
                                          key_out + TA_KEY_LEN/KEY_DERIVE_TIMES, TA_KEY_LEN/KEY_DERIVE_TIMES);
    }
    if (ret != TEE_SUCCESS) {
        tloge("derive ta key failed, ret=0x%x\n", ret);
        return ret;
    }
    rc = memmove_s(ta_key, ta_key_len, key_out, sizeof(key_out));
    if (rc != EOK) {
        tloge("mem move key buffer failed\n");
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

/* Maximun size of derived key is 32 bytes. */
static TEE_Result derive_key(meta_data_t *meta, uint32_t flags)
{
    TEE_Result ret;
    uint32_t out_len = CRYPT_KEY_SIZE;

    if (meta == NULL) {
        tloge("Bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* derive TA rootKey */
    ret = derive_ta_key(meta->ta_root_key, sizeof(meta->ta_root_key), &meta->uuid, flags);
    if (ret != TEE_SUCCESS) {
        tloge("derive ta key fail, ret=0x%x\n", ret);
        return ret;
    }

    struct key_info_t root_key_info;
    root_key_info.key = meta->ta_root_key;
    root_key_info.key_len = sizeof(meta->ta_root_key);
    /* derive file key */
    ret = calc_hmac256(&root_key_info, (uint8_t *)FILEKEY_SALT, (uint32_t)strlen(FILEKEY_SALT),
                       meta->file_key, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("file_key do hash sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    /* derive key to encrypt file name */
    ret = calc_hmac256(&root_key_info, (uint8_t *)FILE_NAME_SALT, (uint32_t)strlen(FILE_NAME_SALT),
                       meta->file_id_key, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("fileIDkey do hash sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    struct key_info_t file_key_info;
    file_key_info.key = meta->file_key;
    file_key_info.key_len = sizeof(meta->file_key);
    /* derive key to encrypt or decrypt file data */
    ret = calc_hmac256(&file_key_info, (uint8_t *)ENCRYPTION1_SALT,
                       (uint32_t)strlen(ENCRYPTION1_SALT), meta->xts_key1, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("xtskey do hash sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    ret = calc_hmac256(&file_key_info, (uint8_t *)ENCRYPTION2_SALT,
                       (uint32_t)strlen(ENCRYPTION2_SALT), meta->xts_key2, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("xtskey2 do hash sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    /* derive key to calculate file's hmac */
    ret = calc_hmac256(&file_key_info, (uint8_t *)MASTER_HMAC_SALT,
                       (uint32_t)strlen(MASTER_HMAC_SALT), meta->hmac_key, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("hmackey do hash sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result encrypt_file_id(meta_data_t *meta)
{
    uint8_t enc_file_id[FILE_NAME_MAX_BUF]                                 = { 0 };
    uint8_t bk_file_id[FILE_NAME_MAX_BUF + sizeof(SFS_BACKUP_FILE_SUFFIX)] = { 0 };

    /* encrypted_file_id */
    if (file_name_transfer(meta, (char *)enc_file_id, sizeof(enc_file_id), (bool)false) != TEE_SUCCESS) {
        tloge("encrypt file_id fail, obj id=%s\n", meta->file_id);
        return TEE_ERROR_GENERIC;
    }
    /* size of bk_file_id is big enough for enc_file_id and suffix */
    if (snprintf_s((char *)bk_file_id, sizeof(bk_file_id), sizeof(bk_file_id) - 1, "%s%s",
        (char *)enc_file_id, SFS_BACKUP_FILE_SUFFIX) < 0) {
        tloge("snprintf_s bkFileId fail!\n");
        return TEE_ERROR_SECURITY;
    }

    meta->encrypted_file_id = TEE_Malloc((size_t)strlen((char *)enc_file_id) + 1, 0);
    if (meta->encrypted_file_id == NULL) {
        tloge("malloc encrypted FileId, size=%u\n", (uint32_t)strlen((char *)enc_file_id) + 1);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memmove_s(meta->encrypted_file_id, (size_t)strlen((char *)enc_file_id) + 1, enc_file_id,
                  (size_t)strlen((char *)enc_file_id)) != EOK) {
        tloge("mem move encFileId error!\n");
        TEE_Free(meta->encrypted_file_id);
        meta->encrypted_file_id = NULL;
        return TEE_ERROR_SECURITY;
    }

    /* backup_file_id */
    meta->backup_file_id = TEE_Malloc((size_t)strlen((char *)bk_file_id) + 1, 0);
    if (meta->backup_file_id == NULL) {
        tloge("malloc backup_file_id fail, size=%u\n", (uint32_t)strlen((char *)bk_file_id) + 1);
        TEE_Free(meta->encrypted_file_id);
        meta->encrypted_file_id = NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memmove_s(meta->backup_file_id, (size_t)strlen((char *)bk_file_id) + 1, bk_file_id,
                  (size_t)strlen((char *)bk_file_id)) != EOK) {
        tloge("mem move bkFileId to meta error!\n");
        TEE_Free(meta->encrypted_file_id);
        meta->encrypted_file_id = NULL;
        TEE_Free(meta->backup_file_id);
        meta->backup_file_id = NULL;
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

TEE_Result derive_file_id(const uint8_t *obj_id, uint32_t obj_id_len, const uint8_t *joint_file_id, uint32_t joint_len,
                          meta_data_t *meta)
{
    TEE_Result ret;

    if (obj_id == NULL || meta == NULL || joint_file_id == NULL || (obj_id_len + 1) < obj_id_len) {
        tloge("Bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* TA file_id */
    meta->file_id = TEE_Malloc(obj_id_len + 1, 0);
    if (meta->file_id == NULL) {
        tloge("malloc file_id fail, size=%u\n", obj_id_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memmove_s(meta->file_id, obj_id_len + 1, obj_id, obj_id_len) != EOK) {
        tloge("mem move obj id error!\n");
        ret = TEE_ERROR_SECURITY;
        goto out;
    }
    meta->file_id_len = obj_id_len;

    meta->joint_file_id = TEE_Malloc(joint_len + 1, 0);
    if (meta->joint_file_id == NULL) {
        tloge("malloc joint_file_id fail, size=%u\n", joint_len);
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    if (memmove_s(meta->joint_file_id, joint_len + 1, joint_file_id, joint_len) != EOK) {
        tloge("mem move joint_file_id error!\n");
        ret = TEE_ERROR_SECURITY;
        goto out;
    }

    meta->arch_version = SFS_ARCH_VERSION_SSA;

    ret = encrypt_file_id(meta);
    if (ret != TEE_SUCCESS) {
        tloge("derive encrypt file id error!\n");
        goto out;
    }

    ret = derive_file_id_po(meta);
    if (ret != TEE_SUCCESS)
        goto out;

    return TEE_SUCCESS;

out:
    tee_free_file_id(meta);
    return ret;
}

meta_data_t *create_meta_data(const uint8_t *obj_id, uint32_t obj_id_len, uint32_t storage_id, uint32_t flags,
                              const TEE_UUID *uuid, TEE_Result *error, uint32_t arch_version)
{
    TEE_Result ret;
    errno_t rc;
    char file_name_new[FILE_NAME_MAX_BUF] = { 0 };

    if (obj_id == NULL || uuid == NULL || error == NULL) {
        tloge("Bad parameter!\n");
        return NULL;
    }

    meta_data_t *meta_data = TEE_Malloc(sizeof(meta_data_t), 0);
    if (meta_data == NULL) {
        tloge("malloc meta data fail\n");
        *error = TEE_ERROR_OUT_OF_MEMORY;
        return NULL;
    }

    meta_data->storage_id = storage_id;
    rc                    = memmove_s(&meta_data->uuid, sizeof(meta_data->uuid), uuid, sizeof(TEE_UUID));
    if (rc != EOK) {
        TEE_Free(meta_data);
        *error = TEE_ERROR_SECURITY;
        tloge("mem move uuid error!\n");
        return NULL;
    }

    (void)memset_s(meta_data->master_hmac, sizeof(meta_data->master_hmac), 0, sizeof(meta_data->master_hmac));

    /* derive ta key to encrypt or decrypt */
    ret = derive_key(meta_data, flags);
    if (ret != TEE_SUCCESS) {
        tloge("derive key fail, ret=0x%x\n", ret);
        *error = ret;
        goto out;
    }

    rc = joint_name((char *)obj_id, obj_id_len, meta_data, file_name_new, sizeof(file_name_new));
    if (rc != EOK) {
        tloge("joint name fail, ret=0x%x\n", ret);
        *error = TEE_ERROR_GENERIC;
        goto out;
    }

    /* init object ID */
    ret = derive_file_id(obj_id, obj_id_len, (uint8_t *)file_name_new, strlen(file_name_new), meta_data);
    if (ret != TEE_SUCCESS) {
        tloge("init object Id fail, ret=0x%x\n", ret);
        *error = ret;
        goto out;
    }

    set_meta_data_verion(meta_data, arch_version);

    *error = TEE_SUCCESS;
    return meta_data;

out:
    free_meta_data(&meta_data);

    return NULL;
}

TEE_Result get_uuid_hmac(const TEE_UUID *uuid, char *uuid_hmac, uint32_t uuid_hmac_len)
{
    TEE_Result ret;
    int32_t rc;
    meta_data_t *meta_data = NULL;

    if (uuid == NULL || uuid_hmac == NULL) {
        tloge("get uuid hmac param check fail!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    meta_data = TEE_Malloc(sizeof(meta_data_t), 0);
    if (meta_data == NULL) {
        tloge("malloc meta_data fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memmove_s(&meta_data->uuid, sizeof(meta_data->uuid), uuid, sizeof(TEE_UUID));
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        tloge("mem move uuid error!\n");
        goto clean;
    }

    ret = derive_key(meta_data, TA_KEY_COMPOSED_OF_TWO_16BYTES_KEYS);
    if (ret != TEE_SUCCESS) {
        tloge("derive fail, ret=0x%x\n", ret);
        goto clean;
    }

    meta_data->arch_version = SFS_ARCH_VERSION_SSA;
    ret                     = get_hname((const char *)uuid, sizeof(TEE_UUID), uuid_hmac, uuid_hmac_len, meta_data);
    if (ret != TEE_SUCCESS) {
        tloge("get hname fail, ret=0x%x\n", ret);
        goto clean;
    }

clean:
    free_meta_data(&meta_data);
    return ret;
}

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
#include "tee_defines.h"
#include "sfs.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_ext_api.h"
#include "sfs_internal.h"
#include "securec.h"
#include "string.h"
#include "tee_crypto_hal.h"
#include "ssa_fs.h"

#define BYTE_LEN 8
TEE_Result get_spec_errno(TEE_Result ret_default)
{
    TEE_Result ret0 = fs_get_serr();
    if (ret0 == TEE_SUCCESS)
        return ret_default;

    return ret0;
}

struct ssa_open_info {
    int32_t file_fd;
    TEE_Result ret;
    uint32_t size;
};

static TEE_Result init_meta_data(struct sfd_t *sfd);
static void free_sfd(struct sfd_t *sfd);
static int32_t check_integrity_v2(struct sfd_t *sfd);
static TEE_Result construct_block_info(struct sfd_t *sfd);
static int32_t get_hmac_from_meta_data_checkfilename(struct sfd_t *sfd, meta_storage_t *sfs_meta);
TEE_Result do_rename(struct sfd_t *sfd, meta_data_t *new_meta_data);

#define SHA_BUFF_HIGH_MASK    0xf0
#define SHA_BUFF_LOW_MASK     0x0f
#define HALF_BYTE_OFFSET      4U
#define DOUBLE(x)             ((x) * 2)
#define IS_SINGLE_DIGIT(x)    ((x) >= 0 && (x) <= 9)
#define IS_HEX_NUM(x)         ((x) >= 10 && (x) <= 15)
#define MIN_TWO_DIGIT         10
/* CAUTION: the size of "dest" MUST be larger than HASH_LEN*2 */
void str_tran(const unsigned char *sha_buff, uint32_t buff_len, char *dest, uint32_t dest_len)
{
    int32_t i;
    bool param_check_fail = (sha_buff == NULL) || (dest == NULL) ||
        (buff_len < HASH_LEN) || (dest_len <= HASH_VERIFY_LEN);

    if (param_check_fail)
        return;

    for (i = 0; i < HASH_LEN; i++) {
        int8_t hb = (sha_buff[i] & SHA_BUFF_HIGH_MASK) >> HALF_BYTE_OFFSET;
        if (IS_SINGLE_DIGIT(hb))
            hb += '0';
        else if (IS_HEX_NUM(hb))
            hb = ((hb - MIN_TWO_DIGIT) + 'A');

        int8_t lb = sha_buff[i] & SHA_BUFF_LOW_MASK;
        if (IS_SINGLE_DIGIT(lb))
            lb += '0';
        else /* lb must be between 10 and 15 */
            lb = (lb - MIN_TWO_DIGIT) + 'A';

        dest[DOUBLE(i)]     = hb;
        dest[DOUBLE(i) + 1] = lb;
    }

    dest[HASH_VERIFY_LEN] = '\0';

    return;
}

int32_t get_hmac_from_meta_data(struct sfd_t *sfd, uint8_t *hmac_buff, uint32_t hmac_buff_len)
{
    /* for fread */
    uint32_t read_ret;
    int32_t error = 0;
    /* for meta_data */
    meta_storage_t sfs_meta;
    /* for hmac */
    uint8_t calculated_hmac[HASH_VERIFY_LEN + 1] = { 0 };

    if (sfd == NULL || hmac_buff == NULL) {
        tloge("check param failed!!\n");
        return -1;
    }

    (void)memset_s(&sfs_meta, sizeof(sfs_meta), 0, sizeof(sfs_meta));
    /* 1. read metadata */
    read_ret = ssa_fs_fread(&sfs_meta, sizeof(sfs_meta), sfd->nfd, &error);
    if (read_ret != sizeof(sfs_meta) || error < 0) {
        tloge("fread metadata failed!!\n");
        return -1;
    }

    /* 2. calculate hmac about metadata */
    if (calculate_hmac((uint8_t *)&sfs_meta, sizeof(meta_storage_header_t),
                       calculated_hmac, sizeof(calculated_hmac), sfd) != TEE_SUCCESS) {
        tloge("get hmac of metadata failed\n");
        return -1;
    }

    /* 3. compare the hmac of metadata */
    if (TEE_MemCompare(sfs_meta.meta_hmac, calculated_hmac, HASH_VERIFY_LEN) != 0) {
        tloge("compare metadata hamc failed!!\n");
        return -1;
    }

    /* 4. check filename + datahmac */
    if (get_hmac_from_meta_data_checkfilename(sfd, &sfs_meta) != 0) {
        tloge("get hmac from meta data check filename failed!!\n");
        return -1;
    }

    sfd->last_block_size = sfs_meta.hdr.last_block_realsize;
    sfd->data_encmeth  = sfs_meta.hdr.encrypto_meth;

    /* 5. read data hmac */
    if (memmove_s(hmac_buff, hmac_buff_len, sfs_meta.data_hmac, sizeof(sfs_meta.data_hmac)) != EOK)
        return -1;

    return 0;
}

void ssa_removefile(const uint8_t *filename, const char *file_desc, uint32_t storage_id)
{
    int32_t ret;
    const char *p_filedesc = ((file_desc == NULL) ? "file" : file_desc);

    if (filename != NULL && strlen((char *)filename) != 0) {
        ret = ssa_fs_fremove((char *)filename, storage_id);
        if (ret != 0) {
            tloge("remove %s failed ret %d, errno %x\n", p_filedesc, ret, fs_get_serr());
            tlogd("remove %s %s failed ret %d, errno %x\n", p_filedesc, (char *)filename, ret, fs_get_serr());
        } else {
            tlogd("remove %s %s  successfully\n", p_filedesc, (char *)filename);
        }
    }

    return;
}

static TEE_Result get_key_value_by_version(struct sfd_t *sfd, uint8_t **key_value, uint32_t *key_value_size)
{
    if (sfd->meta_data->arch_version == SFS_ARCH_VERSION_SSA) {
        *key_value      = sfd->meta_data->hmac_key;
        *key_value_size = sizeof(sfd->meta_data->hmac_key);
    } else {
        tloge("invalid arch_version: %u\n", sfd->meta_data->arch_version);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

bool check_ssa_version_type(struct sfd_t *sfd)
{
    return (sfd->meta_data->arch_version == SFS_ARCH_VERSION_SSA);
}

/* CAUTION: the size of "dest" MUST be larger than HASH_LEN*2 */
TEE_Result calculate_hmac(const uint8_t *src, uint32_t src_len, uint8_t *dest, uint32_t dest_len,
                          const struct sfd_t *sfd)
{
    unsigned char temp_buff[HASH_VERIFY_LEN + 1] = { 0 };
    uint32_t out_len = HASH_VERIFY_LEN + 1;
    TEE_Result ret;
    struct key_info_t key_info;

    if (src == NULL || dest == NULL || sfd == NULL || sfd->meta_data == NULL || src_len > INT32_MAX)
        return TEE_ERROR_BAD_PARAMETERS;

    key_info.key = sfd->meta_data->hmac_key;
    key_info.key_len = sizeof(sfd->meta_data->hmac_key);

    ret = calc_hmac256(&key_info, src, (int32_t)src_len, (uint8_t *)temp_buff, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("do hmac sha256 failed!\n");
        return TEE_ERROR_GENERIC;
    }

    str_tran(temp_buff, out_len, (char *)dest, dest_len);

    return TEE_SUCCESS;
}

TEE_Result ssa_close_and_delete(struct sfd_t *sfd, bool is_delete)
{
    if (sfd == NULL || sfd->meta_data == NULL) {
        tloge("ssa close delete Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    (void)ssa_fs_fclose(sfd->nfd);

    switch (sfd->meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA:
        ssa_removefile(sfd->meta_data->encrypted_file_id, "file", sfd->meta_data->storage_id);
        if (is_delete == true)
            ssa_removefile(sfd->meta_data->backup_file_id, "bkfile", sfd->meta_data->storage_id);
        break;
    default:
        tloge("invalid arch_version 0x%x\n", sfd->meta_data->arch_version);
        return TEE_ERROR_BAD_STATE;
    }

    free_sfd(sfd);

    return TEE_SUCCESS;
}

int32_t get_hmac_of_data(struct sfd_t *sfd, uint8_t *hmac_buff, uint32_t hmac_buff_len)
{
    if (sfd == NULL || sfd->meta_data == NULL || hmac_buff == NULL)
        return -1;

    switch (sfd->meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA:
        return get_hmac_from_meta_data(sfd, hmac_buff, hmac_buff_len);
    default:
        tloge("Invalid arch_version %u\n", sfd->meta_data->arch_version);
        return -1;
    }
}

static bool judge_valid_version(const struct sfd_t *sfd)
{
    (void)sfd;
    return true;
}

static TEE_Result switch_arch_version_rename(struct sfd_t *sfd, const uint8_t *new_obj_id, uint32_t new_obj_len,
                                             meta_data_t *new_meta_data)
{
    TEE_Result ret;
    (void)new_obj_id;
    (void)new_obj_len;

    switch (sfd->meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA: {
        ret = do_rename(sfd, new_meta_data);
        if (ret != TEE_SUCCESS)
            tloge("sfs arch version ssa rename failed, ret = 0x%x\n", ret);
        break;
    }
    default:
        tloge("invalid arch version %u\n", sfd->meta_data->arch_version);
        ret = TEE_ERROR_BAD_FORMAT;
        break;
    }

    return ret;
}

/* CAUTION: the size of "dest" MUST be larger than HASH_LEN*2 */
TEE_Result get_hname(const char *src, int32_t length, char *dest, uint32_t dest_len, meta_data_t *meta)
{
    unsigned char temp_buff[HASH_VERIFY_LEN + 1] = { 0 };
    TEE_Result ret;
    uint32_t out_len = HASH_LEN;

    if (src == NULL || dest == NULL || meta == NULL) {
        tloge("src, dest or meta is NULL\n");
        return (TEE_Result)TEE_ERROR_BAD_PARAMETERS;
    }
    struct key_info_t key_info;
    key_info.key = meta->file_id_key;
    key_info.key_len = sizeof(meta->file_id_key);
    ret = calc_hmac256(&key_info, (uint8_t *)src, length, temp_buff, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_MAC error! %x\n", ret);
        return ret;
    }

    str_tran(temp_buff, (uint32_t)out_len, dest, dest_len);

    return TEE_SUCCESS;
}

TEE_Result calc_filename_datahmac_hash(meta_storage_t *sfs_meta, const struct sfd_t *sfd)
{
    uint8_t *fname_datahmac_src = NULL;
    uint32_t fname_datahmac_len;
    errno_t rc;
    TEE_Result ret;

    if ((sfs_meta == NULL) || (sfd == NULL) || sfd->meta_data == NULL) {
        tloge("sfs_meta or sfd is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    fname_datahmac_len = HASH_NAME_BUFF_LEN + sizeof(sfs_meta->data_hmac);
    fname_datahmac_src = TEE_Malloc((size_t)fname_datahmac_len, 0);
    if (fname_datahmac_src == NULL) {
        tloge("malloc1 blockInfo failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memmove_s(fname_datahmac_src, HASH_NAME_BUFF_LEN, sfd->meta_data->file_id,
                   sfd->meta_data->file_id_len);
    if (rc != EOK) {
        tloge("memmove failed\n");
        TEE_Free(fname_datahmac_src);
        return TEE_ERROR_SECURITY;
    }
    rc = memmove_s(fname_datahmac_src + HASH_NAME_BUFF_LEN, fname_datahmac_len - HASH_NAME_BUFF_LEN,
                   sfs_meta->data_hmac, sizeof(sfs_meta->data_hmac));
    if (rc != EOK) {
        tloge("memmove failed\n");
        TEE_Free(fname_datahmac_src);
        return TEE_ERROR_SECURITY;
    }

    ret = cmd_hash(fname_datahmac_src, fname_datahmac_len, (uint8_t *)sfs_meta->hdr.fname_datahmac_hash,
                   sizeof(sfs_meta->hdr.fname_datahmac_hash));
    if (ret != TEE_SUCCESS) {
        tloge("cmd_hash failed\n");
        TEE_Free(fname_datahmac_src);
        return ret;
    }

    TEE_Free(fname_datahmac_src);
    return TEE_SUCCESS;
}

/* fd is secure file handle */
static int32_t get_last_crypt_block_padding_size(const struct sfd_t *sfd)
{
    if (sfd == NULL)
        return -1;

    return sfd->last_block_size ? (sfd->crypto_block_size - sfd->last_block_size) : 0;
}

static TEE_Result init_meta_data(struct sfd_t *sfd)
{
    uint32_t written_len, write_count;
    meta_storage_t *buf = NULL;
    meta_storage_t sfs_meta;
    TEE_Result ret;

    /* init the meta_data */
    (void)memset_s((void *)&sfs_meta, sizeof(meta_storage_t), 0, sizeof(meta_storage_t));

    buf                          = &sfs_meta;
    buf->hdr.magic_lo            = SFS_STORAGE_MAGIC_LO;
    buf->hdr.magic_hi            = SFS_STORAGE_MAGIC_HI;
    buf->hdr.arch_version        = sfd->meta_data->arch_version;
    buf->hdr.last_block_realsize = 0;
    (void)memset_s((void *)(buf->hdr.reserved), sizeof(buf->hdr.reserved), 0x0, sizeof(buf->hdr.reserved));
    (void)memset_s((void *)(buf->meta_hmac), sizeof(buf->meta_hmac), 0x0, sizeof(buf->meta_hmac));
    (void)memset_s((void *)(buf->data_hmac), sizeof(buf->data_hmac), 0x0, sizeof(buf->data_hmac));

#ifdef CONFIG_THIRD_STORAGE_SUPPORT
    TEE_GenerateRandom(&sfd->first_iv, sizeof(sfd->first_iv));
    buf->hdr.first_iv = sfd->first_iv;
#endif
    buf->hdr.magic_version = META_STORATE_MAGIC_VERSION;
    if (sfd->meta_data->arch_version >= SFS_ARCH_VERSION_SSA) {
        buf->hdr.encrypto_meth = SFS_DATA_ENCRYPTO_XTS;
        sfd->data_encmeth      = SFS_DATA_ENCRYPTO_XTS;
    }

    int32_t fd = sfd->nfd;

    /* write to data file */
    if (ssa_fs_fseek(fd, 0, TEE_DATA_SEEK_SET) != 0) {
        tloge("seek file failed\n");
        ret = get_spec_errno(TEE_ERROR_SEEK_DATA);
        goto err_out;
    }

    ret = TEE_SUCCESS;

    write_count = sizeof(meta_storage_t);
    written_len = ssa_fs_fwrite(buf, write_count, fd);
    if (written_len != write_count) {
        tloge("a written error occurs, expected=%u, actual=%u\n", write_count, written_len);
        ret = get_spec_errno(TEE_ERROR_WRITE_DATA);
    }

err_out:
    return ret;
}

static int32_t get_hmac_from_meta_data_checkfilename(struct sfd_t *sfd, meta_storage_t *sfs_meta)
{
    errno_t rc;

    if (sfs_meta->hdr.magic_version == META_STORATE_MAGIC_VERSION) {
        uint32_t fname_datahmac_hash[DATAHMAC_HASH_SIZE];
        rc = memmove_s(fname_datahmac_hash, sizeof(fname_datahmac_hash), sfs_meta->hdr.fname_datahmac_hash,
                       sizeof(sfs_meta->hdr.fname_datahmac_hash));
        if (rc != EOK) {
            tloge("memove failed!! %d\n", rc);
            return -1;
        }

        if (calc_filename_datahmac_hash(sfs_meta, sfd) != TEE_SUCCESS)
            return -1;

        if (TEE_MemCompare(fname_datahmac_hash, sfs_meta->hdr.fname_datahmac_hash, sizeof(fname_datahmac_hash)) != 0) {
            tloge("compare datahmac failed!!\n");
            return -1;
        }
#ifdef CONFIG_THIRD_STORAGE_SUPPORT
        sfd->first_iv = sfs_meta->hdr.first_iv;
    } else {
        sfd->first_iv = 0;
#endif
    }

    return 0;
}

TEE_Result calculate_block_hash(uint8_t *sha_buff, uint32_t sha_size, const uint8_t *data, uint32_t data_size)
{
    if (sha_buff == NULL || data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    return cmd_hash(data, data_size, sha_buff, sha_size);
}

static TEE_Result master_hmac_params_check(const struct sfd_t *sfd,
    const uint8_t *hmac_buf, const uint32_t *buf_size, uint32_t *cipher_blks)
{
    uint32_t blks = 0;
    struct block_info_t *cur_block_pos = NULL;

    if (sfd == NULL || hmac_buf == NULL || buf_size == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    cur_block_pos = sfd->first_block;
    if (cur_block_pos == NULL || sfd->meta_data == NULL) {
        tloge("cur_block_pos illegal pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    while (cur_block_pos != NULL) {
        blks++;
        cur_block_pos = cur_block_pos->next;
    }

    if (cipher_blks == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *cipher_blks = blks;
    return TEE_SUCCESS;
}

#define EVEN_NUM 2
/* calculate master hmac base on block list in sfd */
TEE_Result calculate_master_hmac(struct sfd_t *sfd, uint8_t *hmac_buf, uint32_t *buf_size)
{
    struct block_info_t *cur_block_pos = NULL;
    uint32_t cipher_blks = 0;
    uint8_t *all_blks_hash = NULL;
    uint8_t *key_value = NULL;
    uint32_t key_value_size;

    TEE_Result ret = master_hmac_params_check(sfd, hmac_buf, buf_size, &cipher_blks);
    if (ret != TEE_SUCCESS)
        return ret;

    /*
     * "DataInSize" MUST be multiple of 64.
     * so, cipher_blks SHOULD be an even number,
     * then "DataInSize" is HASH_LEN*(even).
     */
    if (cipher_blks % EVEN_NUM)
        cipher_blks++;

    all_blks_hash = TEE_Malloc(cipher_blks * HASH_LEN, 0);
    if (all_blks_hash == NULL) {
        tloge("malloc failed, size=%u\n", cipher_blks * HASH_LEN);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    cur_block_pos = sfd->first_block;
    while (cur_block_pos != NULL) {
        if (memmove_s(all_blks_hash + cur_block_pos->block_id * HASH_LEN,
            cipher_blks * HASH_LEN - cur_block_pos->block_id * HASH_LEN, cur_block_pos->hash, HASH_LEN) != EOK) {
            TEE_Free(all_blks_hash);
            return TEE_ERROR_SECURITY;
        }
        cur_block_pos = cur_block_pos->next;
    }

    ret = get_key_value_by_version(sfd, &key_value, &key_value_size);
    if (ret != TEE_SUCCESS) {
        TEE_Free(all_blks_hash);
        return ret;
    }

    struct key_info_t key_info;
    key_info.key = key_value;
    key_info.key_len = key_value_size;
    ret = calc_hmac256(&key_info, all_blks_hash, cipher_blks * HASH_LEN, hmac_buf, buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("do hmac sha256 failed!\n");
        TEE_Free(all_blks_hash);
        return TEE_ERROR_GENERIC;
    }

    TEE_Free(all_blks_hash);
    return TEE_SUCCESS;
}

static TEE_Result cal_construct_block(struct sfd_t *sfd, uint32_t data_size)
{
    int32_t error = 0;
    struct block_info_t *temp = NULL;
    struct block_info_t *next = NULL;
    struct block_info_t *cur_block_pos = NULL;
    struct block_info_t *last_block_pos = NULL;
    uint32_t block_size = CRYPT_BLOCK_SIZE_V3;
    uint8_t *buffer = NULL;
    buffer = malloc(CRYPT_BLOCK_SIZE_V3);
    if (buffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    cur_block_pos = sfd->first_block;
    last_block_pos = cur_block_pos;
    while (data_size > 0) {
        uint32_t read_count = ssa_fs_fread(buffer, block_size, sfd->nfd, &error);
        if (((read_count % block_size) != 0) || (error < 0)) {
            tloge("read encrypto buffer failed, read_count=%u, error=%d\n", read_count, error);
            TEE_Free(buffer);
            return get_spec_errno(TEE_ERROR_READ_DATA);
        }

        if (cur_block_pos == NULL) {
            last_block_pos->next = TEE_Malloc(sizeof(*last_block_pos), 0);
            if (last_block_pos->next == NULL) {
                TEE_Free(buffer);
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            cur_block_pos = last_block_pos->next;
            cur_block_pos->block_id = last_block_pos->block_id + 1;
            cur_block_pos->next = NULL;
        }

        if (calculate_block_hash(cur_block_pos->hash, sizeof(cur_block_pos->hash), buffer, block_size) != TEE_SUCCESS)
            tlogw("cal hash fail\n");
        last_block_pos = cur_block_pos;
        cur_block_pos = cur_block_pos->next;
        data_size -= read_count;
    }

    /*
     * The backup file and the original file share the linked list.
     * When the two files are not the same size, the redundant linked
     * list needs to be released.
     */
    temp = cur_block_pos;
    while (temp != NULL) {
        next = temp->next;
        TEE_Free(temp);
        temp = next;
    }

    last_block_pos->next = NULL;
    TEE_Free(buffer);
    return TEE_SUCCESS;
}

static TEE_Result construct_block_info(struct sfd_t *sfd)
{
    int32_t ret;
    TEE_Result ret_c;
    uint32_t cur_pos, data_size;

    bool param_check_null = (sfd == NULL) || (sfd->meta_data == NULL) || (sfd->first_block == NULL);
    if (param_check_null)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = ssa_fs_finfo(sfd->nfd, &cur_pos, &data_size);
    if (ret < 0) {
        tloge("get info of file %s failed\n", sfd->opened_orig ? "origin" : "backup");
        return get_spec_errno(TEE_ERROR_GENERIC);
    }

    if (data_size < SFS_METADATA_SIZE) {
        tloge("get info of file %s failed, datasize 0x%x\n", sfd->opened_orig ? "origin" : "backup", data_size);
        return get_spec_errno(TEE_ERROR_GENERIC);
    }

    data_size -= SFS_METADATA_SIZE;
    ret = ssa_fs_fseek(sfd->nfd, SFS_METADATA_SIZE, TEE_DATA_SEEK_SET);
    if (ret < 0) {
        tloge("seek file %s failed\n", sfd->opened_orig ? "origin" : "backup");
        return get_spec_errno(TEE_ERROR_SEEK_DATA);
    }

    /* actual_size add padding_size is data_size */
    sfd->size            = data_size;
    bool blocksize_check = (sfd->size >= (sfd->crypto_block_size - sfd->last_block_size)) &&
        (sfd->last_block_size != 0);
    if (blocksize_check)
        sfd->size -= (sfd->crypto_block_size - sfd->last_block_size);

    if (data_size == 0 || (data_size % sfd->crypto_block_size)) {
        tloge("file %s length %u is error\n", sfd->opened_orig ? "origin" : "backup", data_size);
        return get_spec_errno(TEE_ERROR_GENERIC);
    }

    ret_c = cal_construct_block(sfd, data_size);

    return ret_c;
}

/* This function for latest format, include PO */
static int32_t check_integrity_v2(struct sfd_t *sfd)
{
    uint8_t provided_hmac[HASH_VERIFY_LEN + 1]   = { 0 };
    uint8_t calculated_hmac[HASH_VERIFY_LEN + 1] = { 0 };
    uint8_t hmac_buf[HASH_LEN]                   = { 0 };
    uint32_t hmac_buf_len                        = HASH_LEN;

    /* 1. get hmac from meta_data */
    if (get_hmac_of_data(sfd, provided_hmac, HASH_VERIFY_LEN)) {
        tloge("get hmac from meta_data failed\n");
        return -1;
    }

    /* 2. calculate hash of each cipher block */
    if (construct_block_info(sfd)) {
        tloge("construct block info failed\n");
        return -1;
    }

    /* 3. calculate hmac of block hash */
    if (calculate_master_hmac(sfd, hmac_buf, &hmac_buf_len)) {
        tloge("calculate master hmac failed\n");
        return -1;
    }
    str_tran((unsigned char *)hmac_buf, hmac_buf_len, (char *)calculated_hmac, sizeof(calculated_hmac));

    /* 4. compare */
    if (TEE_MemCompare(calculated_hmac, provided_hmac, HASH_VERIFY_LEN) != 0) {
        tloge("checkIntegrity failed\n");
        tloge("calculated_hmac=%s\n", calculated_hmac);
        tloge("provided_hmac=%s\n", provided_hmac);
        return -1;
    }

    tlogd("checkIntegrity success \n");
    return 0;
}

/* fd is secure file handle */
TEE_Result fill_file_hole(struct sfd_t *sfd, uint32_t start_offset, uint32_t size)
{
    uint8_t *fill_buff = NULL;
    uint32_t times, index;
    const uint32_t hole_per_size = 1024;
    TEE_Result error             = TEE_SUCCESS;
    if (start_offset > INT32_MAX) {
        tloge("Invalid offset, more than INT32_MAX");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ssa_seek(sfd, (int32_t)start_offset, TEE_DATA_SEEK_SET) != 0)
        return TEE_ERROR_GENERIC;

    fill_buff = TEE_Malloc(hole_per_size, 0);
    if (fill_buff == NULL) {
        tloge("alloc hole buffer failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    times = size / hole_per_size + ((size % hole_per_size) ? 1 : 0);
    for (index = 0; index < times; index++) {
        uint32_t send_count = hole_per_size * (index + 1) > size ? size % hole_per_size : hole_per_size;
        uint32_t count      = ssa_write(fill_buff, send_count, sfd, &error);
        if ((count != send_count) || (error != TEE_SUCCESS)) {
            TEE_Free(fill_buff);
            return error;
        }
    }
    TEE_Free(fill_buff);

    return TEE_SUCCESS;
}
static void free_sfd(struct sfd_t *sfd)
{
    struct block_info_t *cur_block_pos  = NULL;
    struct block_info_t *next_block_pos = NULL;
    if (sfd != NULL) {
        cur_block_pos = sfd->first_block;
        while (cur_block_pos != NULL) {
            next_block_pos = cur_block_pos->next;
            TEE_Free(cur_block_pos);
            cur_block_pos = next_block_pos;
        }

        TEE_Free(sfd);
    }
}

typedef enum {
    /* origin file does not exist */
    ORI_NOENT = 1,
    /* backup file does not exist */
    BK_NOENT = 2,
    /* origin file intergerity checking fails */
    ORI_CHECK_FAIL = 4,
    /* backup file intergerity checking fails */
    BK_CHECK_FAIL = 8,
} file_status;

static TEE_Result ssa_open_check(struct sfd_t *sfd, const char *file_name, uint32_t flag, int32_t *fd)
{
    TEE_Result ret;

    if (sfd == NULL || file_name == NULL || fd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *fd = ssa_fs_fopen(file_name, flag, sfd->meta_data->storage_id);
    if (*fd < 0) {
        ret = TEE_ERROR_ITEM_NOT_FOUND;
        goto out;
    }

    sfd->nfd = *fd;

    /* check integrity */
    ret = (TEE_Result)check_integrity_v2(sfd);
    if (ret != TEE_SUCCESS) {
        if (ssa_fs_fclose(sfd->nfd) != 0)
            tloge("close error %x\n", fs_get_serr());

        ret = TEE_ERROR_CORRUPT_OBJECT;
        goto out;
    }

    tlogd("intergerity check success in %s file\n", file_name);

out:
    return ret;
}

static TEE_Result ssa_open_init(struct sfd_t *sfd, meta_data_t *meta, uint32_t flag)
{
    tlogd("arch_version = %u\n", meta->arch_version);

    sfd->meta_data         = meta;
    sfd->flags             = flag;
    sfd->update_backup     = false;
    sfd->seek_position     = 0;
    sfd->size              = 0; /* we will update in 'checkIntegrity' */
    sfd->crypto_block_size = meta->crypto_block_size;
    sfd->attr_size         = 0;

    /* init block list */
    sfd->first_block = TEE_Malloc(sizeof(struct block_info_t), 0);
    if (sfd->first_block == NULL) {
        tloge("malloc blockInfo failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    sfd->first_block->block_id = SFS_START_BLOCKID;
    sfd->first_block->next = NULL;

    return TEE_SUCCESS;
}

static void ssa_open_handle_init(struct sfd_t *sfd, const meta_data_t *meta, uint32_t flag,
    struct ssa_open_info *orig, struct ssa_open_info *back)
{
    back->ret = ssa_open_check(sfd, (char *)meta->cur_backup_file_id, flag, &(back->file_fd));
    back->size = sfd->size;

    orig->ret = ssa_open_check(sfd, (char *)meta->cur_encrypted_file_id, flag, &(orig->file_fd));
    orig->size = sfd->size;
}

static TEE_Result ssa_open_handle_orig(const meta_data_t *meta)
{
    TEE_Result ret;

    /* orig is ok , and back is corrupt. */
    if (ssa_fs_fcopy((char *)meta->cur_encrypted_file_id, (char *)meta->cur_backup_file_id, meta->storage_id)) {
        ret = fs_get_serr();
        tloge("Oops, copy origin file to backup file failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_open_handle_back(struct sfd_t *sfd, const meta_data_t *meta, uint32_t flag,
    struct ssa_open_info *orig, struct ssa_open_info *back)
{
    TEE_Result ret;

    if (ssa_fs_fcopy((char *)meta->cur_backup_file_id, (char *)meta->cur_encrypted_file_id, meta->storage_id)) {
        ret = fs_get_serr();
        tloge("Oops, copy backup file to origin file failed, 0x%x\n", ret);
        return ret;
    }

    if (ssa_fs_fclose(back->file_fd)) {
        tloge("close error 0x%x\n", fs_get_serr());
        ret = TEE_ERROR_GENERIC;
        back->file_fd = 0;
        return ret;
    }
    back->file_fd = 0;

    orig->ret = ssa_open_check(sfd, (char *)meta->cur_encrypted_file_id, flag, &(orig->file_fd));
    if (orig->ret != TEE_SUCCESS) {
        ret = fs_get_serr();
        tloge("reopen the origin file failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result handle_orig_back(struct sfd_t *sfd, const meta_data_t *meta, uint32_t flag,
    struct ssa_open_info *orig, struct ssa_open_info *back)
{
    TEE_Result ret;

    if (ssa_fs_fclose(back->file_fd)) {
        tloge("close error 0x%x\n", fs_get_serr());
        ret = TEE_ERROR_GENERIC;
        back->file_fd = 0;
        return ret;
    }
    back->file_fd = 0;

    if (back->size != orig->size) {
        /* the backup file is right, copy back to orig. */
        if (ssa_fs_fclose(orig->file_fd)) {
            tloge("close error 0x%x\n", fs_get_serr());
            ret = TEE_ERROR_GENERIC;
            orig->file_fd = 0;
            return ret;
        }
        orig->file_fd = 0;

        /* orig is ok , and back is corrupt. */
        if (ssa_fs_fcopy((char *)meta->cur_backup_file_id, (char *)meta->cur_encrypted_file_id, meta->storage_id)) {
            ret = fs_get_serr();
            tloge("Oops, copy backup file to origin file failed, 0x%x\n", ret);
            return ret;
        }

        orig->ret = ssa_open_check(sfd, (char *)meta->cur_encrypted_file_id, flag, &(orig->file_fd));
        if (orig->ret != TEE_SUCCESS) {
            ret = fs_get_serr();
            tloge("reopen the origin file failed, 0x%x\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static void ssa_open_handle_clean_fd(struct ssa_open_info *orig, struct ssa_open_info *back)
{
    if (back->file_fd > 0) {
        if (ssa_fs_fclose(back->file_fd) != 0)
            tloge("close error 0x%x\n", fs_get_serr());

        back->file_fd = 0;
    }

    if (orig->file_fd > 0) {
        if (ssa_fs_fclose(orig->file_fd) != 0)
            tloge("close error 0x%x\n", fs_get_serr());

        orig->file_fd = 0;
    }
}

static TEE_Result ssa_open_handle_retry(struct sfd_t *sfd, const meta_data_t *meta,
    uint32_t flag, struct ssa_open_info *back)
{
    TEE_Result ret;
    tlogi("we will try to reopen the file when open file without write\n");
    if (back->ret == TEE_SUCCESS)
        ret = ssa_open_check(sfd, (char *)meta->cur_backup_file_id, flag, &(back->file_fd));
    else
        ret = ssa_open_check(sfd, (char *)meta->cur_encrypted_file_id, flag, &(back->file_fd));
    if (ret != TEE_SUCCESS)
        return fs_get_serr();

    if (ssa_fs_fseek(sfd->nfd, (int32_t)SFS_METADATA_SIZE, TEE_DATA_SEEK_SET)) {
        tloge("seek error 0x%x\n", fs_get_serr());
        if (back->file_fd > 0 && ssa_fs_fclose(back->file_fd) != 0) {
            tloge("close error 0x%x\n", fs_get_serr());
            back->file_fd = 0;
        }
        return fs_get_serr();
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_open_handle(struct sfd_t *sfd, const meta_data_t *meta, uint32_t flag)
{
    TEE_Result ret;
    struct ssa_open_info orig = {0};
    struct ssa_open_info back = {0};

    ssa_open_handle_init(sfd, meta, flag, &orig, &back);
    if (back.ret != TEE_SUCCESS && orig.ret != TEE_SUCCESS) {
        /* all are corrupt */
        if (back.ret == TEE_ERROR_ITEM_NOT_FOUND && orig.ret == TEE_ERROR_ITEM_NOT_FOUND) {
            ret = TEE_ERROR_ITEM_NOT_FOUND;
        } else {
            ret = TEE_ERROR_GENERIC;
        }

        goto out;
    }

    if (back.ret != TEE_SUCCESS) {
        tloge("backup file open error 0x%x\n", back.ret);
        ret = ssa_open_handle_orig(meta);
        if (ret != TEE_SUCCESS) {
            tloge("ssa open handle orig failed, 0x%x\n", ret);
            goto out;
        }
    } else if (orig.ret != TEE_SUCCESS) {
        tloge("origin file open error 0x%x\n", orig.ret);
        ret = ssa_open_handle_back(sfd, meta, flag, &orig, &back);
        if (ret != TEE_SUCCESS) {
            tloge("ssa open handle back failed, 0x%x\n", ret);
            goto out;
        }
    } else {
        /* orig and back all are correct . */
        tlogd("orig and back file are all check ok %s\n", (char *)meta->cur_encrypted_file_id);
        ret = handle_orig_back(sfd, meta, flag, &orig, &back);
        if (ret != TEE_SUCCESS) {
            tloge("ssa open handle orig back failed, 0x%x\n", ret);
            goto out;
        }
    }

    /* we should skip the metadata */
    if (ssa_fs_fseek(sfd->nfd, (int32_t)SFS_METADATA_SIZE, TEE_DATA_SEEK_SET)) {
        tloge("seek error 0x%x\n", fs_get_serr());
        ret = TEE_ERROR_GENERIC;
        goto out;
    }

    return TEE_SUCCESS;

out:
    ssa_open_handle_clean_fd(&orig, &back);
    if ((back.ret == TEE_SUCCESS || orig.ret == TEE_SUCCESS) &&
        !((TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_WRITE |
           TEE_DATA_FLAG_CREATE | TEE_DATA_FLAG_OVERWRITE) & flag))
        return ssa_open_handle_retry(sfd, meta, flag, &back);

    return ret;
}

struct sfd_t *ssa_open(meta_data_t *meta, uint32_t flag, TEE_Result *error)
{
    struct sfd_t *sfd = NULL;

    if (meta == NULL || error == NULL) {
        if (error)
            *error = TEE_ERROR_BAD_PARAMETERS;
        return NULL;
    }

    /* init file handle */
    sfd = TEE_Malloc(sizeof(struct sfd_t), 0);
    if (sfd == NULL) {
        tloge("malloc sfd failed\n");
        *error = TEE_ERROR_OUT_OF_MEMORY;
        return NULL;
    }

    *error = ssa_open_init(sfd, meta, flag);
    if (*error != TEE_SUCCESS) {
        tloge("ssa open init failed");
        goto out_final;
    }

    *error = ssa_open_handle(sfd, meta, flag);
    if (*error != TEE_SUCCESS) {
        tloge("ssa open handle failed, ret = 0x%x\n", *error);
        goto out_final;
    }

    return sfd;

out_final:
    free_sfd(sfd);

    return NULL;
}

TEE_Result ssa_close(struct sfd_t *sfd)
{
    if (sfd == NULL) {
        tloge("ssa close Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    (void)ssa_fs_fclose(sfd->nfd);

    bool copy_flag = sfd->update_backup && (sfd->meta_data != NULL) &&
        (sfd->meta_data->cur_encrypted_file_id != NULL) && (sfd->meta_data->cur_backup_file_id != NULL);
    if (copy_flag) { /* Update the backup file */
        tlogd("file has been written successfully, need to update the backup file\n");
        if (ssa_fs_fcopy((char *)sfd->meta_data->cur_encrypted_file_id,
            (char *)sfd->meta_data->cur_backup_file_id, sfd->meta_data->storage_id) != 0)
            tloge("copy file failed, %x\n", fs_get_serr());
    }

    free_sfd(sfd);
    return TEE_SUCCESS;
}

TEE_Result ssa_sync(const struct sfd_t *sfd)
{
    if (sfd == NULL) {
        tloge("ssa sync Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ssa_fs_fsync(sfd->nfd))
        return fs_get_serr();

    return TEE_SUCCESS;
}

static TEE_Result handle_truncation(struct sfd_t *sfd, uint8_t *buffer,
    uint32_t end_offset, uint32_t head_blocks)
{
    TEE_Result ret;
    errno_t rc;
    uint32_t read_ret;

    if (sfd->crypto_block_size * head_blocks > INT32_MAX) {
        tloge("Invalid size, more than INT32_MAX");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = ssa_seek(sfd, (int32_t)(sfd->crypto_block_size * head_blocks), TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS) {
        tloge("seek to %u failed 0x%x\n", sfd->crypto_block_size * head_blocks, ret);
        return ret;
    }

    rc = memset_s(buffer, BLOCK_SIZE, 0, BLOCK_SIZE);
    if (rc != EOK)
        tloge("memset failed, 0x%x\n", rc);

    ret = TEE_SUCCESS;
    read_ret = ssa_read(buffer, end_offset, sfd, &ret);
    if ((read_ret < end_offset) || (ret != TEE_SUCCESS)) {
        tloge("read failed %u 0x%x\n", read_ret, ret);
        return ret;
    }

    if (check_ssa_version_type(sfd)) {
        if (ssa_fs_ftruncate((char *)sfd->meta_data->cur_encrypted_file_id,
                             sfd->crypto_block_size * head_blocks + SFS_METADATA_SIZE,
                             sfd->meta_data->storage_id)) {
            tloge("truncate file failed\n");
            return get_spec_errno(TEE_ERROR_TRUNCATE_OBJECT);
        }
        sfd->last_block_size = 0;
    } else {
        tloge("invalid file format, version=%u\n", sfd->meta_data->arch_version);
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

static TEE_Result handle_supplement(struct sfd_t *sfd, uint8_t *buffer,
    uint32_t head_blocks, uint32_t append_size)
{
    TEE_Result ret;
    errno_t rc;
    uint32_t write_count;

    if (sfd->crypto_block_size * head_blocks > INT32_MAX) {
        tloge("Invalid size, more than INT32_MAX");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = ssa_seek(sfd, (int32_t)(sfd->crypto_block_size * head_blocks), TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS) {
        tloge("seek to %u failed\n", sfd->crypto_block_size * head_blocks);
        return ret;
    }

    if (append_size == 0) {
        sfd->need_update_hmac = true;
        return TEE_SUCCESS;
    }

    if (append_size > BLOCK_SIZE) {
        ret = TEE_SUCCESS;
        write_count = ssa_write(buffer, BLOCK_SIZE, sfd, &ret);
        if ((write_count != BLOCK_SIZE) || (ret != TEE_SUCCESS))
            return ret;
        append_size -= BLOCK_SIZE;
        rc = memset_s(buffer, BLOCK_SIZE, 0, BLOCK_SIZE);
        if (rc != EOK)
            tlogw("memset failed, 0x%x\n", rc);

        while (append_size > BLOCK_SIZE) {
            ret = TEE_SUCCESS;
            write_count = ssa_write(buffer, BLOCK_SIZE, sfd, &ret);
            if ((write_count != BLOCK_SIZE) || (ret != TEE_SUCCESS))
                return ret;
            append_size -= BLOCK_SIZE;
        }
    }

    if (append_size > 0) {
        ret = TEE_SUCCESS;
        write_count = ssa_write(buffer, append_size, sfd, &ret);
        if ((write_count != append_size) || (ret != TEE_SUCCESS))
            return ret;
    }

    return TEE_SUCCESS;
}
static TEE_Result handle_truncation_supplement(struct sfd_t *sfd,
    uint32_t end_offset, uint32_t head_blocks, uint32_t append_size)
{
    uint8_t *buffer = NULL;
    TEE_Result ret;

    /* malloc for s_fread */
    buffer = TEE_Malloc(BLOCK_SIZE, 0);
    if (buffer == NULL) {
        tloge("malloc buffer failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = handle_truncation(sfd, buffer, end_offset, head_blocks);
    if (ret != TEE_SUCCESS) {
        tloge("ssa truncate handle truncation failed, ret = 0x%x\n", ret);
        goto error_handle;
    }

    ret = handle_supplement(sfd, buffer, head_blocks, append_size);
    if (ret != TEE_SUCCESS) {
        tloge("ssa truncate handle supplement failed, ret = 0x%x\n", ret);
        goto error_handle;
    }

error_handle:
    if (buffer != NULL)
        TEE_Free(buffer);
    return ret;
}

static TEE_Result ssa_truncate_handle(struct sfd_t *sfd, uint32_t len, uint32_t file_len)
{
    uint32_t end_offset, head_blocks, append_size;

    if (len > file_len) {
        end_offset  = file_len % sfd->crypto_block_size;
        head_blocks = file_len / sfd->crypto_block_size;
        append_size = len - file_len + end_offset;
        return handle_truncation_supplement(sfd, end_offset, head_blocks, append_size);
    }

    end_offset  = len % sfd->crypto_block_size;
    head_blocks = len / sfd->crypto_block_size;
    append_size = end_offset;
    if (judge_valid_version(sfd)) {
        struct block_info_t *head = sfd->first_block;
        struct block_info_t *p = NULL;
        struct block_info_t *pre = NULL;
        bool found = false;

        while (head->next) {
            if (head->block_id == head_blocks) {
                found = true;
                break;
            }
            pre = head;
            head = head->next;
        }
        if (found) {
            while (head->next) {
                p          = head->next;
                head->next = p->next;
                TEE_Free(p);
            }
        }
        if (append_size == 0 && pre != NULL) { /* It means the last block is useless */
            TEE_Free(head);
            pre->next = NULL;
        }
    }

    return handle_truncation_supplement(sfd, end_offset, head_blocks, append_size);
}

TEE_Result ssa_truncate(struct sfd_t *sfd, uint32_t len)
{
    uint32_t cur_pos = 0;
    uint32_t file_len = 0;
    TEE_Result ret;

    if (sfd == NULL || sfd->meta_data == NULL) {
        tloge("ssa truncate Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = ssa_info(sfd, &cur_pos, &file_len);
    if (ret != TEE_SUCCESS) {
        tloge("get file info error 0x%x\n", ret);
        return ret;
    }
    tlogd("file size=%u, new_size=%u, pos=%u\n", file_len, len, cur_pos);

    if (len == file_len)
        return TEE_SUCCESS;

    ret = ssa_truncate_handle(sfd, len, file_len);
    if (ret != TEE_SUCCESS) {
        tloge("ssa truncate handle failed, ret = 0x%x\n", ret);
        return ret;
    }
    if (cur_pos > INT32_MAX) {
        tloge("Invalid position, more than INT32_MAX");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = ssa_seek(sfd, (int32_t)cur_pos, TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS)
        return ret;

    sfd->seek_position = cur_pos;
    sfd->size          = len;

    return TEE_SUCCESS;
}

TEE_Result do_rename(struct sfd_t *sfd, meta_data_t *new_meta_data)
{
    TEE_Result ret;

    if (ssa_fs_faccess((char *)new_meta_data->encrypted_file_id, F_OK, sfd->meta_data->storage_id) == 0) {
        tloge("file already exist\n");
        return TEE_ERROR_ACCESS_CONFLICT;
    }
    if (ssa_fs_faccess((char *)new_meta_data->backup_file_id, F_OK, sfd->meta_data->storage_id) == 0) {
        tloge("backup file already exist\n");
        return TEE_ERROR_ACCESS_CONFLICT;
    }

    if (ssa_fs_faccess((char *)sfd->meta_data->backup_file_id, F_OK, sfd->meta_data->storage_id) == 0) {
        if (ssa_fs_frename((char *)sfd->meta_data->backup_file_id, (char *)new_meta_data->backup_file_id,
                           sfd->meta_data->storage_id) != 0) {
            tloge("rename backup file fail\n");
            return get_spec_errno(TEE_ERROR_GENERIC);
        }
    }

    if (ssa_fs_frename((char *)sfd->meta_data->encrypted_file_id, (char *)new_meta_data->encrypted_file_id,
                       sfd->meta_data->storage_id) != 0) {
        tloge("rename file fail\n");
        ret = get_spec_errno(TEE_ERROR_GENERIC);
        (void)ssa_fs_frename((char *)new_meta_data->backup_file_id, (char *)sfd->meta_data->backup_file_id,
            sfd->meta_data->storage_id); /* no need to verify return value here */
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result ssa_rename(struct sfd_t *sfd, const uint8_t *new_obj_id, uint32_t new_obj_len)
{
    meta_data_t *new_meta_data = NULL;
    TEE_Result ret             = TEE_SUCCESS;

    if (sfd == NULL || new_obj_id == NULL || sfd->meta_data == NULL) {
        tloge("ssa rename Bad parameters!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    new_meta_data = create_meta_data(new_obj_id, new_obj_len, sfd->meta_data->storage_id, sfd->flags,
                                     &sfd->meta_data->uuid, &ret, sfd->meta_data->arch_version);
    if ((new_meta_data == NULL) || (ret != TEE_SUCCESS)) {
        tloge("meta create fail %x\n", ret);
        goto clean;
    }

    ret = switch_arch_version_rename(sfd, new_obj_id, new_obj_len, new_meta_data);
    if (ret != TEE_SUCCESS)
        goto clean;

    tlogd("rename file success\n");
    free_meta_data(&sfd->meta_data);
    sfd->meta_data = new_meta_data;
    return TEE_SUCCESS;

clean:
    if (new_meta_data != NULL)
        free_meta_data(&new_meta_data);
    return ret;
}

static TEE_Result ssa_file_sfd_params(uint32_t flag, int32_t nfd, meta_data_t *meta, struct sfd_t *sfd)
{
    TEE_Result ret;
    uint8_t empty_buff[1] = { 0 };

    sfd->seek_position     = 0;
    sfd->size              = 0;
    sfd->attr_size         = 0;
    sfd->nfd               = nfd;
    sfd->flags             = flag;
    sfd->update_backup     = true;
    sfd->opened_orig       = true;
    sfd->meta_data         = meta;
    sfd->crypto_block_size = meta->crypto_block_size;

    /* init the block list */
    sfd->first_block = TEE_Malloc(sizeof(struct block_info_t), 0);
    if (sfd->first_block == NULL) {
        tloge("malloc blockInfo failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    sfd->first_block->next    = NULL;
    sfd->first_block->block_id = SFS_START_BLOCKID;
    ret = calculate_block_hash(sfd->first_block->hash, sizeof(sfd->first_block->hash), empty_buff,
                               sizeof(empty_buff) / sizeof(uint8_t));
    if (ret != TEE_SUCCESS) {
        tloge("calculate first block hash failed 0x%x\n", ret);
        TEE_Free(sfd->first_block);
        sfd->first_block = NULL;
        return ret;
    }

    /* write metadata */
    ret = init_meta_data(sfd);
    if (ret != TEE_SUCCESS) {
        tloge("write metadata failed, 0x%x\n", ret);
        TEE_Free(sfd->first_block);
        sfd->first_block = NULL;
        return ret;
    }

    tlogd("write metadata success\n");
    return TEE_SUCCESS;
}

struct sfd_t *ssa_create(meta_data_t *meta, uint32_t flag, TEE_Result *error)
{
    TEE_Result ret;
    struct sfd_t *sfd = NULL;

    if (error == NULL) {
        tloge("Bad parameters!\n");
        return NULL;
    }
    if (meta == NULL || meta->file_id == NULL) {
        *error = get_spec_errno(TEE_ERROR_BAD_PARAMETERS);
        return NULL;
    }

    /* create data file */
    int32_t nfd = ssa_fs_fcreate((char *)meta->cur_encrypted_file_id, flag, meta->storage_id);
    if (nfd < 0) {
        tloge("create data file failed %x\n", nfd);
        *error = get_spec_errno(TEE_ERROR_GENERIC);
        goto fail;
    }

    /* init file handle */
    sfd = TEE_Malloc(sizeof(struct sfd_t), 0);
    if (sfd == NULL) {
        tloge("malloc sfd failed\n");
        *error = TEE_ERROR_OUT_OF_MEMORY;
        goto alloc_sfd_fail;
    }

    ret = ssa_file_sfd_params(flag, nfd, meta, sfd);
    if (ret != TEE_SUCCESS) {
        *error = ret;
        goto init_fail;
    }

    return sfd;

init_fail:
    free_sfd(sfd);
    sfd = NULL;
alloc_sfd_fail:
    (void)ssa_fs_fclose(nfd);
    (void)ssa_fs_fremove((char *)meta->cur_encrypted_file_id, meta->storage_id);
fail:
    return NULL;
}

typedef struct {
    int32_t offset;
    uint32_t cur_pos;
    uint32_t cur_file_len;
} ssa_seek_param;
static TEE_Result proc_seek_set(const struct sfd_t *sfd, ssa_seek_param *seek_param)
{
    if (seek_param->offset < 0) {
        tloge("Illegal offset %d, file_len %u attrsize %u \n", seek_param->offset, seek_param->cur_file_len,
              sfd->attr_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (judge_valid_version(sfd))
        seek_param->offset += (int32_t)SFS_METADATA_SIZE;

    return TEE_SUCCESS;
}
static TEE_Result proc_seek_cur(const struct sfd_t *sfd, ssa_seek_param *seek_param)
{
    if (seek_param->offset < 0) {
        if ((seek_param->offset + (int32_t)(seek_param->cur_pos)) < (int32_t)(sfd->attr_size))
            seek_param->offset = sfd->attr_size - seek_param->cur_pos;
        return TEE_SUCCESS;
    }

    if ((seek_param->cur_pos + seek_param->offset) > (MAX_FILE_SIZE + sfd->attr_size)) {
        tloge("The data position has overflowed, cur_pos=%u, offset=%d\n", seek_param->cur_pos, seek_param->offset);
        return TEE_ERROR_OVERFLOW;
    }

    return TEE_SUCCESS;
}

static TEE_Result proc_seek_end(const struct sfd_t *sfd, ssa_seek_param *seek_param)
{
    if ((seek_param->offset > 0) &&
        ((seek_param->cur_file_len + (uint32_t)seek_param->offset) > (MAX_FILE_SIZE + sfd->attr_size))) {
        tloge("The data position has overflowed, file_real_len=%u, offset=%d\n", seek_param->cur_file_len,
              seek_param->offset);
        return TEE_ERROR_OVERFLOW;
    }

    if ((seek_param->offset + (int32_t)(seek_param->cur_file_len)) < (int32_t)(sfd->attr_size))
        seek_param->offset = sfd->attr_size - seek_param->cur_file_len;

    int32_t last_block_padding_size = get_last_crypt_block_padding_size(sfd);
    if (last_block_padding_size < 0) {
        tloge("get last block padding size failed 0x%x\n", last_block_padding_size);
        return TEE_ERROR_GENERIC;
    }
    seek_param->offset -= last_block_padding_size;

    return TEE_SUCCESS;
}

typedef TEE_Result (*seek_proc_call_back)(const struct sfd_t *sfd, ssa_seek_param *seek_param);
typedef struct {
    uint32_t whence;
    seek_proc_call_back seek_proc_func;
} seek_proc;

static seek_proc g_ssa_seek_proc[] = { { TEE_DATA_SEEK_SET, proc_seek_set },
                                       { TEE_DATA_SEEK_CUR, proc_seek_cur },
                                       { TEE_DATA_SEEK_END, proc_seek_end } };

TEE_Result ssa_seek(struct sfd_t *sfd, int32_t offset, uint32_t whence)
{
    TEE_Result ret;
    uint32_t cur_pos          = 0;
    uint32_t file_len         = 0;
    uint32_t file_real_len    = 0;
    ssa_seek_param seek_param = { 0 };

    if ((sfd == NULL) || (sfd->meta_data == NULL)) {
        tloge("ssa seek Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = ssa_info(sfd, &cur_pos, &file_real_len);
    if (ret != TEE_SUCCESS) {
        tloge("get file info error, 0x%x\n", ret);
        return ret;
    }

    tlogd("before seek, pos=%u, size=%u\n", cur_pos, file_real_len);

    if (whence > TEE_DATA_SEEK_END)
        return TEE_ERROR_BAD_STATE;

    seek_param.offset       = offset;
    seek_param.cur_pos      = cur_pos;
    seek_param.cur_file_len = file_real_len;
    ret                     = g_ssa_seek_proc[whence].seek_proc_func((const struct sfd_t *)sfd, &seek_param);
    if (ret != TEE_SUCCESS) {
        tloge("ssa seek proc error, 0x%x\n", ret);
        return ret;
    }

    tlogd("offset=%d, whence=%u\n", seek_param.offset, whence);

    int32_t rc = ssa_fs_fseek(sfd->nfd, seek_param.offset, whence);
    if (rc != 0) {
        tloge("fseek failed: offset=%d, whence=%u\n", seek_param.offset, whence);
        return get_spec_errno(TEE_ERROR_SEEK_DATA);
    }

    ret = ssa_info(sfd, &cur_pos, &file_len);
    if (ret != TEE_SUCCESS) {
        tloge("get file info error 0x%x\n", ret);
        return ret;
    }
    tlogd("after seek, pos=%u, size=%u\n", cur_pos, file_len);
    sfd->seek_position = cur_pos;
    sfd->size          = file_len;

    if (cur_pos > file_real_len)
        return fill_file_hole(sfd, file_real_len, cur_pos - file_real_len);

    return TEE_SUCCESS;
}

TEE_Result ssa_info(struct sfd_t *sfd, uint32_t *pos, uint32_t *len)
{
    int32_t last_block_padding_size;

    if (sfd == NULL || sfd->meta_data == NULL || pos == NULL || len == NULL) {
        tloge("ssa info Illegal sfd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* get cur_pos and file_len */
    if (ssa_fs_finfo(sfd->nfd, pos, len)) {
        tloge("get file info error\n");
        return get_spec_errno(TEE_ERROR_GENERIC);
    }
    tlogd("file info : pos/len = %u/%u\n", *pos, *len);

    /* remove the meta_data size */

    if (judge_valid_version(sfd)) {
        (*pos) = (*pos) > SFS_METADATA_SIZE ? ((*pos) - SFS_METADATA_SIZE) : 0;
        (*len) = (*len) > SFS_METADATA_SIZE ? ((*len) - SFS_METADATA_SIZE) : 0;
    }

    last_block_padding_size = get_last_crypt_block_padding_size((const struct sfd_t *)sfd);
    if (last_block_padding_size < 0) {
        tloge("get last block padding size failed %x\n", last_block_padding_size);
        return get_spec_errno(TEE_ERROR_GENERIC);
    }
    tlogd("last_block_padding_size=%d\n", last_block_padding_size);

    if ((int32_t)*len < last_block_padding_size) {
        tlogw("last write operation may be interrupted %u\n", *len);
        *len = 0;
    } else {
        *len -= (uint32_t)last_block_padding_size;
    }
    sfd->seek_position = *pos;
    sfd->size          = *len;

    return TEE_SUCCESS;
}

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
#include "tee_crypto_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_ext_api.h"
#include "sfs_internal.h"
#include "securec.h"
#include "string.h"
#include "ssa_fs.h"
#include "ssa_fs.h"
struct crypto_key {
    bool flag;
    uint8_t key[CRYPT_KEY_SIZE];
};

static struct crypto_key g_gs_key_hash = { false, { 0 } };

static bool check_invalid_version(const struct sfd_t *sfd)
{
    return (sfd->meta_data->arch_version != SFS_ARCH_VERSION_SSA);
}

static bool judge_valid_version(const struct sfd_t *sfd)
{
    (void)sfd;
    return true;
}

static int32_t get_encrypted_file_name(uint8_t **encrypted_file_name, const struct sfd_t *sfd)
{
    switch (sfd->meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA:
        *encrypted_file_name = sfd->meta_data->cur_encrypted_file_id;
        break;
    default:
        tloge("Invalid arch_version, %x\n", sfd->meta_data->arch_version);
        return -1;
    }
    return 0;
}

static TEE_Result ssa_fs_fseek_blk_start(const struct sfd_t *sfd, uint32_t start_pos)
{
    TEE_Result ret;

    ret = (TEE_Result)ssa_fs_fseek(sfd->nfd, start_pos + SFS_METADATA_SIZE, TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS) { /* if error, no need to update hash file */
        tloge("seek file to start offset failed\n");
        return get_spec_errno(TEE_ERROR_SEEK_DATA);
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_fs_fseek_blk_end(const struct sfd_t *sfd, uint32_t end_pos, uint32_t end_offset)
{
    TEE_Result ret;

    ret = (TEE_Result)ssa_fs_fseek(sfd->nfd, end_pos - end_offset + SFS_METADATA_SIZE, TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS) {
        tloge("seek file to end offset failed\n");
        return get_spec_errno(TEE_ERROR_SEEK_DATA);
    }

    return TEE_SUCCESS;
}

// encrypt or decrypt many blocks
static TEE_Result encrypt_blocks(const uint8_t *src, uint32_t len, uint8_t *dst, const struct sfd_t *sfd, uint32_t mode)
{
    TEE_Result ret;
    if (src == NULL || dst == NULL || sfd == NULL || sfd->meta_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tlogd("ready to %s, dataLen=%u, version=%u, bs=%u, block_id=%u\n", mode == TEE_MODE_ENCRYPT ? "encrypt" : "decrypt",
          len, sfd->meta_data->arch_version, sfd->crypto_block_size, sfd->start_block_id);

    switch (sfd->meta_data->arch_version) {
    case SFS_ARCH_VERSION_SSA:
        ret = encrypt_blocks_with_xts(src, len, dst, sfd, mode);
        break;
    default:
        ret = TEE_ERROR_BAD_STATE;
        break; // never
    }

    return ret;
}

static int32_t write_hmac_to_meta_data(const struct sfd_t *sfd, const uint8_t *hmac_buf, uint32_t buf_len)
{
    uint32_t write_ret;
    int32_t ret;

    if (sfd == NULL || hmac_buf == NULL || sfd->meta_data == NULL)
        return -1;

    /* we canot use nfd in sfd directly, otherwise file offset has changed */
    if (check_invalid_version(sfd)) {
        tloge("invalid arch version to write hmac 0x%x\n", sfd->meta_data->arch_version);
        return -1;
    }

    int32_t nfd = ssa_fs_fopen((char *)sfd->meta_data->cur_encrypted_file_id, TEE_DATA_FLAG_ACCESS_WRITE,
                               sfd->meta_data->storage_id);
    if (nfd < 0) {
        tloge("open file %s failed\n", sfd->meta_data->cur_encrypted_file_id);
        return -1;
    }

    ret = ssa_fs_fseek(nfd, SFS_DATAHMAC_OFFSET, TEE_DATA_SEEK_SET);
    if (ret < 0) {
        tloge("seek file %s failed\n", sfd->meta_data->cur_encrypted_file_id);
        (void)ssa_fs_fclose(nfd);
        return -1;
    }

    write_ret = ssa_fs_fwrite(hmac_buf, buf_len, nfd);
    if (write_ret != buf_len) {
        tloge("write data hmac to metadata failed, ret=%u\n", write_ret);
        (void)ssa_fs_fclose(nfd);
        return -1;
    }

    (void)ssa_fs_fclose(nfd);
    return 0;
}

static TEE_Result update_master_hmac(struct sfd_t *sfd)
{
    uint8_t hmac_buf[HASH_LEN]            = { 0 };
    uint8_t hmac_hex[HASH_VERIFY_LEN + 1] = { 0 };
    uint32_t hmac_buf_len = HASH_LEN;
    TEE_Result ret;

    ret = calculate_master_hmac(sfd, hmac_buf, &hmac_buf_len);
    if (ret != TEE_SUCCESS) {
        tloge("calculate master hmac failed %x\n", ret);
        return ret;
    }
    str_tran((unsigned char *)hmac_buf, hmac_buf_len, (char *)hmac_hex, sizeof(hmac_hex));

    ret = (TEE_Result)write_hmac_to_meta_data(sfd, hmac_hex, HASH_VERIFY_LEN);
    if (ret != 0) {
        tloge("write data hmac to meta failed %x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static int32_t set_last_blocksize_to_meta_hdr(int nfd, uint32_t last_block_realsize, const struct sfd_t *sfd)
{
    /* for read metadata */
    uint32_t read_count;
    int32_t error = 0;
    errno_t rc;
    /* for write metadata */
    uint32_t write_count;
    /* for meta_data Header */
    meta_storage_t sfs_meta;
    /* for hmac of data */
    uint8_t calculated_hmac[HASH_VERIFY_LEN + 1] = { 0 };

    /* read origal metadata */
    read_count = ssa_fs_fread(&sfs_meta, sizeof(sfs_meta), nfd, &error);
    if (read_count != sizeof(sfs_meta) || error < 0) {
        tloge("read metadata failed! count %x\n", read_count);
        return -1;
    }

    /* update metadata */
    sfs_meta.hdr.last_block_realsize = last_block_realsize;

    sfs_meta.hdr.magic_version = META_STORATE_MAGIC_VERSION;

    if (calc_filename_datahmac_hash(&sfs_meta, sfd) != TEE_SUCCESS)
        return -1;

#ifdef CONFIG_THIRD_STORAGE_SUPPORT
    sfs_meta.hdr.first_iv = sfd->first_iv;
#endif
    /* calculate hmac of metadata */
    if (calculate_hmac((uint8_t *)&sfs_meta.hdr, sizeof(sfs_meta.hdr), calculated_hmac, sizeof(calculated_hmac), sfd)) {
        tloge("get hmac of metadata failed\n");
        return -1;
    }

    rc = memmove_s(sfs_meta.meta_hmac, sizeof(sfs_meta.meta_hmac), calculated_hmac, sizeof(sfs_meta.meta_hmac));
    if (rc != EOK)
        return -1;

    /* seek to start of file */
    if (ssa_fs_fseek(nfd, 0, TEE_DATA_SEEK_SET)) {
        tloge("seek start of file failed\n");
        return -1;
    }

    /* write metadata */
    tlogd("enc_method is %u\n", sfs_meta.hdr.encrypto_meth);
    write_count = ssa_fs_fwrite(&sfs_meta, sizeof(sfs_meta), nfd);
    if (write_count != sizeof(sfs_meta)) {
        tloge("write metadata failed! count %u\n", write_count);
        return -1;
    }

    return 0;
}

/* fd is secure file handle */
static int32_t set_last_crypt_block_realsize(const struct sfd_t *sfd, uint32_t len)
{
    int32_t ret;
    uint8_t *encrypted_file_name = NULL;

    if (sfd == NULL || sfd->meta_data == NULL)
        return -1;

    if (get_encrypted_file_name(&encrypted_file_name, sfd) != 0)
        return -1;

    if (encrypted_file_name == NULL)
        return -1;

    int32_t fd = ssa_fs_fopen((char *)encrypted_file_name,
                              (uint32_t)(TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE),
                              sfd->meta_data->storage_id);
    if (fd < 0) {
        tloge("open file error fd:%d!\n", fd);
        return -1;
    }

    ret = set_last_blocksize_to_meta_hdr(fd, len, sfd);

    (void)ssa_fs_fclose(fd);

    return ret;
}

TEE_Result ssa_write_mac(struct sfd_t *sfd)
{
    TEE_Result ret = TEE_SUCCESS;

    if (sfd == NULL || sfd->meta_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (judge_valid_version(sfd)) {
        ret = update_master_hmac(sfd);
        if (ret != TEE_SUCCESS) {
            tloge("update master hmac failed\n");
        } else {
            sfd->update_backup = true;
        }
    }

    if (set_last_crypt_block_realsize(sfd, sfd->last_block_size)) {
        tloge("set last crypto blocksize failed\n");
        return TEE_ERROR_GENERIC;
    }

    return ret;
}

static TEE_Result ssa_reset_mac(const struct sfd_t *sfd)
{
    uint8_t hmac_hex[HASH_VERIFY_LEN + 1] = { 0 };

    if (sfd == NULL || sfd->meta_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (judge_valid_version(sfd)) {
        int32_t nfd = ssa_fs_fopen((char *)sfd->meta_data->cur_encrypted_file_id, TEE_DATA_FLAG_ACCESS_WRITE,
                                   sfd->meta_data->storage_id);
        if (nfd < 0) {
            tloge("open file %s failed\n", sfd->meta_data->cur_encrypted_file_id);
            return TEE_ERROR_GENERIC;
        }

        int32_t ret = ssa_fs_fseek(nfd, SFS_DATAHMAC_OFFSET, TEE_DATA_SEEK_SET);
        if (ret < 0) {
            tloge("seek file %s failed\n", sfd->meta_data->cur_encrypted_file_id);
            (void)ssa_fs_fclose(nfd);
            return TEE_ERROR_GENERIC;
        }

        uint32_t write_ret = ssa_fs_fwrite(hmac_hex, HASH_VERIFY_LEN, nfd);
        if (write_ret != HASH_VERIFY_LEN) {
            tloge("write data hmac to metadata failed, ret=%u\n", write_ret);
            (void)ssa_fs_fclose(nfd);
            return TEE_ERROR_GENERIC;
        }

        (void)ssa_fs_fclose(nfd);
    }

    return TEE_SUCCESS;
}

static TEE_Result calculate_hash_for_block(const struct sfd_t *sfd, const uint8_t *crypto_buf,
    uint32_t buf_size, struct block_info_t *cur_block_pos, struct block_info_t *last_block_pos)
{
    uint32_t idx;
    uint32_t block_size;
    uint32_t crypto_blks;

    block_size = sfd->crypto_block_size;
    if (block_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    crypto_blks = buf_size / block_size;

    for (idx = 0; idx < crypto_blks && cur_block_pos != NULL; idx++) {
        (void)calculate_block_hash(cur_block_pos->hash, sizeof(cur_block_pos->hash),
                                   crypto_buf + idx * block_size, block_size);

        if (cur_block_pos->next == NULL && (idx + 1) < crypto_blks) {
            cur_block_pos->next = TEE_Malloc(sizeof(struct block_info_t), 0);
            if (cur_block_pos->next == NULL) {
                tloge("malloc2 blockInfo failed\n");
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            last_block_pos          = cur_block_pos->next;
            last_block_pos->block_id = last_block_pos->block_id + 1;
            last_block_pos->next    = NULL;
        }

        cur_block_pos = cur_block_pos->next;
    }

    return TEE_SUCCESS;
}

static TEE_Result update_block_hash(struct sfd_t *sfd, const uint8_t *crypto_buf,
    uint32_t buf_size, uint32_t start_block_id)
{
    TEE_Result ret;
    struct block_info_t *cur_block_pos  = NULL;
    struct block_info_t *last_block_pos = NULL;
    bool found_start_block              = false;

    tlogd("start block_id=%u, buffer size=%u\n", start_block_id, buf_size);

    cur_block_pos = sfd->first_block;
    if (cur_block_pos == NULL) {
        tloge("illegal pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* find start_block_id entry in list */
    while (cur_block_pos != NULL) {
        if (cur_block_pos->block_id == start_block_id) {
            found_start_block = true;
            break;
        }
        last_block_pos = cur_block_pos;
        cur_block_pos  = cur_block_pos->next;
    }

    /* create a whole list from zero to start_block_id */
    if (!found_start_block) {
        cur_block_pos = last_block_pos;
        while (cur_block_pos->block_id < start_block_id) {
            cur_block_pos->next = TEE_Malloc(sizeof(struct block_info_t), 0);
            if (cur_block_pos->next == NULL) {
                tloge("malloc1 blockInfo failed\n");
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            last_block_pos          = cur_block_pos;
            cur_block_pos           = cur_block_pos->next;
            cur_block_pos->block_id = last_block_pos->block_id + 1;
            cur_block_pos->next     = NULL;
        }
    }

    /* calculate hash one by one */
    ret = calculate_hash_for_block(sfd, crypto_buf, buf_size, cur_block_pos, last_block_pos);
    return ret;
}

#define HUANGLONG_PLATFORM 2
static int32_t derive_ivcounter(const uint8_t *data_in, uint32_t data_in_size, uint8_t *data_out,
                                uint32_t data_out_size, const uint8_t *key_value, uint32_t key_value_size)
{
    if (data_in == NULL || data_out == NULL || key_value == NULL || data_in_size > INT32_MAX)
        return -1;

    /* do hash sha256 */
    TEE_Result ret = cmd_hash(key_value, key_value_size, g_gs_key_hash.key, (size_t)data_out_size);
    if (ret != TEE_SUCCESS) {
        tloge("do hash sha256 failed, ret = 0x%x\n", ret);
        return -1;
    }
    g_gs_key_hash.flag = true;

    /* do hmac sha256 */
    struct key_info_t key_info = {
        .key = g_gs_key_hash.key,
        .key_len = CRYPT_KEY_SIZE,
    };
    ret = calc_hmac256(&key_info, data_in, (int32_t)data_in_size, data_out, &data_out_size);
    if (ret != TEE_SUCCESS) {
        tloge("do hmac sha256 failed, ret = 0x%x\n", ret);
        return -1;
    }
    return 0;
}

#define BLOCK_ID_SIZE 4
TEE_Result encrypt_blocks_with_cbc(const uint8_t *src, uint32_t len, uint8_t *dst, const struct sfd_t *sfd,
                                   uint32_t mode)
{
    uint32_t encrypt_times, encrypt_index;
    size_t crypto_blocksize;
    /* for CBC IV */
    uint8_t iv[CRYPT_KEY_SIZE];
    uint8_t block_id_buffer[BLOCK_ID_SIZE];
    uint32_t block_id;
    errno_t rc;

    if (src == NULL || dst == NULL || sfd == NULL || sfd->meta_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
#ifdef CONFIG_THIRD_STORAGE_SUPPORT
    block_id = sfd->start_block_id + sfd->first_iv;
#else
    block_id = sfd->start_block_id;
#endif
    crypto_blocksize = sfd->crypto_block_size;
    if (crypto_blocksize == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    encrypt_times = len / crypto_blocksize;

    for (encrypt_index = 0; encrypt_index < encrypt_times; encrypt_index++) {
        tlogd("---encrypt %u/%u---\n", encrypt_index, encrypt_times);

        /* generate iv from block id */
        rc = memset_s((void *)iv, sizeof(iv), 0, sizeof(iv));
        if (rc != EOK)
            tloge("memset iv failed, %x\n", rc);

        rc = memset_s((void *)block_id_buffer, sizeof(block_id_buffer), 0, sizeof(block_id_buffer));
        if (rc != EOK)
            tloge("memset block_id failed, %x\n", rc);

        rc = memmove_s(block_id_buffer, sizeof(block_id_buffer), &block_id, sizeof(block_id_buffer));
        if (rc != EOK)
            return TEE_ERROR_SECURITY;

        if (derive_ivcounter(block_id_buffer, sizeof(block_id_buffer), iv, sizeof(iv), sfd->meta_data->ta_root_key,
            sizeof(sfd->meta_data->ta_root_key))) {
            tloge("generate iv from block id failed\n");
            return TEE_ERROR_GENERIC;
        }

        uint32_t encrypt_offset = crypto_blocksize * encrypt_index;

        TEE_Result ret = aes_cbc_crypto(mode, sfd->meta_data->ta_root_key, sizeof(sfd->meta_data->ta_root_key),
            iv, sizeof(iv), (uint8_t *)(src + encrypt_offset), crypto_blocksize, (uint8_t *)(dst + encrypt_offset));
        if (ret != TEE_SUCCESS)
            return ret;

        /* update block id */
        block_id++;
    }
    return TEE_SUCCESS;
}

TEE_Result encrypt_blocks_with_xts(const uint8_t *src, uint32_t len, uint8_t *dst, const struct sfd_t *sfd,
                                   uint32_t mode)
{
    uint32_t encrypt_index;
    uint8_t block_id_buffer[sizeof(uint32_t)];
    uint32_t block_id;

    if (src == NULL || dst == NULL || sfd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    block_id = sfd->start_block_id;

    for (encrypt_index = 0; encrypt_index < len / sfd->crypto_block_size; encrypt_index++) {
        tlogd("---encrypt %u/%u---\n", encrypt_index, len / sfd->crypto_block_size);

        /* generate iv from block id and random */
        (void)memset_s((void *)block_id_buffer, sizeof(block_id_buffer), 0, sizeof(block_id_buffer));
        if (memmove_s(block_id_buffer, sizeof(block_id_buffer), &block_id, sizeof(block_id_buffer)) != EOK)
            return TEE_ERROR_SECURITY;

        struct memref_t tweak = {(uintptr_t)block_id_buffer, sizeof(block_id_buffer)};
        uint32_t crypto_offset = sfd->crypto_block_size * encrypt_index;
        struct memref_t data_in = {(uintptr_t)(src + crypto_offset), sfd->crypto_block_size};
        struct memref_t data_out = {(uintptr_t)(dst + crypto_offset), sfd->crypto_block_size};
        if (aes_xts_crypto(mode, sfd, &tweak, &data_in, &data_out) != TEE_SUCCESS) {
            tloge("encrypt failed\n");
            return TEE_ERROR_GENERIC;
        }

        /* update block id */
        block_id++;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_block_integrity(const struct sfd_t *sfd, const uint8_t *buff,
    uint32_t buff_size, uint32_t block_id)
{
    TEE_Result ret;
    struct block_info_t *cur_block_pos = NULL;
    uint8_t calculated_hash[HASH_LEN];
    uint32_t i;
    errno_t rc;

    if (sfd == NULL || buff == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < buff_size / sfd->crypto_block_size; i++) {
        rc = memset_s((void *)calculated_hash, sizeof(calculated_hash), 0, sizeof(calculated_hash));
        if (rc != EOK)
            tlogw("memset failed\n");

        ret = calculate_block_hash(calculated_hash, sizeof(calculated_hash), buff + i * sfd->crypto_block_size,
                                   sfd->crypto_block_size);
        if (ret != TEE_SUCCESS)
            return ret;

        cur_block_pos = sfd->first_block;
        while (cur_block_pos != NULL) {
            if (cur_block_pos->block_id == (block_id + i))
                break;
            cur_block_pos = cur_block_pos->next;
        }
        if (cur_block_pos == NULL) {
            tloge("block_id is not found in the block list %u\n", block_id + i);
            return TEE_ERROR_BAD_STATE;
        }

        if (TEE_MemCompare(calculated_hash, cur_block_pos->hash, sizeof(cur_block_pos->hash))) {
            tloge("compare hash of block fail, block_id=%u\n", block_id + i);
            return TEE_ERROR_CORRUPT_OBJECT;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result check_read_params(const uint8_t *out_buf, struct sfd_t *sfd, TEE_Result *error)
{
    if (error == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (out_buf == NULL || sfd == NULL || sfd->meta_data == NULL ||
        sfd->meta_data->cur_encrypted_file_id == NULL) {
        tloge("ssa read Illegal sfd\n");
        *error = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sfd->crypto_block_size == 0) {
        tloge("Illegal sfd crypto_block_size\n");
        *error = TEE_ERROR_BAD_STATE;
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_read_init_data(struct ssa_rw_info *r_info, uint32_t *count, struct sfd_t *sfd)
{
    TEE_Result ret;
    uint32_t file_len;
    r_info->start_flag = 0;
    r_info->end_flag = 0;
    r_info->crypto_blocksize = sfd->crypto_block_size;  /* crypto_block_size = 3k */

    /* get cur_pos and file_len */
    ret = ssa_info(sfd, &(r_info->cur_pos), &file_len);
    if (ret != TEE_SUCCESS) {
        tloge("get file info error\n");
        return ret;
    }

    if (r_info->cur_pos + *count > file_len)
        *count = file_len - r_info->cur_pos;

    /* start pos should be CRYPT_BLOCK_SIZE align */
    r_info->start_pos    = GET_ALIGNED_SIZE_DOWN(r_info->cur_pos, r_info->crypto_blocksize);
    r_info->start_offset = r_info->cur_pos - r_info->start_pos;
    r_info->end_pos      = r_info->cur_pos + *count;
    r_info->end_offset   = r_info->end_pos % r_info->crypto_blocksize;

    /* go to start pos */
    if (r_info->start_offset != 0) {
        ret = ssa_seek(sfd, r_info->start_pos, TEE_DATA_SEEK_SET);
        if (ret != TEE_SUCCESS) {
            tloge("seek to start pos failed \n");
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result decrypt_data_block(struct sfd_t *sfd,
    uint32_t read_count, uint32_t start_block_id, uint8_t *buff)
{
    TEE_Result ret;
    sfd->start_block_id = start_block_id;

    ret = check_block_integrity(sfd, buff, read_count, sfd->start_block_id);
    if (ret != TEE_SUCCESS) {
        tloge("block has been corrupted while read\n");
        return ret;
    }
    ret = encrypt_blocks(buff, read_count, buff, sfd, TEE_MODE_DECRYPT);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt file failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result read_data_out(struct ssa_rw_info *r_info, uint8_t *out_buf,
    uint32_t count, struct sfd_t *sfd, uint32_t *total_read_count)
{
    TEE_Result ret;
    int8_t end_of_file = 0;
    uint32_t recv_times, recv_index;
    struct ssa_rw_count_process cnt_proc;
    uint32_t total_actual_count = 0; /* actual total read count */

    cnt_proc.actual_count = count + r_info->start_offset;
    if (r_info->end_offset != 0)
        cnt_proc.actual_count += (r_info->crypto_blocksize - r_info->end_offset);
    recv_times = cnt_proc.actual_count / r_info->trans_size + ((cnt_proc.actual_count % r_info->trans_size) ? 1 : 0);

    for (recv_index = 0; recv_index < recv_times; recv_index++) {
        uint32_t recv_count = (total_actual_count + r_info->trans_size) <= cnt_proc.actual_count ?
            r_info->trans_size : (cnt_proc.actual_count % r_info->trans_size);

        (void)memset_s((void *)(r_info->trans_buff), r_info->trans_size, 0, r_info->trans_size);

        cnt_proc.read_count = ssa_fs_fread(r_info->trans_buff, recv_count, sfd->nfd, (int32_t *)&ret);
        if (cnt_proc.read_count < recv_count) {
            if (ret != TEE_SUCCESS) {
                tloge("a read error occurs, expected=%u, actual=%u, ret=%d\n", recv_count, cnt_proc.read_count, ret);
                return get_spec_errno(TEE_ERROR_READ_DATA);
            }
            end_of_file = 1;
        }

        ret = decrypt_data_block(sfd, cnt_proc.read_count,
            (r_info->start_pos + total_actual_count) / r_info->crypto_blocksize, r_info->trans_buff);
        if (ret != TEE_SUCCESS)
            return ret;

        total_actual_count += cnt_proc.read_count;
        cnt_proc.copy_count = cnt_proc.read_count;

        if (recv_index == 0 && r_info->start_offset != 0)
            cnt_proc.copy_count -= r_info->start_offset;

        if ((recv_index == (recv_times - 1)) && r_info->end_offset != 0) {
            cnt_proc.copy_count -= (r_info->crypto_blocksize - r_info->end_offset);
            r_info->end_flag = 1;
        }

        if (memmove_s(out_buf + *total_read_count, count - *total_read_count,
            recv_index ? r_info->trans_buff : (r_info->trans_buff + r_info->start_offset), cnt_proc.copy_count) != EOK)
            return TEE_ERROR_SECURITY;

        *total_read_count += cnt_proc.copy_count;
        if (end_of_file != 0)
            return TEE_SUCCESS;
    }
    return TEE_SUCCESS;
}

/*
 * Function    : safe file read
 * Description : null
 * Input       : count - read size
 *               sfd   - file handler
 * Output      : out_buf - buffer to store read file content
 * Return      : number of element successfully read
 */
uint32_t ssa_read(uint8_t *out_buf, uint32_t count, struct sfd_t *sfd, TEE_Result *error)
{
    TEE_Result ret;
    uint32_t total_read_count = 0; /* total read useful count */
    struct ssa_rw_info read_info;

    if (check_read_params(out_buf, sfd, error) != TEE_SUCCESS)
        return 0;

    *error = ssa_read_init_data(&read_info, &count, sfd);
    if (*error != TEE_SUCCESS)
        return 0;

    if (read_info.cur_pos >= sfd->size) {
        *error = TEE_SUCCESS;
        return 0;
    }

    /* alloc trans_buff, CRYPT_BLOCK_SIZE align */
    read_info.trans_size = GET_ALIGNED_SIZE_DOWN(TRANS_BUFF_SIZE - get_fs_meta_size(), read_info.crypto_blocksize);
    read_info.trans_buff = TEE_Malloc(read_info.trans_size, 0);
    if (read_info.trans_buff == NULL) {
        tloge("can't alloc trans_buff\n");
        *error = TEE_ERROR_OUT_OF_MEMORY;
        return 0;
    }

    ret = read_data_out(&read_info, out_buf, count, sfd, &total_read_count);
    if (ret != TEE_SUCCESS) {
        tloge("read data fail!\n");
        *error = ret;
    }

    if (read_info.end_flag != 0) {
        ret = ssa_seek(sfd, read_info.end_pos, TEE_DATA_SEEK_SET);
        if (ret != TEE_SUCCESS) {
            tloge("seek to end position fail\n");
            *error = ret;
        }
    }

    TEE_Free(read_info.trans_buff);

    /* *error equal the initial value of invoking function */
    return total_read_count;
}

static TEE_Result check_write_params(const uint8_t *content,
                                     struct sfd_t *sfd, TEE_Result *error)
{
    if ((sfd == NULL) || (content == NULL) || (error == NULL) || (sfd->meta_data == NULL) ||
        (sfd->meta_data->file_id == NULL)) {
        tloge("ssa write Illegal sfd\n");
        *error = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sfd->crypto_block_size == 0) {
        tloge("ssa write crypto block size invalid\n");
        *error = TEE_ERROR_BAD_STATE;
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_file_info_fill_hole(struct sfd_t *sfd, uint32_t count, uint32_t *cur_pos)
{
    TEE_Result ret;
    uint32_t file_len;

    /*
     * get cur_pos and file_len
     * if we update seek_position and size real-time, we don't need to call ssa_info here.
     */
    ret = ssa_info(sfd, cur_pos, &file_len);
    if (ret != TEE_SUCCESS) {
        tloge("get file info error\n");
        return ret;
    }

    tlogd("file info : pos/len = %u/%u count=%u\n", *cur_pos, file_len, count);

    /* count max size is 4M */
    if (*(cur_pos) + count > MAX_FILE_SIZE + sfd->attr_size) {
        tloge("file size is exceed maximum");
        return TEE_ERROR_OVERFLOW;
    }

    /* here is a file hole!! encrypt the file hole first */
    if (*cur_pos > file_len) {
        ret = fill_file_hole(sfd, file_len, *cur_pos - file_len);
        if (ret != TEE_SUCCESS) {
            tloge("fill hole failed\n");
            return ret;
        }
    }

    return TEE_SUCCESS;
}

static void init_write_pos_info(struct ssa_rw_info *w_info, struct sfd_t *sfd, uint32_t count)
{
    /* start pos should be CRYPT_BLOCK_SIZE align */
    w_info->crypto_blocksize = sfd->crypto_block_size;
    w_info->start_pos        = GET_ALIGNED_SIZE_DOWN(w_info->cur_pos, w_info->crypto_blocksize);
    w_info->start_offset     = w_info->cur_pos - w_info->start_pos;
    w_info->end_pos          = w_info->cur_pos + count;
    w_info->end_offset       = w_info->end_pos % w_info->crypto_blocksize;

    tlogd("start_pos = %u, start_offset=%u, end_pos=%u, end_offset=%u\n", pos->start_pos,
        pos->start_offset, pos->end_pos, pos->end_offset);
}

static TEE_Result malloc_write_buffer(uint8_t **trans_buff, uint32_t *trans_size,
    uint8_t **crypto_buff, uint32_t crypto_blocksize)
{
    /* alloc trans_buff, CRYPT_BLOCK_SIZE align */
    *trans_size = GET_ALIGNED_SIZE_DOWN(TRANS_BUFF_SIZE - get_fs_meta_size(), crypto_blocksize);
    tlogd("trans_size = %u\n", *trans_size);
    *trans_buff = TEE_Malloc(*trans_size, 0);
    if (trans_buff == NULL) {
        tloge("can't alloc trans_buff\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    *crypto_buff = TEE_Malloc(crypto_blocksize, 0);
    if (crypto_buff == NULL) {
        tloge("malloc crypto buffer failed\n");
        TEE_Free(trans_buff);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    return TEE_SUCCESS;
}

static void free_write_buffer(uint8_t *trans_buff, uint8_t *crypto_buff)
{
    TEE_Free(crypto_buff);
    TEE_Free(trans_buff);
}

static TEE_Result ssa_init_write_info(struct ssa_rw_info *w_info, uint32_t count, struct sfd_t *sfd)
{
    TEE_Result ret;

    w_info->end_flag = 0;
    w_info->start_flag = 0;
    ret = get_file_info_fill_hole(sfd, count, &w_info->cur_pos);
    if (ret != TEE_SUCCESS)
        return ret;

    init_write_pos_info(w_info, sfd, count);

    if ((w_info->cur_pos + count) > sfd->size)
        /*
         * we can only update this value in sfd in memory,
         * at the last stage, update this value and hmac in meta together.
         */
        sfd->last_block_size = (count + w_info->cur_pos) % w_info->crypto_blocksize;

    /* hmac reset to 0 */
    ret = ssa_reset_mac(sfd);
    if (ret != TEE_SUCCESS) {
        tloge("reset mac failed\n");
        return ret;
    }

    sfd->update_backup = false;

    return TEE_SUCCESS;
}

static TEE_Result fill_start_block_origin(struct ssa_rw_info *w_info,
    struct sfd_t *sfd, uint8_t **dst_addr, uint32_t *add_count, uint32_t *copy_count)
{
    TEE_Result ret;
    uint32_t start_blk_size;
    uint32_t read_count;

    if (w_info->start_pos < sfd->size) {
        /*
         * set file pointer to blk head to read blk
         * if attribute as meta, we should handle this.
         */
        ret = ssa_fs_fseek_blk_start(sfd, w_info->start_pos);
        if (ret != TEE_SUCCESS)
            return ret;

        start_blk_size = w_info->crypto_blocksize;
        read_count = ssa_fs_fread(w_info->crypto_buff, start_blk_size, sfd->nfd, (int32_t *)&ret);
        if (read_count < start_blk_size && ret != TEE_SUCCESS) {
            /* read error, no need to update hash file */
            tloge("a read error occurs, expected=%u, actual=%u, error=0x%x\n", start_blk_size, read_count, ret);
            return get_spec_errno(TEE_ERROR_READ_DATA);
        }

        ret = decrypt_data_block(sfd, read_count, w_info->start_pos / w_info->crypto_blocksize, w_info->crypto_buff);
        if (ret != TEE_SUCCESS) {
            tloge("decrypt data block failed\n");
            return ret;
        }

        errno_t rc = memmove_s(w_info->trans_buff, w_info->trans_size, w_info->crypto_buff, w_info->start_offset);
        if (rc != EOK) {
            tloge("memmove failed\n");
            return TEE_ERROR_SECURITY;
        }
    }

    /*
     * Notice :for else,it is file hole, the content is 0, should't be read out and descrypt
     * Actually, else condition is not exist,
     * Because if file hole exist, we will fill it will zero.
     * Thus, the length of file will update.
     */
    *dst_addr += w_info->start_offset;
    *copy_count -= w_info->start_offset;
    *add_count += w_info->start_offset;

    return TEE_SUCCESS;
}

static TEE_Result fill_end_block_origin(struct ssa_rw_info *w_info,
    struct sfd_t *sfd, uint32_t *add_count)
{
    errno_t rc;
    TEE_Result ret;
    *add_count += (w_info->crypto_blocksize - w_info->end_offset);
    if (w_info->end_pos < sfd->size) {
        uint32_t end_blk_size;

        /* set file pointer to blk head to read block */
        ret = ssa_fs_fseek_blk_end(sfd, w_info->end_pos, w_info->end_offset);
        if (ret != TEE_SUCCESS)
            return ret;

        /* notice:maybe last blk is not a full blk */
        end_blk_size = w_info->crypto_blocksize;

        uint32_t read_count = ssa_fs_fread(w_info->crypto_buff, end_blk_size, sfd->nfd, (int32_t *)&ret);
        if ((read_count < end_blk_size) && (ret != TEE_SUCCESS)) {
            tloge("a read error occurs, expected=%u, actual=%u, error=0x%x\n", end_blk_size, read_count, ret);
            return get_spec_errno(TEE_ERROR_READ_DATA);
        }

        ret = decrypt_data_block(sfd, read_count,
            (w_info->end_pos - w_info->end_offset) / w_info->crypto_blocksize, w_info->crypto_buff);
        if (ret != TEE_SUCCESS) {
            tloge("decrypt data block failed\n");
            return ret;
        }

        rc = memmove_s(w_info->trans_buff + (w_info->end_pos % w_info->trans_size),
                       w_info->trans_size - (w_info->end_pos % w_info->trans_size),
                       w_info->crypto_buff + w_info->end_offset, end_blk_size - w_info->end_offset);
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
    }
    if (sfd->size == 0) {
        rc = memmove_s(w_info->trans_buff + (w_info->end_pos % w_info->trans_size),
                       w_info->trans_size - (w_info->end_pos % w_info->trans_size),
                       w_info->crypto_buff + w_info->end_offset, w_info->crypto_blocksize - w_info->end_offset);
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

static TEE_Result write_data(struct ssa_rw_info *w_info, uint32_t send_count,
    struct sfd_t *sfd, uint32_t *total_write_count)
{
    TEE_Result ret;
    uint32_t write_count;
    uint32_t start_blockid = sfd->start_block_id;

    write_count = ssa_fs_fwrite(w_info->trans_buff, send_count, sfd->nfd);
    if (write_count < send_count) {
        tloge("write_count < send_count failed\n");
        return get_spec_errno(TEE_ERROR_WRITE_DATA);
    }

    if (judge_valid_version(sfd)) {
        ret = update_block_hash(sfd, w_info->trans_buff, send_count, start_blockid);
        if (ret != TEE_SUCCESS) {
            tloge("update blocks hash failed\n");
            return ret;
        }
    }

    *total_write_count += write_count;

    return TEE_SUCCESS;
}

static TEE_Result seek_write_pos(struct ssa_rw_info *w_info,
    struct sfd_t *sfd, uint32_t total_write_count)
{
    TEE_Result ret;
    uint32_t seek_start_pos = w_info->start_pos + total_write_count;
    /*
     * don't set end_flag=0,end seek will use it
     * set file pointer to blk head to read blk, because it had fread to change file pointer
     */
    if (w_info->start_flag != 0 || w_info->end_flag != 0) {
        w_info->start_flag = 0;
        ret = ssa_fs_fseek_blk_start(sfd, seek_start_pos);
        if (ret != TEE_SUCCESS) {
            tloge("seek file to written offset failed\n");
            return get_spec_errno(TEE_ERROR_SEEK_DATA);
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result encrypt_trans_buff(struct sfd_t *sfd,
    struct ssa_rw_info *w_info, uint32_t send_count, uint32_t total_write_count)
{
    TEE_Result ret;

    /*
     * encryt trans_buff, save in fsAgentBuffer's exchange buff
     * We should record write start block ID.
     * total_write_count is align to CRYPTO_BLOCK_SIZE forever, so we dont need to align.
     */
    sfd->crypto_block_size = w_info->crypto_blocksize;
    sfd->start_block_id    = (w_info->start_pos + total_write_count) / w_info->crypto_blocksize;

    ret = encrypt_blocks(w_info->trans_buff, send_count,
        w_info->trans_buff, sfd, TEE_MODE_ENCRYPT);
    if (ret != TEE_SUCCESS) {
        tloge("file encrypt failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result write_data_process(struct ssa_rw_info *w_info,
    struct ssa_rw_count_process *cnt_proc, struct sfd_t *sfd, uint32_t *total_write_count)
{
    TEE_Result ret;

    ret = encrypt_trans_buff(sfd, w_info, cnt_proc->send_count, *total_write_count);
    if (ret != TEE_SUCCESS) {
        tloge("encrypt trans buff fail");
        return ret;
    }

    ret = seek_write_pos(w_info, sfd, *total_write_count);
    if (ret != TEE_SUCCESS) {
        tloge("seek write pos fail");
        return ret;
    };

    ret = write_data(w_info, cnt_proc->send_count, sfd, total_write_count);
    if (ret != TEE_SUCCESS) {
        tloge("write data fail");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result write_content_to_file(struct ssa_rw_info *w_info,
    const uint8_t *content, uint32_t count, struct sfd_t *sfd, uint32_t *total_write_count)
{
    TEE_Result ret;
    uint32_t send_index;
    uint32_t send_times;
    uint8_t *dst_addr = NULL;
    uint32_t padding_size = 0;
    struct ssa_rw_count_process cnt_proc;
    const uint8_t *src_addr = content;

    /* s_fwrite actual writen length : content len + (start_blk add) + (end_blk add) */
    cnt_proc.actual_count = count + w_info->start_offset;
    cnt_proc.add_count = 0;

    if (w_info->end_offset != 0)
        cnt_proc.actual_count += (w_info->crypto_blocksize - w_info->end_offset);

    send_times = (cnt_proc.actual_count / w_info->trans_size) + ((cnt_proc.actual_count % w_info->trans_size) ? 1 : 0);

    for (send_index = 0; send_index < send_times; send_index++) {
        /* no need check return val */
        (void)memset_s((void *)(w_info->trans_buff), w_info->trans_size, 0, w_info->trans_size);

        cnt_proc.send_count = (*total_write_count + w_info->trans_size) <= cnt_proc.actual_count ?
            w_info->trans_size : (cnt_proc.actual_count % w_info->trans_size);
        dst_addr   = w_info->trans_buff;
        cnt_proc.copy_count = cnt_proc.send_count;

        /* fill trans_buff step1: start_blk 's origin part */
        if (send_index == 0 && w_info->start_offset) {
            w_info->start_flag = 1;
            ret = fill_start_block_origin(w_info, sfd, &dst_addr, &cnt_proc.add_count, &cnt_proc.copy_count);
            if (ret != TEE_SUCCESS)
                return ret;
        }
        if ((send_index == send_times - 1) && w_info->end_offset)
            cnt_proc.copy_count -= (w_info->crypto_blocksize - w_info->end_offset);

        /* fill trans_buff step2 : middle_blk */
        if (memmove_s(dst_addr, w_info->trans_size - (dst_addr - w_info->trans_buff),
                      src_addr, cnt_proc.copy_count) != EOK)
            return TEE_ERROR_SECURITY;
        src_addr += cnt_proc.copy_count;

        /* fill trans_buff step3 : end_blk 's origin part */
        if ((send_index == send_times - 1) && w_info->end_offset) {
            w_info->end_flag = 1;
            ret = fill_end_block_origin(w_info, sfd, &cnt_proc.add_count);
            if (ret != TEE_SUCCESS)
                return ret;
        }

        ret = write_data_process(w_info, &cnt_proc, sfd, total_write_count);
        if (ret != TEE_SUCCESS)
            return ret;

        padding_size = cnt_proc.add_count;
    }

    *total_write_count -= padding_size;
    return TEE_SUCCESS;
}

/*
 * Function    : safe file write,a serries call of fs to make encrypto fs write
 * Description : if error occurs, the crypto file is broken which can't be read again
 * Input       : content - content buffer
 *               count   - content size
 *               sfd     - file handler
 * Return      : number of element successfully write
 */
uint32_t ssa_write(const uint8_t *content, uint32_t count, struct sfd_t *sfd, TEE_Result *error)
{
    TEE_Result ret;
    uint32_t total_write_count = 0;
    struct ssa_rw_info write_info;

    if (check_write_params(content, sfd, error) != TEE_SUCCESS)
        return 0;

    if (count == 0) {
        *error = TEE_SUCCESS;
        return 0;
    }

    *error = ssa_init_write_info(&write_info, count, sfd);
    if (*error != TEE_SUCCESS)
        return 0;

    *error = malloc_write_buffer(&write_info.trans_buff, &write_info.trans_size,
                                 &write_info.crypto_buff, write_info.crypto_blocksize);
    if (*error != TEE_SUCCESS)
        return 0;

    *error = write_content_to_file(&write_info, content, count, sfd, &total_write_count);
    if (*error != TEE_SUCCESS)
        goto out;

    if (write_info.end_flag != 0) {
        /* set file pointer pos */
        tlogd("we should seek to %u for real offset\n", write_info.end_pos);
        ret = ssa_fs_fseek_blk_end(sfd, write_info.end_pos, 0);
        if (ret != TEE_SUCCESS) {
            *error = TEE_ERROR_GENERIC;
            goto out;
        }
    }

    sfd->need_update_hmac = true;

out:
    free_write_buffer(write_info.trans_buff, write_info.crypto_buff);
    sfd->size += total_write_count;
    return total_write_count;
}

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
#ifndef __TEE_SFS_H
#define __TEE_SFS_H

#include "tee_defines.h"
#include <crypto_driver_adaptor.h>
#include "sfs_internal.h"

/* Macros for access() */
#define R_OK 4 /* Read */
#define W_OK 2 /* Write */
#define F_OK 0 /* Existence */

#define CRYPT_KEY_SIZE      32 /* file's crypt key size, now it's AES-256 */
#define AES_XTS_SINGLE_UNIT 1024
#define IDENTIFY_SIZE       16 /* TA info, now it's UUID */

/* WARNING: once more definitions for `CRYPT_BLOCK_SIZE', SHOULD update `BLOCK_SIZE' */
#define CRYPT_BLOCK_SIZE         64   /* crypt block size */
#define CRYPT_BLOCK_SIZE_ENHANCE 512  /* increase crypto blocksize to enhance the perf */
#define CRYPT_BLOCK_SIZE_V3      3072 /* increase crypto blocksize to enhance the perf */
/* WARNING: once more definitions for `CRYPT_BLOCK_SIZE', SHOULD update `BLOCK_SIZE' */
#define LAST_SIZE       4
#define HASH_FILE_MAGIC 'h'
#define HASH_VERIFY_LEN (2 * HASH_LEN)
/* DIR_LEN is for mutiple sec storage partition and dir,e.g. sec_storage/dirA/file1.txt */
#define BLOCK_SIZE (CRYPT_BLOCK_SIZE_V3) /* read or write block */

#define SFS_STORAGE_MAGIC_LO 0xfd48d1ef
#define SFS_STORAGE_MAGIC_HI 0x827d9a7b
#define DATAHMAC_HASH_SIZE   8
enum SFS_ARCH_VERSION {
    SFS_ARCH_VERSION_INVALID = 0,
    SFS_ARCH_VERSION_ECB,
    SFS_ARCH_VERSION_AES_CBC, /* AES mode to CBC */
    SFS_ARCH_VERSION_PO,      /* Performance Optimization */
    SFS_ARCH_VERSION_SSA,     /* SSAgent */
    SFS_ARCH_ITEM_NOT_FOUND = 0x10000,
    SFS_ARCH_VERSION_MAX,
};

#define META_STORATE_MAGIC_VERSION 0x5A5A0001

enum SFS_DATA_ENCRYPTO_METHOD {
    SFS_DATA_ENCRYPTO_XTS  = 0,
    SFS_DATA_ENCRYPTO_METHOD_MAX,
};
#define U64_RESERVED_NUM  2
/*
 * we ever need to modify structure of secure storage data we have to increase  arch_version
 * so a new version of secure storage SW can use it to define if the structure of s-storage is
 * new or old one and read it a correct way.
 */
#ifdef CONFIG_THIRD_STORAGE_SUPPORT
typedef struct {
    uint32_t magic_lo;
    uint32_t magic_hi;
    uint32_t arch_version; /* architecture version of storage, current version = 1 */
    uint32_t last_block_realsize;
    uint32_t magic_version;          /* META_STORATE_MAGIC_VERSION */
    uint32_t first_iv;
    uint32_t fname_datahmac_hash[DATAHMAC_HASH_SIZE];
    uint32_t encrypto_meth;          /* 0 xts, etc */
    uint32_t reserved[1]; /* aligned to 64 bytes */
} meta_storage_header_t;
#else
typedef struct {
    uint32_t magic_lo;
    uint32_t magic_hi;
    uint32_t arch_version; /* architecture version of storage, current version = 1 */
    uint32_t last_block_realsize;
    uint32_t magic_version;          /* META_STORATE_MAGIC_VERSION */
    uint32_t fname_datahmac_hash[DATAHMAC_HASH_SIZE];
    uint32_t encrypto_meth;          /* 0 xts, etc */
    uint32_t reserved[U64_RESERVED_NUM]; /* aligned to 64 bytes */
} meta_storage_header_t;
#endif

typedef struct {
    meta_storage_header_t hdr;
    uint8_t meta_hmac[HASH_VERIFY_LEN];
    uint8_t data_hmac[HASH_VERIFY_LEN];
} meta_storage_t;

#define STR_FOR_EMPTY_FILE_HASH "appname"
#define _offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define GET_ALIGNED_SIZE_UP(x, align)   (((x) + (align)-1) / (align) * (align))
#define GET_ALIGNED_SIZE_DOWN(x, align) ((x) / (align) * (align))

#define SFS_METADATA_SIZE   (sizeof(meta_storage_t))
#define SFS_METAHMAC_OFFSET (_offsetof(meta_storage_t, meta_hmac))
#define SFS_DATAHMAC_OFFSET (_offsetof(meta_storage_t, data_hmac))

#define SFS_BACKUP_FILE_SUFFIX ".bk"

#define SFS_START_BLOCKID 0

#define TA_KEY_COMPOSED_OF_TWO_16BYTES_KEYS 0 /* Derive TA root key by combining two 16-bytes keys */

struct block_info_t {
    uint8_t hash[HASH_LEN];
    uint32_t block_id;
    uint32_t reserved;
    struct block_info_t *next;
};

struct sfd_t {
    int32_t nfd; /* Nonsecure file handler */
    uint32_t crypto_block_size;
    uint32_t start_block_id;
    uint32_t flags;
    uint32_t seek_position;
    uint32_t size; /* dataSize. */
    uint32_t last_block_size;
    uint32_t attr_size;
    /*
     * `update_backup' show whether update backup file or not in s_fclose.
     * true: creating file succeed, or,
     *       the last calling s_fwrite succeed.
     * false: opening file succeed without s_fwrite, or,
     *       the last calling s_fwrite fail.
     */
    bool update_backup;
    bool opened_orig; /* true:origal, false:backup */
    bool need_update_hmac;
#ifdef CONFIG_THIRD_STORAGE_SUPPORT
    uint32_t first_iv;
#endif
    meta_data_t *meta_data;
    struct block_info_t *first_block;
    uint32_t data_encmeth; /* add the data encrypto method , 0 xts, etc */
};

struct key_info_t {
    uint8_t *key;
    uint32_t key_len;
};

struct ssa_rw_info {
    int8_t end_flag;
    int8_t start_flag;
    uint32_t start_pos;
    uint32_t start_offset;
    uint32_t end_pos;
    uint32_t end_offset;
    uint32_t cur_pos;
    uint8_t *crypto_buff;
    uint32_t crypto_blocksize;
    uint8_t *trans_buff;
    uint32_t trans_size;
};

struct ssa_rw_count_process {
    uint32_t send_count;
    uint32_t copy_count;
    uint32_t actual_count;
    uint32_t add_count;
    uint32_t read_count;
};

struct sfd_t *ssa_create(meta_data_t *meta, uint32_t flag, TEE_Result *error);

struct sfd_t *ssa_open(meta_data_t *meta, uint32_t flag, TEE_Result *error);

uint32_t ssa_read(uint8_t *out_buf, uint32_t count, struct sfd_t *sfd, TEE_Result *error);

uint32_t ssa_write(const uint8_t *content, uint32_t count, struct sfd_t *sfd, TEE_Result *error);

TEE_Result ssa_close(struct sfd_t *sfd);

TEE_Result ssa_close_and_delete(struct sfd_t *sfd, bool is_delete);

TEE_Result ssa_rename(struct sfd_t *sfd, const uint8_t *new_obj_id, uint32_t new_obj_len);

TEE_Result ssa_sync(const struct sfd_t *sfd);

TEE_Result ssa_seek(struct sfd_t *sfd, int32_t offset, uint32_t whence);

TEE_Result ssa_info(struct sfd_t *sfd, uint32_t *pos, uint32_t *len);

TEE_Result ssa_truncate(struct sfd_t *sfd, uint32_t len);

TEE_Result get_hname(const char *src, int32_t length, char *dest, uint32_t dest_len, meta_data_t *meta);

TEE_Result ssa_write_mac(struct sfd_t *sfd);
void create_object(const struct create_obj_msg_t *create_obj, uint32_t sndr, const TEE_UUID *uuid,
                   struct sfd_t **sfd, uint32_t *obj, TEE_Result *error);
void open_object(struct open_obj_msg_t *open_obj, const TEE_UUID *uuid, uint32_t sndr, struct ssa_agent_rsp *rsp);
TEE_Result calculate_master_hmac(struct sfd_t *sfd, uint8_t *hmac_buf, uint32_t *buf_size);
void str_tran(const unsigned char *sha_buff, uint32_t buff_len, char *dest, uint32_t dest_len);
TEE_Result calc_filename_datahmac_hash(meta_storage_t *sfs_meta, const struct sfd_t *sfd);
TEE_Result calculate_hmac(const uint8_t *src, uint32_t src_len, uint8_t *dest,
                          uint32_t dest_len, const struct sfd_t *sfd);
TEE_Result aes_xts_crypto(uint32_t mode, const struct sfd_t *sfd, const struct memref_t *tweak,
                          const struct memref_t *data_in, struct memref_t *data_out);
TEE_Result fill_file_hole(struct sfd_t *sfd, uint32_t start_offset, uint32_t size);
TEE_Result calculate_block_hash(uint8_t *sha_buff, uint32_t sha_size, const uint8_t *data, uint32_t data_size);
TEE_Result get_spec_errno(TEE_Result ret_default);
TEE_Result calc_hmac256(struct key_info_t *key_info, const uint8_t *src, int32_t length,
                        uint8_t *dest, uint32_t *dest_len);
TEE_Result cmd_hash(const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, size_t dest_len);
uint32_t create_file_instance_to_client(uint32_t sender, struct sfd_t *sfd);
TEE_Result aes_cbc_crypto(uint32_t mode, uint8_t *key_value, uint32_t key_size, const uint8_t *iv,
    uint32_t iv_size, const uint8_t *data_in, uint32_t data_in_size, uint8_t *data_out);
void ssa_removefile(const uint8_t *filename, const char *file_desc, uint32_t storage_id);
int32_t get_hmac_from_meta_data(struct sfd_t *sfd, uint8_t *hmac_buff, uint32_t hmac_buff_len);
TEE_Result do_rename(struct sfd_t *sfd, meta_data_t *new_meta_data);
TEE_Result encrypt_blocks_with_cbc(const uint8_t *src, uint32_t len, uint8_t *dst, const struct sfd_t *sfd,
                                   uint32_t mode);
TEE_Result encrypt_blocks_with_xts(const uint8_t *src, uint32_t len, uint8_t *dst, const struct sfd_t *sfd,
                                   uint32_t mode);
#endif

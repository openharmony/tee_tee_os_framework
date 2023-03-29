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
#ifndef TEE_SFS_INTERNAL_H
#define TEE_SFS_INTERNAL_H

#include <tee_defines.h>
#include "tee_ss_agent_api.h"

#define HMAC_HASH_FUNC      SHA256_HASH
#define HMAC_LEN            32 /* Bytes */
#define HASH_LEN            32 /* Bytes */
#define HASH_VERIFY_LEN     (2 * HASH_LEN)
#define KEYSALT_LEN         16 /* Bytes */
#define AES_BLOCK_SIZE      16 /* Bytes */
#define AES256_KEY_LEN      32 /* Bytes */
#define AES_KEY_LEN         AES256_KEY_LEN
#define TA_ROOT_KEY_LEN     32   /* Bytes */
#define MAX_ATTRIBUTES_SIZE 1024 /* Bytes */
#define CRYPT_KEY_SIZE      32   /* Bytes */

#define FILE_ID_SIZE       HMAC_LEN
#define FILE_ID_ASCII_SIZE (FILE_ID_SIZE * 2 + 1)

/* Following values are used for salting root-key on key-derive. */
#define DERIVE_KEY_SALT_LEN 16

/* The length of salt string have to be at least 16 */
#define FILEKEY_SALT     "0 file key salt."
#define MASTER_HMAC_SALT "master hmacsalt."
#define ENCRYPTION1_SALT "1 aes xti1 salt."
#define ENCRYPTION2_SALT "2 AES XTI2 Salt."
#define FILE_NAME_SALT   "3 FileName salt."

#define TA_ROOTKEY_SIZE 32

#define FILE_DIR_FLAG     "/"
#define CUR_FILE_DIR_FLAG "./"
#define USERID0_DIR_FLAG  "0/"
#define MULTI_USERID      10

#define MAX_CLIENT_OPEN_FILES         24 /* maximum simultaneous open files on private storage per client */
#define MAX_PRIVATE_OPEN_FILES        64 /* maximum simultaneous open files fon shared storage */

__attribute__((weak)) uint32_t g_ssagent_handle;

/* file specific data */
typedef struct {
    struct sfd_t *sfd; /* pointer to secure file descriptor */
    int32_t link_count; /* how many instances uses this file */
    bool first_opened;
} file_link_t;

/* file instance specific data */
typedef struct {
    uint32_t seek_position; /* each file instance has own seek position */
    file_link_t *file_link;
} file_instance_t;

/* Client (TA) data. */
typedef struct {
    TEE_UUID uuid;
    uint32_t task_id;
    uint32_t user_id;
    char dead; /* mark this client is to be unregister */
    bool ssa_enum_enable;
    file_instance_t file_instance[MAX_CLIENT_OPEN_FILES];
} client_t;

/* The architecture version is required in each stored data structures.
 * Sooner or later there may be requirement to modify these structures.
 * It is very easy to make system to backward compatible is any stored
 * data structures has version information.
 */
typedef struct {
    uint32_t arch_version; /* Architecture version */
    uint32_t storage_id;
    uint32_t attributes_size;
    uint32_t crypto_block_size;
    uint8_t *file_id;
    uint32_t file_id_len;
    uint8_t *cur_encrypted_file_id;
    uint8_t *cur_backup_file_id;
    uint8_t *encrypted_file_id;
    uint8_t *backup_file_id;
    uint8_t ta_root_key[TA_ROOTKEY_SIZE];
    uint8_t file_key[CRYPT_KEY_SIZE];
    uint8_t xts_key1[CRYPT_KEY_SIZE];
    uint8_t xts_key2[CRYPT_KEY_SIZE];
    uint8_t hmac_key[CRYPT_KEY_SIZE];
    uint8_t file_id_key[CRYPT_KEY_SIZE];
    uint8_t master_hmac[HASH_VERIFY_LEN];
    TEE_UUID uuid;
    uint8_t *joint_file_id;
} meta_data_t;

typedef void (*ssa_cmd_process)(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
typedef struct {
    uint32_t cmd;
    uint32_t need_ack;
    uint32_t is_file_oper;
    uint32_t is_file_modify;
    ssa_cmd_process fn;
} ssa_cmd_t;

enum SS_AGENT_CMD_OPER_TYPE {
    FILE_OPERATION     = 1,
    NOT_FILE_OPERATION = 2,
    FILE_MODIFY        = 3,
    NOT_FILE_MODIFY    = 4,
};

typedef struct {
    uintptr_t vm_addr;
    uint32_t size;
    bool mapped;
} mem_map_info_t;

#ifndef FILE_NAME_MAX_BUF
#define FILE_NAME_MAX_BUF 256
#endif

meta_data_t *create_meta_data(const uint8_t *obj_id, uint32_t obj_id_len, uint32_t storage_id, uint32_t flags,
                              const TEE_UUID *uuid, TEE_Result *error, uint32_t arch_version);
void free_meta_data(meta_data_t **ppmeta);
void set_meta_data_verion(meta_data_t *meta_data, uint32_t arch_version);
void ssa_create_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_open_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_write_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_read_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_seek_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_truncate_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_rename_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_info_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_close_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_close_and_delete_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
uint32_t get_ree_user_id();
void ssa_get_object_attr(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_sync_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_register_agent(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
void ssa_file_process_abort(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
ssa_cmd_t *ssa_find_cmd(uint32_t cmd);
bool TA_access_check(uint32_t sndr, const TEE_UUID *uuidArry, uint32_t count);
TEE_UUID *get_sender_uuid(uint32_t sender);
int ssa_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size, uint32_t out_task_id, uintptr_t *vm_addr);
void ssa_unmap_from_task(uint32_t task_id, uintptr_t va_addr, uint32_t size, bool mapped);
void close_file_from_client(uint32_t sender, uint32_t obj);
TEE_Result delete_file(uint32_t sender, uint32_t obj);
int32_t get_file_path(uint32_t storage_id, const char *uuid_hmac, uint32_t uuid_hmac_len, char *path,
                      uint32_t path_len);
TEE_Result get_uuid_hmac(const TEE_UUID *uuid, char *uuid_hmac, uint32_t uuid_hmac_len);
void ssa_get_manage_info(const TEE_UUID *uuid, uint32_t *manager);
TEE_Result copy_and_check_file_name(const char *obj_id_in, uint32_t in_len, char *obj_id, uint32_t obj_len);
file_instance_t *get_file_pointer(uint32_t sender, int32_t obj);
client_t *get_sender_client(uint32_t sender);
bool is_enum_enable(const TEE_UUID *uuid);
bool check_shared_access(const struct sfd_t *sfd, uint32_t flags);
uint32_t open_file(meta_data_t *meta, uint32_t sndr, uint32_t flags, struct sfd_t **sfd, TEE_Result *error);
void init_global_param(void);
int32_t file_name_transfer(meta_data_t *meta, char *hash_name, uint32_t hash_name_len, bool is_file_hash);
void reset_meta(meta_data_t *meta);
#endif

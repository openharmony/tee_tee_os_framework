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
#ifndef TEE_SS_AGENT_API_H_
#define TEE_SS_AGENT_API_H_

#include "tee_defines.h"
#include "tee_trusted_storage_api.h"
#include "ta_framework.h"
#include "tee_internal_task_pub.h"
#include "tee_fs.h"
#include <huk_service_msg.h>

#define CALL_SS_AGENT_HELLO 0x01

/* add for rootkey derive */
#define AES_CMAC_DERV_MAX_DATA_IN_SIZE 0x400UL

#define HASH_LEN              32
#define DIR_LEN               64
#define ENUM_FLAG_NOT_ACTIVED 0
#define ENUM_FLAG_ACTIVED     1

#define MAX_SPLIT_NUM         4
#define DOUBLE(x)             ((x) * 2)
#define FILL_NUM              4

struct saved_attr_info_t {
    TEE_ObjectInfo object_info;
    uint32_t attr_count;
    uint32_t attr_size; /* sizeof(attr) */
    uint32_t opt_attr_count;
    uint32_t opt_attr_size;
};

struct __TEE_ObjectEnumHandle {
    uintptr_t enum_handle;
};

struct obj_enum_handle_t {
    uint32_t active_status;
    uint8_t *obj_enum_buf;
    uint32_t obj_enum_buf_len;
    uint32_t offset;
};

enum ssa_gent_commands {
    /* all the cmd from TA must be larger than SS_AGENT_FIRST_CMD */
    SS_AGENT_FIRST_CMD = 0x100,
    SS_AGENT_CREATE_OBJECT           = 0x121,
    SS_AGENT_OPEN_OBJECT             = 0x122,
    SS_AGENT_OPEN_SHARED_OBJECT      = 0x123,
    SS_AGENT_GET_OBJECT_ATTRIBUTES   = 0x124,
    SS_AGENT_WRITE_OBJECT            = 0x125,
    SS_AGENT_READ_OBJECT             = 0x126,
    SS_AGENT_SEEK_OBJECT             = 0x127,
    SS_AGENT_TRUNCATE_OBJECT         = 0x128,
    SS_AGENT_RENAME_OBJECT           = 0x129,
    SS_AGENT_SYNC_OBJECT             = 0x12a,
    SS_AGENT_GET_OBJECT_INFO         = 0x12b,
    SS_AGENT_CLOSE_OBJECT            = 0x12c,
    SS_AGENT_CLOSE_AND_DELETE_OBJECT = 0x12d,
    SS_AGENT_FILE_ABORT              = 0x12e,
    FS_CREATE_OBJECT               = 0x130,
    FS_CLOSE_OBJECT                = 0x131,
    FS_OPEN_OBJECT                 = 0x132,
    FS_SYNC_OBJECT                 = 0x133,
    FS_READ_OBJECT                 = 0x134,
    FS_WRITE_OBJECT                = 0x135,
    FS_SEEK_OBJECT                 = 0x136,
    FS_REMOVE_OBJECT               = 0x137,
    FS_TRUNCATE_OBJECT             = 0x138,
    FS_RENAME_OBJECT               = 0x139,
    FS_COPY_OBJECT                 = 0x13a,
    FS_INFO_OBJECT                 = 0x13b,
    FS_ACCESS_OBJECT               = 0x13c,
    SS_AGENT_EXT_CREATE_OBJECT     = 0x13d,
    SS_AGENT_EXT_OPEN_OBJECT       = 0x13e,
    SS_AGENT_EXT_DELETE_ALL_OBJECT = 0x13f,
    FS_DISK_USAGE_OBJECT           = 0x140,
    SS_AGENT_GET_ENUM_FILE_SIZE    = 0x141,
    SS_AGENT_START_ENUMERATOR      = 0x142,
    SS_AGENT_LOAD_MANAGE_INFO = 0x300,
};

struct buffer_t {
    uint64_t buffer; /* pointer */
    uint32_t len;
};

/* =========================================== */
struct open_obj_msg_t {
    uint32_t storage_id;
    uint64_t object_id; /* pointer */
    uint32_t obj_id_len;
    uint32_t flags;
    uint64_t attr_head; /* pointer */
    uint32_t attr_head_size;
    TEE_UUID target_uuid;
};

struct open_obj_rsp_t {
    uint32_t err;
    uint32_t obj_index;
    uint32_t new_size;
    uint32_t new_seek_pos;
};
/* =========================================== */
struct open_shared_obj_msg_t {
    TEE_UUID source_entity_id;
    uint32_t storage_id;
    uint64_t object_id; /* pointer */
    uint32_t obj_id_len;
};

struct open_shared_obj_rsp_t {
    uint32_t obj_index;
    uint32_t attribute_size;
    uint32_t new_size;
    uint32_t new_seek_pos;
};

/* =========================================== */
struct get_obj_attrs_msg_t {
    uint32_t obj_index;
    uint64_t buffer; /* pointer */
    uint32_t size;
};

struct get_obj_attrs_rsp_t {
    uint32_t size;
};

/* =========================================== */
struct create_obj_msg_t {
    uint32_t storage_id;
    uint64_t object_id; /* pointer */
    uint32_t obj_id_len;
    uint64_t attributes; /* pointer */
    uint32_t attributes_len;
    uint32_t flags;
    uint64_t initial_data; /* pointer */
    uint32_t data_len;
    uint32_t cmd_id;
    TEE_UUID target_uuid;
    uint16_t reserved;
};

struct create_obj_rsp_t {
    uint32_t obj_index;
    uint32_t new_seek_pos;
    uint32_t new_size;
};

/* =========================================== */
struct write_obj_msg_t {
    uint32_t obj_index;
    uint64_t buffer; /* poiner */
    uint32_t len;
    uint16_t reserved;
    uint32_t new_seek_pos;
    uint32_t new_size;
};

struct write_obj_rsp_t {
    uint32_t new_seek_pos;
    uint32_t new_size;
};

/* =========================================== */
struct read_obj_msg_t {
    uint32_t obj_index;
    uint64_t buffer; /* pointer */
    uint32_t len;
};

struct read_obj_rsp_t {
    uint32_t count;
    uint32_t new_seek_pos;
    uint32_t new_size;
    uint16_t reserved;
};

/* =========================================== */
struct seek_obj_msg_t {
    uint32_t obj_index;
    int32_t offset;
    uint32_t whence;
};

struct seek_obj_rsp_t {
    uint32_t new_seek_pos;
    uint32_t new_size;
};
/* =========================================== */
struct truncate_obj_msg_t {
    uint32_t obj_index;
    int32_t size;
};

struct truncate_obj_rsp_t {
    uint32_t new_size;
    uint32_t new_seek_pos;
};

/* =========================================== */
struct rename_obj_msg_t {
    uint32_t obj_index;
    uint64_t new_object_id; /* pointer */
    uint32_t obj_id_len;
};

struct rename_obj_rsp_t {
    uint32_t dummy;
};

/* =========================================== */
struct sync_obj_msg_t {
    uint32_t obj_index;
};

struct sync_obj_rsp_t {
    uint32_t dummy;
};
/* =========================================== */
struct get_info_obj_msg_t {
    uint32_t obj_index;
};

struct get_info_obj_rsp_t {
    uint32_t pos;
    uint32_t len;
};
/* =========================================== */
struct close_obj_msg_t {
    uint32_t obj_index;
};

struct close_obj_rsp_t {
    uint32_t dummy;
};
/* =========================================== */
struct close_delete_obj_msg_t {
    uint32_t obj_index;
};

struct close_delete_obj_rsp_t {
    uint32_t dummy;
};
/* =========================================== */
/* #keyserivce start */
#define SIZE_MAX_EXINFO 64
struct derive_plat_key_msg_t {
    uint32_t key_type;                /* in */
    uint32_t key_size; /* in */         /* bytes */
    uint8_t exinfo[SIZE_MAX_EXINFO]; /* in */
    uint32_t exinfo_size; /* in */     /* bytes */
    uint32_t csc_type;               /* in */
    TEE_UUID csc_uuid;               /* in */
    uint32_t attri_buff_size; /* in */   /* bytes */
    uint64_t attri_buff; /* out */      /* pointer */
};

struct fs_buffer_t {
    uint64_t buffer; /* pointer */
    uint32_t len;
    uint32_t flag;
};

struct fs_read_t {
    uint64_t buffer; /* pointer */
    uint32_t count;
    int32_t fd;
};

struct fs_write_t {
    uint64_t buffer; /* pointer */
    uint32_t count;
    int32_t fd;
};

struct fs_seek_t {
    int32_t fd;
    int32_t offset;
    uint32_t whence;
};

struct fs_remove_t {
    uint64_t buffer; /* pointer */
    uint32_t len;
};

struct fs_truncate_t {
    uint64_t buffer; /* pointer */
    uint32_t name_len;
    uint32_t len;
};

struct fs_rename_t {
    uint64_t old_buf; /* pointer */
    uint32_t old_name_len;
    uint64_t new_buf; /* pointer */
    uint32_t new_name_len;
};

struct fs_copy_t {
    uint64_t from_buf; /* pointer */
    uint32_t from_path_len;
    uint64_t to_buf; /* pointer */
    uint32_t to_path_len;
};

struct fs_info_t {
    int32_t fd;
};

struct fs_access_t {
    uint64_t buf; /* pointer */
    uint32_t path_len;
    int mode;
    char all_path;
};

struct delete_obj_t {
    TEE_UUID target_uuid;
};

struct update_manage_info_t {
    TEE_UUID uuid;
    uint32_t manager;
};

/* =========================================== */
/* #keyserivce end */
union ssa_agent_msg {
    struct buffer_t buffer;
    struct reg_ta_info reg;
    struct reg_agent_buf reg_agent;
    struct create_obj_msg_t create_obj;
    struct open_obj_msg_t open_obj;
    struct open_shared_obj_msg_t open_shared_obj;
    struct get_obj_attrs_msg_t get_obj_attrs;
    struct write_obj_msg_t write_obj;
    struct read_obj_msg_t read_obj;
    struct seek_obj_msg_t seek_obj;
    struct truncate_obj_msg_t truncate_obj;
    struct rename_obj_msg_t rename_obj;
    struct sync_obj_msg_t sync_obj;
    struct get_info_obj_msg_t get_info_obj;
    struct close_obj_msg_t close_obj;
    struct close_delete_obj_msg_t close_and_delete_obj;
    /* #keyserivce start */
    struct derive_plat_key_msg_t key_obj;
    /* #keyserivce end */
    /* fsxxx add */
    struct fs_buffer_t fs_buffer;
    int32_t fd;
    struct fs_read_t fs_read;
    struct fs_write_t fs_write;
    struct fs_seek_t fs_seek;
    struct fs_remove_t fs_remove;
    struct fs_truncate_t fs_truncate;
    struct fs_rename_t fs_rename;
    struct fs_copy_t fs_copy;
    struct fs_info_t fs_info;
    struct fs_access_t fs_access;
    struct delete_obj_t delete_obj;
    struct update_manage_info_t update_manage_info;
    struct huk_srv_msg huk_msg;
    TEE_Result ret;
};

struct fs_create_rsp_t {
    int32_t fd;
};

struct fs_open_rsp_t {
    int32_t fd;
};

struct fs_close_rsp_t {
    int32_t rc;
};

struct fs_read_rsp_t {
    uint32_t count;
    int32_t error;
};

struct fs_write_rsp_t {
    uint32_t count;
};

struct fs_seek_rsp_t {
    int32_t rc;
};

struct fs_remove_rsp_t {
    int32_t rc;
};

struct fs_sync_rsp_t {
    int32_t rc;
};

struct fs_truncate_rsp_t {
    int32_t rc;
};

struct fs_rename_rsp_t {
    int32_t rc;
};

struct fs_copy_rsp_t {
    int32_t rc;
};

struct fs_info_rsp_t {
    int32_t rc;
    uint32_t pos;
    uint32_t len;
};

struct fs_access_rsp_t {
    int32_t rc;
};

struct fs_diskusage_rsp_t {
    int32_t rc;
    uint32_t secure_remain;
    uint32_t data_secure_remain;
};

struct ssa_agent_rsp {
    TEE_Result ret;
    union {
        struct create_obj_rsp_t create_obj;
        struct open_obj_rsp_t open_obj;
        struct open_shared_obj_rsp_t open_shared_obj;
        struct get_obj_attrs_rsp_t get_obj_attrs;
        struct write_obj_rsp_t write_obj;
        struct read_obj_rsp_t read_obj;
        struct seek_obj_rsp_t seek_obj;
        struct truncate_obj_rsp_t truncate_obj;
        struct rename_obj_rsp_t rename_obj;
        struct sync_obj_rsp_t sync_obj;
        struct get_info_obj_rsp_t get_info_obj;
        struct close_obj_rsp_t close_obj;
        struct close_delete_obj_rsp_t close_and_delete_obj;
        /* #keyserivce start */
        struct derive_plat_key_msg_t key_obj;
        /* #keyserivce end */
        struct fs_create_rsp_t fs_create_rsp;
        struct fs_open_rsp_t fs_open_rsp;
        struct fs_close_rsp_t fs_close_rsp;
        struct fs_read_rsp_t fs_read_rsp;
        struct fs_write_rsp_t fs_write_rsp;
        struct fs_seek_rsp_t fs_seek_rsp;
        struct fs_remove_rsp_t fs_remove_rsp;
        struct fs_sync_rsp_t fs_sync_rsp;
        struct fs_truncate_rsp_t fs_truncate_rsp;
        struct fs_rename_rsp_t fs_rename_rsp;
        struct fs_copy_rsp_t fs_copy_rsp;
        struct fs_info_rsp_t fs_info_rsp;
        struct fs_access_rsp_t fs_access_rsp;
        struct fs_diskusage_rsp_t fs_diskusage_rsp;
    };
};

struct object_enum_info {
    uint32_t storage_id;
    uint8_t object_id[HASH_NAME_BUFF_LEN];
    uint32_t object_id_len;
    TEE_ObjectInfo obj_info;
};

#define SS_AGENT_MSG_QUEUE_SIZE 64

struct ss_msg_t {
    uint32_t msg_id;
    uint32_t sender;
    union ssa_agent_msg msg;
};

struct ss_msg_queue_t {
    uint32_t in;
    uint32_t out;
    struct ss_msg_t msg[SS_AGENT_MSG_QUEUE_SIZE];
};

extern struct ss_msg_queue_t g_ssa_msg_queue;

TEE_Result ss_agent_create_object(struct create_obj_msg_t *params, TEE_ObjectHandle *object);

TEE_Result ss_agent_open_object(struct create_obj_msg_t *params, TEE_ObjectHandle *object);

TEE_Result ss_agent_read_object_data(TEE_ObjectHandle object, void *buffer, uint32_t size, uint32_t *count);

TEE_Result ss_agent_write_object_data(TEE_ObjectHandle object, const void *buffer, uint32_t size);

TEE_Result ss_agent_seek_object_data(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence);

TEE_Result ss_agent_rename_object(TEE_ObjectHandle object, const void *new_object_id, uint32_t new_object_id_len);

TEE_Result ss_agent_truncate_object_data(TEE_ObjectHandle object, int32_t size);

TEE_Result ss_agent_get_object_info(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len);

void ss_agent_close_object(TEE_ObjectHandle object);

TEE_Result ss_agent_sync_object(TEE_ObjectHandle object);

TEE_Result ss_agent_close_and_delete_object(TEE_ObjectHandle object);
TEE_Result allocate_enum_handle(TEE_ObjectEnumHandle *obj_enumerator);
void free_enum_handle(TEE_ObjectEnumHandle obj_enumerator);
void reset_enum_handle(TEE_ObjectEnumHandle obj_enumerator);
TEE_Result ta_start_enumerator(TEE_ObjectEnumHandle obj_enumerator);
TEE_Result ta_get_next(TEE_ObjectEnumHandle obj_enumerator, TEE_ObjectInfo *object_info,
                       uint8_t *object_id, size_t *object_id_len);

void ss_agent_proc_cmd(uint32_t snd_cmd, const union ssa_agent_msg *snd_msg, uint32_t ack_cmd,
                       struct ssa_agent_rsp *rsp_msg);
TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len);
TEE_Result ssagent_delete_all(TEE_UUID target);
uint32_t get_object_key_size(TEE_ObjectHandle attributes);
uint32_t get_attr_buf_size(TEE_ObjectHandle object);
TEE_Result copy_attribute(uint8_t **p, const TEE_Attribute *attr);
TEE_Result restore_attrs(TEE_ObjectHandle object, const uint8_t *buff, uint32_t buff_size,
    uint32_t attr_size, uint32_t attr_count);
#endif /* TEE_SS_AGENT_API_H_ */

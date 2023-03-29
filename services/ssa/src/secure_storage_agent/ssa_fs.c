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
#include "ssa_fs.h"
#include <string.h>
#include <tee_init.h>
#include <tee_trusted_storage_api.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <tee_crypto_api.h>
#include <securec.h>
#ifdef CRYPTO_USE_SW_ENGINE
#include <crypto_wrapper.h>
#endif
#include <tee_ss_agent_api.h>
#include "agent.h"
#include "sfs_internal.h"
#include "ssa_fs_error.h"

enum fs_cmd_t {
    SEC_OPEN,
    SEC_CLOSE,
    SEC_READ,
    SEC_WRITE,
    SEC_SEEK,
    SEC_REMOVE,
    SEC_TRUNCATE,
    SEC_RENAME,
    SEC_CREATE,
    SEC_INFO,
    SEC_ACCESS,
    SEC_ACCESS2, /* opt in all path */
    SEC_FSYNC,
    SEC_COPY,
    SEC_DISKUSAGE,
    SEC_DELETE_ALL,
};

enum {
    SEC_WRITE_SLOG,
    SEC_WRITE_SSA,
};

#ifndef FILE_NAME_MAX_BUF
#define FILE_NAME_MAX_BUF 256
#endif

#define DOUBLE_FILE_NAME_MAX_BUF (256 * 2)
#define MAX_MODE_LEN 4
struct sec_storage_t {
    enum fs_cmd_t cmd; /* for s to n */
    int32_t ret;  /* fxxx call's return */
    int32_t ret2; /* just for fread, judge end-of-file or error */
    uint32_t userid;
    uint32_t storageid;
    uint32_t magic;
    uint32_t errnum;
    union __args {
        struct {
            char mode[MAX_MODE_LEN];
            uint32_t name_len;
            uint32_t name[1];
        } open;
        struct {
            int32_t fd;
        } close;
        struct {
            int32_t fd;
            uint32_t count;
            uint32_t buffer[1];
        } read;
        struct {
            int32_t fd;
            uint32_t count;
            uint32_t buffer[1];
        } write;
        struct {
            int32_t fd;
            int32_t offset;
            uint32_t whence;
        } seek;
        struct {
            uint32_t name_len;
            uint32_t name[1];
        } remove;
        struct {
            uint32_t len;
            uint32_t name_len;
            uint32_t name[1];
        } truncate;
        struct {
            uint32_t old_name_len;
            uint32_t new_name_len;
            uint32_t buffer[1]; /* old_name + new_name */
        } rename;
        struct {
            uint32_t from_path_len;
            uint32_t to_path_len;
            uint32_t buffer[1]; /* from_path + to_path */
        } cp;
        struct {
            char mode[MAX_MODE_LEN];
            uint32_t name_len;
            uint32_t name[1];
        } create;
        struct {
            int32_t fd;
            uint32_t cur_pos;
            uint32_t file_len;
        } info;
        struct {
            int mode;
            uint32_t name_len;
            uint32_t name[1];
        } access;
        struct {
            int32_t fd;
        } fsync;
        struct {
            uint32_t sec_storage;
            uint32_t data;
        } diskusage;
        struct {
            uint32_t path_len;
            uint32_t path[1];
        } deleteall;
    } args;
};

/* sec storage share buffer control struct,  agent trans buffer */
static struct sec_storage_t *g_fs_agent_buffer = NULL;

TEE_Result check_file_name(const char *name)
{
    if (name == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * If TA or storage task pass sec_storage/../data/xxx, this will write to data dir.
     * file name must not have ".." str, to against sec_storage/../data attack
     */
    if (strstr(name, FILE_NAME_INVALID_STR)) {
        tloge("Invalid file name(file name contain ..) :%s\n", name);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (strlen(name) > (HASH_NAME_BUFF_LEN - 1)) {
        tloge("Invalid file name name is too long :%s\n", name);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_name_by_storageid_for_ce(const char *obj_id, char *pos)
{
    if (pos == NULL) {
        tloge("invalid paramerers");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *ptr = NULL;

    if (strstr(pos, FILE_DIR_FLAG) == NULL) {
        tloge("For CE storage, the file name must meet the rule 'userid/xxx'");
        return TEE_ERROR_STORAGE_PATH_WRONG;
    }

    if (strncmp(pos, USERID0_DIR_FLAG, strlen(USERID0_DIR_FLAG)) != 0 || strlen(pos) <= strlen(USERID0_DIR_FLAG)) {
        (void)strtok_r(pos, FILE_DIR_FLAG, &ptr);
        if (strlen(ptr) == 0 || !(atoi(pos) >= MULTI_USERID)) {
            tloge("The file name does not match the CE storage ID, obj_id:%s", obj_id);
            return TEE_ERROR_STORAGE_PATH_WRONG;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result check_name_by_storageid(const char *obj_id, uint32_t obj_len, uint32_t storage_id)
{
    char temp[FILE_NAME_MAX_BUF] = { '\0' };
    char *pos                    = temp;
    int rc;

    if (obj_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    rc = memcpy_s(pos, FILE_NAME_MAX_BUF, obj_id, obj_len);
    if (rc != EOK) {
        tloge("copy failed");
        return TEE_ERROR_SECURITY;
    }

    if (strncmp(pos, FILE_DIR_FLAG, strlen(FILE_DIR_FLAG)) == 0)
        pos += strlen(FILE_DIR_FLAG);
    else if (strncmp(pos, CUR_FILE_DIR_FLAG, strlen(CUR_FILE_DIR_FLAG)) == 0)
        pos += strlen(CUR_FILE_DIR_FLAG);

    if (storage_id == TEE_OBJECT_STORAGE_PRIVATE) {
        if (pos == strstr(pos, SFS_PERSO) || pos == strstr(pos, SFS_PRIVATE) ||
            pos == strstr(pos, SFS_PARTITION_TRANSIENT_PERSO) || pos == strstr(pos, SFS_PARTITION_TRANSIENT_PRIVATE)) {
            tloge("The file name does not match the storage ID, obj_id:%s", pos);
            return TEE_ERROR_STORAGE_PATH_WRONG;
        }
    } else if (storage_id == TEE_OBJECT_STORAGE_CE) {
        return check_name_by_storageid_for_ce(obj_id, pos);
    }
    return TEE_SUCCESS;
}

TEE_Result tee_fs_init(void *control)
{
    if (control == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    g_fs_agent_buffer = control;
    if (g_fs_agent_buffer)
        g_fs_agent_buffer->magic = TEE_FS_AGENT_ID;

    return TEE_SUCCESS;
}

void tee_fs_exit(void)
{
    g_fs_agent_buffer = NULL;
}

static TEE_Result fs_ns_error_lookup(uint32_t ns_errno)
{
    uint32_t i;
    for (i = 0; g_fs_error_strings[i].msg != NULL; ++i) {
        if (g_fs_error_strings[i].ns_errno == ns_errno)
            return g_fs_error_strings[i].s_errno;
    }
    return TEE_ERROR_GENERIC;
}

static TEE_Result g_fs_errno = TEE_SUCCESS;
void fs_set_serr(uint32_t ns_errno)
{
    g_fs_errno = fs_ns_error_lookup(ns_errno);
}

TEE_Result fs_get_serr(void)
{
    return g_fs_errno;
}

uint32_t get_fs_meta_size()
{
    return (sizeof(struct sec_storage_t));
}

static bool is_agent_alive(void)
{
    return (g_fs_agent_buffer != NULL) ? true : false;
}

static int32_t encode_open_mode(uint32_t flag, char *mode)
{
    uint32_t use_flag = flag & (uint32_t)(TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ);

    if (mode == NULL)
        return -1;

    switch (use_flag) {
    case TEE_DATA_FLAG_ACCESS_WRITE:
        mode[0] = 'r';
        mode[1] = '+';
        mode[2] = '\0';
        break;
    case TEE_DATA_FLAG_ACCESS_READ:
        mode[0] = 'r';
        mode[1] = '\0';
        break;
    case (TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ):
        mode[0] = 'r';
        mode[1] = '+';
        mode[2] = '\0';
        break;
    default:
        tloge("deny read/write access, flag = 0x%x, use_flag = 0x%x\n", flag, use_flag);
        return -1;
    }
    return 0;
}

#define TEE_EXT_GET_REE_USERID   get_ree_user_id()

int32_t get_fs_agent_lock()
{
    if (!is_agent_alive()) {
        tloge("sec storage is dead\n");
        return -1;
    }

    ssa_obtain_agent_work_lock(TEE_FS_AGENT_ID);
    return 0;
}

int32_t ssa_fs_fopen(const char *name, uint32_t flag, uint32_t storage_id)
{
    char mode[MAX_MODE_LEN] = { 0 };
    uint32_t name_len;
    int32_t fd = -1;
    uint32_t ret_errno = EINVAL;

    if (name == NULL)
        goto return_fd;

    if (encode_open_mode(flag, mode)) {
        tloge("encode open mode error!\n");
        goto return_fd;
    }
    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_fd;
    }

    /* encode args */
    g_fs_agent_buffer->userid = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid = storage_id;
    if (memmove_s(g_fs_agent_buffer->args.open.mode, sizeof(g_fs_agent_buffer->args.open.mode),
        mode, sizeof(mode)) != EOK)
        goto return_unlock;

    name_len = (uint32_t)strlen(name) + 1;
    g_fs_agent_buffer->args.open.name_len = name_len;
    if (memmove_s(g_fs_agent_buffer->args.open.name, FILE_NAME_MAX_BUF, (char *)name, name_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;
    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_OPEN, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }
    /* -1:opt failed, >0:file handler */
    fd = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_fd:
    fs_set_serr(ret_errno);
    return fd;
}

int32_t ssa_fs_fclose(int32_t fd)
{
    int32_t ret = -1;
    uint32_t ret_errno = ESTORAGEDEAD;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto retrun_errno;

    /* encode args */
    g_fs_agent_buffer->args.close.fd = fd;
    tlogd("close file: fd = %d\n", fd);
    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_CLOSE, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        goto return_unlock;
    }
    /* get return val */
    ret       = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
retrun_errno:
    fs_set_serr(ret_errno);
    return ret;
}

static int32_t ssa_fs_fread_params_check(int32_t *error, const void *out_buf, uint32_t count)
{
    if (error == NULL) {
        fs_set_serr(EINVAL);
        return -1;
    }

    if (out_buf == NULL) {
        *error = -1;
        fs_set_serr(EINVAL);
        return -1;
    }

    if (count == 0) {
        *error = 0;
        return -1;
    }

    return 0;
}

/*
 * Notice: total buffer is TRANS_BUFF_SIZE - sizeof(struct sec_storage_t),
 *         if read content is more than it, it need to read for N times.
 */
uint32_t ssa_fs_fread(void *out_buf, uint32_t count, int32_t fd, int32_t *error)
{
    uint32_t ret_errno = ESTORAGEDEAD;
    uint32_t rev_count;
    uint32_t agent_buff_len;
    char *agent_buff = NULL;

    if (ssa_fs_fread_params_check(error, out_buf, count) != 0)
        return 0;

    *error = -1;

    /* exclude sizeof(struct sec_storage_t) */
    uint32_t count_per_time = TRANS_BUFF_SIZE - sizeof(struct sec_storage_t);
    uint32_t left_count     = count;
    char *dst_addr          = (char *)out_buf;
    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto return_errno;

    do {
        g_fs_agent_buffer->args.read.fd = fd;

        rev_count = left_count > count_per_time ? count_per_time : left_count;

        /* encode args */
        g_fs_agent_buffer->args.read.count = rev_count;
        g_fs_agent_buffer->magic = 0;
        /* call ns agent */
        ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_READ, (uint32_t *)(&g_fs_agent_buffer->cmd));
        if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
            tloge("teecd was killed, just return Error\n");
            goto return_unlock;
        }
        /* process return value */
        agent_buff_len = (uint32_t)g_fs_agent_buffer->ret;
        agent_buff     = (char *)g_fs_agent_buffer->args.read.buffer;
        ret_errno      = g_fs_agent_buffer->errnum;

        if (agent_buff_len > rev_count) {
            tloge("the number of items unexpectedly, expected=%u, actual=%u\n", rev_count, agent_buff_len);
            goto return_unlock;
        }

        left_count -= agent_buff_len;
        if (memmove_s(dst_addr, (count - ((uint8_t *)dst_addr - (uint8_t *)out_buf)), agent_buff, agent_buff_len) !=
            EOK)
            goto return_unlock;

        dst_addr += agent_buff_len;

        if ((uint32_t)agent_buff_len < rev_count) {
            if (g_fs_agent_buffer->ret2 == -1)
                tloge("fread failed : total count = %u, leftcount = %u ns errnum=%u\n", count, left_count, ret_errno);
            /* When ret2 is not -1, the end of the file is read */
            break;
        }
    } while (left_count != 0);

    /* judge if end of file or error occurs when left count > 0  */
    *error = g_fs_agent_buffer->ret2;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return count - left_count;
}

/*
 * Notice: total buffer is TRANS_BUFF_SIZE - sizeof(struct sec_storage_t),
 *         if write content is more than it, it need to write for N times.
 */
uint32_t ssa_fs_fwrite(const void *content, uint32_t count, int32_t fd)
{
    uint32_t ret_errno = EINVAL;
    uint32_t send_count;
    uint32_t agent_buff_len;
    char *src_addr = NULL;
    uint32_t count_per_time = TRANS_BUFF_SIZE - sizeof(struct sec_storage_t); /* exclude sizeof(struct sec_storage_t) */
    uint32_t left_count = count;

    if (content == NULL || count == 0)
        goto return_errno;

    src_addr = (char *)content;
    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    do {
        g_fs_agent_buffer->args.write.fd = fd;

        send_count = left_count > count_per_time ? count_per_time : left_count;

        /* encode args */
        g_fs_agent_buffer->args.write.count = send_count;

        if (memmove_s(g_fs_agent_buffer->args.write.buffer, count_per_time, src_addr, send_count) != EOK)
            break;

        tlogd("write count=%u\n", g_fs_agent_buffer->args.write.count);
        g_fs_agent_buffer->magic = 0;
        g_fs_agent_buffer->ret2  = SEC_WRITE_SSA;

        /* call ns agent */
        ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_WRITE, (uint32_t *)(&g_fs_agent_buffer->cmd));
        if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
            tloge("teecd was killed, just return Error\n");
            ret_errno = ESTORAGEDEAD;
            break;
        }

        agent_buff_len = (uint32_t)g_fs_agent_buffer->ret;
        ret_errno      = g_fs_agent_buffer->errnum;

        /* process return value */
        if (agent_buff_len > send_count) {
            tloge("the number of items unexpectedly, expected=%u, actual=%u\n", send_count, agent_buff_len);
            break;
        }
        left_count -= agent_buff_len;
        src_addr += agent_buff_len;
        if (agent_buff_len < send_count) {
            tloge("fwrite failed : total count = %u, leftcount = %u\n", count, left_count);
            tloge("ns errnum=%u\n", ret_errno);
            break;
        }
    } while (left_count != 0);

    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return count - left_count;
}

int32_t ssa_fs_fseek(int32_t fd, int32_t offset, uint32_t whence)
{
    int32_t ret = -1;
    uint32_t ret_errno = ESTORAGEDEAD;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto return_errno;

    /* encode args */
    g_fs_agent_buffer->args.seek.fd     = fd;
    g_fs_agent_buffer->args.seek.offset = offset;
    g_fs_agent_buffer->args.seek.whence = whence;
    g_fs_agent_buffer->magic            = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_SEEK, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_fremove(const char *name, uint32_t storage_id)
{
    uint32_t ret_errno = EINVAL;
    int32_t ret = -1;
    uint32_t name_len;

    if (name == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    /* encode args */
    name_len = (uint32_t)strlen(name) + 1;
    g_fs_agent_buffer->userid = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid = storage_id;
    g_fs_agent_buffer->args.remove.name_len = name_len;
    if (memmove_s(g_fs_agent_buffer->args.remove.name, FILE_NAME_MAX_BUF, (char *)name, name_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_REMOVE, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_fsync(int32_t fd)
{
    int32_t ret = -1;
    uint32_t ret_errno = ESTORAGEDEAD;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto return_errno;

    /* encode args */
    g_fs_agent_buffer->args.fsync.fd = fd;
    tlogd("fsync file: fd = %d\n", fd);
    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_FSYNC, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        goto return_unlock;
    }
    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_ftruncate(const char *name, uint32_t len, uint32_t storage_id)
{
    uint32_t name_len;
    int32_t ret = -1;
    uint32_t ret_errno = EINVAL;

    if (name == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    /* encode args */
    g_fs_agent_buffer->magic = 0;
    g_fs_agent_buffer->userid = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid = storage_id;
    g_fs_agent_buffer->args.truncate.len = len;
    name_len = (uint32_t)strlen(name) + 1;
    g_fs_agent_buffer->args.truncate.name_len = name_len;
    if (memmove_s(g_fs_agent_buffer->args.truncate.name, FILE_NAME_MAX_BUF, (char *)name, name_len) != EOK)
        goto return_unlock;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_TRUNCATE, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_frename(const char *old_name, const char *new_name, uint32_t storage_id)
{
    uint32_t old_name_len, new_name_len;
    int32_t ret = -1;
    uint32_t ret_errno = EINVAL;

    if (old_name == NULL || new_name == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    old_name_len = (uint32_t)strlen(old_name) + 1;
    new_name_len = (uint32_t)strlen(new_name) + 1;

    /* encode args */
    g_fs_agent_buffer->userid                   = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid                = storage_id;
    g_fs_agent_buffer->args.rename.old_name_len = old_name_len;
    g_fs_agent_buffer->args.rename.new_name_len = new_name_len;

    if (memmove_s((char *)g_fs_agent_buffer->args.rename.buffer,
        DOUBLE_FILE_NAME_MAX_BUF, (char *)old_name, old_name_len) != EOK)
        goto return_unlock;

    if (memmove_s((char *)(g_fs_agent_buffer->args.rename.buffer) + old_name_len,
        (DOUBLE_FILE_NAME_MAX_BUF - old_name_len), (char *)new_name, new_name_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_RENAME, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_fcopy(const char *from_path, const char *to_path, uint32_t storage_id)
{
    uint32_t from_path_len, to_path_len;
    int32_t ret = -1;
    uint32_t ret_errno = EINVAL;

    if (from_path == NULL || to_path == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    from_path_len = (uint32_t)strlen(from_path) + 1;
    to_path_len   = (uint32_t)strlen(to_path) + 1;

    /* encode args */
    g_fs_agent_buffer->userid                = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid             = storage_id;
    g_fs_agent_buffer->args.cp.from_path_len = from_path_len;
    g_fs_agent_buffer->args.cp.to_path_len   = to_path_len;
    if (memmove_s((char *)g_fs_agent_buffer->args.cp.buffer, DOUBLE_FILE_NAME_MAX_BUF,
        (char *)from_path, from_path_len) != EOK)
        goto return_unlock;

    if (memmove_s((char *)(g_fs_agent_buffer->args.cp.buffer) + from_path_len, DOUBLE_FILE_NAME_MAX_BUF - from_path_len,
        (char *)to_path, to_path_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_COPY, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_fcreate(const char *name, uint32_t flag, uint32_t storage_id)
{
    uint32_t name_len;
    char mode[MAX_MODE_LEN] = { 0 };
    uint32_t ret_errno = EINVAL;
    int32_t fd = -1;

    if (name == NULL)
        goto return_errno;

    if (encode_open_mode(flag, mode))
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    name_len = (uint32_t)strlen(name) + 1;

    /* encode args */
    g_fs_agent_buffer->userid = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid = storage_id;
    if (memmove_s(g_fs_agent_buffer->args.create.mode, sizeof(g_fs_agent_buffer->args.create.mode),
        mode, sizeof(mode)) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->args.create.name_len = name_len;
    if (memmove_s((char *)(g_fs_agent_buffer->args.create.name), FILE_NAME_MAX_BUF,
        (char *)name, name_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_CREATE, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }
    /* -1:opt failed, >0:file handler */
    fd = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return fd;
}

int32_t ssa_fs_finfo(int32_t fd, uint32_t *pos, uint32_t *len)
{
    int32_t ret = -1;
    uint32_t ret_errno = ESTORAGEDEAD;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto return_errno;

    /* encode args */
    g_fs_agent_buffer->args.info.fd = fd;
    g_fs_agent_buffer->magic        = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_INFO, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        goto return_unlock;
    }

    /* process return value */
    if (pos != NULL)
        *pos = g_fs_agent_buffer->args.info.cur_pos;
    if (len != NULL)
        *len = g_fs_agent_buffer->args.info.file_len;
    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

static int32_t _ssa_fs_faccess(const char *path, int mode, char all_path, uint32_t storage_id)
{
    uint32_t name_len;
    int32_t ret = -1;
    uint32_t ret_errno = EINVAL;
    uint32_t sec_cmd;

    if (path == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        ret_errno = ESTORAGEDEAD;
        goto return_errno;
    }

    name_len = (uint32_t)strlen(path) + 1;

    /* encode args */
    g_fs_agent_buffer->userid               = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid            = storage_id;
    g_fs_agent_buffer->args.access.mode     = mode;
    g_fs_agent_buffer->args.access.name_len = name_len;
    if (memmove_s(g_fs_agent_buffer->args.access.name, FILE_NAME_MAX_BUF, (char *)path, name_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;
    /* call ns agent */
    if (all_path == 0) {
        sec_cmd = SEC_ACCESS;
    } else {
        sec_cmd = SEC_ACCESS2;
    }
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, sec_cmd, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        ret_errno = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

/*
 * difference between faccess and faccess2: faccess2 can detect all path file,
 * but faccess can just detect secure storage dir.
 */
int32_t ssa_fs_faccess(const char *name, int mode, uint32_t storage_id)
{
    return _ssa_fs_faccess(name, mode, 0, storage_id);
}

int32_t ssa_fs_faccess2(const char *name, int mode)
{
    return _ssa_fs_faccess(name, mode, 1, TEE_OBJECT_STORAGE_PRIVATE);
}

int32_t ssa_fs_disk_usage(uint32_t *secure_remain, uint32_t *data_secure_remain)
{
    int32_t ret = -1;
    uint32_t ret_errno = ESTORAGEDEAD;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0)
        goto return_errno;

    /* encode args */
    g_fs_agent_buffer->userid = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->magic  = 0;
    g_fs_agent_buffer->storageid = TEE_OBJECT_STORAGE_PRIVATE;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_DISKUSAGE, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        goto return_unlock;
    }

    ret = g_fs_agent_buffer->ret;
    ret_errno = g_fs_agent_buffer->errnum;

    /* process return value */
    if (secure_remain != NULL)
        *secure_remain = g_fs_agent_buffer->args.diskusage.sec_storage;
    if (data_secure_remain != NULL)
        *data_secure_remain = g_fs_agent_buffer->args.diskusage.data;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(ret_errno);
    return ret;
}

int32_t ssa_fs_delete_all(const char *path, uint32_t path_len)
{
    int32_t ret = -1;
    uint32_t err_no = EINVAL;

    if (path == NULL)
        goto return_errno;

    /* obtaion tee fs's work lock */
    if (get_fs_agent_lock() != 0) {
        err_no = ESTORAGEDEAD;
        goto return_errno;
    }

    /* encode args */
    g_fs_agent_buffer->userid                  = TEE_EXT_GET_REE_USERID;
    g_fs_agent_buffer->storageid               = TEE_OBJECT_STORAGE_PRIVATE;
    g_fs_agent_buffer->args.deleteall.path_len = path_len;
    if (memmove_s(g_fs_agent_buffer->args.deleteall.path, FILE_NAME_MAX_BUF, path, path_len) != EOK)
        goto return_unlock;

    g_fs_agent_buffer->magic = 0;

    /* call ns agent */
    ssa_send_agent_cmd(TEE_FS_AGENT_ID, SEC_DELETE_ALL, (uint32_t *)(&g_fs_agent_buffer->cmd));
    if (g_fs_agent_buffer->magic != TEE_FS_AGENT_ID) {
        tloge("teecd was killed, just return Error\n");
        err_no = ESTORAGEDEAD;
        goto return_unlock;
    }

    ret    = g_fs_agent_buffer->ret;
    err_no = g_fs_agent_buffer->errnum;

return_unlock:
    ssa_agent_work_unlock(TEE_FS_AGENT_ID);
return_errno:
    fs_set_serr(err_no);
    return ret;
}

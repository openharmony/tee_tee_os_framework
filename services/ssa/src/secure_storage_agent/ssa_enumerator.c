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
#include "ssa_enumerator.h"
#include "string.h"
#include "securec.h"
#include "tee_defines.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "sfs_internal.h"
#include "sfs.h"
#include "ssa_helper.h"
#include "ssa_fs.h"

#define MIN_TWO_DIGIT 10
static char hex2asc(char n)
{
    if (n >= MIN_TWO_DIGIT)
        return 'a' + (n - MIN_TWO_DIGIT);
    else
        return '0' + n;
}

#define BYTE_LEN              8U
#define HALF_BYTE_OFFSET      4U
#define EVEN_NUM_CHECKER      2
#define LOW_BIT_MASK          0x0f
#define TIME_LOW_OFFSET_MAX   24U
#define TIME_MID_OFFSET_MAX   8U
#define TIME_HI_OFFSET_MAX    8U
#define POS_ARRAY_LEN         5
#define HALF_OF(x)            ((x) / 2)
static TEE_Result convert_uuid_to_str(const TEE_UUID *uuid, char *buff, int buffsize)
{
    const uint8_t add_pos_array[POS_ARRAY_LEN] = { 8, 12, 16, 20, 64 }; /* add_pos_array[4]=64 is not used */
    uint32_t i;
    uint8_t add_pos = 0;
    unsigned char uuid_buff[sizeof(TEE_UUID)];

    if (uuid == NULL || buff == NULL)
        return TEE_ERROR_GENERIC;

    if (buffsize < UUID_STR_LEN) {
        tloge("buffer size is not big enough for uuid string.\n");
        return TEE_ERROR_GENERIC;
    }

    char *buff_pos  = buff;
    uint32_t offset = 0;
    for (i = 0; i < sizeof(uint32_t); i++)
        uuid_buff[i] = uuid->timeLow >> (TIME_LOW_OFFSET_MAX - i * BYTE_LEN);

    offset += sizeof(uint32_t);
    for (i = 0; i < sizeof(uint16_t); i++)
        uuid_buff[offset + i] = uuid->timeMid >> (TIME_MID_OFFSET_MAX - i * BYTE_LEN);

    offset += sizeof(uint16_t);
    for (i = 0; i < sizeof(uint16_t); i++)
        uuid_buff[offset + i] = uuid->timeHiAndVersion >> (TIME_HI_OFFSET_MAX - i * BYTE_LEN);

    offset += sizeof(uint16_t);
    for (i = 0; i < sizeof(uuid->clockSeqAndNode); i++)
        uuid_buff[offset + i] = uuid->clockSeqAndNode[i];

    for (i = 0; i < sizeof(TEE_UUID); i++) {
        if (i == add_pos_array[add_pos]) {
            *buff_pos = '-';
            buff_pos++;
            add_pos++;
        }

        if (i % EVEN_NUM_CHECKER != 0)
            *buff_pos = hex2asc((*(uuid_buff + HALF_OF(i))) & LOW_BIT_MASK);
        else
            *buff_pos = hex2asc((*(uuid_buff + HALF_OF(i))) >> HALF_BYTE_OFFSET);

        buff_pos++;
    }

    return TEE_SUCCESS;
}

static TEE_Result gen_enum_file_name(const char *partition, const TEE_UUID *uuid,
                                     char *name_buf, uint32_t name_buf_len)
{
    errno_t ret_s;
    TEE_Result ret;
    uint32_t offset = 0;

    if (strstr(partition, SFS_PARTITION_TRANSIENT) == partition) {
        ret_s = memcpy_s(name_buf, name_buf_len, SFS_PARTITION_TRANSIENT, strlen(SFS_PARTITION_TRANSIENT));
        if (ret_s != EOK) {
            tloge("memcpy ENUM_FILE_NAME_PREFIX into name buffer failed.\n");
            return TEE_ERROR_SECURITY;
        }
        offset += strlen(SFS_PARTITION_TRANSIENT);
    }

    ret_s = memcpy_s(name_buf + offset, name_buf_len - offset, ENUM_FILE_NAME_PREFIX, strlen(ENUM_FILE_NAME_PREFIX));
    if (ret_s != EOK) {
        tloge("memcpy ENUM_FILE_NAME_PREFIX into name buffer failed.\n");
        return TEE_ERROR_SECURITY;
    }

    offset += strlen(ENUM_FILE_NAME_PREFIX);

    ret = convert_uuid_to_str(uuid, name_buf + offset, name_buf_len - offset);
    if (ret != TEE_SUCCESS) {
        tloge("failed to convert uuid to str.\n");
        return ret;
    }

    name_buf[name_buf_len - 1] = '\0';

    return TEE_SUCCESS;
}

static TEE_Result internal_open_enum_file(const char *partition, uint32_t sndr, struct sfd_t **sfd)
{
    TEE_Result ret;
    char enum_file_name[ENUM_FILE_NAME_LEN] = { 0 };

    TEE_UUID *uuid = get_sender_uuid(sndr);
    if (uuid == NULL) {
        tloge("get uuid fail");
        return TEE_ERROR_GENERIC;
    }

    ret = gen_enum_file_name(partition, uuid, enum_file_name, sizeof(enum_file_name));
    if (ret != TEE_SUCCESS) {
        tloge("failed to generate the enum file name.\n");
        return ret;
    }

    ret = ssa_internal_fopen(enum_file_name, uuid, sfd);
    if (ret != TEE_SUCCESS) {
        tloge("open enum file failed ret=0x%x\n", ret);
        return ret;
    }

    if ((*sfd)->size % sizeof(struct object_enum_info) != 0) {
        tloge("file size error, file size:%u", (*sfd)->size);
        ssa_internal_fclose(*sfd);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_enum_file_size(const char *partition, uint32_t sndr, uint32_t *file_size)
{
    struct sfd_t *sfd = NULL;
    TEE_Result ret;

    ret = internal_open_enum_file(partition, sndr, &sfd);
    if (ret == TEE_SUCCESS) {
        *file_size = sfd->size;
        ssa_internal_fclose(sfd);
        return TEE_SUCCESS;
    } else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
        *file_size = 0;
        return TEE_SUCCESS;
    } else {
        return ret;
    }
}

void ssa_get_enum_file_size(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;
    uint32_t transient_file_size = 0;
    uint32_t persist_file_size   = 0;

    if (rsp == NULL) {
        tloge("get enum file size invalid rsp\n");
        return;
    }

    if (msg == NULL) {
        tloge("get enum file size invalid msg\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    ret = get_enum_file_size(SFS_PARTITION_TRANSIENT, sndr, &transient_file_size);
    if (ret != TEE_SUCCESS) {
        tloge("get transient enum_file size fail, ret=%x ", ret);
        rsp->ret = ret;
        return;
    }

    ret = get_enum_file_size(SFS_PARTITION_PERSISTENT, sndr, &persist_file_size);
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        tloge("get persiset enum_file size fail, ret=%x ", ret);
        return;
    }

    rsp->get_info_obj.len = transient_file_size + persist_file_size;
    rsp->ret              = ret;
}

static uint32_t start_enumerator(const char *partition, uint32_t sndr, uint8_t *buff, uint32_t buff_len,
                                 TEE_Result *ret)
{
    struct sfd_t *sfd = NULL;
    uint32_t count;

    *ret = internal_open_enum_file(partition, sndr, &sfd);
    if (*ret == TEE_ERROR_ITEM_NOT_FOUND) {
        *ret = TEE_SUCCESS;
        return 0;
    } else if (*ret != TEE_SUCCESS) {
        return 0;
    }

    count = ssa_read(buff, buff_len, sfd, ret);
    if (*ret != TEE_SUCCESS)
        tloge("read enumerator file fail %x\n", *ret);

    ssa_internal_fclose(sfd);
    return count;
}

void ssa_start_enumerator(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;
    mem_map_info_t read_buf_info;
    uint32_t count;

    if (rsp == NULL) {
        tloge("start enumerator invalid rsp\n");
        return;
    }

    if (msg == NULL || msg->read_obj.buffer == 0) {
        tloge("start enumerator invalid msg\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    read_buf_info.vm_addr = 0;
    read_buf_info.size    = msg->read_obj.len;
    read_buf_info.mapped  = false;
    if (ssa_map_from_task(sndr, msg->read_obj.buffer, msg->read_obj.len, g_ssagent_handle,
                          &read_buf_info.vm_addr)) {
        tloge("map buffer from %u fail\n", sndr);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }
    read_buf_info.mapped = true;

    count = start_enumerator(SFS_PARTITION_TRANSIENT, sndr, (uint8_t *)read_buf_info.vm_addr, msg->read_obj.len, &ret);
    if (ret != TEE_SUCCESS)
        goto clean;

    if (msg->read_obj.len < count) {
        tloge("read obj len is error, msg->readObj.len:%u, count:%u", msg->read_obj.len, count);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    uint32_t count2 = start_enumerator(SFS_PARTITION_PERSISTENT, sndr, (uint8_t *)(read_buf_info.vm_addr + count),
        msg->read_obj.len - count, &ret);
    if (ret != TEE_SUCCESS)
        goto clean;

    if (msg->read_obj.len - count < count2) {
        tloge("read obj len is error, expect len:%u, count:%u", msg->read_obj.len - count, count2);
        ret = TEE_ERROR_GENERIC;
    }

clean:
    ssa_unmap_from_task(g_ssagent_handle, read_buf_info.vm_addr, read_buf_info.size, read_buf_info.mapped);
    rsp->ret = ret;
}

static struct object_enum_info *find_obj(const uint8_t *file_buf, uint32_t file_buf_len, const uint8_t *object_id,
    uint32_t object_id_len)
{
    struct object_enum_info *obj_info     = NULL;
    struct object_enum_info *obj_info_end = NULL;
    int32_t ret;

    obj_info     = (struct object_enum_info *)file_buf;
    obj_info_end = (struct object_enum_info *)(file_buf + file_buf_len);

    while (obj_info < obj_info_end) {
        if (obj_info->object_id_len != object_id_len) {
            obj_info++;
            continue;
        }

        ret = TEE_MemCompare(obj_info->object_id, object_id, object_id_len);
        if (ret == 0)
            return obj_info;

        obj_info++;
    }

    return NULL;
}

static TEE_Result internal_create_enum_file(const char *partition, uint32_t sndr, struct sfd_t **sfd,
                                            uint32_t *oper_flag, uint32_t flags)
{
    meta_data_t *meta = NULL;
    TEE_Result ret;
    char enum_file_name[ENUM_FILE_NAME_LEN] = { 0 };

    tlogd("internal_create_enum_file enter");

    TEE_UUID *uuid = get_sender_uuid(sndr);
    if (uuid == NULL) {
        tloge("get uuid fail");
        return TEE_ERROR_GENERIC;
    }

    ret = gen_enum_file_name(partition, uuid, enum_file_name, sizeof(enum_file_name));
    if (ret != TEE_SUCCESS) {
        tloge("failed to generate the enum file name.\n");
        return ret;
    }

    meta = create_meta_data((uint8_t *)enum_file_name, strlen(enum_file_name), TEE_OBJECT_STORAGE_PRIVATE,
                            flags, uuid, &ret, SFS_ARCH_VERSION_SSA);
    if (meta == NULL) {
        tloge("create_sec_enum_file:meta create fail\n");
        return ret;
    }

    if (meta->encrypted_file_id == NULL)
        goto clean;

    if (ssa_fs_faccess((char *)meta->encrypted_file_id, F_OK, meta->storage_id) == 0) {
        /* secure enumerator file has already been created. */
        tlogd("enumerator file already exists, filename is %s\n", meta->encrypted_file_id);
        *sfd = ssa_open(meta, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &ret);
        if (*sfd != NULL) {
            *oper_flag = ENUM_OPEN;
            return TEE_SUCCESS;
        }

        if (ret != TEE_ERROR_ITEM_NOT_FOUND)
            goto clean;
    }

    /* file not exit, or open file return TEE_ERROR_ITEM_NOT_FOUND, create file */
    *sfd = ssa_create(meta, TEE_DATA_FLAG_ACCESS_WRITE, &ret);
    if (*sfd == NULL) {
        tloge("create fail ret=0x%x\n", ret);
        goto clean;
    }

    *oper_flag = ENUM_CREATE;
    return TEE_SUCCESS;

clean:
    free_meta_data(&meta);
    return ret;
}

static TEE_Result get_obj_enum_info(const struct create_obj_msg_t *create_obj, uint32_t data_size,
                                    struct object_enum_info *obj_enum_info)
{
    struct saved_attr_info_t *attrinfo = NULL;
    errno_t ret_s;

    attrinfo = (struct saved_attr_info_t *)(uintptr_t)create_obj->attributes;

    obj_enum_info->obj_info.objectType = attrinfo->object_info.objectType;
#ifndef GP_SUPPORT
    obj_enum_info->obj_info.objectSize    = attrinfo->object_info.objectSize;
    obj_enum_info->obj_info.maxObjectSize = attrinfo->object_info.maxObjectSize;
#else
    obj_enum_info->obj_info.keySize    = attrinfo->object_info.keySize;
    obj_enum_info->obj_info.maxKeySize = attrinfo->object_info.maxKeySize;
#endif
    obj_enum_info->obj_info.objectUsage  = attrinfo->object_info.objectUsage;
    obj_enum_info->obj_info.dataSize     = data_size;
    obj_enum_info->obj_info.dataPosition = attrinfo->object_info.dataPosition;
    obj_enum_info->obj_info.handleFlags  = attrinfo->object_info.handleFlags;

    ret_s = memcpy_s(obj_enum_info->object_id, HASH_NAME_BUFF_LEN, (uint8_t *)(uintptr_t)create_obj->object_id,
                     create_obj->obj_id_len);
    if (ret_s != EOK) {
        tloge("copy objId failed\n");
        return TEE_ERROR_SECURITY;
    }

    obj_enum_info->object_id_len = create_obj->obj_id_len;
    obj_enum_info->storage_id    = create_obj->storage_id;

    return TEE_SUCCESS;
}

static TEE_Result update_obj_info(const struct create_obj_msg_t *create_obj, uint32_t data_size, uint8_t *file_buf,
                                  uint32_t old_file_len, uint32_t *new_file_len)
{
    struct object_enum_info *origin_obj_enum_info = NULL;
    errno_t ret_s;
    int32_t res;
    struct object_enum_info obj_enum_info = { 0 };

    /* eunmarator file content */
    TEE_Result ret = get_obj_enum_info(create_obj, data_size, &obj_enum_info);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get the memory for obj_enum_info.\n");
        return TEE_ERROR_GENERIC;
    }

    origin_obj_enum_info = find_obj(file_buf, old_file_len, obj_enum_info.object_id, obj_enum_info.object_id_len);
    if (origin_obj_enum_info == NULL) {
        ret_s = memcpy_s(file_buf + old_file_len, *new_file_len - old_file_len, &obj_enum_info,
            sizeof(struct object_enum_info));
        if (ret_s != EOK) {
            tloge("copy enum info failed\n");
            return TEE_ERROR_SECURITY;
        }
    } else {
        *new_file_len = old_file_len;
        res           = TEE_MemCompare(origin_obj_enum_info, &obj_enum_info, sizeof(struct object_enum_info));
        if (res == 0) {
            tlogd("The info of obj_enum_info is not changed\n");
            return TEE_SUCCESS;
        }

        if ((uint64_t)(uintptr_t)origin_obj_enum_info - (uint64_t)(uintptr_t)file_buf > 0xFFFFFFFF)
            return TEE_ERROR_GENERIC;

        uint32_t offset = (uint64_t)(uintptr_t)origin_obj_enum_info - (uint64_t)(uintptr_t)file_buf;
        ret_s = memcpy_s(origin_obj_enum_info, old_file_len - offset, &obj_enum_info, sizeof(struct object_enum_info));
        if (ret_s != EOK) {
            tloge("Failed to copy obj_enum_info\n");
            return TEE_ERROR_SECURITY;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result add_objinfo_into_enum_file(const struct create_obj_msg_t *create_obj, uint32_t data_size, uint32_t sndr)
{
    TEE_Result ret;
    struct sfd_t *sfd = NULL;
    uint8_t *file_buf = NULL;
    uint32_t count;
    uint32_t oper_flag = ENUM_INVALID_OPER;

    if (create_obj == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = internal_create_enum_file((const char *)(uintptr_t)create_obj->object_id, sndr,
                                    &sfd, &oper_flag, create_obj->flags);
    if (ret != TEE_SUCCESS)
        return ret;

    if (sfd->size % sizeof(struct object_enum_info) != 0) {
        tloge("file size error, file size:%u", sfd->size);
        ret = TEE_ERROR_GENERIC;
        goto close_or_delete;
    }

    uint32_t old_file_len = sfd->size;
    uint32_t new_file_len = sfd->size + sizeof(struct object_enum_info);
    file_buf              = TEE_Malloc(new_file_len, 0);
    if (file_buf == NULL) {
        tloge("malloc memory failed size=0x%x\n", new_file_len);
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto close_or_delete;
    }

    count = ssa_read(file_buf, old_file_len, sfd, &ret);
    if (count != old_file_len) {
        tloge("read enum file failed\n");
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    ret = update_obj_info(create_obj, data_size, file_buf, old_file_len, &new_file_len);
    if (ret != TEE_SUCCESS)
        goto clean;

    count = ssa_internal_fwrite(sfd, file_buf, new_file_len);
    if (count != new_file_len) {
        tloge("write enum file failed, count=%u\n", count);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    oper_flag = ENUM_INVALID_OPER;

clean:
    TEE_Free(file_buf);
close_or_delete:
    if (oper_flag == ENUM_CREATE)
        ssa_internal_fremove(sfd);
    else
        ssa_internal_fclose(sfd);
    return ret;
}

TEE_Result update_objinfo_in_enum_file(const uint8_t *object_id, uint32_t object_id_len,
                                       uint32_t new_size, uint32_t new_pos, uint32_t sndr)
{
    struct object_enum_info *obj_enum_info = NULL;
    struct sfd_t *sfd               = NULL;
    TEE_Result ret;
    uint8_t *file_buf = NULL;
    uint32_t file_len;
    uint32_t count;

    if (object_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = internal_open_enum_file((char *)object_id, sndr, &sfd);
    if (ret != TEE_SUCCESS)
        return ret;

    file_len = sfd->size;
    file_buf = TEE_Malloc(file_len, 0);
    if (file_buf == NULL) {
        tloge("malloc memory failed size=0x%x\n", file_len);
        ssa_internal_fclose(sfd);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    count = ssa_read(file_buf, file_len, sfd, &ret);
    if (count != sfd->size) {
        tloge("read enum file failed\n");
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    obj_enum_info = find_obj(file_buf, file_len, object_id, object_id_len);
    if (obj_enum_info == NULL) {
        tloge("Failed to find the obj info about %s\n", object_id);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    obj_enum_info->obj_info.dataSize     = new_size;
    obj_enum_info->obj_info.dataPosition = new_pos;

    count = ssa_internal_fwrite(sfd, file_buf, file_len);
    if (count != file_len) {
        tloge("write enum file failed, count=%u\n", count);
        ret = TEE_ERROR_GENERIC;
    }

clean:
    ssa_internal_fclose(sfd);
    TEE_Free(file_buf);
    return ret;
}

TEE_Result rename_obj_in_enum_file(const uint8_t *origin_obj_id, const uint8_t *new_obj_id, uint32_t new_obj_id_len,
                                   uint32_t sndr)
{
    struct object_enum_info *obj_enum_info = NULL;
    TEE_Result ret;
    struct sfd_t *sfd = NULL;
    uint32_t count;

    if (origin_obj_id == NULL || new_obj_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = internal_open_enum_file((char *)origin_obj_id, sndr, &sfd);
    if (ret != TEE_SUCCESS)
        return ret;

    uint32_t file_len = sfd->size;
    uint8_t *file_buf = TEE_Malloc(file_len, 0);
    if (file_buf == NULL) {
        ssa_internal_fclose(sfd);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    count = ssa_read(file_buf, file_len, sfd, &ret);
    if (count != sfd->size) {
        tloge("read enum file failed\n");
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    uint32_t origin_id_len = strlen((const char *)origin_obj_id);
    obj_enum_info          = find_obj(file_buf, file_len, origin_obj_id, origin_id_len);
    if (obj_enum_info == NULL) {
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    if (memcpy_s(obj_enum_info->object_id, HASH_NAME_BUFF_LEN,
        new_obj_id, new_obj_id_len) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    obj_enum_info->object_id_len = new_obj_id_len;

    count = ssa_internal_fwrite(sfd, file_buf, file_len);
    if (count != sfd->size) {
        tloge("write enum file failed, count=%u\n", count);
        ret = TEE_ERROR_GENERIC;
    }

clean:
    TEE_Free(file_buf);
    ssa_internal_fclose(sfd);
    return ret;
}

static TEE_Result delete_enum_obj(const uint8_t *file_buf, uint32_t file_buf_len, const uint8_t *object_id,
                                  uint32_t object_id_len)
{
    errno_t ret_s;
    struct object_enum_info *obj_enum_info = NULL;
    struct object_enum_info *obj_info_last = NULL;

    obj_enum_info = find_obj(file_buf, file_buf_len, object_id, object_id_len);
    if (obj_enum_info == NULL) {
        tloge("Failed to find the obj info about %s\n", object_id);
        return TEE_ERROR_GENERIC;
    }

    obj_info_last = (struct object_enum_info *)(file_buf + file_buf_len - sizeof(struct object_enum_info));
    if (obj_enum_info != obj_info_last) {
        ret_s = memmove_s(obj_enum_info, sizeof(struct object_enum_info), obj_info_last,
            sizeof(struct object_enum_info));
        if (ret_s != EOK) {
            tloge("Failed to delete objinfo from file buf.\n");
            return TEE_ERROR_SECURITY;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result delete_obj_in_enum_file(const uint8_t *object_id, uint32_t object_id_len, uint32_t sndr)
{
    TEE_Result ret;
    struct sfd_t *sfd = NULL;
    bool del_flag     = false;

    if (object_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = internal_open_enum_file((char *)object_id, sndr, &sfd);
    if (ret != TEE_SUCCESS)
        return ret;

    uint32_t origin_file_len = sfd->size;
    uint8_t *file_buf        = TEE_Malloc(origin_file_len, 0);
    if (file_buf == NULL) {
        tloge("malloc memory failed size=0x%x\n", origin_file_len);
        ssa_internal_fclose(sfd);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint32_t count = ssa_read(file_buf, origin_file_len, sfd, &ret);
    if (count != origin_file_len || ret != TEE_SUCCESS) {
        tloge("read enum file failed\n");
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    ret = delete_enum_obj(file_buf, origin_file_len, object_id, object_id_len);
    if (ret != TEE_SUCCESS) {
        tloge("delete enum obj fail!");
        goto clean;
    }

    uint32_t new_file_len = origin_file_len - sizeof(struct object_enum_info);
    if (new_file_len == 0) {
        del_flag = true;
        goto clean;
    }

    count = ssa_internal_fwrite(sfd, file_buf, new_file_len);
    if (count != new_file_len) {
        tloge("write enum file failed, count=%u\n", count);
        ret = TEE_ERROR_GENERIC;
    }

clean:
    if (del_flag)
        ssa_internal_fremove(sfd);
    else
        ssa_internal_fclose(sfd);
    sfd = NULL;
    TEE_Free(file_buf);
    return ret;
}

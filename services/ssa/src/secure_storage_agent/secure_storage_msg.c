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
#include <string.h>
#include <sys/mman.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_init.h"
#include "tee_ext_api.h"
#include "tee_ss_agent_api.h"
#include "sfs_internal.h"
#include "sfs.h"
#include "securec.h"
#include "permsrv_api.h"
#include "ssa_helper.h"
#include "ssa_enumerator.h"
#include "tee_internal_task_pub.h"

#ifndef CMAC_DERV_MAX_DATA_IN_SIZE
#define CMAC_DERV_MAX_DATA_IN_SIZE    0x400UL
#endif
/* Returns a pointer to open file. Obj is an index of open files of TA. */
file_instance_t *get_file_pointer(uint32_t sender, int32_t obj)
{
    tlogd("objID: %d\n", obj);
    client_t *client = get_sender_client(sender);
    if (client == NULL) {
        tloge("Illegal client\n");
        return NULL;
    }

    if ((obj <= 0) || (obj > MAX_CLIENT_OPEN_FILES)) {
        tloge("Object not found\n");
        return NULL;
    }

    if (client->file_instance[obj - 1].file_link == NULL) {
        tloge("Object not found\n");
        return NULL;
    }
    if (client->file_instance[obj - 1].file_link->sfd == NULL) {
        /* requested file has been deleted, remove this instance */
        tloge("requested file has been deleted");

        if (client->file_instance[obj - 1].file_link->link_count != 0)
            client->file_instance[obj - 1].file_link->link_count--;

        client->file_instance[obj - 1].file_link = NULL;

        tloge("Object not found\n");
        return NULL;
    }

    return (&client->file_instance[obj - 1]);
}

static TEE_Result get_object_attr_header(struct sfd_t *sfd, uint8_t *buff, uint32_t buff_size)
{
    uint32_t count;
    TEE_Result error = TEE_SUCCESS;

    if (sfd == NULL || buff == NULL || sfd->meta_data == NULL || sfd->meta_data->file_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (buff_size < sizeof(struct saved_attr_info_t))
        return TEE_ERROR_SHORT_BUFFER;

    tlogd("arch_version=%u\n", sfd->meta_data->arch_version);
    count = ssa_read(buff, sizeof(struct saved_attr_info_t), sfd, &error);
    if ((count == sizeof(struct saved_attr_info_t)) && (error == TEE_SUCCESS)) {
        sfd->attr_size = sizeof(struct saved_attr_info_t) + ((struct saved_attr_info_t *)buff)->attr_size;
        return TEE_SUCCESS;
    }

    return error;
}

static TEE_Result ssa_read_attr(struct sfd_t *sfd, uint8_t *vm_addr, union ssa_agent_msg *msg,
                                file_instance_t *fpointer, struct ssa_agent_rsp *rsp)
{
    uint32_t count;
    TEE_Result ret;
    TEE_Result error = TEE_SUCCESS;

    if (sfd->meta_data->arch_version == SFS_ARCH_VERSION_SSA) {
        count = ssa_read(vm_addr, msg->get_obj_attrs.size, fpointer->file_link->sfd, &error);
        if ((count == msg->get_obj_attrs.size) && (error == TEE_SUCCESS)) {
            ret = TEE_SUCCESS;
        } else {
            rsp->get_obj_attrs.size = 0;
            ret = error;
            tloge("read error:0x%x\n", error);
        }
    } else {
        tloge("invalid sfs arch version %u\n", sfd->meta_data->arch_version);
        ret = TEE_ERROR_BAD_FORMAT;
    }

    return ret;
}

static bool judge_valid_version(struct sfd_t *sfd)
{
    (void)sfd;
    return true;
}

void ssa_create_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    mem_map_info_t obj_id_info         = { 0 };
    mem_map_info_t attributes_info     = { 0 };
    mem_map_info_t initial_data        = { 0 };
    struct create_obj_msg_t create_obj = { 0 };
    TEE_Result ret;
    char obj_id[HASH_NAME_BUFF_LEN]   = { 0 };

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    ret = create_param_mapping(msg, sndr, &obj_id_info, &attributes_info, &initial_data);
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        goto clean;
    }

    ret = copy_and_check_file_name((char *)obj_id_info.vm_addr, obj_id_info.size, obj_id, sizeof(obj_id));
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        goto clean;
    }

    TEE_UUID *uuid = get_sender_uuid(sndr);
    if (uuid == NULL) {
        tloge("uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    create_obj.attributes      = attributes_info.vm_addr;
    create_obj.attributes_len  = attributes_info.size;
    create_obj.object_id       = (uintptr_t)obj_id;
    create_obj.obj_id_len      = strlen(obj_id);
    create_obj.initial_data    = initial_data.vm_addr;
    create_obj.data_len        = initial_data.size;
    create_obj.storage_id      = msg->create_obj.storage_id;
    create_obj.flags           = msg->create_obj.flags;

    create_object_proc(&create_obj, sndr, uuid, rsp);
    if (rsp->ret != TEE_SUCCESS)
        goto clean;

    if (is_enum_enable(uuid)) {
        if (add_objinfo_into_enum_file(&create_obj, rsp->create_obj.new_size, sndr) != TEE_SUCCESS)
            tloge("add object info into enum file failed\n");
    }
clean:
    create_param_unmapping(&obj_id_info, &attributes_info, &initial_data);
}

void open_object(struct open_obj_msg_t *open_obj, const TEE_UUID *uuid, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    struct sfd_t *sfd = NULL;
    TEE_Result error  = TEE_ERROR_GENERIC;
    uint32_t obj;

    if (rsp == NULL)
        return;

    if (open_obj == NULL || uuid == NULL || open_obj->object_id == 0) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    meta_data_t *meta = create_meta_data((uint8_t *)(uintptr_t)open_obj->object_id, open_obj->obj_id_len,
                                         open_obj->storage_id, open_obj->flags, uuid, &error, SFS_ARCH_VERSION_SSA);
    if (meta == NULL) {
        tloge("meta create fail\n");
        rsp->ret = error;
        return;
    }

    obj = open_file(meta, sndr, open_obj->flags, &sfd, &error);
    if (error == TEE_ERROR_ITEM_NOT_FOUND) {
        /* file nonexist, need not print error log */
        goto out;
    } else if ((error != TEE_SUCCESS) || (obj == 0)) {
        tloge("open fail %x\n", error);
        goto out;
    }

    if ((open_obj->attr_head_size != 0) && (open_obj->attr_head != 0)) {
        error = get_object_attr_header(sfd, (uint8_t *)(uintptr_t)open_obj->attr_head, open_obj->attr_head_size);
        if (error != TEE_SUCCESS) {
            tloge("read attribute head fail, %x\n", error);
            goto closeFile;
        }
    }

    rsp->ret                   = TEE_SUCCESS;
    rsp->open_obj.obj_index    = obj;
    rsp->open_obj.err          = 0;
    rsp->open_obj.new_seek_pos = sfd->seek_position;
    rsp->open_obj.new_size     = sfd->size - sfd->attr_size;
    tlogd("objID %u opened\n", rsp->open_obj.obj_index);
    tlogd("totalSize=%u, attr_size=%u\n", sfd->size, sfd->attr_size);

    return;

closeFile:
    close_file_from_client(sndr, obj);
    return;
out:
    free_meta_data(&meta);
    rsp->ret = error;
}

void ssa_open_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    mem_map_info_t obj_id_info        = { 0 };
    mem_map_info_t attributes_info    = { 0 };
    TEE_UUID *uuid                    = NULL;
    struct open_obj_msg_t open_obj    = { 0 };
    TEE_Result ret;
    char obj_id[HASH_NAME_BUFF_LEN]   = { 0 };

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    uuid = get_sender_uuid(sndr);
    if (uuid == NULL) {
        tloge("uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    ret = open_param_mapping(msg, sndr, &obj_id_info, &attributes_info);
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        goto clean;
    }

    ret = copy_and_check_file_name((char *)obj_id_info.vm_addr, obj_id_info.size, obj_id, sizeof(obj_id));
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        goto clean;
    }

    open_obj.attr_head      = attributes_info.vm_addr;
    open_obj.attr_head_size = attributes_info.size;
    open_obj.storage_id     = msg->open_obj.storage_id;
    open_obj.flags          = msg->open_obj.flags;
    open_obj.object_id      = (uintptr_t)obj_id;
    open_obj.obj_id_len     = strlen(obj_id);
    open_object(&open_obj, uuid, sndr, rsp);

clean:
    open_param_unmapping(&obj_id_info, &attributes_info);
}

static TEE_Result ssa_get_objects_attrinfo(const union ssa_agent_msg *msg, uint32_t sndr,
    mem_map_info_t *attr_info,  file_instance_t **fpointer)
{
    int32_t obj;

    obj = (int32_t)msg->get_obj_attrs.obj_index;

    *fpointer = get_file_pointer(sndr, obj);

    if (((*fpointer) == NULL) || (((*fpointer)->file_link) == NULL) ||
        ((*fpointer)->file_link->sfd == NULL)) {
        tloge("get session Fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    attr_info->vm_addr = 0;
    attr_info->size    = msg->get_obj_attrs.size;
    attr_info->mapped  = false;

    if (ssa_map_from_task(sndr, msg->get_obj_attrs.buffer, msg->get_obj_attrs.size,
                          g_ssagent_handle, &attr_info->vm_addr) != 0) {
        tloge("map objectAttrs from 0x%x fail\n", sndr);
        return TEE_ERROR_GENERIC;
    }

    attr_info->mapped = true;

    return TEE_SUCCESS;
}

void ssa_get_object_attr(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;
    mem_map_info_t obj_attr_info;
    struct sfd_t *sfd = NULL;
    file_instance_t *fpointer = NULL;

    if (rsp == NULL)
        return;

    if (msg == NULL || msg->get_obj_attrs.buffer == 0) {
        tloge("invalid msg or buffer!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    /* get objects will map buffer */
    ret = ssa_get_objects_attrinfo(msg, sndr, &obj_attr_info, &fpointer);
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        return;
    }

    sfd = fpointer->file_link->sfd;
    if (sfd->meta_data == NULL) {
        tloge("meta_data is null\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        goto clean;
    }

    rsp->ret = ssa_read_attr(sfd, (uint8_t *)obj_attr_info.vm_addr, msg, fpointer, rsp);

clean:
    ssa_unmap_from_task(g_ssagent_handle, obj_attr_info.vm_addr, obj_attr_info.size, obj_attr_info.mapped);
}

static TEE_Result ssa_write_obj_params_check(const union ssa_agent_msg *msg, uint32_t sndr,
    struct ssa_agent_rsp *rsp, TEE_UUID **uuid, file_instance_t **fpointer)
{
    int32_t obj;

    if (rsp == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg->write_obj.buffer == 0) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *uuid = get_sender_uuid(sndr);
    if (*uuid == NULL) {
        tloge("write object uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        return TEE_ERROR_GENERIC;
    }

    if (msg->write_obj.len > MAX_FILE_SIZE) {
        tloge("write count is too big\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj = (int32_t)msg->write_obj.obj_index;

    *fpointer = get_file_pointer(sndr, obj);
    if (((*fpointer) == NULL) || ((*fpointer)->file_link == NULL) || ((*fpointer)->file_link->sfd == NULL)) {
        tloge("get session Fail\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_write_object_data(mem_map_info_t write_info, const union ssa_agent_msg *msg,
    struct sfd_t *sfd)
{
    uint32_t ret;
    TEE_Result error = TEE_SUCCESS;

    ret = ssa_write((uint8_t *)write_info.vm_addr, msg->write_obj.len, sfd, &error);
    if ((ret != msg->write_obj.len) || (error != TEE_SUCCESS)) {
        tloge("write fail ret 0x%x err 0x%x\n", ret, error);
        return error;
    }

    if (sfd->need_update_hmac) {
        sfd->need_update_hmac = false;

        error = ssa_write_mac(sfd);
        if (error != TEE_SUCCESS) {
            tloge("write mac fail 0x%x", error);
            return error;
        }
    }

    return TEE_SUCCESS;
}

void ssa_write_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t ret;
    mem_map_info_t write_buffer_info;
    struct sfd_t *sfd = NULL;
    TEE_UUID *uuid = NULL;
    file_instance_t *fpointer = NULL;

    ret = ssa_write_obj_params_check(msg, sndr, rsp, &uuid, &fpointer);
    if (ret != TEE_SUCCESS)
        return;

    sfd                = fpointer->file_link->sfd;
    sfd->seek_position = fpointer->seek_position;
    tlogd("set seek:%u\n", sfd->seek_position);

    if ((sfd->flags & TEE_DATA_FLAG_ACCESS_WRITE) == 0) {
        tloge("access conflict %x\n", sfd->flags);
        rsp->ret = TEE_ERROR_ACCESS_CONFLICT;
        return;
    }

    write_buffer_info.vm_addr = 0;
    write_buffer_info.size    = msg->write_obj.len;
    write_buffer_info.mapped  = false;

    if (ssa_map_from_task(sndr, msg->write_obj.buffer, msg->write_obj.len,
                          g_ssagent_handle, &write_buffer_info.vm_addr) != 0) {
        tloge("map writeBuffer from 0x%x fail\n", sndr);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    write_buffer_info.mapped = true;
    ret = ssa_write_object_data(write_buffer_info, msg, sfd);
    if (ret != TEE_SUCCESS) {
        rsp->ret = ret;
        goto clean;
    }

    fpointer->seek_position     = sfd->seek_position;
    rsp->write_obj.new_seek_pos = fpointer->seek_position;
    rsp->write_obj.new_size     = sfd->size - sfd->attr_size;
    rsp->ret                    = TEE_SUCCESS;

    if (is_enum_enable(uuid)) {
        ret = update_objinfo_in_enum_file(sfd->meta_data->file_id, sfd->meta_data->file_id_len, rsp->write_obj.new_size,
                                          rsp->write_obj.new_seek_pos, sndr);
        if (ret != TEE_SUCCESS)
            tloge("Failed to update the info of object in enum file.\n");
    }
clean:
    ssa_unmap_from_task(g_ssagent_handle, write_buffer_info.vm_addr, write_buffer_info.size, write_buffer_info.mapped);
}

void ssa_read_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t ret;
    TEE_Result error = TEE_SUCCESS;
    mem_map_info_t read_buffer_info;

    if (rsp == NULL)
        return;

    if (msg == NULL || msg->read_obj.buffer == 0) {
        tloge("invalid msg or buffer!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    uint32_t obj = msg->read_obj.obj_index;
    file_instance_t *fpointer = get_file_pointer(sndr, obj);
    if ((fpointer == NULL) || (fpointer->file_link == NULL) || (fpointer->file_link->sfd == NULL)) {
        tloge("get session Fail %x\n", obj);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }
    fpointer->file_link->sfd->seek_position = fpointer->seek_position;
    if ((fpointer->file_link->sfd->flags & TEE_DATA_FLAG_ACCESS_READ) == 0) {
        tloge("access conflict %x\n", fpointer->file_link->sfd->flags);
        rsp->ret = TEE_ERROR_ACCESS_CONFLICT;
        return;
    }

    read_buffer_info.vm_addr = 0;
    read_buffer_info.size    = msg->read_obj.len;
    read_buffer_info.mapped  = false;

    if (ssa_map_from_task(sndr, msg->read_obj.buffer, msg->read_obj.len,
        g_ssagent_handle, &read_buffer_info.vm_addr) != 0) {
        tloge("map writeBuffer from 0x%x fail\n", sndr);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }
    read_buffer_info.mapped = true;

    ret = ssa_read((uint8_t *)read_buffer_info.vm_addr, msg->read_obj.len, fpointer->file_link->sfd, &error);
    if (error != TEE_SUCCESS) {
        tloge("read fail %x\n", error);
        rsp->ret = error;
        goto clean;
    }

    fpointer->seek_position = fpointer->file_link->sfd->seek_position;
    tlogd("restore seek:%u\n", fpointer->file_link->sfd->seek_position);

    rsp->ret                   = TEE_SUCCESS;
    rsp->read_obj.new_seek_pos = fpointer->seek_position;
    rsp->read_obj.new_size     = fpointer->file_link->sfd->size - fpointer->file_link->sfd->attr_size;
    rsp->read_obj.count        = ret;
clean:
    ssa_unmap_from_task(g_ssagent_handle, read_buffer_info.vm_addr, read_buffer_info.size, read_buffer_info.mapped);
}

static TEE_Result ssa_seek_params_check(union ssa_agent_msg *msg, uint32_t sndr,
                                        struct ssa_agent_rsp *rsp, TEE_UUID **uuid)
{
    if (rsp == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *uuid = get_sender_uuid(sndr);
    if (*uuid == NULL) {
        tloge("seek object uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg->seek_obj.offset > MAX_FILE_SIZE) {
        tloge("offset is too big\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

void ssa_seek_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    int32_t new_offset;
    struct sfd_t *sfd  = NULL;
    TEE_UUID *uuid     = NULL;

    TEE_Result ret = ssa_seek_params_check(msg, sndr, rsp, &uuid);
    if (ret != TEE_SUCCESS)
        return;

    int32_t offset = msg->seek_obj.offset;

    file_instance_t *fpointer = get_file_pointer(sndr, msg->seek_obj.obj_index);
    bool check_ptr_null = (fpointer == NULL) || (fpointer->file_link == NULL) || (fpointer->file_link->sfd == NULL);
    if (check_ptr_null) {
        tloge("get session Fail %x\n", msg->seek_obj.obj_index);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }
    sfd = fpointer->file_link->sfd;

    if (msg->seek_obj.whence == TEE_DATA_SEEK_SET) {
        if (offset < 0)
            offset = 0;
        new_offset = offset + (int32_t)sfd->attr_size;
    } else {
        new_offset = offset;
    }

    ret        = ssa_seek(sfd, new_offset, msg->seek_obj.whence);
    if (ret != TEE_SUCCESS) {
        tloge("ssa seek fail %x", ret);
        rsp->ret = ret;
        return;
    }

    fpointer->seek_position = sfd->seek_position;

    if (sfd->need_update_hmac) {
        sfd->need_update_hmac = false;

        ret = ssa_write_mac(sfd);
        if (ret != TEE_SUCCESS) {
            tloge("write mac fail %x", ret);
            rsp->ret = ret;
            return;
        }
    }

    rsp->seek_obj.new_seek_pos = fpointer->seek_position;
    rsp->seek_obj.new_size     = sfd->size - sfd->attr_size;

    if (is_enum_enable(uuid)) {
        ret = update_objinfo_in_enum_file(sfd->meta_data->file_id, sfd->meta_data->file_id_len, rsp->seek_obj.new_size,
                                          rsp->seek_obj.new_seek_pos, sndr);
        if (ret != TEE_SUCCESS)
            tloge("Failed to update the info of object in enum file.\n");
    }
    rsp->ret = TEE_SUCCESS;
}

static void ssa_truncate_params_check(const union ssa_agent_msg *msg, uint32_t sndr,
    struct ssa_agent_rsp *rsp, file_instance_t **fpointer, TEE_UUID **uuid)
{
    uint32_t obj;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    *uuid = get_sender_uuid(sndr);
    if (*uuid == NULL) {
        tloge("truncate object uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    if (msg->truncate_obj.size > MAX_FILE_SIZE) {
        tloge("truncate size is too big\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    obj = (uint32_t)msg->truncate_obj.obj_index;
    *fpointer = get_file_pointer(sndr, (int32_t)obj);

    bool is_fp_invalid = (*fpointer == NULL) || ((*fpointer)->file_link == NULL) ||
                         ((*fpointer)->file_link->sfd == NULL) ||
                         ((*fpointer)->file_link->sfd->meta_data == NULL);
    if (is_fp_invalid) {
        tloge("get session fail 0x%x\n", obj);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void ssa_truncate_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;
    file_instance_t *fpointer = NULL;
    uint32_t new_size;
    struct sfd_t *sfd = NULL;
    TEE_UUID *uuid    = NULL;

    ssa_truncate_params_check(msg, sndr, rsp, &fpointer, &uuid);
    if (rsp == NULL || rsp->ret != TEE_SUCCESS || fpointer == NULL)
        return;

    new_size = (uint32_t)msg->truncate_obj.size;
    sfd = fpointer->file_link->sfd;

    tlogd("oldSize=%u, new_size=%d, attr_size=%u\n", sfd->size, msg->truncate_obj.size, sfd->attr_size);

    sfd->seek_position = fpointer->seek_position;
    if (judge_valid_version(sfd))
        new_size += sfd->attr_size;

    ret = ssa_truncate(sfd, new_size);

    if (sfd->need_update_hmac) {
        sfd->need_update_hmac = false;

        ret = ssa_write_mac(sfd);
        if (ret != TEE_SUCCESS) {
            tloge("write mac fail %x", ret);
            rsp->ret = ret;
            return;
        }
    }

    fpointer->seek_position = sfd->seek_position;

    rsp->truncate_obj.new_size = sfd->size;
    if (judge_valid_version(sfd))
        rsp->truncate_obj.new_size -= sfd->attr_size;
    rsp->truncate_obj.new_seek_pos = fpointer->seek_position;

    if (is_enum_enable(uuid)) {
        ret = update_objinfo_in_enum_file(sfd->meta_data->file_id, sfd->meta_data->file_id_len,
            rsp->truncate_obj.new_size, rsp->truncate_obj.new_seek_pos, sndr);
        if (ret != TEE_SUCCESS)
            tloge("Failed to update the info of object in enum file.\n");
    }
    rsp->ret = TEE_SUCCESS;
}

static TEE_Result ssa_rename_params_check(const union ssa_agent_msg *msg, uint32_t sndr,
    file_instance_t **fpointer, TEE_UUID **uuid)
{
    TEE_Result ret;

    if (msg == NULL || msg->rename_obj.new_object_id == 0) {
        tloge("invalid msg or buffer!\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        return ret;
    }

    *uuid = get_sender_uuid(sndr);
    if (*uuid == NULL) {
        tloge("rename object uuid read fail\n");
        ret = TEE_ERROR_GENERIC;
        return ret;
    }
    uint32_t obj = msg->rename_obj.obj_index;
    tlogd("Rename: IDlen %u\n", msg->rename_obj.objIdLen);

    *fpointer = get_file_pointer(sndr, (int32_t)obj);
    bool pointer_flag = ((*fpointer) == NULL) || ((*fpointer)->file_link == NULL);
    if (pointer_flag) {
        tloge("get session fail %x\n", obj);
        ret = TEE_ERROR_BAD_PARAMETERS;
        return ret;
    }

    if (((*fpointer)->file_link->sfd == NULL) || ((*fpointer)->file_link->sfd->meta_data == NULL)) {
        tloge("get sfd fail!\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        return ret;
    }

    bool flag = (((*fpointer)->file_link->sfd->flags & TEE_DATA_FLAG_ACCESS_WRITE_META) == 0);
    if (flag) {
        ret = TEE_ERROR_ACCESS_CONFLICT;
        tloge("Access conflict %x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_rename_object_proc(const union ssa_agent_msg *msg, uint32_t sndr,
    mem_map_info_t *new_object_id_info, struct sfd_t *sfd, const TEE_UUID *uuid)
{
    TEE_Result ret;
    TEE_Result ret_enum;
    char new_obj_id[HASH_NAME_BUFF_LEN]          = { 0 };
    uint8_t origin_object_id[HASH_NAME_BUFF_LEN] = { 0 };

    ret = copy_and_check_file_name((char *)new_object_id_info->vm_addr, new_object_id_info->size,
        new_obj_id, sizeof(new_obj_id));
    if (ret != TEE_SUCCESS)
        return ret;

    ret = check_name_by_storageid(new_obj_id, strlen(new_obj_id), sfd->meta_data->storage_id);
    if (ret != TEE_SUCCESS)
        return ret;

    if (sfd->meta_data->file_id != NULL) {
        if (memcpy_s(origin_object_id, HASH_NAME_BUFF_LEN, sfd->meta_data->file_id,
            sfd->meta_data->file_id_len) != EOK) {
            tloge("Failed to copy origin object id.\n");
            ret = TEE_ERROR_GENERIC;
            return ret;
        }
    }

    ret = ssa_rename(sfd, (uint8_t *)new_obj_id, msg->rename_obj.obj_id_len);
    if (ret == TEE_SUCCESS) {
        sfd->need_update_hmac = false;
        ret = ssa_write_mac(sfd);
        if (ret != TEE_SUCCESS) {
            tloge("write mac fail %x", ret);
            return ret;
        }
    }
    if (is_enum_enable(uuid)) {
        ret_enum = rename_obj_in_enum_file(origin_object_id, (uint8_t *)new_obj_id,
            msg->rename_obj.obj_id_len, sndr);
        if (ret_enum != TEE_SUCCESS)
            tloge("Failed to rename the obj info in enum file.\n");
    }

    return ret;
}

void ssa_rename_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    mem_map_info_t new_object_id_info;
    file_instance_t *fpointer = NULL;
    TEE_UUID *uuid = NULL;

    if (rsp == NULL)
        return;

    rsp->ret = ssa_rename_params_check(msg, sndr, &fpointer, &uuid);
    if (rsp->ret != TEE_SUCCESS)
        return;

    new_object_id_info.vm_addr = 0;
    new_object_id_info.size    = msg->rename_obj.obj_id_len;
    new_object_id_info.mapped  = false;

    if (ssa_map_from_task(sndr, msg->rename_obj.new_object_id, msg->rename_obj.obj_id_len, g_ssagent_handle,
                          &new_object_id_info.vm_addr) != 0) {
        tloge("map objectID from 0x%x fail\n", sndr);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }
    new_object_id_info.mapped = true;

    struct sfd_t *sfd = fpointer->file_link->sfd;
    rsp->ret = ssa_rename_object_proc(msg, sndr, &new_object_id_info, sfd, uuid);
    if (rsp->ret != TEE_SUCCESS)
        tloge("ssa rename object failed.\n");

    ssa_unmap_from_task(g_ssagent_handle, new_object_id_info.vm_addr,
        new_object_id_info.size, new_object_id_info.mapped);
}

void ssa_info_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;
    uint32_t pos = 0;
    uint32_t len = 0;
    uint32_t obj;
    file_instance_t *fpointer = NULL;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    obj      = (uint32_t)msg->get_info_obj.obj_index;
    fpointer = get_file_pointer(sndr, (int32_t)obj);
    if ((fpointer == NULL) || (fpointer->file_link == NULL) || (fpointer->file_link->sfd == NULL)) {
        tloge("get session Fail %x\n", obj);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    ret                   = ssa_info(fpointer->file_link->sfd, &pos, &len);
    rsp->ret              = ret;
    rsp->get_info_obj.pos = pos - fpointer->file_link->sfd->attr_size;
    rsp->get_info_obj.len = len - fpointer->file_link->sfd->attr_size;
}

void ssa_close_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t obj;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    obj = (uint32_t)msg->close_obj.obj_index;

    tlogd("close Obj: %u\n", obj);
    close_file_from_client(sndr, obj);
    rsp->ret = TEE_SUCCESS;
}

void ssa_sync_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t obj;

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    obj = (uint32_t)msg->sync_obj.obj_index;

    file_instance_t *fpointer = get_file_pointer(sndr, obj);
    if ((fpointer == NULL) || (fpointer->file_link == NULL)) {
        tloge("get session Fail %x\n", obj);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    (void)ssa_sync(fpointer->file_link->sfd);
    rsp->ret = TEE_SUCCESS;
}

void ssa_close_and_delete_object(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp)
{
    uint32_t obj;
    TEE_Result ret;
    struct sfd_t *sfd                  = NULL;
    uint8_t obj_id[HASH_NAME_BUFF_LEN] = { 0 };

    if (rsp == NULL)
        return;

    if (msg == NULL) {
        tloge("invalid msg!\n");
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    TEE_UUID *uuid = get_sender_uuid(sndr);
    if (uuid == NULL) {
        tloge("delete object uuid read fail\n");
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }
    obj                       = (uint32_t)msg->close_and_delete_obj.obj_index;
    file_instance_t *fpointer = get_file_pointer(sndr, obj);
    if ((fpointer == NULL) || (fpointer->file_link == NULL) || (fpointer->file_link->sfd == NULL)) {
        tloge("get session Fail %x\n", obj);
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }
    sfd = fpointer->file_link->sfd;

    tlogd("flags %x\n", sfd->flags);
    if ((sfd->flags & TEE_DATA_FLAG_ACCESS_WRITE_META) == 0) {
        tloge("Access conflict, %x\n", sfd->flags);
        close_file_from_client(sndr, obj);
        rsp->ret = TEE_ERROR_ACCESS_CONFLICT;
        return;
    }

    if (sfd->meta_data != NULL && sfd->meta_data->file_id != NULL) {
        int32_t rc = memcpy_s(obj_id, HASH_NAME_BUFF_LEN, sfd->meta_data->file_id, sfd->meta_data->file_id_len);
        if (rc != EOK) {
            rsp->ret = TEE_ERROR_SECURITY;
            return;
        }
    }

    rsp->ret = delete_file(sndr, obj);
    if (rsp->ret != TEE_SUCCESS)
        return;

    if (is_enum_enable(uuid)) {
        ret = delete_obj_in_enum_file(obj_id, strlen((char *)obj_id), sndr);
        if (ret != TEE_SUCCESS)
            tloge("Failed to delete obj info from enum file.\n");
    }
}


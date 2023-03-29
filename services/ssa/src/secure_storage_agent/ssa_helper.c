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
#include "string.h"
#include "tee_log.h"
#include "tee_ss_agent_api.h"
#include "sfs.h"
#include "ssa_helper.h"

TEE_Result create_param_mapping(const union ssa_agent_msg *msg, uint32_t sndr, mem_map_info_t *obj_id_info,
                                mem_map_info_t *attributes_info, mem_map_info_t *initial_data)
{
    if (msg == NULL || obj_id_info == NULL || attributes_info == NULL || initial_data == NULL ||
        msg->create_obj.object_id == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    obj_id_info->vm_addr = 0;
    obj_id_info->size = msg->create_obj.obj_id_len;
    obj_id_info->mapped = false;
    attributes_info->vm_addr = 0;
    attributes_info->size = msg->create_obj.attributes_len;
    attributes_info->mapped = false;
    initial_data->vm_addr = 0;
    initial_data->size = msg->create_obj.data_len;
    initial_data->mapped = false;

    if (ssa_map_from_task(sndr, msg->create_obj.object_id, msg->create_obj.obj_id_len, g_ssagent_handle,
                          &obj_id_info->vm_addr) != 0) {
        tloge("map objectID from 0x%x fail\n", sndr);
        goto clean;
    }
    obj_id_info->mapped = true;

    bool attr_is_valid = (msg->create_obj.attributes != 0) && (msg->create_obj.attributes_len != 0);
    if (attr_is_valid) {
        if (ssa_map_from_task(sndr, msg->create_obj.attributes, msg->create_obj.attributes_len, g_ssagent_handle,
                              &attributes_info->vm_addr) != 0) {
            tloge("map attributes from 0x%x fail\n", sndr);
            goto clean;
        }
        attributes_info->mapped = true;
    }

    bool initial_data_valid = (msg->create_obj.initial_data != 0) && (msg->create_obj.data_len != 0);
    if (initial_data_valid) {
        if (ssa_map_from_task(sndr, msg->create_obj.initial_data, msg->create_obj.data_len, g_ssagent_handle,
                              &initial_data->vm_addr) != 0) {
            tloge("map initialData from 0x%x fail\n", sndr);
            goto clean;
        }
        initial_data->mapped = true;
    }

    return TEE_SUCCESS;
clean:
    create_param_unmapping(obj_id_info, attributes_info, initial_data);
    return TEE_ERROR_GENERIC;
}

void create_param_unmapping(const mem_map_info_t *obj_id_info, const mem_map_info_t *attributes_info,
                            const mem_map_info_t *initial_data)
{
    if (obj_id_info != NULL)
        ssa_unmap_from_task(g_ssagent_handle, obj_id_info->vm_addr, obj_id_info->size, obj_id_info->mapped);

    if (attributes_info != NULL)
        ssa_unmap_from_task(g_ssagent_handle, attributes_info->vm_addr, attributes_info->size, attributes_info->mapped);

    if (initial_data != NULL)
        ssa_unmap_from_task(g_ssagent_handle, initial_data->vm_addr, initial_data->size, initial_data->mapped);
}

void create_object_proc(const struct create_obj_msg_t *create_obj, uint32_t sndr,
                        const TEE_UUID *uuid, struct ssa_agent_rsp *rsp)
{
    struct sfd_t *sfd = NULL;
    TEE_Result error  = TEE_ERROR_GENERIC;
    uint32_t obj      = 0;

    if (rsp == NULL)
        return;

    if (create_obj == NULL || uuid == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    create_object(create_obj, sndr, uuid, &sfd, &obj, &error);
    if (error != TEE_SUCCESS) {
        rsp->ret = error;
        return;
    }

    rsp->ret                  = TEE_SUCCESS;
    rsp->create_obj.obj_index = obj;
    /* update new_seek_pos if has initial data */
    rsp->create_obj.new_seek_pos = 0; /* The initial data position in the data stream is set to 0 */
    rsp->create_obj.new_size     = sfd->size - sfd->attr_size;
    tlogd("obj %u created\n", rsp->create_obj.obj_index);
}

TEE_Result open_param_mapping(const union ssa_agent_msg *msg, uint32_t sndr,
                              mem_map_info_t *obj_id_info, mem_map_info_t *attributes_info)
{
    if (msg == NULL || obj_id_info == NULL || attributes_info == NULL || msg->open_obj.object_id == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    obj_id_info->vm_addr = 0;
    obj_id_info->size = msg->open_obj.obj_id_len;
    obj_id_info->mapped = false;
    attributes_info->vm_addr = 0;
    attributes_info->size = msg->open_obj.attr_head_size;
    attributes_info->mapped = false;

    if (ssa_map_from_task(sndr, msg->open_obj.object_id, msg->open_obj.obj_id_len,
        g_ssagent_handle, &obj_id_info->vm_addr) != 0) {
        tloge("map objectID from 0x%x fail\n", sndr);
        goto clean;
    }
    obj_id_info->mapped = true;

    if ((msg->open_obj.attr_head != 0) && (msg->open_obj.attr_head_size != 0)) {
        if (ssa_map_from_task(sndr, msg->open_obj.attr_head, msg->open_obj.attr_head_size, g_ssagent_handle,
                              &attributes_info->vm_addr) != 0) {
            tloge("map attributes from 0x%x fail\n", sndr);
            goto clean;
        }
        attributes_info->mapped = true;
    }

    return TEE_SUCCESS;

clean:
    open_param_unmapping(obj_id_info, attributes_info);
    return TEE_ERROR_GENERIC;
}

void open_param_unmapping(const mem_map_info_t *obj_id_info, const mem_map_info_t *attributes_info)
{
    if (obj_id_info != NULL)
        ssa_unmap_from_task(g_ssagent_handle, obj_id_info->vm_addr, obj_id_info->size, obj_id_info->mapped);

    if (attributes_info != NULL)
        ssa_unmap_from_task(g_ssagent_handle, attributes_info->vm_addr, attributes_info->size, attributes_info->mapped);
}

TEE_Result ssa_internal_fcreate(const char *file_name, const TEE_UUID *uuid, struct sfd_t **sfd)
{
    meta_data_t *meta = NULL;
    TEE_Result ret = TEE_ERROR_GENERIC;

    if (file_name == NULL || sfd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    meta = create_meta_data((uint8_t *)file_name, strlen(file_name), TEE_OBJECT_STORAGE_PRIVATE,
                            TA_KEY_COMPOSED_OF_TWO_16BYTES_KEYS, uuid, &ret, SFS_ARCH_VERSION_SSA);
    if (meta == NULL) {
        tloge("meta data create fail\n");
        return TEE_ERROR_GENERIC;
    }

    *sfd = ssa_create(meta, TEE_DATA_FLAG_ACCESS_WRITE, &ret);
    if (*sfd == NULL) {
        tloge("create fail ret=0x%x\n", ret);
        goto clean;
    }

    return TEE_SUCCESS;

clean:
    free_meta_data(&meta);
    return ret;
}

TEE_Result ssa_internal_fopen(const char *file_name, const TEE_UUID *uuid, struct sfd_t **sfd)
{
    meta_data_t *meta = NULL;
    TEE_Result ret = TEE_ERROR_GENERIC;

    if (file_name == NULL || sfd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    meta = create_meta_data((uint8_t *)file_name, strlen(file_name), TEE_OBJECT_STORAGE_PRIVATE,
                            TA_KEY_COMPOSED_OF_TWO_16BYTES_KEYS, uuid, &ret, SFS_ARCH_VERSION_SSA);
    if (meta == NULL) {
        tloge("meta data create fail\n");
        ret = TEE_ERROR_GENERIC;
        return ret;
    }

    *sfd = ssa_open(meta, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &ret);
    if (*sfd == NULL) {
        tloge("open fail ret=0x%x\n", ret);
        goto clean;
    }

    return TEE_SUCCESS;

clean:
    free_meta_data(&meta);
    return ret;
}

uint32_t ssa_internal_fwrite(struct sfd_t *sfd, const uint8_t *in_buff, uint32_t len)
{
    TEE_Result ret;
    uint32_t count;

    if (sfd == NULL || in_buff == NULL)
        return 0;

    ret = ssa_seek(sfd, 0, TEE_DATA_SEEK_SET);
    if (ret != TEE_SUCCESS) {
        tloge("seek file failed ret=0x%x\n", ret);
        return 0;
    }

    count = ssa_write(in_buff, len, sfd, &ret);
    if (ret != TEE_SUCCESS || count != len) {
        tloge("ssa write fail, ret=%x", ret);
        return 0;
    }

    ret = ssa_truncate(sfd, count);
    if (ret != TEE_SUCCESS) {
        tloge("truncate error, ret:%x", ret);
        return ret;
    }

    sfd->need_update_hmac = false;
    ret                   = ssa_write_mac(sfd);
    if (ret != TEE_SUCCESS) {
        tloge("write mac fail %x", ret);
        return 0;
    }

    return count;
}

void ssa_internal_fclose(struct sfd_t *sfd)
{
    TEE_Result ret;
    meta_data_t *meta = NULL;

    if (sfd == NULL)
        return;

    meta = sfd->meta_data;

    ret = ssa_close(sfd);
    sfd = NULL;
    if (ret != TEE_SUCCESS)
        tloge("close file failed\n");

    free_meta_data(&meta);
    return;
}

void ssa_internal_fremove(struct sfd_t *sfd)
{
    meta_data_t *meta = NULL;

    if (sfd == NULL)
        return;

    meta = sfd->meta_data;
    (void)ssa_close_and_delete(sfd, true);
    sfd = NULL;
    free_meta_data(&meta);

    return;
}

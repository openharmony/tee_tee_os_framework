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
#include "ta_framework.h"
#include "tee_ss_agent_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_obj.h"
/* #keyserivce start */
#include "tee_ext_api.h"
/* #keyserivce end */
#include "tee_log.h"
#include "securec.h"
#include "ipclib.h"
#include "tee_property_inner.h"
#include "tee_obj_attr.h"
#include "tee_inner_uuid.h"
#include "mem_ops.h"
#include <ipclib_hal.h>

static TEE_UUID g_uuid = TEE_SERVICE_SSA;

static TEE_Result restore_attr_buff(TEE_Attribute *attr, uint8_t **buff)
{
    uint32_t attrlen = 0;
    errno_t rc = memmove_s(&attrlen, sizeof(attrlen), *buff, sizeof(uint32_t));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    *buff += sizeof(attrlen);
    attr->content.ref.length = attrlen;
    attr->content.ref.buffer = TEE_Malloc(attrlen, 0);
    if (attr->content.ref.buffer == NULL) {
        tloge("Failed to allocate object attribute buffer\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memmove_s(attr->content.ref.buffer, attr->content.ref.length, *buff, attr->content.ref.length);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    *buff += attr->content.ref.length;
    return TEE_SUCCESS;
}

static TEE_Result restore_attr_value(TEE_Attribute *attr, uint8_t **buff)
{
    errno_t rc = memmove_s(&(attr->content.value.a), sizeof(attr->content.value.a), *buff, sizeof(uint32_t));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    *buff += sizeof(uint32_t);
    rc = memmove_s(&(attr->content.value.b), sizeof(attr->content.value.b), *buff, sizeof(uint32_t));
    *buff += sizeof(uint32_t);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

/* only used in create object */
TEE_Result restore_attrs(TEE_ObjectHandle object, const uint8_t *buff, uint32_t buff_size,
    uint32_t attr_size, uint32_t attr_count)
{
    uint32_t i, j;
    uint32_t attr_id;
    TEE_Result ret;
    bool check = (object == NULL || buff == NULL || object->ObjectInfo == NULL ||
                  attr_count == 0 || attr_count > MAX_ATTR_COUNT_VALUE || buff_size < attr_count * sizeof(uint32_t));

    if (check) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_DATA) ||
        ((object->ObjectInfo->objectType == (uint32_t)TEE_TYPE_DATA_GP1_1)))
        return TEE_SUCCESS;

    object->Attribute = (TEE_Attribute *)TEE_Malloc(attr_count * sizeof(TEE_Attribute), 0);
    if ((object->Attribute) == (TEE_Attribute *)NULL) {
        tloge("Failed to allocate memory for object attribute.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    for (i = 0; i < attr_count; i++) {
        if (memmove_s(&attr_id, sizeof(uint32_t), buff, sizeof(uint32_t)) != EOK) {
            ret = TEE_ERROR_SECURITY;
            goto clean;
        }
        buff += sizeof(uint32_t);

        object->Attribute[i].attributeID = attr_id;
        if (TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID)) /* buffer attribute */
            ret = restore_attr_buff(&(object->Attribute[i]), (uint8_t **)&buff);
        else
            ret = restore_attr_value(&(object->Attribute[i]), (uint8_t **)&buff);

        if (ret != TEE_SUCCESS)
            goto clean;
    }

    object->attributesLen = attr_count;

    return TEE_SUCCESS;
clean:
    for (j = 0; j < i; j++) {
        if (TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID)) {
            if (object->Attribute[j].content.ref.buffer != NULL) {
                TEE_Free(object->Attribute[j].content.ref.buffer);
                object->Attribute[j].content.ref.buffer = NULL;
            }
        }
    }
    TEE_Free(object->Attribute);
    object->Attribute = NULL;

    (void)attr_size;
    return ret;
}

/* copy a attribute to buffer *p */
TEE_Result copy_attribute(uint8_t **p, const TEE_Attribute *attr)
{
    errno_t rc;
    uint32_t attr_len;

    if ((p == NULL) || (*p == NULL) || (attr == NULL)) {
        tloge("params invalid\n");
        return TEE_ERROR_GENERIC;
    }

    tlogd("attributeID=0x%x\n", attr->attributeID);
    rc = memmove_s(*p, sizeof(attr->attributeID), &(attr->attributeID), sizeof(attr->attributeID));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    *p += sizeof(attr->attributeID);

    if (TEE_ATTR_IS_BUFFER(attr->attributeID)) {
        /* buffer attribute */
        if (attr->content.ref.buffer == NULL) {
            tloge("params invalid, buffer attribute is null\n");
            return TEE_ERROR_GENERIC;
        }

        attr_len = (uint32_t)attr->content.ref.length;
        rc = memmove_s(*p, sizeof(attr_len), &attr_len, sizeof(attr_len));
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
        *p += sizeof(attr_len);
        rc = memmove_s(*p, attr->content.ref.length, attr->content.ref.buffer, attr->content.ref.length);
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
        *p += attr->content.ref.length;
    } else {
        rc = memmove_s(*p, sizeof(attr->content.value.a), &(attr->content.value.a), sizeof(attr->content.value.a));
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
        *p += sizeof(attr->content.value.a);
        rc = memmove_s(*p, sizeof(attr->content.value.b), &(attr->content.value.b), sizeof(attr->content.value.b));
        if (rc != EOK)
            return TEE_ERROR_SECURITY;
        *p += sizeof(attr->content.value.b);
    }

    return TEE_SUCCESS;
}

#define DOUBLE_SIZE   2
/* Calculate size of attributes */
uint32_t get_attr_buf_size(TEE_ObjectHandle object)
{
    uint32_t i;
    uint32_t attr_count;
    uint32_t attr_buf_size = 0;
    if (object == NULL || (object->ObjectInfo) == NULL || (object->Attribute) == NULL) {
        tloge("params invalid\n");
        return (uint32_t)TEE_ERROR_BAD_PARAMETERS;
    }

    attr_count = get_attr_count_for_object_type(object->ObjectInfo->objectType);

    for (i = 0; i < attr_count; i++) {
        attr_buf_size += sizeof(uint32_t);                            /* type */
        if (TEE_ATTR_IS_BUFFER(object->Attribute[i].attributeID)) { /* buffer attribute */
            attr_buf_size += (sizeof(uint32_t) + object->Attribute[i].content.ref.length);
        } else {
            attr_buf_size += DOUBLE_SIZE * sizeof(uint32_t);
            tlogd("this is a value attribute\n");
        }
    }
    return attr_buf_size;
}

static uint32_t get_gtask_and_ssa_handle(uint32_t *global_handle, uint32_t *ss_agent_handle)
{
    uint32_t global_taskid;

    if (global_handle == NULL || ss_agent_handle == NULL)
        return OS_ERROR;

    if (ipc_hunt_by_name(GLOBAL_SERVICE_NAME, &global_taskid) != 0) {
        tloge("Get global_handle handle error\n");
        return OS_ERROR;
    }
	*global_handle = taskid_to_pid(global_taskid);

    if (ipc_hunt_by_name(SSA_SERVICE_NAME, ss_agent_handle) != 0) {
        tloge("Get ssa handle error\n");
        return OS_ERROR;
    }
    return SRE_OK;
}

void ss_agent_proc_cmd(uint32_t snd_cmd, const union ssa_agent_msg *snd_msg,
                       uint32_t ack_cmd, struct ssa_agent_rsp *rsp_msg)
{
    uint32_t sndr = 0;
    uint32_t global_handle = 0;
    uint32_t rcv_cmd       = 0;
    uint32_t i;
    uint32_t ret;
    uint8_t *ret_data      = NULL;
    uint32_t ss_agent_handle;

    if (snd_msg == NULL || rsp_msg == NULL)
        return;

    ret = get_gtask_and_ssa_handle(&global_handle, &ss_agent_handle);
    if (ret != SRE_OK)
        return;

    ret = (uint32_t)ipc_msg_snd(snd_cmd, ss_agent_handle, snd_msg, sizeof(union ssa_agent_msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return;
    }

    do {
        ret = (uint32_t)ipc_msg_rcv_a(OS_WAIT_FOREVER, &rcv_cmd, rsp_msg, sizeof(struct ssa_agent_rsp), &sndr);
        if (ret != SRE_OK) {
            if (ret == SRE_IPC_NO_CHANNEL_ERR) {
                rsp_msg->ret = TEE_ERROR_COMMUNICATION;
                tloge("msg rcv fail to get channel\n");
                break;
            }
            tloge("msg rcv error %x\n", ret);
            continue;
        }

        if (ack_cmd != rcv_cmd || (ss_agent_handle != sndr && global_handle != sndr)) {
            tloge("Recv unexpected msg snd cmd 0x%x, rcv cmd 0x%x, from 0x%x\n", snd_cmd, rcv_cmd, sndr);

            ret_data = (uint8_t *)(rsp_msg);
            for (i = 0; i < sizeof(struct ssa_agent_rsp); i++)
                tloge("msg get from sndr 0x%x is ret_data[%u] = 0x%x\n", sndr, i, ret_data[i]);

            continue;
        }

        break;
    } while (1);
}

#define ECC_MAX_KEY_SIZE_IN_BYTE 66
#define ECC_MAX_KEY_SIZE_IN_BIT  521
#define BITS_OF_ONE_BYTE         8
uint32_t get_object_key_size(TEE_ObjectHandle attributes)
{
    if (attributes == NULL || attributes->ObjectInfo == NULL)
        return 0;

    uint32_t key_size;
    uint32_t api_level = tee_get_ta_api_level();
#ifndef GP_SUPPORT
    key_size = attributes->ObjectInfo->maxObjectSize;
#else
    key_size = attributes->ObjectInfo->maxKeySize;
#endif
    if (api_level <= API_LEVEL1_0)
        return key_size;
    bool check = (attributes->ObjectInfo->objectType == TEE_TYPE_ECDSA_PUBLIC_KEY ||
        attributes->ObjectInfo->objectType == TEE_TYPE_ECDSA_KEYPAIR ||
        attributes->ObjectInfo->objectType == TEE_TYPE_ECDH_PUBLIC_KEY ||
        attributes->ObjectInfo->objectType == TEE_TYPE_ECDH_KEYPAIR);
    if (check && (key_size == ECC_MAX_KEY_SIZE_IN_BYTE))
        return ECC_MAX_KEY_SIZE_IN_BIT;
    return key_size * BITS_OF_ONE_BYTE;
}

static void ssa_agent_init_msg(union ssa_agent_msg *msg, struct ssa_agent_rsp *rsp)
{
    (void)memset_s(msg, sizeof(*msg), 0, sizeof(*msg));
    (void)memset_s(rsp, sizeof(*rsp), 0, sizeof(*rsp));
}

static void fill_obj_info(TEE_ObjectHandle obj, uint32_t flags)
{
#ifndef GP_SUPPORT
    obj->ObjectInfo->maxObjectSize = (uint32_t)TEE_DATA_OBJECT_MAX_SIZE;
    obj->ObjectInfo->objectType    = (uint32_t)TEE_TYPE_DATA;
    obj->ObjectInfo->objectSize    = 0;

#else
    obj->ObjectInfo->maxKeySize = (uint32_t)TEE_DATA_OBJECT_MAX_SIZE;
    obj->ObjectInfo->objectType = (uint32_t)TEE_TYPE_DATA_GP1_1;
    obj->ObjectInfo->keySize    = 0;
#endif
    obj->ObjectInfo->dataSize     = 0;
    obj->ObjectInfo->dataPosition = 0;
    obj->ObjectInfo->objectUsage  = (uint32_t)TEE_USAGE_DEFAULT;
    /* Set initialized flag:For a persistent object, always set */
    obj->ObjectInfo->handleFlags =
        ((uint32_t)TEE_HANDLE_FLAG_PERSISTENT) | ((uint32_t)TEE_HANDLE_FLAG_INITIALIZED) | flags;
}


static TEE_Result fill_obj_info_to_attr_buf(TEE_ObjectHandle object, uint8_t *attr_buf,
                                            uint32_t attr_buf_size, uint32_t attr_count, uint32_t attr_size)
{
    if (object == NULL || attr_buf == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    errno_t rc = memmove_s(attr_buf, attr_buf_size, object->ObjectInfo, sizeof(TEE_ObjectInfo));
    if (rc != EOK) {
        tloge("memmove obj info fail\n");
        return TEE_ERROR_SECURITY;
    }

    ((struct saved_attr_info_t *)attr_buf)->attr_count     = attr_count;
    ((struct saved_attr_info_t *)attr_buf)->attr_size      = attr_size;
    ((struct saved_attr_info_t *)attr_buf)->opt_attr_count = 0;
    ((struct saved_attr_info_t *)attr_buf)->opt_attr_size  = 0;

    return TEE_SUCCESS;
}

static TEE_Result fill_obj_data(TEE_ObjectHandle object, struct create_obj_msg_t *params)
{
    if (object == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /*
     * object_id_len is shorter than  or equal to HASH_NAME_BUFF_LEN-1,
     * and HASH_NAME_BUFF_LEN-1 is shorter than sizeof(dataName).
     */
    errno_t rc;
    rc = memmove_s(object->dataName, sizeof(object->dataName),
                   (void *)(uintptr_t)(params->object_id), params->obj_id_len);
    if (rc != EOK) {
        tloge("memmove obj name fail\n");
        return TEE_ERROR_SECURITY;
    }

    object->dataName[params->obj_id_len] = '\0';
    object->dataLen                 = params->obj_id_len;
    object->storage_id              = params->storage_id;

    return TEE_SUCCESS;
}

static TEE_Result ssa_send_msg_and_rcv(union ssa_agent_msg *msg, struct ssa_agent_rsp *rsp,
                                       struct create_obj_msg_t *params, TEE_ObjectHandle object)
{
    if (msg == NULL || rsp == NULL || object == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    rsp->ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(params->cmd_id, msg, params->cmd_id, rsp);
    if (rsp->ret == TEE_SUCCESS) {
        object->dataPtr                  = (void *)(uintptr_t)rsp->create_obj.obj_index;
        object->ObjectInfo->dataSize     = rsp->create_obj.new_size;
        object->ObjectInfo->dataPosition = rsp->create_obj.new_seek_pos;
    } else {
        tloge("ssagent proc cmd fail\n");
        return rsp->ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result add_object_to_list(uint32_t obj_inserted, TEE_ObjectHandle object)
{
    if (object == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (obj_inserted)                    /* to avoiding insert two obj if Attribute is not NULL */
        (void)delete_object(object);     /* no need to verify return value here */
    if (add_object(object) != TEE_SUCCESS) {
        tloge("insert new object to list failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    return TEE_SUCCESS;
}

static TEE_Result fill_msg_info(union ssa_agent_msg *msg, struct create_obj_msg_t *params,
                                uint8_t *obj_id, uint8_t *attr_buf, uint32_t attr_buf_size)
{
    uint8_t *buf      = NULL;
    uint32_t buf_size = 0;

    msg->create_obj.storage_id     = params->storage_id;
    msg->create_obj.object_id      = (uintptr_t)obj_id;
    msg->create_obj.obj_id_len     = params->obj_id_len;
    msg->create_obj.attributes     = (uintptr_t)attr_buf;
    msg->create_obj.attributes_len = attr_buf_size;
    msg->create_obj.flags          = params->flags;
    msg->create_obj.target_uuid     = params->target_uuid;

    bool initial_data_ready = (params->data_len > 0) &&
                              (params->data_len <= MAX_FILE_SIZE) &&
                              ((void *)(uintptr_t)(params->initial_data) != NULL);
    if (initial_data_ready) {
        buf_size = params->data_len;
        buf = alloc_sharemem_aux(&g_uuid, buf_size);
        if (buf == NULL) {
            tloge("malloc shared_buff for initial_data failed, size=%u\n", params->data_len);
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        msg->create_obj.data_len     = params->data_len;
        msg->create_obj.initial_data = (uintptr_t)buf;

        errno_t rc = memmove_s(buf, params->data_len, (void *)(uintptr_t)(params->initial_data), params->data_len);
        if (rc != EOK) {
            tloge("memmove initial data failed\n");
            return TEE_ERROR_SECURITY;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result ssa_populate_msg(union ssa_agent_msg *msg, struct create_obj_msg_t *params,
                                   uint8_t *attr_buf, uint32_t attr_buf_size)
{
    errno_t rc;
    uint8_t *obj_id = NULL;
    uint32_t obj_id_size;
    TEE_Result ret;

    if (msg == NULL || attr_buf == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_size = params->obj_id_len + 1;
    obj_id = alloc_sharemem_aux(&g_uuid, obj_id_size);
    if (obj_id == NULL) {
        tloge("malloc shared_buff for obj_id failed, size=%u\n", obj_id_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memmove_s(obj_id, obj_id_size, (void *)(uintptr_t)(params->object_id), obj_id_size);
    if (rc != EOK) {
        tloge("memmove object_id failed\n");
        return TEE_ERROR_SECURITY;
    }

    ret = fill_msg_info(msg, params, obj_id, attr_buf, attr_buf_size);

    return ret;
}

static TEE_Result alloc_transient_obj_fill_info(TEE_ObjectHandle attributes,
                                               uint32_t attr_count, TEE_ObjectHandle *object, uint32_t flags)
{
    TEE_Result ret;

    uint32_t key_size = get_object_key_size(attributes);
    ret = TEE_AllocateTransientObject(attributes->ObjectInfo->objectType, key_size, object);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute TEE_AllocateTransientObject. ret=%x\n", ret);
        return ret;
    }

    ret = TEE_PopulateTransientObject(*object, attributes->Attribute, attr_count);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute TEE_PopulateTransientObject.ret=%x\n", ret);
        TEE_FreeTransientObject(*object);
        return ret;
    }

    (*object)->ObjectInfo->objectUsage = attributes->ObjectInfo->objectUsage;
    (*object)->ObjectInfo->handleFlags =
        (uint32_t)TEE_HANDLE_FLAG_INITIALIZED | (uint32_t)TEE_HANDLE_FLAG_PERSISTENT | flags;

    return TEE_SUCCESS;
}

static TEE_Result fill_attributes_to_object(struct create_obj_msg_t *params, TEE_ObjectHandle *object,
                                            uint8_t **attr_buf, uint32_t *attr_buf_size)
{
    TEE_Result ret;
    TEE_ObjectHandle attributes = (TEE_ObjectHandle)(uintptr_t)(params->attributes);
    if (attributes->ObjectInfo == NULL || attributes->Attribute == NULL) {
        tloge("invalid params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t attr_count = get_attr_count_for_object_type(attributes->ObjectInfo->objectType);
    if (attr_count == 0) {
        tloge("invalid objectType, 0x%x\n", attributes->ObjectInfo->objectType);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = alloc_transient_obj_fill_info(attributes, attr_count, object, params->flags);
    if (ret != TEE_SUCCESS)
        return ret;

    uint32_t attr_head_size = sizeof(struct saved_attr_info_t);
    *attr_buf_size  = attr_head_size;

    uint32_t attr_body_size = get_attr_buf_size(*object);
    if (attr_body_size == (uint32_t)TEE_ERROR_BAD_PARAMETERS) {
        tloge("get attr buf size error ret =0x%x\n", attr_body_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    *attr_buf_size += attr_body_size;

    *attr_buf = alloc_sharemem_aux(&g_uuid, *attr_buf_size);
    if (*attr_buf == NULL) {
        tloge("malloc shared_buff for attr_buf failed, size=%u\n", *attr_buf_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *point = *attr_buf;

    ret = fill_obj_info_to_attr_buf(*object, point,
                                    sizeof(TEE_ObjectInfo), attr_count, *attr_buf_size - attr_head_size);
    if (ret != TEE_SUCCESS)
        return ret;

    point += sizeof(struct saved_attr_info_t);

    uint32_t i;
    for (i = 0; i < attr_count; i++)
        (void)copy_attribute(&point, &((*object)->Attribute[i])); /* no need to verify return value here */

    return TEE_SUCCESS;
}

static TEE_Result create_obj_and_fill_default_data(struct create_obj_msg_t *params, TEE_ObjectHandle *object,
                                                   uint8_t **attr_buf, uint32_t *attr_buf_size)
{
    TEE_Result ret;

    if (tee_obj_new(object) != TEE_SUCCESS) {
        tloge("not available to allocate the object handle\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    fill_obj_info(*object, params->flags);

    *attr_buf_size = sizeof(struct saved_attr_info_t);
    *attr_buf = alloc_sharemem_aux(&g_uuid, sizeof(struct saved_attr_info_t));
    if (*attr_buf == NULL) {
        tloge("malloc shared_buff for attr_buf failed, size=%u\n", *attr_buf_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = fill_obj_info_to_attr_buf(*object, *attr_buf, sizeof(struct saved_attr_info_t), 0, 0);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static void free_temp_object(TEE_ObjectHandle attributes, TEE_ObjectHandle *object)
{
    if (attributes == TEE_HANDLE_NULL) {
        (void)tee_obj_free(object); /* never return fail */
    } else {
        /* Set object to transient so it can be deleted */
        (*object)->ObjectInfo->handleFlags &= (~TEE_HANDLE_FLAG_PERSISTENT);
        TEE_FreeTransientObject(*object);
    }
}

TEE_Result ss_agent_create_object(struct create_obj_msg_t *params, TEE_ObjectHandle *object)
{
    TEE_Result ret;
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_size;
    uint32_t obj_inserted  = false;
    TEE_ObjectHandle tmp_object = NULL;

    ssa_agent_init_msg(&msg, &rsp);
    if (params == NULL || (void *)(uintptr_t)(params->object_id) == NULL || object == NULL) {
        tloge("object params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *object = NULL;

    if (params->attributes == TEE_HANDLE_NULL) {
        ret = create_obj_and_fill_default_data(params, &tmp_object, &attr_buf, &attr_buf_size);
        if (ret != TEE_SUCCESS)
            goto errorHandler;
    } else {
        ret = fill_attributes_to_object(params, &tmp_object, &attr_buf, &attr_buf_size);
        if (ret != TEE_SUCCESS)
            goto errorHandler;

        obj_inserted = true;
    }

    ret = fill_obj_data(tmp_object, params);
    if (ret != TEE_SUCCESS)
        goto errorHandler;

    ret = ssa_populate_msg(&msg, params, attr_buf, attr_buf_size);
    if (ret != TEE_SUCCESS)
        goto errorHandler;

    ret = ssa_send_msg_and_rcv(&msg, &rsp, params, tmp_object);
    if (ret != TEE_SUCCESS)
        goto errorHandler;

    ret = add_object_to_list(obj_inserted, tmp_object);
    if (ret != TEE_SUCCESS)
        goto closeAndDeleteObj;

    *object = tmp_object;
    goto out;

closeAndDeleteObj:
    msg.close_and_delete_obj.obj_index = (uintptr_t)tmp_object->dataPtr;
    ss_agent_proc_cmd(SS_AGENT_CLOSE_AND_DELETE_OBJECT, &msg, SS_AGENT_CLOSE_AND_DELETE_OBJECT, &rsp);
errorHandler:
    free_temp_object((TEE_ObjectHandle)(uintptr_t)(params->attributes), &tmp_object);

out: /* this is successful end. free share memory */
    (void)free_sharemem((void *)(uintptr_t)(msg.create_obj.object_id), msg.create_obj.obj_id_len + 1);
    (void)free_sharemem((void *)(uintptr_t)(msg.create_obj.initial_data), msg.create_obj.data_len);
    (void)free_sharemem(attr_buf, attr_buf_size);
    return ret;
}

static TEE_Result open_obj_proc_cmd(struct create_obj_msg_t *params, struct saved_attr_info_t *attr_head,
                                    uint32_t attr_head_size, union ssa_agent_msg *msg, struct ssa_agent_rsp *rsp)
{
    uint8_t *shared_buff = NULL;
    uint32_t shared_buff_size = params->obj_id_len;

    if (msg == NULL || rsp == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    shared_buff = alloc_sharemem_aux(&g_uuid, shared_buff_size);
    if (shared_buff == NULL) {
        tloge("malloc shared_buff for obj_id failed, size=%u\n", shared_buff_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memmove_s(shared_buff, shared_buff_size, (void *)(uintptr_t)(params->object_id), shared_buff_size);
    if (rc != EOK) {
        tloge("memmove object_id failed\n");
        (void)free_sharemem(shared_buff, shared_buff_size);
        return TEE_ERROR_SECURITY;
    }

    msg->open_obj.storage_id     = (uintptr_t)params->storage_id;
    msg->open_obj.object_id      = (uintptr_t)shared_buff;
    msg->open_obj.obj_id_len     = shared_buff_size;
    msg->open_obj.flags          = params->flags;
    msg->open_obj.attr_head_size = attr_head_size;
    msg->open_obj.attr_head      = (uintptr_t)attr_head;
    msg->open_obj.target_uuid    = params->target_uuid;

    rsp->ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(params->cmd_id, msg, params->cmd_id, rsp);

    (void)free_sharemem(shared_buff, shared_buff_size);

    return rsp->ret;
}

static TEE_Result ssa_read_attribute_restore(struct saved_attr_info_t *attr_head, TEE_ObjectHandle object,
                                             union ssa_agent_msg *msg, struct ssa_agent_rsp *rsp)
{
    uint8_t *shared_buff = NULL;
    uint32_t shared_buff_size;
    TEE_Result ret;

    shared_buff_size = attr_head->attr_size;
    shared_buff      = alloc_sharemem_aux(&g_uuid, shared_buff_size);
    if (shared_buff == NULL) {
        tloge("alloc shared_buff for attrBuf failed, size=%u\n", attr_head->attr_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg->get_obj_attrs.buffer    = (uintptr_t)shared_buff;
    msg->get_obj_attrs.size      = shared_buff_size;
    msg->get_obj_attrs.obj_index = (uintptr_t)object->dataPtr;

    rsp->ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_GET_OBJECT_ATTRIBUTES, msg, SS_AGENT_GET_OBJECT_ATTRIBUTES, rsp);

    if (rsp->ret != TEE_SUCCESS) {
        tloge("get attribute error!\n");
        (void)free_sharemem(shared_buff, shared_buff_size);
        return rsp->ret;
    }

    ret = restore_attrs(object, shared_buff, shared_buff_size, attr_head->attr_size, attr_head->attr_count);

    (void)free_sharemem(shared_buff, shared_buff_size);

    return ret;
}

static TEE_Result fill_object_data_from_rsp(TEE_ObjectHandle object,
                                            struct ssa_agent_rsp *rsp, struct saved_attr_info_t *attr_head)
{
    errno_t rc;

    object->dataPtr = (void *)(uintptr_t)rsp->open_obj.obj_index;
    rc = memmove_s(object->ObjectInfo, sizeof(TEE_ObjectInfo), &attr_head->object_info, sizeof(TEE_ObjectInfo));
    if (rc != EOK) {
        tloge("memmove_s object info fail!\n");
        return TEE_ERROR_SECURITY;
    }
    object->ObjectInfo->dataSize     = rsp->open_obj.new_size;
    object->ObjectInfo->dataPosition = rsp->open_obj.new_seek_pos;

    return TEE_SUCCESS;
}

static TEE_Result obj_restore_attrbutes(struct create_obj_msg_t *params, struct saved_attr_info_t *attr_head,
                                        TEE_ObjectHandle object, union ssa_agent_msg *msg, struct ssa_agent_rsp *rsp)
{
    TEE_Result ret;

    if (object == NULL || msg == NULL || rsp == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = fill_object_data_from_rsp(object, rsp, attr_head);
    if (ret != TEE_SUCCESS)
        return ret;

    if (attr_head->attr_size > 0) {
        ret = ssa_read_attribute_restore(attr_head, object, msg, rsp);
        if (ret != TEE_SUCCESS) {
            tloge("restore attribute fail!\n");
            msg->close_obj.obj_index = (uintptr_t)object->dataPtr;
            ss_agent_proc_cmd(SS_AGENT_CLOSE_OBJECT, msg, SS_AGENT_CLOSE_OBJECT, rsp);
            return ret;
        }
    }

    object->ObjectInfo->handleFlags =
        (uint32_t)TEE_HANDLE_FLAG_PERSISTENT | (uint32_t)TEE_HANDLE_FLAG_INITIALIZED | params->flags;

    ret = add_object(object);
    if (ret != TEE_SUCCESS) {
        msg->close_obj.obj_index = (uintptr_t)object->dataPtr;
        ss_agent_proc_cmd(SS_AGENT_CLOSE_OBJECT, msg, SS_AGENT_CLOSE_OBJECT, rsp);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result ss_agent_open_object(struct create_obj_msg_t *params, TEE_ObjectHandle *object)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    struct saved_attr_info_t *attr_head = NULL;
    uint32_t attr_head_size = 0;
    TEE_Result ret;
    TEE_ObjectHandle tmp_object = NULL;

    ssa_agent_init_msg(&msg, &rsp);
    if (params == NULL || (void *)(uintptr_t)(params->object_id) == NULL || object == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *object = NULL;

    if (tee_obj_new(&tmp_object) != TEE_SUCCESS) {
        tloge("not available to allocate the object handle\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = fill_obj_data(tmp_object, params);
    if (ret != TEE_SUCCESS)
        goto errorHandler;

    attr_head_size = sizeof(struct saved_attr_info_t);
    attr_head      = alloc_sharemem_aux(&g_uuid, attr_head_size);
    if (attr_head == NULL) {
        tloge("malloc attr_head failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto errorHandler;
    }

    ret = open_obj_proc_cmd(params, attr_head, attr_head_size, &msg, &rsp);
    if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
        /* file not exist, needn't print error log */
        goto errorHandler;
    } else if (ret != TEE_SUCCESS) {
        /* open fail, return */
        tloge("open failed, ret=0x%x\n", ret);
        goto errorHandler;
    }

    ret = obj_restore_attrbutes(params, attr_head, tmp_object, &msg, &rsp);
    if (ret != TEE_SUCCESS)
        goto errorHandler;

    *object = tmp_object;
    goto out;

errorHandler:
    (void)tee_obj_free(&tmp_object);

out:
    (void)free_sharemem(attr_head, attr_head_size);
    return ret;
}

static TEE_Result write_object_data_proc(TEE_ObjectHandle object, const void *buffer, uint32_t size)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    uint8_t *buf      = NULL;
    uint32_t split    = 1;
    const uint8_t *p  = NULL;
    uint32_t written  = 0;

    p = buffer;

    msg.write_obj.obj_index = (uintptr_t)object->dataPtr;
    uint32_t buf_size       = size;
    buf                     = alloc_sharemem_aux(&g_uuid, buf_size);
    /* If there is no enough memory for buffer, try to spit writing to smaller parts */
    while ((buf == NULL) && (split < MAX_SPLIT_NUM)) {
        split = DOUBLE(split);
        buf_size = size / split + FILL_NUM;
        buf      = alloc_sharemem_aux(&g_uuid, buf_size);
    }

    if (buf == NULL) {
        ss_agent_proc_cmd(SS_AGENT_FILE_ABORT, &msg, SS_AGENT_FILE_ABORT, &rsp);
        tloge("malloc shared_buff failed, size=%u, split=%u\n", size, split);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* if the size is odd, then it is not possible to divide it to parts with same size. */
    /* Here the first parts are bigger and latest part is smaller. */
    while (written < size) {
        /* msg content are overwrote during msg-sending so they have be to rewrite */
        msg.write_obj.buffer = (uintptr_t)buf;

        if (size - written > buf_size)
            msg.write_obj.len = buf_size;
        else
            msg.write_obj.len = size - written;

        if (memmove_s(buf, buf_size, p, msg.write_obj.len) != EOK) {
            rsp.ret = TEE_ERROR_SECURITY;
            break;
        }
        p += msg.write_obj.len;
        written += msg.write_obj.len;

        rsp.ret = TEE_ERROR_GENERIC;

        ss_agent_proc_cmd(SS_AGENT_WRITE_OBJECT, &msg, SS_AGENT_WRITE_OBJECT, &rsp);

        if (rsp.ret != TEE_SUCCESS) {
            tloge("write error\n");
            break;
        }
    }

    if (rsp.ret == TEE_SUCCESS) {
        object->ObjectInfo->dataSize     = rsp.write_obj.new_size;
        object->ObjectInfo->dataPosition = rsp.write_obj.new_seek_pos;
    }

    (void)free_sharemem(buf, buf_size);
    return rsp.ret;
}

TEE_Result ss_agent_write_object_data(TEE_ObjectHandle object, const void *buffer, uint32_t size)
{
    tlogd("start, write %u bytes\n", size);

    if (buffer == NULL || object == NULL || object->ObjectInfo == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return write_object_data_proc(object, buffer, size);
}

static TEE_Result read_object_data_proc(TEE_ObjectHandle object, void *buffer, uint32_t size, uint32_t *count)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    uint32_t split = 1;
    uint32_t read_count = 0;
    uint8_t *p = buffer;
    uint32_t buf_size = size;
    uint8_t *buf = alloc_sharemem_aux(&g_uuid, size);

    /* If there is no enough memory for buffer, try to spit data to smaller parts */
    while ((buf == NULL) && (split < MAX_SPLIT_NUM)) {
        split = DOUBLE(split);
        buf_size = size / split + FILL_NUM;
        buf      = alloc_sharemem_aux(&g_uuid, buf_size);
    }
    if (buf == NULL) {
        tloge("malloc shared_buff failed, size=%u, split=%u\n", size, split);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* if the size is odd, then it is not possible to divide it to parts with same size. */
    /* Here the first parts are bigger and latest part is smaller. */
    while (read_count < size) {
        /* msg content are overwrote during msg-sending so they have be to rewrite */
        msg.read_obj.obj_index = (uintptr_t)object->dataPtr;
        if (size - read_count > buf_size)
            msg.read_obj.len = buf_size;
        else
            msg.read_obj.len = size - read_count;

        msg.read_obj.buffer = (uintptr_t)buf;
        rsp.ret = TEE_ERROR_GENERIC;

        ss_agent_proc_cmd(SS_AGENT_READ_OBJECT, &msg, SS_AGENT_READ_OBJECT, &rsp);

        if (rsp.ret == TEE_SUCCESS) {
            object->ObjectInfo->dataSize     = rsp.read_obj.new_size;
            object->ObjectInfo->dataPosition = rsp.read_obj.new_seek_pos;
            if (rsp.read_obj.count == 0) {
                /* no more data */
                break;
            }

            if (memmove_s(p, size, buf, rsp.read_obj.count) != EOK) {
                rsp.ret = TEE_ERROR_SECURITY;
                break;
            }
            p += rsp.read_obj.count;
            read_count += rsp.read_obj.count;
        } else {
            read_count = 0;
            break;
        }
    }
    *count = read_count;

    (void)free_sharemem(buf, buf_size);
    return rsp.ret;
}

TEE_Result ss_agent_read_object_data(TEE_ObjectHandle object, void *buffer, uint32_t size, uint32_t *count)
{
    tlogd("start, read %u bytes\n", size);

    if (object == NULL || buffer == NULL || count == NULL || (object->ObjectInfo) == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return read_object_data_proc(object, buffer, size, count);
}

TEE_Result ss_agent_seek_object_data(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    TEE_Result ret;

    if (object == NULL || (object->ObjectInfo) == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.seek_obj.obj_index = (uintptr_t)object->dataPtr;
    msg.seek_obj.offset    = offset;
    msg.seek_obj.whence    = whence;

    rsp.ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_SEEK_OBJECT, &msg, SS_AGENT_SEEK_OBJECT, &rsp);

    ret = rsp.ret;

    if (ret == TEE_SUCCESS) {
        object->ObjectInfo->dataSize     = rsp.seek_obj.new_size;
        object->ObjectInfo->dataPosition = rsp.seek_obj.new_seek_pos;
    }

    return ret;
}

TEE_Result ss_agent_truncate_object_data(TEE_ObjectHandle object, int32_t size)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    TEE_Result ret;

    if (object == NULL || (object->ObjectInfo) == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.truncate_obj.obj_index = (uintptr_t)object->dataPtr;
    msg.truncate_obj.size      = size;

    rsp.ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_TRUNCATE_OBJECT, &msg, SS_AGENT_TRUNCATE_OBJECT, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        object->ObjectInfo->dataSize     = rsp.truncate_obj.new_size;
        object->ObjectInfo->dataPosition = rsp.truncate_obj.new_seek_pos;
        tlogd("seek %u, size %u\n", rsp.truncateObj.new_seek_pos, rsp.truncateObj.newSize);
    }

    return ret;
}

TEE_Result ss_agent_rename_object(TEE_ObjectHandle object, const void *new_object_id, uint32_t new_object_id_len)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    uint8_t *buf     = NULL;
    uint32_t buf_size;
    TEE_Result ret;
    errno_t rc;

    if (object == NULL || new_object_id == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.rename_obj.obj_index = (uintptr_t)object->dataPtr;

    buf_size = new_object_id_len;
    buf      = alloc_sharemem_aux(&g_uuid, buf_size);
    if (buf == NULL) {
        tloge("malloc shared_buff failed, size=%u\n", new_object_id_len);
        ss_agent_proc_cmd(SS_AGENT_FILE_ABORT, &msg, SS_AGENT_FILE_ABORT, &rsp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memmove_s(buf, buf_size, new_object_id, buf_size);
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto out;
    }

    msg.rename_obj.new_object_id = (uintptr_t)buf;
    msg.rename_obj.obj_id_len    = buf_size;

    rsp.ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_RENAME_OBJECT, &msg, SS_AGENT_RENAME_OBJECT, &rsp);

    ret = rsp.ret;

    if (ret == TEE_SUCCESS) {
        ret = tee_obj_setname(object, (uint8_t *)new_object_id, new_object_id_len);
        if (ret != TEE_SUCCESS) {
            tloge("tee obj set name failed , 0x%x\n", ret);
            goto out;
        }
    }

out:
    (void)free_sharemem(buf, buf_size);
    return ret;
}

TEE_Result ss_agent_get_object_info(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len)
{
    TEE_Result ret;
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    errno_t rc;

    if (object == NULL || pos == NULL || len == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.get_info_obj.obj_index = (uintptr_t)object->dataPtr;

    rc = memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    if (rc != EOK)
        tlogw("memset failed, %x\n", rc);
    rsp.ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_GET_OBJECT_INFO, &msg, SS_AGENT_GET_OBJECT_INFO, &rsp);

    ret  = rsp.ret;
    *pos = rsp.get_info_obj.pos;
    *len = rsp.get_info_obj.len;
    return ret;
}

void ss_agent_close_object(TEE_ObjectHandle object)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;

    if (object == NULL || (object->ObjectInfo) == NULL) {
        tloge("params invalid\n");
        return;
    }

    msg.close_obj.obj_index = (uintptr_t)object->dataPtr;
    rsp.ret                 = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_CLOSE_OBJECT, &msg, SS_AGENT_CLOSE_OBJECT, &rsp);

    /* Set object to to transient so it can be deleted */
    object->ObjectInfo->handleFlags &= (uint32_t)(~TEE_HANDLE_FLAG_PERSISTENT);
    TEE_FreeTransientObject(object);
}

TEE_Result ss_agent_close_and_delete_object(TEE_ObjectHandle object)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    TEE_Result ret;

    if (object == NULL || (object->ObjectInfo) == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.close_and_delete_obj.obj_index = (uintptr_t)object->dataPtr;
    rsp.ret                            = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_CLOSE_AND_DELETE_OBJECT, &msg, SS_AGENT_CLOSE_AND_DELETE_OBJECT, &rsp);

    ret = rsp.ret;
    /* Set object to to transient so it can be deleted */
    object->ObjectInfo->handleFlags &= (uint32_t)(~TEE_HANDLE_FLAG_PERSISTENT);
    TEE_FreeTransientObject(object);

    return ret;
}

TEE_Result ss_agent_sync_object(TEE_ObjectHandle object)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;
    TEE_Result ret;

    if (object == NULL) {
        tloge("params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.sync_obj.obj_index = (uintptr_t)object->dataPtr;
    rsp.ret                = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_SYNC_OBJECT, &msg, SS_AGENT_SYNC_OBJECT, &rsp);

    ret = rsp.ret;
    return ret;
}

TEE_Result ssagent_delete_all(TEE_UUID target)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;

    msg.delete_obj.target_uuid = target;
    rsp.ret                    = TEE_ERROR_GENERIC;
    ss_agent_proc_cmd(SS_AGENT_EXT_DELETE_ALL_OBJECT, &msg, SS_AGENT_EXT_DELETE_ALL_OBJECT, &rsp);

    return rsp.ret;
}

static uint32_t get_enum_file_size()
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;

    ssa_agent_init_msg(&msg, &rsp);
    rsp.ret = TEE_ERROR_GENERIC;

    ss_agent_proc_cmd(SS_AGENT_GET_ENUM_FILE_SIZE, &msg, SS_AGENT_GET_ENUM_FILE_SIZE, &rsp);

    if (rsp.ret != TEE_SUCCESS) {
        tloge("Failed to get the enum file size.\n");
        return 0;
    }

    return rsp.get_info_obj.len;
}

TEE_Result allocate_enum_handle(TEE_ObjectEnumHandle *obj_enumerator)
{
    if (obj_enumerator == NULL) {
        tloge("obj_enumerator is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *obj_enumerator = (TEE_ObjectEnumHandle)TEE_Malloc(sizeof(struct __TEE_ObjectEnumHandle), 0);
    if (*obj_enumerator == NULL) {
        tloge("allocate memory for enumerator failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    (*obj_enumerator)->enum_handle = (uintptr_t)TEE_Malloc(sizeof(struct obj_enum_handle_t), 0);
    if ((*obj_enumerator)->enum_handle == 0) {
        tloge("allocate memory for enumerator failed\n");
        TEE_Free(*obj_enumerator);
        *obj_enumerator = NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    return TEE_SUCCESS;
}

void free_enum_handle(TEE_ObjectEnumHandle obj_enumerator)
{
    if (obj_enumerator == NULL) {
        tloge("obj_enumerator is null");
        return;
    }

    struct obj_enum_handle_t *enum_handle = (struct obj_enum_handle_t *)(obj_enumerator->enum_handle);
    if (enum_handle != NULL) {
        TEE_Free(enum_handle->obj_enum_buf);
        enum_handle->obj_enum_buf = NULL;
        TEE_Free((void *)obj_enumerator->enum_handle);
        obj_enumerator->enum_handle = 0;
    }

    TEE_Free(obj_enumerator);
    obj_enumerator = 0;
}

void reset_enum_handle(TEE_ObjectEnumHandle obj_enumerator)
{
    errno_t ret_s;

    if (obj_enumerator == NULL) {
        tloge("obj_enumerator is null");
        return;
    }

    struct obj_enum_handle_t *enum_handle = (struct obj_enum_handle_t *)(obj_enumerator->enum_handle);
    if (enum_handle == NULL) {
        tloge("enum_handle is null");
        return;
    }

    TEE_Free(enum_handle->obj_enum_buf);
    enum_handle->obj_enum_buf = NULL;

    ret_s = memset_s(enum_handle, sizeof(struct obj_enum_handle_t), 0, sizeof(struct obj_enum_handle_t));
    if (ret_s != EOK) {
        tloge("Failed to memset objectEnumerator, please check.\n");
        return;
    }
}

TEE_Result ta_start_enumerator(TEE_ObjectEnumHandle obj_enumerator)
{
    union ssa_agent_msg msg;
    struct ssa_agent_rsp rsp;

    if (obj_enumerator == NULL || obj_enumerator->enum_handle == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    struct obj_enum_handle_t *enum_handle = (struct obj_enum_handle_t *)(obj_enumerator->enum_handle);

    if (enum_handle->active_status == ENUM_FLAG_ACTIVED) {
        tlogd("Enumerator has been started!");
        reset_enum_handle(obj_enumerator);
    }

    uint32_t enum_file_len = get_enum_file_size();
    if (enum_file_len == 0) {
        enum_handle->active_status = ENUM_FLAG_ACTIVED;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    uint8_t *buf = alloc_sharemem_aux(&g_uuid, enum_file_len);
    if (buf == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    msg.read_obj.len    = enum_file_len;
    msg.read_obj.buffer = (uintptr_t)buf;
    rsp.ret             = TEE_ERROR_GENERIC;
    ss_agent_proc_cmd(SS_AGENT_START_ENUMERATOR, &msg, SS_AGENT_START_ENUMERATOR, &rsp);
    if (rsp.ret != TEE_SUCCESS) {
        tloge("Failed to get the enumerator information.\n");
        (void)free_sharemem(buf, enum_file_len);
        return rsp.ret;
    }

    enum_handle->obj_enum_buf = TEE_Malloc(enum_file_len, 0);
    if (enum_handle->obj_enum_buf == NULL) {
        (void)free_sharemem(buf, enum_file_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t ret_s = memcpy_s(enum_handle->obj_enum_buf, enum_file_len, buf, enum_file_len);
    if (ret_s != EOK) {
        tloge("mem copy obj_enum_buf fail");
        rsp.ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    enum_handle->offset           = 0;
    enum_handle->obj_enum_buf_len = enum_file_len;
    enum_handle->active_status    = ENUM_FLAG_ACTIVED;

    (void)free_sharemem(buf, enum_file_len);
    return TEE_SUCCESS;

clean:
    TEE_Free(enum_handle->obj_enum_buf);
    (void)free_sharemem(buf, enum_file_len);
    return rsp.ret;
}

TEE_Result ta_get_next(TEE_ObjectEnumHandle obj_enumerator, TEE_ObjectInfo *object_info,
                       uint8_t *object_id, size_t *object_id_len)
{
    struct object_enum_info *obj_enum_info = NULL;
    errno_t ret_s;

    bool param_check = (obj_enumerator == NULL) || (obj_enumerator->enum_handle == 0) || (object_info == NULL) ||
                       (object_id == NULL) || (object_id_len == NULL);
    if (param_check)
        return TEE_ERROR_BAD_PARAMETERS;

    struct obj_enum_handle_t *enum_handle = (struct obj_enum_handle_t *)(obj_enumerator->enum_handle);

    if (enum_handle->active_status == ENUM_FLAG_NOT_ACTIVED) {
        tloge("The object enumerator is not started.\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    if (enum_handle->offset >= enum_handle->obj_enum_buf_len ||
        enum_handle->offset % sizeof(struct object_enum_info) != 0) {
        tloge("There are no more object in the enumeration.\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    if (enum_handle->obj_enum_buf == NULL) {
        tloge("There are no object in the enumeration.\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    obj_enum_info = (struct object_enum_info *)(enum_handle->obj_enum_buf + enum_handle->offset);

    ret_s = memcpy_s(object_info, sizeof(TEE_ObjectInfo), &(obj_enum_info->obj_info), sizeof(TEE_ObjectInfo));
    if (ret_s != EOK) {
        tloge("Failed to copy object info.\n");
        return TEE_ERROR_SECURITY;
    }

    if (*object_id_len < obj_enum_info->object_id_len + 1) {
        tloge("object id len is too short");
        *object_id_len = obj_enum_info->object_id_len + 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    ret_s = memcpy_s(object_id, *object_id_len, obj_enum_info->object_id, obj_enum_info->object_id_len);
    if (ret_s != EOK) {
        tloge("Failed to copy ObjectID.\n");
        return TEE_ERROR_SECURITY;
    }

    *object_id_len            = obj_enum_info->object_id_len;
    object_id[*object_id_len] = '\0';
    enum_handle->offset += sizeof(struct object_enum_info);

    return TEE_SUCCESS;
}


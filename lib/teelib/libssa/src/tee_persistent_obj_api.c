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
#include "tee_trusted_storage_api.h"
#include "ta_framework.h"
#include "tee_ss_agent_api.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "crypto_inner_defines.h"
#include "tee_ext_trusted_storage_api.h"
#include "tee_obj_attr.h"

#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do { \
    } while (0)
#endif

#define LITTLE_TO_BIG 3UL

/* rotate 32-bits word by 16 bits */
#define TEE_CRYS_COMMON_ROT32(x) (((x) >> 16) | ((x) << 16))

/* inverse the bytes order in a word */
#define TEE_CRYS_COMMON_REVERSE32(x)  (((TEE_CRYS_COMMON_ROT32((x)) & 0xff00ff00UL) >> 8) | \
                                       ((TEE_CRYS_COMMON_ROT32((x)) & 0x00ff00ffUL) << 8))
#define HALF_OF(x) ((x) / 2)
static void tee_convert_bytes_words_and_array_endianness(
    uint32_t *buf_ptr,
    uint32_t  size_words)
{
    uint32_t i, tmp;

    if (buf_ptr == NULL)
        return;

    /* Reverse words order and bytes in each word */
    for (i = 0; i < HALF_OF(size_words); i++) {
        tmp = TEE_CRYS_COMMON_REVERSE32(buf_ptr[i]);
        buf_ptr[i] = TEE_CRYS_COMMON_REVERSE32(buf_ptr[size_words - i - 1]);
        buf_ptr[size_words - i - 1] = tmp;
    }
    if (size_words & 1UL)
        buf_ptr[HALF_OF(size_words)] = TEE_CRYS_COMMON_REVERSE32(buf_ptr[HALF_OF(size_words)]);

    return;
}

TEE_Result  tee_ConvertLswMswWordsToMsbLsbBytes(
    uint8_t *out8_ptr,
    uint32_t out_size,
    uint32_t *in32_ptr,
    uint32_t  size_in_bytes)
{
    /* FUNCTION DECLARATIONS */
    uint32_t size_in_words;

    if (out8_ptr == NULL || in32_ptr == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Size in words rounded up */
    size_in_words = (size_in_bytes + (UINT32_SIZE - 1)) / UINT32_SIZE;

    /* Reverse words order and bytes according to endianness of CPU */
    tee_convert_bytes_words_and_array_endianness(in32_ptr, size_in_words);

    /* Copy output buffer */
    if ((uintptr_t)out8_ptr != (uintptr_t)in32_ptr) {
        if (out_size < size_in_bytes)
            return TEE_ERROR_BAD_PARAMETERS;
        if (memmove_s(out8_ptr, out_size,
                      (uint8_t *)in32_ptr + ((UINT32_SIZE - (size_in_bytes & LITTLE_TO_BIG)) & LITTLE_TO_BIG),
                      size_in_bytes) != EOK)
            return TEE_ERROR_SECURITY;
        /* Revert the input buffer to previous state */
        tee_convert_bytes_words_and_array_endianness(in32_ptr, size_in_words);
    }

    return TEE_SUCCESS;
}

static TEE_Result check_object_id(const void *object_id, size_t object_id_len, size_t object_id_max_len)
{
    if (object_id == NULL ||
        strnlen(object_id, object_id_max_len) >= object_id_max_len) {
        tloge("bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (strlen((const char *)object_id) != object_id_len) {
        tloge("objectID string length is less than objectIDLen!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_file_name(object_id)) {
        tloge("file name invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_object_param(uint32_t storage_id, const void *object_id, size_t object_id_len)
{
    TEE_Result ret = check_object_id(object_id, object_id_len, MAX_FILE_ID_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("Check object id failed!\n");
        return ret;
    }

    if (check_name_by_storageid(object_id, object_id_len, storage_id)) {
        tloge("Check name by storage id failed!\n");
        return TEE_ERROR_STORAGE_PATH_WRONG;
    }

    return TEE_SUCCESS;
}

static TEE_Result g_create_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_ITEM_NOT_FOUND,
    TEE_ERROR_ACCESS_CONFLICT,
    TEE_ERROR_OUT_OF_MEMORY,
    TEE_ERROR_STORAGE_NO_SPACE,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_open_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_ITEM_NOT_FOUND,
    TEE_ERROR_ACCESS_CONFLICT,
    TEE_ERROR_OUT_OF_MEMORY,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_read_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_write_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_STORAGE_NO_SPACE,
    TEE_ERROR_OVERFLOW,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_truncate_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_STORAGE_NO_SPACE,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_seek_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_OVERFLOW,
    TEE_ERROR_CORRUPT_OBJECT,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};
static TEE_Result g_close_obj_specify_value[] = {
    TEE_SUCCESS,
    TEE_ERROR_STORAGE_NOT_AVAILABLE
};

typedef enum object_operation_type {
    OBJECT_OP_CREATE = 0,
    OBJECT_OP_OPEN,
    OBJECT_OP_READ,
    OBJECT_OP_WRITE,
    OBJECT_OP_TRUNCATE,
    OBJECT_OP_SEEK,
    OBJECT_OP_CLOSE
}obj_oper_type;

typedef struct object_operation_info {
    obj_oper_type oper_type;
    TEE_Result *spec_return_value;
    uint32_t value_num;
}obj_oper_info;

static obj_oper_info g_obj_oper_list[] = {
    { OBJECT_OP_CREATE,   g_create_obj_specify_value,   ELEM_NUM(g_create_obj_specify_value) },
    { OBJECT_OP_OPEN,     g_open_obj_specify_value,     ELEM_NUM(g_open_obj_specify_value) },
    { OBJECT_OP_READ,     g_read_obj_specify_value,     ELEM_NUM(g_read_obj_specify_value) },
    { OBJECT_OP_WRITE,    g_write_obj_specify_value,    ELEM_NUM(g_write_obj_specify_value) },
    { OBJECT_OP_TRUNCATE, g_truncate_obj_specify_value, ELEM_NUM(g_truncate_obj_specify_value) },
    { OBJECT_OP_SEEK,     g_seek_obj_specify_value,     ELEM_NUM(g_seek_obj_specify_value) },
    { OBJECT_OP_CLOSE,    g_close_obj_specify_value,    ELEM_NUM(g_close_obj_specify_value) }
};

static void check_oper_object_return_value(TEE_Result return_val, uint32_t oper_type)
{
    if (oper_type > OBJECT_OP_CLOSE)
        return;

    uint32_t i;
    bool is_gp_specify_value = false;

    TEE_Result *gp_specify_value = g_obj_oper_list[oper_type].spec_return_value;
    uint32_t value_num = g_obj_oper_list[oper_type].value_num;

    for (i = 0; i < value_num; i++) {
        if (gp_specify_value[i] == return_val) {
            is_gp_specify_value = true;
            break;
        }
    }

    if (is_gp_specify_value)
        return;

    TEE_Panic(return_val);
}

static TEE_Result check_create_storage_id(uint32_t storage_id)
{
    bool storage_valid_flag = (storage_id == TEE_OBJECT_STORAGE_PRIVATE) ||
        (storage_id == TEE_OBJECT_STORAGE_CE);

    if (!storage_valid_flag) {
        tloge("bad storageID!\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    return TEE_SUCCESS;
}

static void fill_id_params(struct create_obj_msg_t *params, uint32_t cmd_id, uint32_t storage_id,
                           const void *object_id, uint32_t object_id_len)
{
    params->cmd_id = cmd_id;
    params->storage_id = storage_id;
    params->object_id = (uintptr_t)object_id;
    params->obj_id_len = object_id_len;
}

static void fill_data_params(struct create_obj_msg_t *params, const void *initial_data, uint32_t initial_data_len,
                             uint32_t flags, TEE_ObjectHandle attributes)
{
    params->flags = flags;
    params->initial_data = (uintptr_t)initial_data;
    params->data_len = initial_data_len;
    params->attributes = (uintptr_t)attributes;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, const void *objectID, size_t objectIDLen, uint32_t flags,
    TEE_ObjectHandle attributes, const void *initialData, size_t initialDataLen, TEE_ObjectHandle *object)
{
    TEE_Result ret = check_create_storage_id(storageID);
    if (ret != TEE_SUCCESS)
        return ret;

    if ((attributes != NULL) && (check_object_valid(attributes) != TEE_SUCCESS)) {
        tloge("The attributes is invalid object!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = check_object_param(storageID, objectID, objectIDLen);
    if (ret != TEE_SUCCESS) {
        tloge("Object id is invalid!\n");
        TEE_Panic(ret);
        return ret;
    }

    /* if no w&r permission ,add default read */
    if (((flags & TEE_DATA_FLAG_ACCESS_WRITE) == 0) &&
        ((flags & TEE_DATA_FLAG_ACCESS_READ) == 0))
        flags = (flags | TEE_DATA_FLAG_ACCESS_READ);

    TEE_UUID uuid = {0};
    struct create_obj_msg_t params;
    params.target_uuid = uuid;
    fill_id_params(&params, SS_AGENT_CREATE_OBJECT, storageID, objectID, objectIDLen);
    fill_data_params(&params, initialData, initialDataLen, flags, attributes);
    ret = ss_agent_create_object(&params, object);
    check_oper_object_return_value(ret, OBJECT_OP_CREATE);

    return ret;
}

static TEE_Result open_object_by_storage_id(uint32_t storage_id, const void *object_id, size_t object_id_len,
    uint32_t flags, TEE_ObjectHandle *object)
{
    TEE_UUID uuid = {0};
    struct create_obj_msg_t params;
    params.target_uuid = uuid;
    fill_id_params(&params, SS_AGENT_OPEN_OBJECT, storage_id, object_id, object_id_len);
    fill_data_params(&params, NULL, 0, flags, TEE_HANDLE_NULL);
    return ss_agent_open_object(&params, object);
}

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void *objectID, size_t objectIDLen,
                                    uint32_t flags, TEE_ObjectHandle *object)
{
    TEE_Result ret;
    /* para */
    bool storage_valid_flag = (storageID == TEE_OBJECT_STORAGE_PRIVATE) ||
        (storageID == TEE_OBJECT_STORAGE_CE);
    if (storage_valid_flag != true) {
        tloge("bad storageID!\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    ret = check_object_param(storageID, objectID, objectIDLen);
    if (ret != TEE_SUCCESS) {
        tloge("Object id is invalid!\n");
        TEE_Panic(ret);
        return ret;
    }
    /* start: if no w&r permission ,add default read */
    if (((flags & TEE_DATA_FLAG_ACCESS_WRITE) == 0) && ((flags & TEE_DATA_FLAG_ACCESS_READ) == 0)) {
        flags = (flags | TEE_DATA_FLAG_ACCESS_READ);
        tlogd("add read\n");
    }

    ret = open_object_by_storage_id(storageID, objectID, objectIDLen, flags, object);
    check_oper_object_return_value(ret, OBJECT_OP_OPEN);
    return ret;
}

static TEE_Result check_operator_object_valid(TEE_ObjectHandle object)
{
    if (object == NULL) {
        tloge("Object is NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("Object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("Bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) == 0) {
        tloge("Object is not a persistent object\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count)
{
    if (buffer == NULL || count == NULL || size == 0 || size > MAX_FILE_SIZE) {
        tloge("bad parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_operator_object_valid(object);
    if (ret != TEE_SUCCESS) {
        tloge("Object is not a valid object!\n");
        TEE_Panic(ret);
        return ret;
    }

    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_READ) == 0) {
        tloge("Access denied\n");
        TEE_Panic(TEE_ERROR_ACCESS_DENIED);
        return TEE_ERROR_ACCESS_DENIED;
    }

    ret = ss_agent_read_object_data(object, buffer, size, count);
    check_oper_object_return_value(ret, OBJECT_OP_READ);

    return ret;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void *buffer, size_t size)
{
    if (buffer == NULL || size == 0 || size > MAX_FILE_SIZE) {
        tloge("bad parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_operator_object_valid(object);
    if (ret != TEE_SUCCESS) {
        tloge("Object is not a valid persistent object!\n");
        TEE_Panic(ret);
        return ret;
    }

    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE) == 0) {
        tloge("Access denied\n");
        TEE_Panic(TEE_ERROR_ACCESS_DENIED);
        return TEE_ERROR_ACCESS_DENIED;
    }

    ret = ss_agent_write_object_data(object, buffer, size);
    check_oper_object_return_value(ret, OBJECT_OP_WRITE);
    return ret;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, size_t size)
{
    if (size > MAX_FILE_SIZE) {
        tloge("bad parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_operator_object_valid(object);
    if (ret != TEE_SUCCESS) {
        tloge("Object is not a valid object!\n");
        TEE_Panic(ret);
        return ret;
    }

    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE) == 0) {
        tloge("Access denied\n");
        TEE_Panic(TEE_ERROR_ACCESS_DENIED);
        return TEE_ERROR_ACCESS_DENIED;
    }

    ret = ss_agent_truncate_object_data(object, (int32_t)size);
    check_oper_object_return_value(ret, OBJECT_OP_TRUNCATE);
    return ret;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
    int32_t offset_size = (offset < 0) ? (-offset) : offset;

    if (offset_size > MAX_FILE_SIZE) {
        tloge("bad parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_operator_object_valid(object);
    if (ret != TEE_SUCCESS) {
        tloge("Object is not a valid object!\n");
        TEE_Panic(ret);
        return ret;
    }

    ret = ss_agent_seek_object_data(object, offset, whence);
    check_oper_object_return_value(ret, OBJECT_OP_SEEK);
    return ret;
}

static void close_object_by_storage_id(TEE_ObjectHandle object)
{
    ss_agent_close_object(object);
}

static void delete_object_by_storage_id(TEE_ObjectHandle object)
{
    if (ss_agent_close_and_delete_object(object) != TEE_SUCCESS)
        tloge("Close and del object failed\n");
}

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
    if (object == TEE_HANDLE_NULL) {
        tloge("object is TEE_HANDLE_NULL.\n");
        return;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return;
    }

    if (object->ObjectInfo == NULL) {
        tloge("bad parameter!\n");
        return;
    }

    /* check permission */
    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) == 0) {
        tloge("Access denied, Can not delete, only close object.\n");
        /* if object no write meta flag,
         * we only close the file so that free resource */
        if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
            tlogd("this is a persistent object\n");
            close_object_by_storage_id(object);
        } else {
            tlogd("this is a transitent object\n");
            TEE_FreeTransientObject(object);
            tlogd("TEE_CloseObject end!\n");
        }
        return;
    }

    delete_object_by_storage_id(object);
    return;
}

TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
    TEE_Result ret = check_operator_object_valid(object);
    if (ret != TEE_SUCCESS) {
        tloge("Object is not a valid object!\n");
        TEE_Panic(ret);
        return ret;
    }

    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) == 0) {
        tloge("Access denied\n");
        TEE_Panic(TEE_ERROR_ACCESS_DENIED);
        return TEE_ERROR_ACCESS_DENIED;
    }

    ret = ss_agent_close_and_delete_object(object);
    check_oper_object_return_value(ret, OBJECT_OP_CLOSE);
    return ret;
}

TEE_Result TEE_SyncPersistentObject(TEE_ObjectHandle object)
{
    /* param check */
    if (object == TEE_HANDLE_NULL) {
        tloge("object is TEE_HANDLE_NULL.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return ss_agent_sync_object(object);
}

TEE_Result TEE_RenamePersistentObject(
    TEE_ObjectHandle object,
    void *newObjectID,
    size_t newObjectIDLen)
{
    if (object == NULL || newObjectID == NULL ||
        strnlen(newObjectID, HASH_NAME_BUFF_LEN) >= HASH_NAME_BUFF_LEN) {
        tloge("bad parameter!\n");
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (strlen((const char *)newObjectID) != newObjectIDLen) {
        tloge("newObjectID string length is less than newObjectIDLen!\n");
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_file_name(newObjectID)) {
        tloge("file name invalid!\n");
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* check permission */
    if ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) == 0) {
        tloge("Access denied\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    return ss_agent_rename_object(object, newObjectID, newObjectIDLen);
}

static pthread_mutex_t g_enum_mutex = PTHREAD_MUTEX_INITIALIZER;
TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *obj_enumerator)
{
    TEE_Result ret;

    if (obj_enumerator == TEE_HANDLE_NULL) {
        tloge("objectEnumerator is null.\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (mutex_lock_ops(&g_enum_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = allocate_enum_handle(obj_enumerator);
    if (ret != TEE_SUCCESS) {
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return ret;
    }

    ret = add_enum_object_in_list(*obj_enumerator);
    if (ret != TEE_SUCCESS) {
        tloge("add enum object fail, ret:0x%x", ret);
        free_enum_handle(*obj_enumerator);
        *obj_enumerator = NULL;
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return ret;
    }

    (void)pthread_mutex_unlock(&g_enum_mutex);

    return TEE_SUCCESS;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle obj_enumerator)
{
    if (obj_enumerator == TEE_HANDLE_NULL) {
        tloge("The objectEnumerator is NULL, return\n");
        return;
    }

    if (mutex_lock_ops(&g_enum_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return;
    }

    if (check_enum_object_in_list(obj_enumerator) != TEE_SUCCESS) {
        tloge("enum object is invalid");
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return;
    }

    delete_enum_object_in_list(obj_enumerator);
    free_enum_handle(obj_enumerator);
    obj_enumerator = NULL;

    (void)pthread_mutex_unlock(&g_enum_mutex);
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle obj_enumerator)
{
    if (obj_enumerator == TEE_HANDLE_NULL) {
        tloge("bad object parameter!\n");
        return;
    }

    if (mutex_lock_ops(&g_enum_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return;
    }

    if (check_enum_object_in_list(obj_enumerator) != TEE_SUCCESS) {
        tloge("enum object is invalid");
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return;
    }

    reset_enum_handle(obj_enumerator);

    (void)pthread_mutex_unlock(&g_enum_mutex);
}

TEE_Result TEE_StartPersistentObjectEnumerator(
    TEE_ObjectEnumHandle obj_enumerator, uint32_t storage_id)
{
    TEE_Result ret;

    if (storage_id != TEE_OBJECT_STORAGE_PRIVATE) {
        tloge("bad storageID!\n");
        return  TEE_ERROR_ITEM_NOT_FOUND;
    }

    if (obj_enumerator == TEE_HANDLE_NULL) {
        tloge("objectEnumerator is null, please check.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (mutex_lock_ops(&g_enum_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (check_enum_object_in_list(obj_enumerator) != TEE_SUCCESS) {
        tloge("enum object is invalid");
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = ta_start_enumerator(obj_enumerator);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute ta_start_enumerator, ret=0x%x\n", ret);
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return ret;
    }

    (void)pthread_mutex_unlock(&g_enum_mutex);

    return TEE_SUCCESS;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle obj_enumerator,
                                       TEE_ObjectInfo *object_info,
                                       void *object_id,
                                       size_t *object_id_len)
{
    TEE_Result ret;

    if (obj_enumerator == NULL || object_info == NULL ||
        object_id == NULL || object_id_len == NULL) {
        tloge("Bad parameters, please check.\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (mutex_lock_ops(&g_enum_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (check_enum_object_in_list(obj_enumerator) != TEE_SUCCESS) {
        tloge("enum object is invalid");
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = ta_get_next(obj_enumerator, object_info, object_id, object_id_len);
    if (ret != TEE_SUCCESS) {
        (void)pthread_mutex_unlock(&g_enum_mutex);
        return ret;
    }

    (void)pthread_mutex_unlock(&g_enum_mutex);

    return TEE_SUCCESS;
}

TEE_Result tee_ext_create_persistent_object(
    TEE_UUID target, uint32_t storage_id, const void *object_id, size_t object_id_len, uint32_t flags,
    TEE_ObjectHandle attributes, const void *initial_data, size_t initial_data_len, TEE_ObjectHandle *object)
{
    (void)object_id;
    (void)object_id_len;
    (void)initial_data;
    (void)initial_data_len;
    (void)flags;
    (void)attributes;
    (void)object;
    (void)target;
    (void)storage_id;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_open_persistent_object(
    TEE_UUID target,
    uint32_t storage_id,
    const void *object_id, size_t object_id_len,
    uint32_t flags,
    TEE_ObjectHandle *object)
{
    (void)target;
    (void)storage_id;
    (void)object_id;
    (void)object_id_len;
    (void)flags;
    (void)object;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_delete_all_objects(TEE_UUID target)
{
    (void)target;
    return TEE_ERROR_NOT_SUPPORTED;
}


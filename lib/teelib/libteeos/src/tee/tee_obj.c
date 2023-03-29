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
#include "tee_obj.h"
#include <dlist.h>
#include <securec.h>

#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_fs.h"
#include "tee_trusted_storage_api.h"

#define OBJ_ROBUST_MAX_VALUE  1
#define OBJ_SUCCESS           0
#define OBJ_ERROR             (-1)
#define TEE_OBJECT_FREE_MAGIC 0xabcdabcd

struct valid_objects {
    TEE_ObjectHandle obj_id;
    TEE_ObjectHandle first_obj_link;
    struct dlist_node list;
};

static struct dlist_node g_object_head;
static pthread_mutex_t g_object_mutex;

struct valid_enum_objects {
    TEE_ObjectEnumHandle enum_obj_id;
    struct dlist_node list;
};
static struct dlist_node g_enum_obj_info_list;

#define MEMORY_DUMP_BLOCK_SIZE 16
#define MEMORY_DUMP_LINE_SIZE  64

void tee_memory_dump(const uint8_t *data, uint32_t count)
{
    // backward compatibility
    (void)data;
    (void)count;
}

TEE_Result tee_obj_setname(TEE_ObjectHandle object, const uint8_t *name, uint32_t len)
{
    errno_t rc;

    if ((object == NULL) || (name == NULL) || (len > (HASH_NAME_BUFF_LEN - 1)))
        return TEE_ERROR_BAD_PARAMETERS;

    rc = memmove_s(object->dataName, sizeof(object->dataName), name, len);
    if (rc != EOK) {
        tloge("move name is failed, name : %s\n", name);
        return TEE_ERROR_SECURITY;
    }

    object->dataName[len] = '\0';
    object->dataLen       = len;

    return TEE_SUCCESS;
}

TEE_Result tee_obj_new(TEE_ObjectHandle *object)
{
    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *object = TEE_Malloc(sizeof(struct __TEE_ObjectHandle) + sizeof(TEE_ObjectInfo), 0);
    if (*object == NULL) {
        tloge("not available to allocate the object handle\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    (*object)->ObjectInfo = (TEE_ObjectInfo *)(*object + 1);

    return TEE_SUCCESS;
}

TEE_Result tee_obj_free(TEE_ObjectHandle *object)
{
    if ((object == NULL) || (*object == NULL))
        return TEE_ERROR_BAD_PARAMETERS;

    (*object)->infoattrfd = (void *)TEE_OBJECT_FREE_MAGIC;

    TEE_Free(*object);
    *object = NULL;

    return TEE_SUCCESS;
}

TEE_Result tee_obj_init(void)
{
    (void)pthread_mutex_init(&g_object_mutex, NULL);
	dlist_init(&g_object_head);
    dlist_init(&g_enum_obj_info_list);
    return TEE_SUCCESS;
}

int mutex_lock_ops(pthread_mutex_t *mutex)
{
    int ret;
    if (mutex == NULL)
        return OBJ_ERROR;

    ret = pthread_mutex_lock(mutex);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mutex);

    return ret;
}

void dump_object(void)
{
    struct valid_objects *vo = NULL;
    TEE_ObjectHandle object  = NULL;

    if (dlist_empty(&g_object_head)) {
        tlogd("not found any valid obj in list\n");
        return;
    }

    if (mutex_lock_ops(&g_object_mutex) != 0) {
        tloge("mutex lock ops is failed\n");
        return;
    }
    dlist_for_each_entry(vo, &g_object_head, struct valid_objects, list) {
        object = vo->obj_id;
        if (object && object->ObjectInfo != 0)
            tlogd("obj_id=0x%x, type=0x%x, fileName=%s\n", vo->obj_id, object->ObjectInfo->objectType,
                  object->dataName);
    }
    (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
}

TEE_Result check_object(const TEE_ObjectHandle object)
{
    struct valid_objects *vo = NULL;

    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (mutex_lock_ops(&g_object_mutex) != 0) {
        tloge("mutex lock ops is failed\n");
        return TEE_ERROR_GENERIC;
    }
    dlist_for_each_entry(vo, &g_object_head, struct valid_objects, list) {
        if (vo->obj_id == object) {
            (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
            return TEE_SUCCESS;
        }
    }
    (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result add_object(TEE_ObjectHandle object)
{
    struct valid_objects *new_vo = NULL;
    struct valid_objects *tmp_vo = NULL;
    TEE_ObjectHandle tmp_object  = NULL;

    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    new_vo = TEE_Malloc(sizeof(*new_vo), 0);
    if (new_vo == NULL) {
        tloge("apply new valid object failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Init new list entry */
    dlist_init(&new_vo->list);
    new_vo->obj_id         = object;
    new_vo->first_obj_link = NULL;

    if (mutex_lock_ops(&g_object_mutex) != 0) {
        tloge("mutex lock ops failed\n");
        TEE_Free(new_vo);
        return TEE_ERROR_GENERIC;
    }
    /* Find the first same object for permission checking in future */
    dlist_for_each_entry(tmp_vo, &g_object_head, struct valid_objects, list) {
        tmp_object = tmp_vo->obj_id;
        if ((tmp_object != NULL) && (tmp_object->dataLen == object->dataLen) &&
            (TEE_MemCompare(tmp_object->dataName, object->dataName, object->dataLen) == 0)) {
            new_vo->first_obj_link = tmp_vo->obj_id;
            break;
        }
    }

    /* Insert to list head */
    dlist_insert_head(&new_vo->list, &g_object_head);
    (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */

    return TEE_SUCCESS;
}

TEE_Result delete_object(const TEE_ObjectHandle object)
{
    struct valid_objects *vo  = NULL;
    struct valid_objects *tmp = NULL;

    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (mutex_lock_ops(&g_object_mutex) != 0) {
        tloge("mutex lock ops failed\n");
        return TEE_ERROR_GENERIC;
    }
    dlist_for_each_entry_safe(vo, tmp, &g_object_head, struct valid_objects, list) {
        if (vo->obj_id == object) {
            dlist_delete(&vo->list);
            TEE_Free(vo);
            vo = NULL;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
    return TEE_SUCCESS;
}

struct object_permission {
    bool r;
    bool w;
    bool rs;
    bool ws;
    bool ro;
    bool wo;
};

#define perm_bool(value) (((value) != 0) ? true : false)

TEE_Result check_permission(const char *object_id, size_t object_id_len, uint32_t flags)
{
    struct valid_objects *vo      = NULL;
    struct object_permission perm = { 0 };
    bool perm_check_ret           = false;
    TEE_ObjectHandle object       = NULL;

    if (object_id == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (mutex_lock_ops(&g_object_mutex) != 0) {
        tloge("mutex lock ops failed\n");
        return TEE_ERROR_GENERIC;
    }
    dlist_for_each_entry(vo, &g_object_head, struct valid_objects, list) {
        if (vo->first_obj_link != NULL)
            object = vo->first_obj_link;
        else
            object = vo->obj_id;

        if ((object != NULL) && (object->dataLen == object_id_len) &&
            (TEE_MemCompare(object->dataName, object_id, object_id_len) == 0)) {
            /* check permission */
            if ((object->ObjectInfo == NULL) ||
                ((object->ObjectInfo->handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META) != 0)) {
                (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
                return TEE_ERROR_ACCESS_CONFLICT;
            }
            perm.r  = perm_bool(flags & TEE_DATA_FLAG_ACCESS_READ) && perm_bool(flags & TEE_DATA_FLAG_SHARE_READ);
            perm.w  = perm_bool(flags & TEE_DATA_FLAG_ACCESS_WRITE) && perm_bool(flags & TEE_DATA_FLAG_SHARE_WRITE);
            perm.ro = perm_bool(flags & TEE_DATA_FLAG_ACCESS_READ) && perm_bool(flags);
            perm.wo = perm_bool(flags & TEE_DATA_FLAG_ACCESS_WRITE) && perm_bool(flags);
            perm.ws = perm_bool(object->ObjectInfo->handleFlags & TEE_DATA_FLAG_SHARE_WRITE);
            perm.rs = perm_bool(object->ObjectInfo->handleFlags & TEE_DATA_FLAG_SHARE_READ);
            perm_check_ret = ((perm.r && perm.rs && (!perm.wo)) || (perm.w && perm.ws && (!perm.ro)) ||
                              (perm.r && perm.rs && perm.w && perm.ws));

            if (!perm_check_ret) {
                tloge("can't share\n");
                (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
                return TEE_ERROR_ACCESS_CONFLICT;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_object_mutex); /* no need to verify return value here */
    return TEE_SUCCESS;
}

TEE_Result check_enum_object_in_list(const TEE_ObjectEnumHandle object)
{
    struct valid_enum_objects *valid_enum_obj = NULL;

    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    dlist_for_each_entry(valid_enum_obj, &g_enum_obj_info_list, struct valid_enum_objects, list) {
        if (valid_enum_obj->enum_obj_id == object)
            return TEE_SUCCESS;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result add_enum_object_in_list(const TEE_ObjectEnumHandle object)
{
    struct valid_enum_objects *new_enum_obj = NULL;

    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    new_enum_obj = TEE_Malloc(sizeof(*new_enum_obj), 0);
    if (new_enum_obj == NULL) {
        tloge("apply new valid object failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Init new list entry */
    dlist_init(&new_enum_obj->list);
    new_enum_obj->enum_obj_id = object;

    dlist_insert_head(&new_enum_obj->list, &g_enum_obj_info_list);
    return TEE_SUCCESS;
}

void delete_enum_object_in_list(const TEE_ObjectEnumHandle object)
{
    struct valid_enum_objects *valid_enum_obj = NULL;
    struct valid_enum_objects *tmp_enum_obj   = NULL;

    if (object == NULL)
        return;

    dlist_for_each_entry_safe(valid_enum_obj, tmp_enum_obj, &g_enum_obj_info_list, struct valid_enum_objects, list) {
        if (valid_enum_obj->enum_obj_id == object) {
            dlist_delete(&valid_enum_obj->list);
            TEE_Free(valid_enum_obj);
            break;
        }
    }
}

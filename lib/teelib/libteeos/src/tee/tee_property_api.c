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
#include "tee_property_api.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <securec.h>
#include <dlist.h>
#include <ipclib.h>

#include "tee_mem_mgmt_api.h"
#include "tee_bitmap.h"
#include "tee_log.h"
#include "tee_ss_agent_api.h"
#include "ta_framework.h"
#include <tee_huk_get_device_id.h>
#include "tee_property_inner.h"

#define PROP_ERROR   (-1)
#define PROP_SUCCESS 0

#define TEE_INTERNAL_CORE_MAJOR_VERSION       1
#define TEE_INTERNAL_CORE_MINOR_VERSION       2
#define TEE_INTERNAL_CORE_MAINTENANCE_VERSION 0
#define TEE_INTERNAL_CORE_RESERVED_VERSION    0

// TEE_API_VERSION should match with TEE_INTERNAL_CORE_VERSION
#define TEE_API_VERSION "v1.2.0"
#define TEE_INTERNAL_CORE_VERSION                                                        \
    ((TEE_INTERNAL_CORE_MAJOR_VERSION << 24) | (TEE_INTERNAL_CORE_MINOR_VERSION << 16) | \
     (TEE_INTERNAL_CORE_MAINTENANCE_VERSION << 8) | TEE_INTERNAL_CORE_RESERVED_VERSION)
#define TEE_BUILD_VER "B309"

#define TEE_IMP_VERSION "TEE-1.0.0"

#define TEE_MANUFACTURER          "TEE"
#define TEE_FIRMWARE_IMP_VERSION  "ATF-1.5"
#define TEE_FIRMWARE_MANUFACTURER "TEE"

#define TEE_TIME_PROTECT_LEVEL 100
#define TA_TIME_PROTECT_LEVEL  100
#define MAX_BIG_INT_SIZE       32
#define STR_SUBFIX_LEN         1 // len for '\0'

// format: "identity:interger:uuid"
#define IDENTITY_STRING_LEN (IDENTITY_PREFIX_STRLEN + U32_DECIMAL_MAX_STRLEN + 1 + UUID_FORMAT_STRLEN)

static TEE_UUID g_device_id;

enum bool_prop_t {
    PROP_INVALID = -1,
    PROP_FALSE   = 0,
    PROP_TRUE    = 1
};

enum prop_type {
    T_STRING = 1,
    T_BOOL,
    T_U32,
    T_U64,
    T_BINARY,
    T_UUID,
    T_IDENTITY,
};

struct prop_item {
    char *name;
    enum prop_type type;
    uintptr_t val;
    uint32_t val_len;
    struct dlist_node list;
};

struct prop_set {
    Pseudo_PropSetHandle set;
    struct dlist_node head;
};

#define PROP_SET 3
enum {
    PROP_SET_TEE    = 0,
    PROP_SET_CLIENT = 1,
    PROP_SET_TA     = 2,
};
#define sel_prop_set(pesudo_handle) ((pesudo_handle) - (uint32_t)TEE_PROPSET_TEE_IMPLEMENTATION)

static struct prop_set g_property[PROP_SET] = {
    { TEE_PROPSET_TEE_IMPLEMENTATION, { &(g_property[PROP_SET_TEE].head), &(g_property[PROP_SET_TEE].head) } },
    { TEE_PROPSET_CURRENT_CLIENT, { &(g_property[PROP_SET_CLIENT].head), &(g_property[PROP_SET_CLIENT].head) } },
    { TEE_PROPSET_CURRENT_TA, { &(g_property[PROP_SET_TA].head), &(g_property[PROP_SET_TA].head) } }
};

struct enum_handle {
    Pseudo_PropSetHandle set;
    struct prop_item *item;
    uint32_t handle;
    struct dlist_node list;
};

static bool g_init_done = false;

static dlist_head(g_enum_head);
#define TEE_PROPERTY_HANDLE_MAX 1024
#define PROPERTY_MAP_SIZE       (TEE_PROPERTY_HANDLE_MAX / 8)
static uint8_t g_handle_bitmap[PROPERTY_MAP_SIZE];
static pthread_mutex_t g_bitmap_mutex = PTHREAD_MUTEX_INITIALIZER;

#define UUID_FORMAT_STRLEN    37
#define MAX_PROPERTY_NAME_LEN 255

// overwrite GP standard interface, enable it only in GP certificate
#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

static int mutex_lock_ops(pthread_mutex_t *mtx)
{
    int ret;
    ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

static TEE_Result add_prop_item(Pseudo_PropSetHandle set, const char *name, enum prop_type type, uintptr_t val,
                                uint32_t val_len)
{
    struct prop_item *item = NULL;
    size_t len;

    bool check = ((name == NULL) || (strnlen(name, MAX_PROPERTY_NAME_LEN) >= MAX_PROPERTY_NAME_LEN));
    if (check) {
        tloge("invalid property name\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sel_prop_set(set) >= PROP_SET) {
        tloge("invalid property set value\n");
        return TEE_ERROR_GENERIC;
    }

    len  = strlen(name) + STR_SUBFIX_LEN + val_len;
    item = TEE_Malloc(sizeof(*item) + len, 0);
    if (item == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    item->name = (char *)(item + STR_SUBFIX_LEN);
    item->val  = (uintptr_t)(item->name + strlen(name) + STR_SUBFIX_LEN);
    if (memcpy_s(item->name, len, name, len) != EOK) {
        TEE_Free(item);
        return TEE_ERROR_SECURITY;
    }

    item->type    = type;
    item->val_len = val_len;

    if ((type == T_BOOL) || (type == T_U32)) {
        item->val = val;
    } else {
        if (val_len != 0) {
            if (memcpy_s((void *)(item->val), item->val_len, (void *)val, val_len) != EOK) {
                tloge("copy item val failed\n");
                TEE_Free(item);
                return TEE_ERROR_SECURITY;
            }
        }
    }

    dlist_insert_tail(&item->list, &g_property[sel_prop_set(set)].head);
    return TEE_SUCCESS;
}

struct init_property_set {
    Pseudo_PropSetHandle set;
    const char *name;
    enum prop_type type;
    uintptr_t val;
    uint32_t val_len;
};

static const struct init_property_set g_property_set[] = {
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.apiversion", T_STRING, (uintptr_t)TEE_API_VERSION, sizeof(TEE_API_VERSION)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.internalCore.version", T_U32, TEE_INTERNAL_CORE_VERSION, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.description", T_STRING, (uintptr_t)TEE_BUILD_VER, sizeof(TEE_BUILD_VER)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.deviceID", T_UUID, (uintptr_t)&g_device_id, sizeof(TEE_UUID)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.systemTime.protectionLevel", T_U32, TEE_TIME_PROTECT_LEVEL, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.TAPersistentTime.protectionLevel", T_U32, TA_TIME_PROTECT_LEVEL, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.arith.maxBigIntSize", T_U32, MAX_BIG_INT_SIZE, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.ecc", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.nist", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.bsi-r", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.bsi-t", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.ietf", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.cryptography.octa", T_BOOL, false, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.trustedStorage.antiRollback.protectionLevel", T_U32, 0, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.trustedStorage.rollbackDetection.protectionLevel", T_U32, 0, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.trustedos.implementation.version", T_STRING, (uintptr_t)TEE_IMP_VERSION, sizeof(TEE_IMP_VERSION)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.trustedos.implementation.binaryversion",
      T_STRING, (uintptr_t)TEE_IMP_VERSION, sizeof(TEE_IMP_VERSION)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.trustedos.manufacturer", T_STRING, (uintptr_t)TEE_MANUFACTURER, sizeof(TEE_MANUFACTURER)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.firmware.implementation.version",
      T_STRING, (uintptr_t)TEE_IMP_VERSION, sizeof(TEE_FIRMWARE_IMP_VERSION)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.firmware.implementation.binaryversion",
      T_BINARY, (uintptr_t)TEE_IMP_VERSION, sizeof(TEE_FIRMWARE_IMP_VERSION)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.firmware.manufacturer",
      T_STRING, (uintptr_t)TEE_FIRMWARE_MANUFACTURER, sizeof(TEE_FIRMWARE_MANUFACTURER)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.event.maxSources", T_U32, 0, sizeof(uint32_t)
    },
    { TEE_PROPSET_TEE_IMPLEMENTATION,
      "gpd.tee.api_level", T_U32, TEE_MAX_API_LEVEL_CONFIG, sizeof(uint32_t)
    },
};

static TEE_Identity *create_client_identity(uint32_t login_method, const TEE_UUID *client_uuid)
{
    TEE_Identity *identity = NULL;
    if (client_uuid == NULL)
        return NULL;

    identity = TEE_Malloc(sizeof(*identity), 0);
    if (identity == NULL) {
        tloge("apply identity failed\n");
        return NULL;
    }

    identity->login = login_method;
    if (memcpy_s(&identity->uuid, sizeof(identity->uuid), client_uuid, sizeof(*client_uuid)) != EOK) {
        tloge("create identity failed\n");
        TEE_Free(identity);
        return NULL;
    }

    return identity;
}

void init_property(uint32_t login_method, const TEE_UUID *client_uuid, const struct ta_property *prop)
{
    TEE_Result ret = TEE_SUCCESS;
    TEE_Result id_ret;
    uint32_t i;
    if (prop == NULL) // client_uuid may be null, don't need to check it
        return;

    g_init_done = false;

    if (mutex_lock_ops(&g_bitmap_mutex) != 0)
        return;
    set_bitmap(g_handle_bitmap, TEE_PROPERTY_HANDLE_MAX, 0);
    (void)pthread_mutex_unlock(&g_bitmap_mutex);

    id_ret = get_device_id_prop((uint8_t *)(&g_device_id), sizeof(g_device_id));
    if (id_ret != TEE_SUCCESS) {
        if (id_ret == TEE_ERROR_NOT_SUPPORTED)
            tlogw("device id not supported\n");
        else
            tloge("get device id prop failed\n");
    }
    for (i = 0; i < sizeof(g_property_set) / sizeof(g_property_set[0]); i++)
        ret |= add_prop_item(g_property_set[i].set, g_property_set[i].name, g_property_set[i].type,
                             g_property_set[i].val, g_property_set[i].val_len);

    TEE_Identity *identity = create_client_identity(login_method, client_uuid);
    ret |= add_prop_item(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", T_IDENTITY, (uintptr_t)identity,
                         (identity != NULL) ? sizeof(*identity) : 0);
    ret |= add_prop_item(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.endian", T_U32, 0, sizeof(uint32_t));
    ret |= add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.appID", T_UUID, (uintptr_t)(&prop->uuid), sizeof(TEE_UUID));
    ret |=
        add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.singleInstance", T_BOOL, prop->single_instance, sizeof(uint32_t));
    ret |= add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.multiSession", T_BOOL, prop->multi_session, sizeof(uint32_t));
    ret |=
        add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.instanceKeepAlive", T_BOOL, prop->keep_alive, sizeof(uint32_t));
    ret |= add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.dataSize", T_U32, prop->heap_size, sizeof(uint32_t));
    ret |= add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.stackSize", T_U32, prop->stack_size, sizeof(uint32_t));
    ret |= add_prop_item(TEE_PROPSET_CURRENT_TA, "gpd.ta.endian", T_U32, 0, sizeof(uint32_t));
    if (ret != TEE_SUCCESS)
        tloge("fail to add some property\n");
    g_init_done = true;
}

void init_non_std_property(char *buff, uint32_t len)
{
    char *name     = NULL;
    char *new_name = NULL;
    char *val      = NULL;
    uint32_t i;
    uint32_t end_flag = 0;

    if (buff == NULL || len > NOTIFY_MAX_LEN) {
        tloge("invalid parameter\n");
        return;
    }

    g_init_done = false;
    val  = buff;
    name = buff;

    for (i = 0; i < len; i++) {
        if (*(buff + i) == ':') {
            if ((uintptr_t)val <= (uintptr_t)name) {
                *(buff + i) = '\0';
                val         = buff + i + 1;
            }
        } else if ((*(buff + i) == '\n') || (*(buff + i) == '\0')) {
            if (*(buff + i) == '\0')
                end_flag = 1;

            *(buff + i) = '\0';
            new_name    = buff + i + 1;

            if (add_prop_item(TEE_PROPSET_CURRENT_TA, name, T_STRING, (uintptr_t)val,
                              (uintptr_t)new_name - (uintptr_t)val) != TEE_SUCCESS)
                tlogd("add non std property failed\n");

            if (end_flag == 1)
                break;

            name = new_name;
        }
    }
    g_init_done = true;
}

static bool is_pseudo_handle(TEE_PropSetHandle handle)
{
    return handle >= TEE_PROPSET_TEE_IMPLEMENTATION;
}

static bool is_valid_enum_handle(TEE_PropSetHandle handle)
{
    if (handle == TEE_PROPSET_UNKNOW)
        return false;

    if (mutex_lock_ops(&g_bitmap_mutex) != 0)
        return false;

    bool ret = is_bit_seted(g_handle_bitmap, TEE_PROPERTY_HANDLE_MAX, handle);
    (void)pthread_mutex_unlock(&g_bitmap_mutex);
    return ret;
}

static bool is_last_item(uint32_t set, const struct prop_item *item)
{
    struct dlist_node *set_head = NULL;

    if ((item == NULL) || (sel_prop_set(set) >= PROP_SET))
        return false;

    set_head = &(g_property[sel_prop_set(set)].head);

    return item->list.next == set_head;
}

static bool is_enumerator_started(const struct enum_handle *handle)
{
    if (handle == NULL)
        return false;

    return handle->item != NULL;
}

static struct prop_item *find_pseuprop_item(TEE_PropSetHandle set, const char *name)
{
    struct prop_item *i_item = NULL;
    struct dlist_node *set_head = NULL;
    bool find_flag = false;

    if (name == NULL)
        return NULL;
    if (strnlen(name, MAX_PROPERTY_NAME_LEN) >= MAX_PROPERTY_NAME_LEN)
        return NULL;

    uint32_t index = sel_prop_set(set);
    if (index >= (sizeof(g_property) / sizeof(g_property[0])))
        return NULL;

    set_head = &(g_property[index].head);
    dlist_for_each_entry(i_item, set_head, struct prop_item, list) {
        if (TEE_MemCompare(name, i_item->name, strlen(name) + 1) == 0) {
            find_flag = true;
            break;
        }
    }

    if (!find_flag)
        return NULL;

    return i_item;
}

static struct enum_handle *find_enum_handle(TEE_PropSetHandle enumerator)
{
    struct enum_handle *handle = NULL;

    dlist_for_each_entry(handle, &g_enum_head, struct enum_handle, list) {
        if (handle->handle == enumerator)
            return handle;
    }

    return NULL;
}

static struct prop_item *get_prop_item(TEE_PropSetHandle enumerator, const char *name)
{
    struct prop_item *item     = NULL;
    struct enum_handle *handle = NULL;

    if (!g_init_done)
        return NULL;
    if (is_pseudo_handle(enumerator)) {
        item = find_pseuprop_item(enumerator, name);
        if (item == NULL)
            return NULL;
    } else {
        if (!is_valid_enum_handle(enumerator))
            return NULL;

        handle = find_enum_handle(enumerator);
        if (handle == NULL)
            return NULL;

        item = handle->item;
    }

    return item;
}

static void convert_uuid_to_str(const TEE_UUID *uuid, char *buff, uint32_t len)
{
    if ((uuid == NULL) || (len < UUID_FORMAT_STRLEN)) {
        tloge("invalid parameter\n");
        return;
    }

    int ret = snprintf_s(buff, len, UUID_FORMAT_STRLEN, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0],
                         uuid->clockSeqAndNode[1], uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
                         uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6],
                         uuid->clockSeqAndNode[7]); // refer uuid format definitions
    if (ret <= 0)
        tloge("convert uuid to string failed\n");
}

#define ALP_TO_DIGIT_GAP 10
static int8_t asc2hex(char a)
{
    if ((a >= '0') && (a <= '9'))
        return a - '0';
    else if ((a >= 'a') && (a <= 'f'))
        return (a - 'a') + ALP_TO_DIGIT_GAP;
    else if ((a >= 'A') && (a <= 'F'))
        return (a - 'A') + ALP_TO_DIGIT_GAP;

    return PROP_ERROR;
}

#define CHAR_COUNT_PER_BYTE 2
#define HALF_BYTE_SIZE      4
static int get_byte_value_from_buff(const char *buff, uint32_t len, uint8_t *res)
{
    bool check = ((buff == NULL) || (len < CHAR_COUNT_PER_BYTE));
    if (check) {
        tloge("invalid parameter\n");
        return PROP_ERROR;
    }

    int8_t h_val = asc2hex(*buff);
    int8_t l_val = asc2hex(*(buff + 1));
    if (((int)h_val == PROP_ERROR) || ((int)l_val == PROP_ERROR))
        return PROP_ERROR;

    *res = (uint8_t)(((uint8_t)h_val << HALF_BYTE_SIZE) | (uint8_t)l_val);
    return PROP_SUCCESS;
}

#define ADD_POS_COUNT_IN_UUID 5
#define BYTE_COUNT_IN_UUID    16
#define BITS_COUNT_PER_BYTE   8

#define ADD_POS_INIT_INDEX   0
#define ADD_POS_FIRST_INDEX  1
#define ADD_POS_SECOND_INDEX 2
#define ADD_POS_THIRD_INDEX  3
#define ADD_POS_FOUR_INDEX   4
static int32_t convert_str_to_uuid(const char *buff, uint32_t len, TEE_UUID *uuid)
{
    const char *p                                = buff;
    uint8_t add_pos_array[ADD_POS_COUNT_IN_UUID] = { 8, 13, 18, 23, 36 }; // fixed values, refer UUID format definitions
    uint8_t add_pos                              = 0;

    uint8_t tmp_val;
    uint8_t *set_val = NULL;
    int i;

    bool check = ((buff == NULL) || (uuid == NULL) || (len != UUID_FORMAT_STRLEN) || (*(buff + len - 1) != '\0'));
    if (check) {
        tloge("invalid parameter\n");
        return PROP_ERROR;
    }

    set_val = uuid->clockSeqAndNode;
    for (i = 0; i < BYTE_COUNT_IN_UUID; i++) {
        if (get_byte_value_from_buff(p, len - (p - buff), &tmp_val) != 0)
            return PROP_ERROR;

        p += CHAR_COUNT_PER_BYTE;

        switch (add_pos) {
        case ADD_POS_INIT_INDEX:
            uuid->timeLow = (uuid->timeLow << BITS_COUNT_PER_BYTE) + tmp_val;
            break;
        case ADD_POS_FIRST_INDEX:
            uuid->timeMid = (uuid->timeMid << BITS_COUNT_PER_BYTE) + tmp_val;
            break;
        case ADD_POS_SECOND_INDEX:
            uuid->timeHiAndVersion = (uuid->timeHiAndVersion << BITS_COUNT_PER_BYTE) + tmp_val;
            break;
        case ADD_POS_THIRD_INDEX:
        case ADD_POS_FOUR_INDEX:
            *set_val++ = tmp_val;
            break;
        default:
            tloge("invalid uuid format\n");
            return PROP_ERROR;
        }

        if ((uint8_t)(p - buff) == add_pos_array[add_pos]) {
            if (*p != '-')
                break;
            p++;
            add_pos++;
        }
    }
    // not touch the end of buff
    if (p != (buff + len - 1))
        return PROP_ERROR;

    return PROP_SUCCESS;
}

static int32_t convert_str_to_identity(const char *buff, uint32_t len, TEE_Identity *identity)
{
    const char *p_login = buff;
    const char *p_uuid  = buff;
    char *tmp_buff      = NULL;
    char *endptr        = NULL;

    bool check = ((buff == NULL) || (identity == NULL));
    if (check) {
        tloge("invalid parameter\n");
        return PROP_ERROR;
    }

    if (*(buff + len - 1) != '\0')
        return PROP_ERROR;

    tmp_buff = TEE_Malloc(len, 0);
    if (tmp_buff == NULL)
        return PROP_ERROR;

    if (memcpy_s(tmp_buff, len, buff, len) != EOK) {
        TEE_Free(tmp_buff);
        return PROP_ERROR;
    }

    while (*p_uuid++ != '\0') {
        if (*p_uuid == ':') {
            p_uuid++;
            break;
        }

        if ((uint32_t)(p_uuid - p_login) > len) {
            TEE_Free(tmp_buff);
            return PROP_ERROR;
        }
    }

    identity->login = strtoul(p_login, &endptr, 0);
    if (endptr != (p_uuid - 1)) {
        TEE_Free(tmp_buff);
        return PROP_ERROR;
    }

    if (convert_str_to_uuid(p_uuid, len - (uint32_t)(p_uuid - p_login), &identity->uuid) != 0) {
        TEE_Free(tmp_buff);
        return PROP_ERROR;
    }

    TEE_Free(tmp_buff);
    return PROP_SUCCESS;
}

static enum bool_prop_t convert_bool_str(const char *buff, uint32_t len)
{
    if (buff == NULL)
        return PROP_INVALID;

    if ((len == sizeof("true")) && (TEE_MemCompare(buff, "true", len) == 0))
        return PROP_TRUE;
    else if ((len == sizeof("false")) && (TEE_MemCompare(buff, "false", len) == 0))
        return PROP_FALSE;

    return PROP_INVALID;
}

#define IDENTITY_PREFIX_STRLEN 10 // format: "identity:interger:uuid"
#define U32_DECIMAL_MAX_STRLEN 11 // 0xffffffff have 10 digits
#define U64_DECIMAL_MAX_STRLEN 21 // 0xffffffffffffffff have 20 digits

static TEE_Result copy_result_to_buff(const char *result_buff, size_t result_len, char *buff, size_t *buff_len)
{
    bool check = ((result_buff == NULL) || (buff == NULL) || (buff_len == NULL));
    if (check) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*buff_len < result_len) {
        *buff_len = result_len;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(buff, *buff_len, result_buff, result_len) != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

static TEE_Result raw_item_to_str(const struct prop_item *item, char *buff, size_t *buff_len)
{
    return copy_result_to_buff((const char *)item->val, item->val_len, buff, buff_len);
}

static TEE_Result bool_item_to_str(const struct prop_item *item, char *buff, size_t *buff_len)
{
    char *val_str = NULL;
    size_t val_size;

    if ((item->val) != 0) {
        val_str  = "true";
        val_size = sizeof("true");
    } else {
        val_str  = "false";
        val_size = sizeof("false");
    }
    return copy_result_to_buff(val_str, val_size, buff, buff_len);
}

#define MAX_U32_DIGIT_STR_LEN 11
static TEE_Result u32_item_to_string(const struct prop_item *item, char *buff, size_t *buff_len)
{
    char *val_str = NULL;
    size_t val_size;
    char u32_buff[MAX_U32_DIGIT_STR_LEN] = { 0 };

    if (snprintf_s(u32_buff, sizeof(u32_buff), sizeof(u32_buff) - 1, "%u", (uint32_t)item->val) < 0)
        return TEE_ERROR_GENERIC;

    val_str  = u32_buff;
    val_size = strlen(u32_buff) + 1;
    return copy_result_to_buff(val_str, val_size, buff, buff_len);
}

static TEE_Result u64_item_to_string(const struct prop_item *item, char *buff, size_t *buff_len)
{
    char *val_str = NULL;
    size_t val_size;
    char u64_buff[U64_DECIMAL_MAX_STRLEN] = { 0 };

    if (snprintf_s(u64_buff, sizeof(u64_buff), sizeof(u64_buff) - 1, "%llu", (unsigned long long)item->val) < 0)
        return TEE_ERROR_GENERIC;

    val_str  = u64_buff;
    val_size = strlen(u64_buff) + 1;
    return copy_result_to_buff(val_str, val_size, buff, buff_len);
}

static TEE_Result uuid_item_to_string(const struct prop_item *item, char *buff, size_t *buff_len)
{
    char uuid[UUID_FORMAT_STRLEN] = { 0 };

    convert_uuid_to_str((const TEE_UUID *)item->val, uuid, sizeof(uuid));

    return copy_result_to_buff(uuid, sizeof(uuid), buff, buff_len);
}

static TEE_Result identity_item_to_string(const struct prop_item *item, char *buff, size_t *buff_len)
{
    uint32_t add_pos                      = 0;
    char u32_buff[U32_DECIMAL_MAX_STRLEN] = { 0 };
    char uuid_buff[UUID_FORMAT_STRLEN]    = { 0 };
    char *identity_buff                   = NULL;
    TEE_Result ret;

    const TEE_Identity *identity = (const TEE_Identity *)(item->val);
    if (identity == NULL) {
        *buff = '\0';
        return TEE_SUCCESS;
    }

    identity_buff = TEE_Malloc(IDENTITY_STRING_LEN, 0);
    if (identity_buff == NULL) {
        tloge("apply identity buff failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (snprintf_s(u32_buff, sizeof(u32_buff), sizeof(u32_buff) - 1, "%u", identity->login) < 0) {
        tloge("output u32 operation failed\n");
        TEE_Free(identity_buff);
        return TEE_ERROR_SECURITY;
    }

    convert_uuid_to_str(&identity->uuid, uuid_buff, UUID_FORMAT_STRLEN);
    if (memcpy_s(identity_buff, IDENTITY_STRING_LEN, "identity:", strlen("identity:")) != EOK) {
        tloge("copy itendity err2\n");
        TEE_Free(identity_buff);
        return TEE_ERROR_SECURITY;
    }
    add_pos += strlen("identity:");
    if (memcpy_s(identity_buff + add_pos, IDENTITY_STRING_LEN - add_pos, u32_buff, strlen(u32_buff)) != EOK) {
        tloge("copy identity err3\n");
        TEE_Free(identity_buff);
        return TEE_ERROR_SECURITY;
    }
    add_pos += (uint32_t)strlen(u32_buff);

    *(identity_buff + add_pos) = ':';
    add_pos++;

    if (memcpy_s(identity_buff + add_pos, IDENTITY_STRING_LEN - add_pos, uuid_buff, UUID_FORMAT_STRLEN) != EOK) {
        tloge("copy identity err4\n");
        TEE_Free(identity_buff);
        return TEE_ERROR_SECURITY;
    }

    ret = copy_result_to_buff(identity_buff, IDENTITY_STRING_LEN, buff, buff_len);
    TEE_Free(identity_buff);

    return ret;
}

typedef TEE_Result (*convert_item_to_str)(const struct prop_item *item, char *buff, size_t *buff_len);
struct type_func_mapping_t {
    enum prop_type type;
    convert_item_to_str func;
};

static const struct type_func_mapping_t g_type_func_map[] = {
    { T_BINARY,   raw_item_to_str },
    { T_STRING,   raw_item_to_str },
    { T_BOOL,     bool_item_to_str },
    { T_U32,      u32_item_to_string },
    { T_U64,      u64_item_to_string },
    { T_UUID,     uuid_item_to_string },
    { T_IDENTITY, identity_item_to_string }
};

/*
 * below APIs are defined by Global Platform or Platform SDK released previously
 * for compatibility:
 * don't change function name / return value type / parameters types / parameters names
 */
TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator, const char *name, char *valueBuffer,
                                   size_t *valueBufferLen)
{
    struct prop_item *item = NULL;
    TEE_Result ret         = TEE_ERROR_ITEM_NOT_FOUND;
    uint32_t i;

    bool check = ((valueBuffer == NULL) || (valueBufferLen == NULL) || (*valueBufferLen == 0));
    if (check) {
        tloge("invalid parameter\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    for (i = 0; i < (sizeof(g_type_func_map) / sizeof(g_type_func_map[0])); i++) {
        if (item->type == g_type_func_map[i].type) {
            ret = g_type_func_map[i].func(item, valueBuffer, valueBufferLen);
            break;
        }
    }

    return ret;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator, const char *name, bool *value)
{
    struct prop_item *item = NULL;
    int8_t ret;

    if (value == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (item->type) {
    case T_BOOL:
        *value = (bool)(item->val);
        break;
    case T_STRING:
        ret = convert_bool_str((char *)(item->val), item->val_len);
        if (ret == PROP_INVALID)
            return TEE_ERROR_BAD_FORMAT;

        *value = (bool)ret;
        break;
    default:
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator, const char *name, uint32_t *value)
{
    struct prop_item *item = NULL;
    char *endptr           = NULL;
    uint32_t tmp_val;

    if (value == NULL) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (item->type) {
    case T_BOOL:
    case T_U32:
        *value = (uint32_t)(item->val);
        break;
    case T_STRING:
        tmp_val = strtoul((char *)(item->val), &endptr, 0);

        if (endptr != ((char *)(item->val) + item->val_len - 1))
            return TEE_ERROR_BAD_FORMAT;

        *value = tmp_val;
        break;
    default:
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU64(TEE_PropSetHandle propsetOrEnumerator, const char *name, uint64_t *value)
{
    struct prop_item *item = NULL;
    char *endptr           = NULL;
    uint64_t tmp_val;

    if (value == NULL) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (item->type) {
    case T_BOOL:
    case T_U32:
    case T_U64:
        *value = (uint64_t)(item->val);
        break;
    case T_STRING:
        tmp_val = (uint64_t)strtoull((char *)(item->val), &endptr, 0);

        if (endptr != ((char *)(item->val) + item->val_len - 1))
            return TEE_ERROR_BAD_FORMAT;

        *value = tmp_val;
        break;
    default:
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator, const char *name, void *valueBuffer,
                                        size_t *valueBufferLen)
{
    struct prop_item *item = NULL;
    size_t val_size;

    if ((valueBuffer == NULL) || (valueBufferLen == NULL)) {
        tloge("invalid parameter\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    if ((item->type == T_BOOL) || (item->type == T_U32))
        return TEE_ERROR_BAD_FORMAT;

    val_size = item->val_len;

    if (*valueBufferLen < val_size) {
        *valueBufferLen = val_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(valueBuffer, val_size, (void *)(item->val), val_size) != EOK)
        return TEE_ERROR_SECURITY;

    *valueBufferLen = val_size;
    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator, const char *name, TEE_UUID *value)
{
    struct prop_item *item = NULL;
    int32_t ret;
    TEE_UUID uuid = { 0 };
    errno_t rc;

    if (value == NULL) {
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (item->type) {
    case T_UUID:
        rc = memcpy_s(value, sizeof(*value), (void *)(item->val), sizeof(uuid));
        if (rc != EOK) {
            TEE_Panic(TEE_ERROR_SECURITY);
            return TEE_ERROR_SECURITY;
        }
        break;
    case T_STRING:
        ret = convert_str_to_uuid((char *)(item->val), item->val_len, &uuid);
        if (ret == PROP_ERROR)
            return TEE_ERROR_BAD_FORMAT;

        rc = memcpy_s(value, sizeof(*value), &uuid, sizeof(uuid));
        if (rc != EOK) {
            TEE_Panic(TEE_ERROR_SECURITY);
            return TEE_ERROR_SECURITY;
        }
        break;
    default:
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

#define CLOCK_SEQ_COUNT_IN_UUID 8
TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator, const char *name, TEE_Identity *identity)
{
    struct prop_item *item = NULL;

    if (identity == NULL) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item = get_prop_item(propsetOrEnumerator, name);
    if (item == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    switch (item->type) {
    case T_IDENTITY:
        if (item->val != 0) {
            if (memcpy_s(identity, sizeof(*identity), (void *)(item->val), sizeof(*identity)) != EOK)
                return TEE_ERROR_SECURITY;
        } else {
            (void)memset_s(identity, sizeof(*identity), 0, sizeof(*identity));
        }
        break;
    case T_STRING:
        if (convert_str_to_identity((char *)item->val, item->val_len, identity) != 0)
            return TEE_ERROR_BAD_FORMAT;
        break;
    default:
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
    struct enum_handle *handle = NULL;
    int32_t ret;

    if (enumerator == NULL) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = TEE_Malloc(sizeof(*handle), 0);
    if (handle == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    if (mutex_lock_ops(&g_bitmap_mutex) != 0) {
        TEE_Free(handle);
        return TEE_ERROR_GENERIC;
    }
    ret = get_valid_bit(g_handle_bitmap, TEE_PROPERTY_HANDLE_MAX);
    if (ret == PROP_ERROR) {
        (void)pthread_mutex_unlock(&g_bitmap_mutex);
        TEE_Free(handle);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    handle->set    = TEE_PROPSET_UNKNOW;
    handle->handle = (uint32_t)ret;
    set_bitmap(g_handle_bitmap, TEE_PROPERTY_HANDLE_MAX, handle->handle);
    (void)pthread_mutex_unlock(&g_bitmap_mutex);
    dlist_insert_tail(&handle->list, &g_enum_head);

    *enumerator = (uint32_t)handle->handle;
    return TEE_SUCCESS;
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
    if (!is_pseudo_handle(enumerator) || is_valid_enum_handle(enumerator)) {
        struct enum_handle *handle = find_enum_handle(enumerator);
        if (handle != NULL) {
            if (mutex_lock_ops(&g_bitmap_mutex) != 0)
                return;
            clear_bitmap(g_handle_bitmap, TEE_PROPERTY_HANDLE_MAX, enumerator);
            (void)pthread_mutex_unlock(&g_bitmap_mutex);
            dlist_delete(&handle->list);
            TEE_Free(handle);
        }
    }
}

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator, TEE_PropSetHandle propSet)
{
    struct enum_handle *handle = NULL;

    if (!is_pseudo_handle(propSet) || !is_valid_enum_handle(enumerator))
        return;

    handle = find_enum_handle(enumerator);
    if (handle != NULL) {
        handle->set = (Pseudo_PropSetHandle)propSet;
        switch (handle->set) {
        case TEE_PROPSET_TEE_IMPLEMENTATION:
            handle->item = find_pseuprop_item(propSet, "gpd.tee.apiversion");
            break;
        case TEE_PROPSET_CURRENT_CLIENT:
            handle->item = find_pseuprop_item(propSet, "gpd.client.identity");
            break;
        case TEE_PROPSET_CURRENT_TA:
            handle->item = find_pseuprop_item(propSet, "gpd.ta.appID");
            break;
        default:
            tloge("invalid property type 0x%x\n", handle->set);
            break;
        }
    }
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
    struct enum_handle *handle = NULL;

    if (is_pseudo_handle(enumerator) || !is_valid_enum_handle(enumerator))
        return;

    handle = find_enum_handle(enumerator);
    if (handle == NULL)
        return;

    handle->set  = TEE_PROPSET_UNKNOW;
    handle->item = NULL;
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer, size_t *nameBufferLen)
{
    struct enum_handle *handle = NULL;
    size_t name_size;

    bool check = ((nameBuffer == NULL) || (nameBufferLen == NULL));
    if (check) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = (is_pseudo_handle(enumerator) || !is_valid_enum_handle(enumerator));
    if (check) {
        tloge("item no found\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    handle = find_enum_handle(enumerator);
    if (handle == NULL) {
        tloge("item no found\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    check = ((handle->set == TEE_PROPSET_UNKNOW) || (handle->item == NULL) || (handle->item->name == NULL) ||
             (strnlen(handle->item->name, MAX_PROPERTY_NAME_LEN) >= MAX_PROPERTY_NAME_LEN));
    if (check) {
        tloge("item no found\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    name_size = strlen(handle->item->name) + 1;
    if (*nameBufferLen < name_size) {
        *nameBufferLen = name_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(nameBuffer, *nameBufferLen, handle->item->name, name_size) != EOK)
        return TEE_ERROR_GENERIC;

    *nameBufferLen = name_size;

    return TEE_SUCCESS;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
    struct enum_handle *handle = NULL;

    if (is_pseudo_handle(enumerator) || !is_valid_enum_handle(enumerator))
        return TEE_ERROR_ITEM_NOT_FOUND;

    handle = find_enum_handle(enumerator);
    if (handle == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    if (!is_enumerator_started(handle))
        return TEE_ERROR_ITEM_NOT_FOUND;

    if (is_last_item(handle->set, handle->item)) {
        handle->item = NULL;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    handle->item = dlist_entry(handle->item->list.next, struct prop_item, list);
    return TEE_SUCCESS;
}

uint32_t tee_get_ta_api_level(void)
{
    uint32_t value = 0;

    if (TEE_GetPropertyAsU32(TEE_PROPSET_CURRENT_TA, "gpd.ta.api_level", &value) != TEE_SUCCESS)
        return API_LEVEL1_0;

    return value;
}

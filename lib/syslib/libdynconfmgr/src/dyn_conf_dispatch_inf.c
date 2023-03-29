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
#include "dyn_conf_dispatch_inf.h"
#include <securec.h>
#include <errno.h>
#include <tee_log.h>
#include <dlist.h>
#include <ta_framework.h>
#include <tee_sharemem.h>

#ifdef TEE_SUPPORT_DYN_CONF
int32_t handle_conf_node_to_obj(struct dlist_node **pos, handler_conf_to_obj handle, void *obj, uint32_t obj_size)
{
    struct conf_node_t *node = NULL;
    uint64_t total_size;
    uint64_t tmp_size = 0;
    int32_t ret;

    if (pos == NULL || *pos == NULL || obj_size == 0 ||
        obj == NULL || obj_size >= MAX_IMAGE_LEN) {
        tloge("params invalied while handle conf node to obj\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    node = dlist_entry(*pos, struct conf_node_t, head);
    if (node == NULL || node->size >= MAX_IMAGE_LEN || node->size == 0) {
        tloge("node is invalied\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    total_size = node->size;

    *pos = dlist_get_next(*pos);
    while (1) {
        node = dlist_entry(*pos, struct conf_node_t, head);
        if (node == NULL || node->size >= MAX_IMAGE_LEN || node->size == 0) {
            tloge("node is invalied\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        if (handle != NULL)
            ret = handle(pos, node, obj, obj_size);
        else
            ret = TEE_SUCCESS;
        if (ret != TEE_SUCCESS)
            return ret;

        tmp_size += DYN_CONF_TAG_LEN + DYN_CONF_TYPE_LEN + DYN_CONF_LEN_LEN + node->size;
        if (tmp_size >= total_size)
            break;

        *pos = dlist_get_next(*pos);
    }

    return TEE_SUCCESS;
}

int32_t trans_str_to_int(const char *buff, uint32_t len, uint32_t base, uint64_t *num)
{
    char *endptr = NULL;
    char tmp_buff[MAX_UINT64_HEX_LEN + LEN_OF_HEX_TRIM + 1] = { 0 };

    if (buff == NULL || len == 0 || (base != BASE_OF_HEX && base != BASE_OF_TEN) || num == NULL) {
        tloge("invalied params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* if the base is 16, the length cannot larger than the len of '0xffffffffffffffff' */
    if (base == BASE_OF_HEX && len > MAX_UINT64_HEX_LEN + LEN_OF_HEX_TRIM) {
        tloge("trans hex num, len %u should not larger than MAX_UINT64_HEX_LEN + LEN_OF_HEX_TRIM\n", len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (base == BASE_OF_TEN && len > MAX_UINT64_LEN) {
        tloge("trans num, len %u should not larger than MAX_UINT64_LEN\n", len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(tmp_buff, MAX_UINT64_HEX_LEN + LEN_OF_HEX_TRIM, buff, len) != 0) {
        tloge("trans num memcpy failed\n");
        return TEE_ERROR_GENERIC;
    }
    tmp_buff[len] = '\0';

    errno = 0;
    *num = strtoull(tmp_buff, &endptr, base);
    /* if endptr <= tmp_buff, means endptr == NULL or some other invalied situations */
    if (errno != 0 || endptr <= tmp_buff || *endptr != '\0') {
        tloge("trans buff failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static uint32_t get_conf_len(const char *buff)
{
    int32_t ret;
    char len_buff[DYN_CONF_LEN_LEN + LEN_OF_HEX_TRIM + 1] = { 0 };
    uint64_t num = 0;

    ret = snprintf_s(len_buff, DYN_CONF_LEN_LEN + LEN_OF_HEX_TRIM + 1, DYN_CONF_LEN_LEN + LEN_OF_HEX_TRIM,
                     "0x%s", buff);
    if (ret < 0) {
        tloge("get len buff error\n");
        return 0;
    }

    ret = trans_str_to_int(len_buff, DYN_CONF_LEN_LEN + LEN_OF_HEX_TRIM, BASE_OF_HEX, &num);
    if (ret != 0)
        return 0;

    if (num > MAX_IMAGE_LEN) {
        tloge("get len buff larger than MAX_IMAGE_LEN\n");
        return 0;
    }

    return (uint32_t)num;
}

static int32_t push_conf_queue(struct conf_queue_t *conf_queue, uint32_t tag, uint32_t type,
                               uint32_t size, const char *value)
{
    struct conf_node_t *conf_node = NULL;

    conf_node = (struct conf_node_t *)malloc(sizeof(*conf_node));
    if (conf_node == NULL) {
        tloge("conf_node malloc failed\n");
        return TEE_ERROR_GENERIC;
    }

    (void)memset_s(conf_node, sizeof(*conf_node), 0, sizeof(*conf_node));
    conf_node->tag = tag;
    conf_node->type = type;
    conf_node->size = size;
    conf_node->value = value;

    dlist_insert_tail(&conf_node->head, &conf_queue->queue);

    return TEE_SUCCESS;
}

static int32_t parse_dyn_conf(struct conf_queue_t *conf_queue, const char *start, uint32_t size)
{
    /* tag(DYN_CONF_TAG_LEN) | type(DYN_CONF_TYPE_LEN) | len(DYN_CONF_LEN_LEN) | value */
    char tag_buff[DYN_CONF_TAG_LEN + 1] = { 0 };
    char type_buff[DYN_CONF_TYPE_LEN + 1] = { 0 };
    char len_buff[DYN_CONF_LEN_LEN + 1] = { 0 };
    uint32_t index = 0;
    uint32_t len;
    uint64_t tag;
    uint64_t type;

    while ((index < size) && (size > DYN_CONF_TAG_LEN + DYN_CONF_TYPE_LEN + DYN_CONF_LEN_LEN)) {
        /* 1. handle tag */
        if (memcpy_s(tag_buff, DYN_CONF_TAG_LEN + 1, start + index, DYN_CONF_TAG_LEN) != 0) {
            tloge("set tag buff failed\n");
            return TEE_ERROR_GENERIC;
        }

        if (trans_str_to_int(tag_buff, DYN_CONF_TAG_LEN, BASE_OF_TEN, &tag) != TEE_SUCCESS ||
            tag > DYN_CONF_TAG_MAX) {
            tloge("set tag failed\n");
            return TEE_ERROR_GENERIC;
        }

        index += DYN_CONF_TAG_LEN;
        /* 2. handle type */
        if (index >= size || memcpy_s(type_buff, DYN_CONF_TYPE_LEN + 1, start + index, DYN_CONF_TYPE_LEN) != 0) {
            tloge("set type buff failed\n");
            return TEE_ERROR_GENERIC;
        }

        if (trans_str_to_int(type_buff, DYN_CONF_TYPE_LEN, BASE_OF_TEN, &type) != TEE_SUCCESS ||
            type > DYN_CONF_TYPE_MAX) {
            tloge("set type failed\n");
            return TEE_ERROR_GENERIC;
        }
        index += DYN_CONF_TYPE_LEN;
        /* 3. handle length */
        if (index >= size || memcpy_s(len_buff, DYN_CONF_LEN_LEN + 1, start + index, DYN_CONF_LEN_LEN) != 0) {
            tloge("set len buff failed\n");
            return TEE_ERROR_GENERIC;
        }

        len = get_conf_len(len_buff);
        if (len == 0 || len >= MAX_IMAGE_LEN || index + len + DYN_CONF_LEN_LEN > size) {
            tloge("the attr's len is invalied\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        index += DYN_CONF_LEN_LEN;
        /* 4. push the node into queue */
        if (push_conf_queue(conf_queue, (uint32_t)tag, (uint32_t)type, len, start + index) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        /* 5. if the type is class, means that we must parse its childs */
        if (type == TYPE_CLASS) {
            if (parse_dyn_conf(conf_queue, start + index, len) != TEE_SUCCESS)
                return TEE_ERROR_GENERIC;
        }

        index += len;
    }

    return TEE_SUCCESS;
}

static void free_conf_queue(const struct conf_queue_t *conf_queue)
{
    struct dlist_node *pos = NULL;
    struct dlist_node *n = NULL;

    dlist_for_each_safe(pos, n, &conf_queue->queue) {
        struct conf_node_t *conf_node = dlist_entry(pos, struct conf_node_t, head);
        dlist_delete(&conf_node->head);
        free(conf_node);
    }
}

void unregister_conf(handler_uninstall_obj uninstall_obj_func, void *obj, uint32_t obj_size)
{
    if (obj == NULL || obj_size == 0 || obj_size >= MAX_IMAGE_LEN || uninstall_obj_func == NULL) {
        tloge("valid params while unregister conf\n");
        return;
    }

    uninstall_obj_func(obj, obj_size);
}

uint16_t get_num_of_tag(const struct conf_queue_t *conf_queue, uint32_t tag)
{
    struct dlist_node *pos = NULL;
    uint32_t count = 0;

    if (conf_queue == NULL) {
        tloge("valid params while get num of tag\n");
        return 0;
    }

    dlist_for_each(pos, &conf_queue->queue) {
        struct conf_node_t *conf_node = dlist_entry(pos, struct conf_node_t, head);
        if (conf_node->tag == tag)
            count++;
    }

    return count;
}

/*
 * build section
 * build all objs that you want to use from tlv
 */
static int32_t check_target_type_invalied(uint32_t size, const char *value)
{
    if (value == NULL || size > MAX_IMAGE_LEN) {
        tloge("target type invalied param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[CHIP_TYPE_LEN_MAX] = { 0 };
    if (tee_get_chip_type(buff, CHIP_TYPE_LEN_MAX) != 0)
        return TEE_ERROR_GENERIC;

    char *origin = malloc(size + 1);
    if (origin == NULL) {
        tloge("malloc for chip type value failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (memset_s(origin, size + 1, 0, size + 1) != 0 || memcpy_s(origin, size + 1, value, size) != 0) {
        free(origin);
        tloge("mem opera for chip type value failed\n");
        return TEE_ERROR_GENERIC;
    }

    char *target = origin;
    char *rest = NULL;
    while (1) {
        target = strtok_r(target, ",", &rest);
        if (target == NULL)
            break;

        if (strlen(target) == strlen(buff) && memcmp(target, buff, strlen(buff)) == 0) {
            free(origin);
            return TEE_SUCCESS;
        }
        target = NULL;
    }

    free(origin);
    return TEE_ERROR_GENERIC;
}

int32_t check_item_chip_type(const struct dlist_node *now, uint32_t chip_type_tag)
{
    if (now == NULL) {
        tloge("valid params while check item chip type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct dlist_node *tmp = NULL;
    dlist_for_each(tmp, now) {
        struct conf_node_t *conf_node = dlist_entry(tmp, struct conf_node_t, head);
        if (conf_node == NULL)
            break;

        /* if chip type is not set, means all platform can regist */
        if (conf_node->type == 0)
            return TEE_SUCCESS;

        if (conf_node->tag == chip_type_tag)
            return check_target_type_invalied(conf_node->size, conf_node->value);
    }

    return TEE_ERROR_GENERIC;
}

int32_t tlv_to_uuid(const char *uuid_buff, uint32_t size, struct tee_uuid *uuid)
{
    if (uuid_buff == NULL || size > MAX_UUID_SIZE || uuid == NULL || strlen(uuid_buff) < size) {
        tloge("invalied param while tlv to uuid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i;
    uint64_t data[UUID_STRUCT_LEN] = { 0 };

    const char *ptr = uuid_buff;
    uint8_t flag = 0;
    flag |= (uint8_t)(trans_str_to_int(ptr, UUID_TIMELOW_LEN, BASE_OF_HEX, &data[DATA_TIMELOW_IDX]) != 0);
    ptr = ptr + UUID_TIMELOW_LEN + 1;
    flag |= (uint8_t)(trans_str_to_int(ptr, UUID_TIMEMID_LEN, BASE_OF_HEX, &data[DATA_TIMEMID_IDX]) != 0);
    ptr = ptr + UUID_TIMEMID_LEN + 1;
    flag |= (uint8_t)(trans_str_to_int(ptr, UUID_HIVERSION_LEN, BASE_OF_HEX, &data[DATA_HVER_IDX]) != 0);
    ptr = ptr + UUID_HIVERSION_LEN + 1;

    for (i = 0; i < UUID_SEQ_SIZE; i++) {
        flag |= (uint8_t)(trans_str_to_int(ptr, UUID_SEQ_LEN, BASE_OF_HEX, &data[i + DATA_HVER_IDX + 1]) != 0);
        ptr = ptr + UUID_SEQ_LEN;
        if (i == 1)
            ptr = ptr + 1;
    }

    if (flag != 0) {
        tloge("get uuid failed\n");
        return TEE_ERROR_GENERIC;
    }

    flag = (uint8_t)(data[DATA_TIMELOW_IDX] > TIMELOW_MAX || data[DATA_TIMEMID_IDX] > TIMEMID_MAX ||
                     data[DATA_HVER_IDX] > TIMEMID_MAX);
    for (i = 0; i < UUID_SEQ_SIZE; i++)
        flag |= (uint8_t)(data[i + DATA_HVER_IDX + 1] > TIMESEQ_MAX);

    if (flag != 0) {
        tloge("uuid parse invalied\n");
        return TEE_ERROR_GENERIC;
    }

    uuid->timeLow = data[DATA_TIMELOW_IDX];
    uuid->timeMid = data[DATA_TIMEMID_IDX];
    uuid->timeHiAndVersion = data[DATA_HVER_IDX];
    for (i = 0; i < UUID_SEQ_SIZE; i++)
        uuid->clockSeqAndNode[i] = data[i + DATA_HVER_IDX + 1];

    return TEE_SUCCESS;
}

int32_t register_conf(const struct dyn_conf_t *dyn_conf, handler_install_obj install_obj_func,
                      void *obj, uint32_t obj_size)
{
    int32_t ret;
    char *buff = NULL;
    struct conf_queue_t conf_queue = {
        .queue = dlist_head_init(conf_queue.queue),
    };

    if (obj == NULL || dyn_conf == NULL ||
        dyn_conf->dyn_conf_size > MAX_IMAGE_LEN - 1 ||
        dyn_conf->dyn_conf_size == 0 ||
        install_obj_func == NULL) {
        tloge("valid params while register conf\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    buff = malloc(dyn_conf->dyn_conf_size);
    if (buff == NULL) {
        tloge("malloc buff for dyn conf failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (memcpy_s(buff, dyn_conf->dyn_conf_size, dyn_conf->dyn_conf_buffer, dyn_conf->dyn_conf_size) != EOK) {
        tloge("Failed to copy extension\n");
        ret = TEE_ERROR_GENERIC;
        goto out;
    }

    ret = parse_dyn_conf(&conf_queue, buff, dyn_conf->dyn_conf_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to parse dyn conf\n");
        goto out;
    }

    ret = install_obj_func(obj, obj_size, &conf_queue);
    if (ret != TEE_SUCCESS)
        tloge("Failed to load dyn conf\n");

out:
    if (buff != NULL)
        free(buff);

    free_conf_queue(&conf_queue);
    return ret;
}

#else
int32_t register_conf(const struct dyn_conf_t *dyn_conf, handler_install_obj handle, void *obj, uint32_t obj_size)
{
    (void)dyn_conf;
    (void)handle;
    (void)obj;
    (void)obj_size;
    return TEE_SUCCESS;
}

void unregister_conf(handler_uninstall_obj uninstall_obj_func, void *obj, uint32_t obj_size)
{
    (void)uninstall_obj_func;
    (void)obj;
    (void)obj_size;
}

uint16_t get_num_of_tag(const struct conf_queue_t *conf_queue, uint32_t tag)
{
    (void)conf_queue;
    (void)tag;
    return 0;
}

int32_t handle_conf_node_to_obj(struct dlist_node **pos, handler_conf_to_obj handle, void *obj, uint32_t obj_size)
{
    (void)pos;
    (void)handle;
    (void)obj;
    (void)obj_size;
    return TEE_SUCCESS;
}
#endif

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

#include "drv_dyn_conf_builder.h"
#include <securec.h>
#include <tee_log.h>
#include <dlist.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include <drv_dyn_conf_mgr.h>
#include <target_type.h>
#include <ta_framework.h>
#include <mem_ops.h>
#include "drvcall_dyn_conf_builder.h"
#include "tee_inner_uuid.h"

#ifdef TEE_SUPPORT_DYN_CONF

static struct tee_uuid g_drv_server_uuid = DRVMGR;

static int32_t check_uuid_valid(struct tee_uuid uuid)
{
    char *buff[sizeof(uuid)] = { 0 };

    if (memcmp(buff, &uuid, sizeof(uuid)) == 0)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

/*
 * free section
 * the func that free all things you have malloced
 */
static void do_free_drv_conf(void **list, uint16_t *list_size, uint32_t st_size)
{
    if (*list != NULL && (*list_size) != 0) {
        free_sharemem(*list, (*list_size) * st_size);
        *list = NULL;
        *list_size = 0;
    }
}

static void free_drv_conf(struct drv_conf_t *drv_conf)
{
    if (drv_conf == NULL)
        return;

    do_free_drv_conf((void **)&(drv_conf->io_map_list),
                     &(drv_conf->io_map_list_size), sizeof(struct addr_region_t));
    do_free_drv_conf((void **)&(drv_conf->irq_list), &(drv_conf->irq_list_size), sizeof(uint64_t));
    do_free_drv_conf((void **)&(drv_conf->map_secure_list),
                     &(drv_conf->map_secure_list_size), sizeof(struct drv_map_secure_t));
    do_free_drv_conf((void **)&(drv_conf->map_nosecure_list),
                     &(drv_conf->map_nosecure_list_size), sizeof(struct drv_map_nosecure_t));
    do_free_drv_conf((void **)&(drv_conf->mac_info_list),
                     &(drv_conf->mac_info_list_size), sizeof(struct drv_mac_info_t));
    do_free_drv_conf((void **)&(drv_conf->cmd_perm_list),
                     &(drv_conf->cmd_perm_list_size), sizeof(struct drv_cmd_perm_info_t));
}

static void free_drv_tlv(struct drv_tlv *drv)
{
    free_drv_conf(&drv->drv_conf);
    free_drvcall_perm(&drv->drvcall_perm_apply);
    free(drv);
}

/*
 * init section
 * init all objs that you want to use
 */
static int32_t init_drv_conf_mani(const struct drv_mani_t *mani, struct drv_conf_t *drv_conf)
{
    if (mani->service_name_size >= DRV_NAME_MAX_LEN) {
        tloge("service name is too long %u\n", mani->service_name_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(drv_conf->mani.service_name, DRV_NAME_MAX_LEN, mani->service_name, mani->service_name_size) != 0) {
        tloge("memcpy service name to drv conf failed\n");
        return TEE_ERROR_GENERIC;
    }
    drv_conf->mani.service_name[mani->service_name_size] = '\0';
    drv_conf->mani.service_name_size = mani->service_name_size;
    drv_conf->mani.keep_alive = mani->keep_alive;
    drv_conf->mani.data_size = mani->data_size;
    drv_conf->mani.stack_size = mani->stack_size;
    drv_conf->mani.hardware_type = mani->hardware_type;

    return TEE_SUCCESS;
}

/*
 * scan the conf_queue from start
 * when we find item_tag, then we will check it's chip_type
 * if chip type is invalid, it will be set DRV_PERM_UNUSED
 */
static int32_t init_drv_conf_filter_chip_type(const struct conf_queue_t *conf_queue, struct tag_crew tags,
                                              void **list, uint16_t *list_size, uint32_t size)
{
    struct dlist_node *pos = NULL;
    uint32_t count = 0;
    uint8_t flag = 0;

    dlist_for_each(pos, &conf_queue->queue) {
        struct conf_node_t *conf_node = dlist_entry(pos, struct conf_node_t, head);
        if (conf_node->tag != tags.item_tag && conf_node->tag != tags.data_tag)
            continue;

        /* check if chip type is valid */
        if (conf_node->tag == tags.item_tag) {
            if (check_item_chip_type(pos, tags.type_tag) != TEE_SUCCESS) {
                flag = 0;
                conf_node->tag = DRV_PERM_UNUSED;
                continue;
            }
            flag = 1;
            continue;
        }

        /* if chip type is invalid, then ignore it */
        if (conf_node->tag == tags.data_tag && flag == 0)
            continue;

        /* if value is not NULL, means at least has one region */
        if (conf_node->size > 0)
            count++;

        /* each split_tag means a new region */
        for (uint32_t i = 0; i < conf_node->size; i++) {
            if (conf_node->value[i] == tags.split_tag)
                count++;
        }
        flag = 0;
    }

    /* count is 0 means xml don't contain this tag, so it is no need to init */
    if (count == 0)
        return TEE_SUCCESS;

    uint32_t tmp_size = count * size;
    if (size == 0 || count >= (MAX_IMAGE_LEN / size)) {
        tloge("tmp size is invalid %u\n", tmp_size);
        return TEE_ERROR_GENERIC;
    }

    *list = alloc_sharemem_aux(&g_drv_server_uuid, tmp_size);
    if (*list == NULL) {
        tloge("malloc for tlv list failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (memset_s(*list, tmp_size, 0, tmp_size) != 0) {
        tloge("memset for tlv list failed\n");
        (void)free_sharemem(*list, tmp_size);
        *list = NULL;
        return TEE_ERROR_GENERIC;
    }

    *list_size = count;

    return TEE_SUCCESS;
}

static int32_t init_drv_io_map(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    drv_conf->io_map_list_index = 0;
    struct tag_crew tags;
    tags.item_tag = DRV_PERM_DRV_IO_MAP_ITEM;
    tags.data_tag = DRV_PERM_DRV_IO_MAP_ITEM_IOMAP;
    tags.type_tag = DRV_PERM_DRV_IO_MAP_ITEM_CHIP_TYPE;
    tags.split_tag = ';';

    return init_drv_conf_filter_chip_type(conf_queue, tags, (void **)&(drv_conf->io_map_list),
                                          &(drv_conf->io_map_list_size), sizeof(struct addr_region_t));
}

static int32_t init_drv_irq(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    drv_conf->irq_list_index = 0;
    struct tag_crew tags;
    tags.item_tag = DRV_PERM_IRQ_ITEM;
    tags.data_tag = DRV_PERM_IRQ_ITEM_IRQ;
    tags.type_tag = DRV_PERM_IRQ_ITEM_CHIP_TYPE;
    tags.split_tag = ',';

    return init_drv_conf_filter_chip_type(conf_queue, tags, (void **)&(drv_conf->irq_list),
                                          &(drv_conf->irq_list_size), sizeof(uint64_t));
}

static int32_t init_drv_map_secure(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    struct tag_crew tags;
    tags.item_tag = DRV_PERM_MAP_SECURE_ITEM;
    tags.data_tag = DRV_PERM_MAP_SECURE_ITEM_REGION;
    tags.type_tag = DRV_PERM_MAP_SECURE_ITEM_CHIP_TYPE;
    tags.split_tag = ';';

    return init_drv_conf_filter_chip_type(conf_queue, tags, (void **)&(drv_conf->map_secure_list),
                                          &(drv_conf->map_secure_list_size), sizeof(struct drv_map_secure_t));
}

static int32_t init_drv_map_nosecure(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    struct tag_crew tags;
    tags.item_tag = DRV_PERM_MAP_NOSECURE_ITEM;
    tags.data_tag = DRV_PERM_MAP_NOSECURE_ITEM_UUID;
    tags.type_tag = DRV_PERM_MAP_NOSECURE_ITEM_CHIP_TYPE;
    tags.split_tag = ',';

    return init_drv_conf_filter_chip_type(conf_queue, tags, (void **)&(drv_conf->map_nosecure_list),
                                          &(drv_conf->map_nosecure_list_size), sizeof(struct drv_map_nosecure_t));
}

static int32_t init_drv_mac_info(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    drv_conf->mac_info_list_index = 0;
    drv_conf->mac_info_list_size = get_num_of_tag(conf_queue, DRV_PERM_DRV_MAC_INFO_ITEM);

    if (drv_conf->mac_info_list_size == 0)
        return TEE_SUCCESS;

    /* drv_conf->mac_info_list_size <= 0xffff means tmp_size cannot larger than 0xFFFFFFFF */
    uint32_t tmp_size = drv_conf->mac_info_list_size * sizeof(struct drv_mac_info_t);
    if (tmp_size >= MAX_IMAGE_LEN) {
        tloge("mac info tmp size is invalid %u\n", tmp_size);
        return TEE_ERROR_GENERIC;
    }

    drv_conf->mac_info_list = alloc_sharemem_aux(&g_drv_server_uuid, tmp_size);
    if (drv_conf->mac_info_list == NULL) {
        tloge("malloc for mac list failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t init_drv_cmd_perm(struct drv_conf_t *drv_conf, const struct conf_queue_t *conf_queue)
{
    drv_conf->cmd_perm_list_index = 0;
    drv_conf->cmd_perm_list_size = get_num_of_tag(conf_queue, DRV_PERM_DRV_CMD_PERM_INFO_ITEM);

    if (drv_conf->cmd_perm_list_size == 0)
        return TEE_SUCCESS;

    /* drv_conf->cmd_perm_list_size < 0xffff means tmp_size cannot larger than 0xFFFFFFFF */
    uint32_t tmp_size = drv_conf->cmd_perm_list_size * sizeof(struct drv_cmd_perm_info_t);
    if (tmp_size >= MAX_IMAGE_LEN) {
        tloge("cmd perm tmp size is invalid %u\n", tmp_size);
        return TEE_ERROR_GENERIC;
    }

    drv_conf->cmd_perm_list = alloc_sharemem_aux(&g_drv_server_uuid, tmp_size);
    if (drv_conf->cmd_perm_list == NULL) {
        tloge("malloc for cmd_perm list failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t init_drv_conf(const struct drv_mani_t *mani, struct drv_conf_t *drv_conf,
                             const struct conf_queue_t *conf_queue)
{
    if (memset_s(drv_conf, sizeof(*drv_conf), 0, sizeof(*drv_conf)) != 0) {
        tloge("memset for init drv conf failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* init drv conf manifest by manifest.txt */
    if (init_drv_conf_mani(mani, drv_conf) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    if (init_drv_io_map(drv_conf, conf_queue) != TEE_SUCCESS ||
        init_drv_irq(drv_conf, conf_queue) != TEE_SUCCESS ||
        init_drv_map_secure(drv_conf, conf_queue) != TEE_SUCCESS ||
        init_drv_map_nosecure(drv_conf, conf_queue) != TEE_SUCCESS ||
        init_drv_mac_info(drv_conf, conf_queue) != TEE_SUCCESS ||
        init_drv_cmd_perm(drv_conf, conf_queue) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    /* init drv basic info */
    drv_conf->drv_basic_info.thread_limit = 1;
    drv_conf->drv_basic_info.exception_mode = DYN_CONF_SYSCRASH_TAG;
    drv_conf->drv_basic_info.virt2phys = false;

    return TEE_SUCCESS;
}

static int32_t handle_drv_basic_info_thread_limit(uint32_t *thread_limit, uint32_t size, const char *value)
{
    uint64_t tmp_limit;

    if (value == NULL || size > MAX_UINT32_LEN || size == 0) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (trans_str_to_int(buff, size, BASE_OF_TEN, &tmp_limit) != TEE_SUCCESS) {
        tloge("get thread limit failed, and thread_limit\n");
        return TEE_ERROR_GENERIC;
    }

    if (tmp_limit > THREAD_LIMIT_MAX) {
        tlogi("get thread limit %llu larger than THREAD_LIMIT_MAX %u\n",
                (unsigned long long)tmp_limit, THREAD_LIMIT_MAX);
        *thread_limit = THREAD_LIMIT_MAX;
        return TEE_SUCCESS;
    }

    *thread_limit = (uint32_t)tmp_limit;
    if (*thread_limit == 0) {
        tloge("get thread limit should not be 0\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_basic_info_exception_mode(uint8_t *exception_mode, uint32_t size, const char *value)
{
    if (value == NULL || size >= MAX_IMAGE_LEN) {
        tloge("invalid param\n");
        return TEE_ERROR_GENERIC;
    }

    char buff[size + 1];
    if (memcpy_s(buff, size + 1, value, size) != 0) {
        tloge("memcpy failed\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (strncmp(buff, "restart", size + 1) == 0) {
        *exception_mode = DYN_CONF_RESTART_TAG;
        return TEE_SUCCESS;
    }

    if (strncmp(buff, "ddos", size + 1) == 0) {
        *exception_mode = DYN_CONF_DDOS_TAG;
        return TEE_SUCCESS;
    }

    if (strncmp(buff, "syscrash", size + 1) == 0) {
        *exception_mode = DYN_CONF_SYSCRASH_TAG;
        return TEE_SUCCESS;
    }

    tloge("cannot handle exception_mode %s\n", buff);
    return TEE_ERROR_GENERIC;
}

static int32_t build_drv_basic_info(struct dlist_node **pos, const struct conf_node_t *node,
                                    void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv basic info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_DRV_BASIC_INFO_UPGRADE:
        if (node->size == 1 && node->value[0] == '1')
            drv_conf->drv_basic_info.upgrade = true;
        break;
    case DRV_PERM_DRV_BASIC_INFO_VIRT2PHYS:
        if (node->size == 1 && node->value[0] == '1')
            drv_conf->drv_basic_info.virt2phys = true;
        break;
    case DRV_PERM_DRV_BASIC_INFO_THREAD_LIMIT:
        /* thread_limit has been checked in handle_drv_basic_info_thread_limit */
        if (handle_drv_basic_info_thread_limit(&drv_conf->drv_basic_info.thread_limit, node->size, node->value) != 0)
            return TEE_ERROR_GENERIC;
        break;
    case DRV_PERM_DRV_BASIC_INFO_EXCEPTION_MODE:
        if (handle_drv_basic_info_exception_mode(&drv_conf->drv_basic_info.exception_mode,
                                                 node->size, node->value) != 0)
            return TEE_ERROR_GENERIC;
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

/* build io map */
static int32_t tlv_to_iomap_region(const char *iomap_buff, uint32_t buff_len, struct addr_region_t *list,
                                   uint32_t list_size, uint16_t *count)
{
    uint32_t i;
    char buff[MAX_UINT64_LEN + 1] = { 0 };
    const char *head = iomap_buff;

    if (buff_len == 0) {
        tloge("iomap buff len is 0\n");
        return TEE_ERROR_GENERIC;
    }

    for (i = 0; i <= buff_len; i++) {
        (void)memset_s(buff, MAX_UINT64_LEN + 1, 0, MAX_UINT64_LEN + 1);

        if (iomap_buff[i] == ',' || iomap_buff[i] == ';' || iomap_buff[i] == '\0') {
            uint64_t offset = (uint64_t)(uintptr_t)(&iomap_buff[i] - head);
            if (offset > MAX_UINT64_LEN || offset == 0) {
                tloge("get iomap range offset failed %llu\n", (unsigned long long)offset);
                return TEE_ERROR_GENERIC;
            }

            if (memcpy_s(buff, MAX_UINT64_LEN, head, (size_t)offset) != 0) {
                tloge("memcpy for iomap buff failed\n");
                return TEE_ERROR_GENERIC;
            }
            buff[(uint32_t)offset] = '\0';
            if (i < buff_len)
                head = (const char *)&iomap_buff[i + 1];
        }

        if (*count >= list_size) {
            tloge("io map region list overflow\n");
            return TEE_ERROR_GENERIC;
        }

        if (iomap_buff[i] == ',') {
            if (trans_str_to_int(buff, strnlen(buff, MAX_UINT64_LEN),
                                 BASE_OF_HEX, &list[*count].start) != TEE_SUCCESS) {
                tloge("get iomap region start failed\n");
                return TEE_ERROR_GENERIC;
            }
        } else if (iomap_buff[i] == ';' || iomap_buff[i] == '\0') {
            if (trans_str_to_int(buff, strnlen(buff, MAX_UINT64_LEN),
                                 BASE_OF_HEX, &list[*count].end) != TEE_SUCCESS) {
                tloge("get iomap region end failed\n");
                return TEE_ERROR_GENERIC;
            }
            *count = *count + 1;
        }
    }

    return TEE_SUCCESS;
}

static int32_t check_drv_io_map_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;
    if (drv_conf == NULL) {
        tloge("invalid drv conf\n");
        return TEE_ERROR_GENERIC;
    }

    uint32_t i;
    for (i = 0; i < drv_conf->io_map_list_size; i++) {
        if (drv_conf->io_map_list[i].start % 0x1000 != 0 ||
            drv_conf->io_map_list[i].end % 0x1000 != 0) {
            tloge("io map region should be aligned by 0x1000\n");
            return TEE_ERROR_GENERIC;
        }

        if (drv_conf->io_map_list[i].end <= drv_conf->io_map_list[i].start) {
            tloge("io map region end must larger than start\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_io_map_item_iomap(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    if (size == 0 || value == NULL || size >= MAX_IMAGE_LEN) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *iomap_buff = NULL;
    /* size has been checked in handle_conf_node_to_obj, size is smaller than MAX_IMAGE_LEN */
    iomap_buff = malloc(size + 1);
    if (iomap_buff == NULL) {
        tloge("malloc for iomap buff failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* if walk in this func, iomap list size couldn't be zero */
    if (memcpy_s(iomap_buff, size + 1, value, size) != 0) {
        tloge("memcpy for iomap buff failed\n");
        free(iomap_buff);
        return TEE_ERROR_GENERIC;
    }
    iomap_buff[size] = '\0';

    if (tlv_to_iomap_region(iomap_buff, strnlen(iomap_buff, MAX_IMAGE_LEN),
                            drv_conf->io_map_list, drv_conf->io_map_list_size,
                            &drv_conf->io_map_list_index) != 0) {
        tloge("tlv to iomap region failed \n");
        free(iomap_buff);
        return TEE_ERROR_GENERIC;
    }

    free(iomap_buff);
    return TEE_SUCCESS;
}

static int32_t build_drv_io_map_item(struct dlist_node **pos, const struct conf_node_t *node,
                                     void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;

    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv io map item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_DRV_IO_MAP_ITEM_IOMAP:
        if (handle_drv_io_map_item_iomap(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv io map item iomap failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_io_map(struct dlist_node **pos, const struct conf_node_t *node, void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv io map\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_DRV_IO_MAP_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_io_map_item, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv io map item failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip in build iomap\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

/* build drv irq */
static int32_t handle_drv_irq_item_irq(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    int32_t ret = TEE_SUCCESS;
    char buff[MAX_UINT64_LEN + 1];

    if (size == 0 || value == NULL || size >= MAX_IMAGE_LEN) {
        tloge("size is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *irq_buff = malloc(size + 1);
    if (irq_buff == NULL) {
        tloge("malloc for irq buff failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (memcpy_s(irq_buff, size + 1, value, size) != 0) {
        ret = TEE_ERROR_GENERIC;
        goto out;
    }
    irq_buff[size] = '\0';

    char *head = irq_buff;
    for (uint32_t i = 0; i <= size; i++) {
        (void)memset_s(buff, MAX_UINT64_LEN + 1, 0, MAX_UINT64_LEN + 1);

        if (irq_buff[i] == ',' || irq_buff[i] == '\0') {
            uint64_t offset = (uint64_t)(uintptr_t)(&irq_buff[i] - head);
            if (offset > MAX_UINT64_LEN || offset == 0) {
                tloge("get irq offset failed %llu\n", (unsigned long long)offset);
                ret = TEE_ERROR_GENERIC;
                goto out;
            }

            if (memcpy_s(buff, MAX_UINT64_LEN, head, (size_t)offset) != 0) {
                tloge("memcpy for irq buff failed\n");
                ret = TEE_ERROR_GENERIC;
                goto out;
            }
            buff[(uint32_t)offset] = '\0';
            if (i < size)
                head = &irq_buff[i + 1];

            if (drv_conf->irq_list_index >= drv_conf->irq_list_size ||
                trans_str_to_int(buff, strnlen(buff, MAX_UINT64_LEN), BASE_OF_TEN,
                                 &drv_conf->irq_list[drv_conf->irq_list_index]) != TEE_SUCCESS) {
                tloge("get irq failed\n");
                ret = TEE_ERROR_GENERIC;
                goto out;
            }
            drv_conf->irq_list_index = drv_conf->irq_list_index + 1;
        }
    }

out:
    free(irq_buff);
    return ret;
}

static int32_t build_drv_irq_item(struct dlist_node **pos, const struct conf_node_t *node,
                                  void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;

    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv irq item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_IRQ_ITEM_IRQ:
        if (handle_drv_irq_item_irq(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv irq item irq failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t check_drv_irq_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;

    uint32_t i;
    for (i = 0; i < drv_conf->irq_list_size; i++) {
        if (drv_conf->irq_list[i] < IRQ_MIN) {
            tloge("invalid irq %llu\n", (unsigned long long)drv_conf->irq_list[i]);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

static int32_t build_drv_irq(struct dlist_node **pos, const struct conf_node_t *node, void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv irq\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_IRQ_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_irq_item, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv irq item failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip drv irq\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

/* build map secure */
static int32_t tlv_to_map_secure_region(const char *secure_buff, uint32_t secure_buff_len,
                                        struct drv_map_secure_t *list, uint32_t list_size, uint16_t *count)
{
    if (secure_buff_len == 0) {
        tloge("secure buff len is 0\n");
        return TEE_ERROR_GENERIC;
    }

    uint32_t i;
    char buff[MAX_UINT64_LEN + 1] = { 0 };
    const char *head = secure_buff;
    for (i = 0; i <= secure_buff_len; i++) {
        (void)memset_s(buff, MAX_UINT64_LEN + 1, 0, MAX_UINT64_LEN + 1);

        if (secure_buff[i] == ',' || secure_buff[i] == ';' || secure_buff[i] == '\0') {
            uint64_t offset = (uint64_t)(uintptr_t)(&secure_buff[i] - head);
            if (offset > MAX_UINT64_LEN || offset == 0) {
                tloge("get map_secure range offset failed %llu\n", (unsigned long long)offset);
                return TEE_ERROR_GENERIC;
            }

            if (memcpy_s(buff, MAX_UINT64_LEN, head, (size_t)offset) != 0) {
                tloge("memcpy for map_secure buff failed\n");
                return TEE_ERROR_GENERIC;
            }
            buff[(uint32_t)offset] = '\0';
            if (i < secure_buff_len)
                head = (const char *)&secure_buff[i + 1];
        }

        if (*count >= list_size) {
            tloge("map_secure region list overflow\n");
            return TEE_ERROR_GENERIC;
        }

        if (secure_buff[i] == ',') {
            if (trans_str_to_int(buff, strnlen(buff, MAX_UINT64_LEN),
                                 BASE_OF_HEX, &list[*count].region.start) != TEE_SUCCESS) {
                tloge("get map_secure region start failed\n");
                return TEE_ERROR_GENERIC;
            }
        } else if (secure_buff[i] == ';' || secure_buff[i] == '\0') {
            if (trans_str_to_int(buff, strnlen(buff, MAX_UINT64_LEN),
                                 BASE_OF_HEX, &list[*count].region.end) != TEE_SUCCESS) {
                tloge("get map_secure region end failed\n");
                return TEE_ERROR_GENERIC;
            }
            *count = *count + 1;
        }
    }

    return TEE_SUCCESS;
}

static int32_t get_ava_pos_in_map_secure(const struct drv_conf_t *drv_conf, uint16_t *uuid_pos, uint16_t *region_pos)
{
    uint32_t i;
    for (i = 0; i < drv_conf->map_secure_list_size; i++) {
        if (check_uuid_valid(drv_conf->map_secure_list[i].uuid) != TEE_SUCCESS)
            break;
    }
    *uuid_pos = i;

    for (i = 0; i < drv_conf->map_secure_list_size; i++) {
        if (drv_conf->map_secure_list[i].region.start == 0 &&
            drv_conf->map_secure_list[i].region.end == 0)
            break;
    }
    *region_pos = i;

    return TEE_SUCCESS;
}

static int32_t handle_drv_map_secure_item_uuid(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    struct tee_uuid uuid;

    int32_t ret = tlv_to_uuid(value, size, &uuid);
    if (ret != TEE_SUCCESS)
        return ret;

    uint32_t i;
    uint16_t uuid_pos;
    uint16_t region_pos;
    if (get_ava_pos_in_map_secure(drv_conf, &uuid_pos, &region_pos) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    if (uuid_pos == region_pos) {
        if (region_pos < drv_conf->map_secure_list_size &&
            memcpy_s(&drv_conf->map_secure_list[region_pos].uuid, sizeof(drv_conf->map_secure_list[region_pos].uuid),
                     &uuid, sizeof(uuid)) != 0) {
            tloge("memcpy for uuid in map secure list failed\n");
            return TEE_ERROR_GENERIC;
        }
    } else if (region_pos > uuid_pos) {
        for (i = uuid_pos; i < region_pos; i++) {
            if (i < drv_conf->map_secure_list_size &&
                memcpy_s(&drv_conf->map_secure_list[i].uuid, sizeof(drv_conf->map_secure_list[i].uuid),
                         &uuid, sizeof(uuid)) != 0) {
                tloge("memcpy for uuid in map sercure list failed\n");
                return TEE_ERROR_GENERIC;
            }
        }
    } else {
        tloge("uuid pos cannot larger than region pos, something wrong happeds\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_map_secure_item_region(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    if (size >= MAX_IMAGE_LEN) {
        tloge("param is invalid %u\n", size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = TEE_ERROR_GENERIC;
    uint16_t uuid_pos;
    uint16_t region_pos;
    if (get_ava_pos_in_map_secure(drv_conf, &uuid_pos, &region_pos) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    char *iomap_buff = malloc(size + 1);
    if (iomap_buff == NULL) {
        tloge("malloc for iomap buff failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (memset_s(iomap_buff, size + 1, 0, size + 1) != 0 || memcpy_s(iomap_buff, size + 1, value, size) != 0) {
        tloge("memset or memcpy for iomap buff failed\n");
        goto out;
    }

    if (uuid_pos == region_pos) {
        if (tlv_to_map_secure_region(iomap_buff, strnlen(iomap_buff, MAX_IMAGE_LEN),
                                     drv_conf->map_secure_list, drv_conf->map_secure_list_size, &region_pos) != 0)
            goto out;
    } else if (uuid_pos > region_pos) {
        if (tlv_to_map_secure_region(iomap_buff, strnlen(iomap_buff, MAX_IMAGE_LEN),
                                     drv_conf->map_secure_list, drv_conf->map_secure_list_size, &region_pos) != 0)
            goto out;

        for (uint32_t i = uuid_pos; i < region_pos; i++) {
            if (i < drv_conf->map_secure_list_size &&
                memcpy_s(&drv_conf->map_secure_list[i].uuid, sizeof(drv_conf->map_secure_list[i].uuid),
                         &drv_conf->map_secure_list[uuid_pos - 1].uuid,
                         sizeof(drv_conf->map_secure_list[uuid_pos - 1].uuid)) != 0) {
                tloge("memcpy map secure region uuid failed\n");
                goto out;
            }
        }
    } else {
        tloge("region pos cannot larger than uuid pos, something wrong happeds\n");
        goto out;
    }

    ret = TEE_SUCCESS;
out:
    free(iomap_buff);
    return ret;
}

static int32_t build_drv_map_secure_item(struct dlist_node **pos, const struct conf_node_t *node,
                                         void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;

    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv map secure item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_MAP_SECURE_ITEM_UUID:
        if (handle_drv_map_secure_item_uuid(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv map secure item uuid failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case DRV_PERM_MAP_SECURE_ITEM_REGION:
        if (handle_drv_map_secure_item_region(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv map secure item region failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t check_drv_map_secure_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;

    uint32_t i;
    for (i = 0; i < drv_conf->map_secure_list_size; i++) {
        if (drv_conf->map_secure_list[i].region.start % 0x1000 != 0 ||
            drv_conf->map_secure_list[i].region.end % 0x1000 != 0) {
            tloge("map secure region should be aligned by 4K\n");
            return TEE_ERROR_GENERIC;
        }

        if (drv_conf->map_secure_list[i].region.end <= drv_conf->map_secure_list[i].region.start) {
            tloge("map secure region end must larger than start\n");
            return TEE_ERROR_GENERIC;
        }

        if (check_uuid_valid(drv_conf->map_secure_list[i].uuid) != TEE_SUCCESS) {
            tloge("map secure uuid is invalid\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_map_secure(struct dlist_node **pos, const struct conf_node_t *node,
                                    void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv map secure\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_MAP_SECURE_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_map_secure_item,
                                    drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv map secure item failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        tlogd("skip drv map secure\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

/* build map nosecure */
static int32_t check_drv_map_nosecure_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;

    uint32_t i;
    for (i = 0; i < drv_conf->map_nosecure_list_size; i++) {
        if (check_uuid_valid(drv_conf->map_nosecure_list[i].uuid) != TEE_SUCCESS) {
            tloge("map nosecure uuid is invalid\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_map_nosecure_item_uuid(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    if (size >= MAX_IMAGE_LEN) {
        tloge("size is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *buff = malloc(size + 1);
    if (buff == NULL) {
        tloge("malloc for nosecure item failed\n");
        return TEE_ERROR_GENERIC;
    }

    int32_t ret = TEE_SUCCESS;
    if (memcpy_s(buff, size + 1, value, size) != 0) {
        tloge("memcpy for nosecure item failed\n");
        ret = TEE_ERROR_GENERIC;
        goto out;
    }
    buff[size] = '\0';

    char *head = buff;
    uint32_t i;
    for (i = 0; i <= size; i++) {
        if (buff[i] == ',' || buff[i] == '\0') {
            uint32_t offset = (uint32_t)(uintptr_t)(&buff[i] - head);
            if (drv_conf->map_nosecure_list_index >= drv_conf->map_nosecure_list_size) {
                tloge("map nosecure list index overflow\n");
                ret = TEE_ERROR_GENERIC;
                goto out;
            }

            ret = tlv_to_uuid(head, offset, &drv_conf->map_nosecure_list[drv_conf->map_nosecure_list_index].uuid);
            if (ret != TEE_SUCCESS)
                goto out;

            drv_conf->map_nosecure_list_index++;
            if (i < size)
                head = &buff[i + 1];
        }
    }

out:
    /* buff cannot be NULL */
    free(buff);
    return ret;
}

static int32_t build_drv_map_nosecure_item(struct dlist_node **pos, const struct conf_node_t *node,
                                           void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;

    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv map nosecure item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_MAP_NOSECURE_ITEM_UUID:
        if (handle_drv_map_nosecure_item_uuid(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv map nosecure item uuid failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_map_nosecure(struct dlist_node **pos, const struct conf_node_t *node,
                                      void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv map nonsecure\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_MAP_NOSECURE_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_map_nosecure_item,
                                    drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv map nosecure item failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

/* build mac info */
static int32_t check_drv_mac_info_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;

    uint32_t i, j;
    for (i = 0; i < drv_conf->mac_info_list_size; i++) {
        if (check_uuid_valid(drv_conf->mac_info_list[i].uuid) != TEE_SUCCESS) {
            tloge("mac info uuid is invalid\n");
            return TEE_ERROR_GENERIC;
        }
        for (j = i + 1; j < drv_conf->mac_info_list_size; j++) {
            if (memcmp(&drv_conf->mac_info_list[i].uuid, &drv_conf->mac_info_list[j].uuid,
                       sizeof(drv_conf->mac_info_list[i].uuid)) == 0) {
                tloge("mac info uuid %08x-%04x-%04x set more than one time\n",
                         drv_conf->mac_info_list[i].uuid.timeLow, drv_conf->mac_info_list[i].uuid.timeMid,
                         drv_conf->mac_info_list[i].uuid.timeHiAndVersion);
                return TEE_ERROR_GENERIC;
            }
        }
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_mac_info_item_permission(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    if (drv_conf->mac_info_list_index >= drv_conf->mac_info_list_size) {
        tloge("mac_info_list_index is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = combine_perms(&drv_conf->mac_info_list[drv_conf->mac_info_list_index].perm, size, value);

    return ret;
}

static int32_t handle_drv_mac_info_item_uuid(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    struct tee_uuid uuid;
    uint32_t count = drv_conf->mac_info_list_index;

    if (count >= drv_conf->mac_info_list_size) {
        tloge("mac_info_list_index is overflow %u\n", count);
        return TEE_ERROR_GENERIC;
    }

    int32_t ret = tlv_to_uuid(value, size, &uuid);
    if (ret != TEE_SUCCESS)
        return ret;

    if (memcpy_s(&drv_conf->mac_info_list[count].uuid, sizeof(drv_conf->mac_info_list[count].uuid),
                 &uuid, sizeof(struct tee_uuid)) != 0) {
        tloge("memcpy for uuid in mac info list failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_mac_info_item(struct dlist_node **pos, const struct conf_node_t *node,
                                       void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;
    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv mac info item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_DRV_MAC_INFO_ITEM_UUID:
        if (handle_drv_mac_info_item_uuid(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv mac info item uuid failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case DRV_PERM_DRV_MAC_INFO_ITEM_PERMISSION:
        if (handle_drv_mac_info_item_permission(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv mac info item permission failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_mac_info(struct dlist_node **pos, const struct conf_node_t *node,
                                  void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv mac info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_DRV_MAC_INFO_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_mac_info_item,
                                    drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv mac info item failed\n");
            return TEE_ERROR_GENERIC;
        }
        drv_conf->mac_info_list_index = drv_conf->mac_info_list_index + 1;
        break;
    default:
        tlogd("skip in build drv mac info\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

/* build cmd perm info */
static int32_t check_drv_cmd_perm_invalid(const void *obj)
{
    const struct drv_conf_t *drv_conf = (const struct drv_conf_t *)obj;

    uint32_t i, j;
    for (i = 0; i < drv_conf->cmd_perm_list_size; i++) {
        if (drv_conf->cmd_perm_list[i].perm == 0) {
            tloge("cmd perm is invalid\n");
            return TEE_ERROR_GENERIC;
        }
        for (j = i + 1; j < drv_conf->cmd_perm_list_size; j++) {
            if (drv_conf->cmd_perm_list[i].cmd == drv_conf->cmd_perm_list[j].cmd) {
                tloge("cmd %llx has been set more than one time in cmd perm\n",
                         (unsigned long long)drv_conf->cmd_perm_list[i].cmd);
                return TEE_ERROR_GENERIC;
            }
        }
    }

    return TEE_SUCCESS;
}

static int32_t handle_drv_cmd_perm_info_item_cmd(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    uint64_t tmp_cmd = 0;
    if (size == 0 || size > MAX_UINT32_LEN) {
        tloge("param invalid while handle cmd perm info item cmd\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed while handle cmd perm info item cmd\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    if (trans_str_to_int(buff, size, BASE_OF_HEX, &tmp_cmd) != TEE_SUCCESS) {
        tloge("get cmd failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (tmp_cmd > DRV_CMD_MAX) {
        tloge("get cmd %llu is larger than DRV_CMD_MAX\n", (unsigned long long)tmp_cmd);
        return TEE_ERROR_GENERIC;
    }

    if (drv_conf->cmd_perm_list_index >= drv_conf->cmd_perm_list_size) {
        tloge("cmd_perm_list_index is overflow %u\n", drv_conf->cmd_perm_list_index);
        return TEE_ERROR_GENERIC;
    }

    drv_conf->cmd_perm_list[drv_conf->cmd_perm_list_index].cmd = (uint32_t)tmp_cmd;

    return TEE_SUCCESS;
}

static int32_t handle_drv_cmd_perm_info_item_permission(struct drv_conf_t *drv_conf, uint32_t size, const char *value)
{
    if (size == 0 || size > MAX_UINT32_LEN) {
        tloge("param invalid while handle cmd perm info item permission\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char buff[MAX_UINT32_LEN + 1];
    if (memcpy_s(buff, sizeof(buff), value, size) != 0) {
        tloge("memcpy failed while handle cmd perm info item permission\n");
        return TEE_ERROR_GENERIC;
    }
    buff[size] = '\0';

    uint64_t off = 0;
    if (trans_str_to_int(buff, size, BASE_OF_TEN, &off) != TEE_SUCCESS) {
        tloge("get perm failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (off == 0 || off > BIT_NUM_OF_UINT64) {
        tloge("cmd permssion must in range of [1, 64]\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (drv_conf->cmd_perm_list_index >= drv_conf->cmd_perm_list_size) {
        tloge("cmd_perm_list_index is overflow %u\n", drv_conf->cmd_perm_list_index);
        return TEE_ERROR_GENERIC;
    }

    drv_conf->cmd_perm_list[drv_conf->cmd_perm_list_index].perm = (1 << (off - 1));

    return TEE_SUCCESS;
}

static int32_t build_drv_cmd_perm_info_item(struct dlist_node **pos, const struct conf_node_t *node,
                                            void *obj, uint32_t obj_size)
{
    (void)pos;
    struct drv_conf_t *drv_conf = NULL;
    if (obj_size != sizeof(*drv_conf)) {
        tloge("obj size is invalid while build drv cmd perm info item\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv_conf = (struct drv_conf_t *)obj;

    switch (node->tag) {
    case DRV_PERM_DRV_CMD_PERM_INFO_ITEM_CMD:
        if (handle_drv_cmd_perm_info_item_cmd(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv cmd perm info item cmd failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    case DRV_PERM_DRV_CMD_PERM_INFO_ITEM_PERMISSION:
        if (handle_drv_cmd_perm_info_item_permission(drv_conf, node->size, node->value) != TEE_SUCCESS) {
            tloge("handle drv cmd perm info item permission failed\n");
            return TEE_ERROR_GENERIC;
        }
        break;
    default:
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_cmd_perm_info(struct dlist_node **pos, const struct conf_node_t *node,
                                       void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv cmd perm info\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    switch (node->tag) {
    case DRV_PERM_DRV_CMD_PERM_INFO_ITEM:
        if (handle_conf_node_to_obj(pos, build_drv_cmd_perm_info_item,
                                    drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS) {
            tloge("build drv cmd perm info item failed\n");
            return TEE_ERROR_GENERIC;
        }
        drv_conf->cmd_perm_list_index = drv_conf->cmd_perm_list_index + 1;
        break;
    default:
        tlogd("skip in build drv cmd perm info\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
        break;
    }

    return TEE_SUCCESS;
}

static int32_t build_drv_drvcall_conf(struct dlist_node **pos, const struct conf_node_t *node,
                                      void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv drvcall conf\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drvcall_perm_apply_t *drvcall_perm = &drv->drvcall_perm_apply;
    int32_t ret = build_drvcall_perm_apply(pos, node, drvcall_perm, sizeof(*drvcall_perm));
    if (ret != 0) {
        tloge("drv build drvcall conf fail\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static struct dyn_conf_build_func dyn_conf_funcs[] = {
    { DRV_PERM_DRV_BASIC_INFO, build_drv_basic_info, NULL },
    { DRV_PERM_DRV_IO_MAP, build_drv_io_map, check_drv_io_map_invalid },
    { DRV_PERM_IRQ, build_drv_irq, check_drv_irq_invalid },
    { DRV_PERM_MAP_SECURE, build_drv_map_secure, check_drv_map_secure_invalid },
    { DRV_PERM_MAP_NOSECURE, build_drv_map_nosecure, check_drv_map_nosecure_invalid },
    { DRV_PERM_DRV_CMD_PERM_INFO, build_drv_cmd_perm_info, check_drv_cmd_perm_invalid },
    { DRV_PERM_DRV_MAC_INFO, build_drv_mac_info, check_drv_mac_info_invalid },
    { DRV_PERM_DRVCALL_PERM_APPLY, build_drv_drvcall_conf, NULL },
};

/* build drv conf */
static int32_t build_drv_conf(struct dlist_node **pos, const struct conf_node_t *node, void *obj, uint32_t obj_size)
{
    struct drv_tlv *drv = NULL;

    if (obj_size != sizeof(*drv)) {
        tloge("obj size is invalid while build drv conf\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    drv = (struct drv_tlv *)obj;
    struct drv_conf_t *drv_conf = &drv->drv_conf;

    uint32_t dyn_conf_funcs_size = sizeof(dyn_conf_funcs) / sizeof(dyn_conf_funcs[0]);
    uint32_t i;
    for (i = 0; i < dyn_conf_funcs_size; i++) {
        if (node->tag != dyn_conf_funcs[i].tag)
            continue;

        if (dyn_conf_funcs[i].handle != NULL &&
            handle_conf_node_to_obj(pos, dyn_conf_funcs[i].handle, drv, sizeof(*drv)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        if (dyn_conf_funcs[i].checker != NULL && dyn_conf_funcs[i].checker(drv_conf) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;

        break;
    }

    if (i == dyn_conf_funcs_size) {
        tlogd("skip in build drv conf\n");
        if (handle_conf_node_to_obj(pos, NULL, drv_conf, sizeof(*drv_conf)) != TEE_SUCCESS)
            return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t send_drv_conf(const struct drv_tlv *drv_conf, uint32_t drv_conf_size)
{
    uint64_t args[] = {
        (uintptr_t)drv_conf,
        drv_conf_size,
    };

    uint32_t lens[] = {
        drv_conf_size,
        0,
    };

    /* the main thread just handle register cmd */
    return drv_call_new("drvmgr", REGISTER_DRV_CONF, args, lens, ARRAY_SIZE(args));
}

void dump_drv_conf(void)
{
    uint64_t args[] = {};
    uint32_t lens[] = {};
#ifndef CONFIG_DISABLE_MULTI_DRV
    (void)drv_call_new("drvmgr_multi", DUMP_DRV_CONF, args, lens, ARRAY_SIZE(args));
#else
    (void)drv_call_new("drvmgr", DUMP_DRV_CONF, args, lens, ARRAY_SIZE(args));
#endif
}

static int32_t send_drv_service_name(const char *service_name, uint32_t name_size)
{
    uint64_t args[] = {
        (uintptr_t)service_name,
        name_size,
    };

    uint32_t lens[] = {
        name_size,
        0,
    };
#ifndef CONFIG_DISABLE_MULTI_DRV
    return drv_call_new("drvmgr_multi", UNREGISTER_DRV_CONF, args, lens, ARRAY_SIZE(args));
#else
    return drv_call_new("drvmgr", UNREGISTER_DRV_CONF, args, lens, ARRAY_SIZE(args));
#endif
}

void uninstall_drv_permission(const void *obj, uint32_t obj_size)
{
    if (obj == NULL) {
        tloge("obj is invalid while uninstall drv permission\n");
        return;
    }

    if (obj_size == 0 || obj_size >= DRV_NAME_MAX_LEN) {
        tloge("obj size is invalid while uninstall drv permission\n");
        return;
    }

    const char *service_name = (const char *)obj;
    if (send_drv_service_name(service_name, obj_size) != 0)
        tloge("uninstall drv permission failed");
}

int32_t install_drv_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    /* 1. check the param */
    if (obj == NULL || conf_queue == NULL) {
        tloge("param is invalid while install drv permission\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (obj_size != sizeof(struct drv_mani_t)) {
        tloge("obj size is invalid while install drv permission\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* 2. parse the obj to what you want */
    struct drv_mani_t *mani = (struct drv_mani_t *)obj;

    /* 3.create new obj */
    struct drv_tlv *drv = (struct drv_tlv *)malloc(sizeof(struct drv_tlv));
    if (drv == NULL) {
        tloge("drv malloc failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* 4.init new obj */
    (void)memset_s(drv, sizeof(*drv), 0, sizeof(*drv));

    int32_t ret = -1;
    if (memcpy_s(&drv->uuid, sizeof(drv->uuid), &mani->srv_uuid, sizeof(mani->srv_uuid)) != 0) {
        tloge("set uuid to drv fail\n");
        goto out;
    }

    ret = init_drv_conf(mani, &drv->drv_conf, conf_queue);
    if (ret != TEE_SUCCESS)
        goto out;

    if (init_drvcall_conf(&drv->drvcall_perm_apply, conf_queue) != 0)
        goto out;

    /* 5.handle new obj */
    if (!dlist_empty(&conf_queue->queue)) {
        struct dlist_node *pos = dlist_get_next(&conf_queue->queue);
        ret = handle_conf_node_to_obj(&pos, build_drv_conf, drv, sizeof(*drv));
        if (ret != TEE_SUCCESS) {
            tloge("handle drv conf failed\n");
            goto out;
        }
    }

    /* 6.do something else */
    ret = send_drv_conf(drv, sizeof(*drv));

out:
    /* 7.err handle, free obj */
    free_drv_tlv(drv);
    return ret;
}

#else
int32_t install_drv_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue)
{
    (void)obj;
    (void)obj_size;
    (void)conf_queue;
    return TEE_SUCCESS;
}

void uninstall_drv_permission(const void *obj, uint32_t obj_size)
{
    (void)obj;
    (void)obj_size;
}

void dump_drv_conf(void)
{
    return;
}

#endif

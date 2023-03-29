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
#include "crypto_syscall_common.h"
#include <securec.h>
#include <tee_log.h>
#include "drv_param_ops.h"
#include <sys/mman.h>
#include "crypto_mgr_syscall.h"

bool check_hal_params_is_invalid(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    if (drv == NULL || ops == NULL) {
        tloge("drv or ops is NULL\n");
        return true;
    }

    if (args == 0 || args_len != (uint32_t)sizeof(struct crypto_ioctl)) {
        tloge("invalid input arg or args_len:%u\n", args_len);
        return true;
    }

    return false;
}

int32_t do_power_on(const struct crypto_drv_ops_t *ops)
{
    if (ops == NULL) {
        tloge("ops is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (ops->power_on == NULL)
        return CRYPTO_SUCCESS;

    int32_t ret = ops->power_on();
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do power on failed. ret = %d\n", ret);

    return ret;
}

void do_power_off(const struct crypto_drv_ops_t *ops)
{
    int32_t ret;
    if (ops == NULL || ops->power_off == NULL)
        return;

    ret = ops->power_off();
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do power off failed, ret = %d\n", ret);
}

uint32_t change_pkcs5_to_nopad(uint32_t alg_type)
{
    switch (alg_type) {
    case CRYPTO_TYPE_AES_ECB_PKCS5:
        return CRYPTO_TYPE_AES_ECB_NOPAD;
    case CRYPTO_TYPE_AES_CBC_PKCS5:
        return CRYPTO_TYPE_AES_CBC_NOPAD;
    case CRYPTO_TYPE_AES_CBC_MAC_PKCS5:
        return CRYPTO_TYPE_AES_CBC_MAC_NOPAD;
    default:
        break;
    }

    return alg_type;
}

static int32_t copy_to_shared_buf(const void *buf, uint32_t buf_size, uint8_t **shared_buf)
{
    if (memmove_s(*shared_buf, sizeof(uint32_t), &buf_size, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += sizeof(uint32_t);

    if (buf_size == 0)
        return CRYPTO_SUCCESS;

    if (memmove_s(*shared_buf, buf_size, buf, buf_size) != EOK) {
        tloge("copy buf failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += buf_size;

    return CRYPTO_SUCCESS;
}

int32_t fill_share_mem(uint8_t *shared_buf, const struct memref_t *fill_data, uint32_t fill_data_count)
{
    if (shared_buf == NULL || fill_data == NULL) {
        tloge("shared buf or fill data is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    for (uint32_t i = 0; i < fill_data_count; i++) {
        int32_t ret = copy_to_shared_buf((void *)(uintptr_t)fill_data[i].buffer, fill_data[i].size, &shared_buf);
        if (ret != CRYPTO_SUCCESS) {
            tloge("fill share memory failed! fill data No. = %d\n", i);
            return ret;
        }
    }
    return CRYPTO_SUCCESS;
}

static bool check_share_mem_size(const uint8_t *share_mem, uint32_t total_nums, uint32_t buf_len)
{
    uint32_t share_mem_size = 0;
    uint32_t temp_size = 0;

    for (uint32_t i = 0; i < total_nums; i++) {
        if (memcpy_s(&temp_size, sizeof(uint32_t), share_mem, sizeof(uint32_t)) != EOK) {
            tloge("get buf size failed\n");
            return false;
        }

        if (temp_size > buf_len) {
            tloge("the %d size is too big\n", i);
            return false;
        }

        share_mem_size += sizeof(uint32_t) + temp_size;
        share_mem += sizeof(uint32_t) + temp_size;
        if (share_mem_size > buf_len) {
            tloge("share mem size is too big\n");
            return false;
        }
    }

    if (share_mem_size == buf_len) {
        return true;
    } else {
        tloge("share memory size = %u is not equal to get share memory size = %u\n", buf_len, share_mem_size);
        return false;
    }
}

static int32_t copy_from_shared_buf(uint64_t *buf_ptr, uint32_t *buf_size, uint8_t **shared_buf)
{
    if (memcpy_s(buf_size, sizeof(uint32_t), *shared_buf, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size fail\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += sizeof(uint32_t);

    if (*buf_size == 0)
        *buf_ptr = 0;
    else
        *buf_ptr = (uint64_t)(uintptr_t)*shared_buf;

    *shared_buf += *buf_size;
    return CRYPTO_SUCCESS;
}

static int32_t get_share_mem(uint8_t *shared_buf, struct memref_t *get_data, struct crypto_ioctl *ioctl_args)
{
    int32_t ret = CRYPTO_BAD_PARAMETERS;

    bool check = check_share_mem_size(shared_buf, ioctl_args->total_nums, ioctl_args->buf_len);
    if (!check) {
        tloge("invalid params. arg count = %u\n", ioctl_args->total_nums);
        return ret;
    }

    for (uint32_t i = 0; i < ioctl_args->total_nums; i++) {
        ret = copy_from_shared_buf(&(get_data[i].buffer), &(get_data[i].size), &shared_buf);
        if (ret != CRYPTO_SUCCESS) {
            tloge("get share memory failed! get data No. = %u\n", i);
            return ret;
        }
    }

    return ret;
}

static int32_t map_hal_share_mem(uint32_t taskid, uint8_t **drv_share_buf, struct crypto_ioctl *ioctl)
{
    if (ioctl->buf_len == 0 || ioctl->buf_len > SHARE_MEMORY_MAX_SIZE) {
        tloge("ioctl share memory size is invalid. size = %u\n", ioctl->buf_len);
        return CRYPTO_OVERFLOW;
    }

    (void)taskid;
    *drv_share_buf = (uint8_t *)malloc(ioctl->buf_len);
    if (*drv_share_buf == NULL) {
        tloge("malloc map buf failed\n");
        return CRYPTO_OVERFLOW;
    }

    int32_t ret = copy_from_client(ioctl->buf, ioctl->buf_len, (uintptr_t)*drv_share_buf, ioctl->buf_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("copy from share buf failed. ret = %d\n", ret);
        (void)memset_s(*drv_share_buf, ioctl->buf_len, 0, ioctl->buf_len);
        free(*drv_share_buf);
        *drv_share_buf = NULL;
    }

    return ret;
}

static int32_t malloc_memref_array(struct memref_t **memref_addr, uint32_t memref_count)
{
    if (memref_count == 0 || memref_count > CRYPTO_PARAM_COUNT_MAX) {
        tloge("memref count error. memref count = %u\n", memref_count);
        *memref_addr = NULL;
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t memref_len = memref_count * sizeof(struct memref_t);
    *memref_addr = (struct memref_t *)malloc(memref_len);
    if (*memref_addr == NULL) {
        tloge("malloc memref array fail\n");
        return CRYPTO_OVERFLOW;
    }

    (void)memset_s(*memref_addr, memref_len, 0, memref_len);

    return CRYPTO_SUCCESS;
}

void driver_free_share_mem_and_buf_arg(void *buf1, uint32_t buf1_size, void *buf2, uint32_t buf2_size)
{
    if (buf1 != NULL) {
        (void)memset_s(buf1, buf1_size, 0, buf1_size);
        free(buf1);
    }

    if (buf2 != NULL) {
        (void)memset_s(buf2, buf2_size, 0, buf2_size);
        free(buf2);
    }
}

int32_t prepare_hard_engine_params(uint32_t taskid, uint8_t **share_buf,
    struct memref_t **buf_arg, struct crypto_ioctl *ioctl_args)
{
    if (share_buf == NULL || buf_arg == NULL || ioctl_args == NULL) {
        tloge("share buf or arg or ioctl is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = map_hal_share_mem(taskid, share_buf, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = malloc_memref_array(buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto error;

    ret = get_share_mem(*share_buf, *buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto error;

    return ret;

error:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    *share_buf = NULL;
    *buf_arg = NULL;
    return ret;
}

#define DOUBLE_SIZE   2
#define ATTR_IS_BUFFER(attribute_id) ((((attribute_id) << 2) >> 31) == 0)
static bool check_attrs_size(const void *share_mem, uint32_t attr_total_len)
{
    uint32_t share_mem_size = 0;
    uint32_t temp_size = 0;
    uint32_t attr_id = 0;
    const uint32_t *attr_count = share_mem;

    share_mem_size += sizeof(uint32_t);
    if (share_mem_size > attr_total_len) {
        tloge("over size. total size = %u, get size = %u\n", attr_total_len, share_mem_size);
        return false;
    }
    share_mem += sizeof(uint32_t);

    for (uint32_t i = 0; i < *attr_count; i++) {
        if (memcpy_s(&attr_id, sizeof(uint32_t), share_mem, sizeof(uint32_t)) != EOK) {
            tloge("get attr id failed\n");
            return false;
        }

        share_mem_size += sizeof(uint32_t);
        if (share_mem_size > attr_total_len) {
            tloge("over size. total size = %u, get size = %u\n", attr_total_len, share_mem_size);
            return false;
        }
        share_mem += sizeof(uint32_t);

        if (ATTR_IS_BUFFER(attr_id)) {
            if (memcpy_s(&temp_size, sizeof(uint32_t), share_mem, sizeof(uint32_t)) != EOK) {
                tloge("get buf size failed\n");
                return false;
            }
            share_mem_size += sizeof(uint32_t) + temp_size;
            if (share_mem_size > attr_total_len) {
                tloge("over size. total size = %u, get size = %u\n", attr_total_len, share_mem_size);
                return false;
            }
            share_mem += sizeof(uint32_t) + temp_size;
        } else {
            share_mem_size += DOUBLE_SIZE * sizeof(uint32_t);
            if (share_mem_size > attr_total_len) {
                tloge("over size. total size = %u, get size = %u\n", attr_total_len, share_mem_size);
                return false;
            }
            share_mem += DOUBLE_SIZE * sizeof(uint32_t);
        }
    }

    if (share_mem_size == attr_total_len) {
        return true;
    } else {
        tloge("share memory size = %u is not equal to get share memory size = %u\n", attr_total_len, share_mem_size);
        return false;
    }
}

/*
 * |<--------------------------------------crypto_arg->buffer----------------------------------->|
 * |<- attr count ->|<- attr ID1 ->|<- buffer attr ->| or |<- value attr ->|<- attr ID2 ->|......|
 * |    4 bytes     |   4 bytes    |
 *
 * |<----------- buffer attr ----------->|
 * |<- buffer size ->|<----- buffer ---->|
 * |     4 bytes     | buffer size bytes |
 *
 * |<------- value attr ------>|
 * |<- value a ->|<- value b ->|
 * |   4 bytes   |   4 bytes   |
 */
int32_t restore_attrs(struct asymmetric_params_t *asymmetric_params, const struct memref_t *crypto_arg)
{
    if (asymmetric_params == NULL || crypto_arg == NULL) {
        tloge("asymmetric params or crypto arg is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t attr_total_len = crypto_arg->size;
    void *arg_buf = (void *)(uintptr_t)crypto_arg->buffer;

    if (attr_total_len == 0 || arg_buf == NULL || *(uint32_t *)arg_buf == 0) {
        asymmetric_params->param_count = 0;
        asymmetric_params->attribute = 0;
        return CRYPTO_SUCCESS;
    }

    if (!check_attrs_size(arg_buf, attr_total_len))
        return CRYPTO_BAD_PARAMETERS;

    uint32_t *attr_count = arg_buf;
    struct crypto_attribute_t *attr = (struct crypto_attribute_t *)malloc(*attr_count *
        sizeof(struct crypto_attribute_t));
    if (attr == NULL) {
        tloge("Failed to allocate memory for attribute\n");
        return CRYPTO_OVERFLOW;
    }

    (void)memset_s(attr, *attr_count * sizeof(struct crypto_attribute_t), 0, *attr_count *
        sizeof(struct crypto_attribute_t));

    uint32_t attr_offset = sizeof(uint32_t);
    arg_buf += attr_offset;
    for (uint32_t i = 0; i < *attr_count; i++) {
        attr[i].attribute_id = *(uint32_t *)arg_buf;
        attr_offset += sizeof(uint32_t);
        arg_buf += attr_offset;
        if (ATTR_IS_BUFFER(attr[i].attribute_id)) {
            attr[i].content.ref.length = *(uint32_t *)arg_buf;
            attr_offset += sizeof(uint32_t);
            arg_buf += attr_offset;
            attr[i].content.ref.buffer = (uint64_t)(uintptr_t)arg_buf;
            attr_offset += attr[i].content.ref.length;
        } else {
            attr[i].content.value.a = *(uint32_t *)arg_buf;
            attr_offset += sizeof(uint32_t);
            arg_buf += attr_offset;
            attr[i].content.value.b = *(uint32_t *)arg_buf;
            attr_offset += sizeof(uint32_t);
        }
        arg_buf += attr_offset;
    }
    asymmetric_params->param_count = *attr_count;
    asymmetric_params->attribute = (uint64_t)(uintptr_t)attr;
    return CRYPTO_SUCCESS;
}

static uint32_t get_ctx_size_ops(uint32_t alg_type, const struct crypto_drv_ops_t *ops)
{
    uint32_t driver_ability;

    if (ops->get_ctx_size == NULL) {
        tloge("hardware engine get ctx size fun is null\n");
        return 0;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    if (ops->get_driver_ability == NULL)
        driver_ability = 0;
    else
        driver_ability = ops->get_driver_ability();

    if ((driver_ability & DRIVER_PADDING) != DRIVER_PADDING)
        alg_type = change_pkcs5_to_nopad(alg_type);

    int32_t ctx_size = ops->get_ctx_size(alg_type);
    do_power_off(ops);
    return ctx_size;
}

int32_t get_ctx_size_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    (void)drv;
    if (ops == NULL) {
        tloge("ops is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (args == 0 || args_len != (uint32_t)sizeof(uint32_t)) {
        tloge("invalid input arg or args_len:%u\n", args_len);
        return true;
    }

    uint32_t *alg_type = (uint32_t *)(uintptr_t)args;

    return get_ctx_size_ops(*alg_type, ops);
}

static int32_t ctx_copy_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, uint32_t alg_type)
{
    if (ops->ctx_copy == NULL || drv->private_data == NULL ||
        ops->get_ctx_size == NULL) {
        tloge("hardware engine ctx copy fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    uint8_t *src_buffer = get_ctx_ctx_buf();
    if (src_buffer == NULL)
        return CRYPTO_OVERFLOW;

    int32_t ctx_size = ops->get_ctx_size(alg_type);
    bool check = ((ctx_size <= 0) || (ctx_size > MAX_CRYPTO_CTX_SIZE));
    if (check) {
        tloge("Get ctx size failed, ctx size=%d\n", ctx_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = ops->ctx_copy(alg_type, src_buffer, ctx_size, drv->private_data, ctx_size);
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do ctx copy failed. ret = %d\n", ret);

    return ret;
}

int32_t ctx_copy_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    if (drv == NULL || ops == NULL) {
        tloge("drv or ops is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (args == 0 || args_len < sizeof(uint32_t)) {
        tloge("invalid input arg or args_len:%u\n", args_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t *alg_type = (uint32_t *)(uintptr_t)args;

    int32_t ret = ctx_copy_ops(drv, ops, *alg_type);
    if (ret != CRYPTO_SUCCESS)
        tloge("ctx copy fail\n");

    return ret;
}

int32_t get_driver_ability_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    (void)drv;
    if (ops == NULL) {
        tloge("get driver ability ops is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (args == 0 || args_len != (uint32_t)sizeof(uint32_t)) {
        tloge("invalid input arg or args_len:%u\n", args_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ops->get_driver_ability == NULL) {
        tloge("ops get driver ability is invalid\n");
        return 0;
    }
    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    int32_t ability = ops->get_driver_ability();
    do_power_off(ops);
    return ability;
}

int32_t check_alg_support_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    (void)drv;
    if (ops == NULL) {
        tloge("check alg support ops is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (args == 0 || args_len != (uint32_t)sizeof(uint32_t)) {
        tloge("invalid input arg or args_len:%u\n", args_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t *alg_type = (uint32_t *)(uintptr_t)args;

    if (ops->is_alg_support == NULL) {
        tloge("generate is not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    return ops->is_alg_support(*alg_type);
}

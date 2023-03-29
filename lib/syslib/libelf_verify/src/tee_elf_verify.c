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
#include "tee_elf_verify.h"
#include <fileio.h>
#include "tee_elf_verify.h"
#include "tee_mem_mgmt_api.h"
#include "tee_inner_uuid.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include "securec.h"
#include "permission_service.h"
#include "tee_crypto_hal.h"
#include "tee_load_ext_mf.h"
#include "ta_verify_key.h"
#include "tee_elf_verify_openssl.h"
#include "tee_perm_img.h"
#include "tee_comm_elf_verify.h"
#include "tee_v3_elf_verify.h"
#include "tee_elf_verify_inner.h"

/*
 * use g_img_info&g_image_hd save the infomation
 * when loading the image
 */
static load_img_info g_img_info = { { { 0 }, { 0 }, NULL, NULL, NULL, { 0 } },
    NULL, NULL, 0, 0, 0, false };
static ta_property_t *g_ta_property_ptr = NULL;

static ta_payload_layer_t g_ta_payload = { { 0 }, NULL, NULL, 0 };
static uint32_t g_img_size = 0;

ta_property_t *get_ta_property_ptr(void)
{
    return g_ta_property_ptr;
}

load_img_info *get_img_info(void)
{
    return &g_img_info;
}

ta_payload_layer_t *get_ta_payload(void)
{
    return &g_ta_payload;
}

uint32_t get_img_size(void)
{
    return g_img_size;
}

bool overflow_check(uint32_t a, uint32_t b)
{
    if (a > UINT32_MAX_VALUE - b)
        return true;
    return false;
}

void copy_hash_data(elf_hash_data *hash_data, uint8_t *hash_src, uint32_t hash_src_size)
{
    if (hash_data == NULL || hash_src == NULL)
        return;

    if (hash_data != NULL && hash_data->hash_size >= MAX_IMAGE_HASH_SIZE) {
        if (memcpy_s(hash_data->elf_hash, hash_data->hash_size, hash_src, hash_src_size) != 0) {
            tloge("copy hash data fail\n");
            hash_data->hash_size = 0;
            return;
        }
        hash_data->hash_size = hash_src_size;
    }
}

bool boundary_check(uint32_t max_size, uint32_t input_size)
{
    if (input_size > max_size) {
        tloge("Failed to pass boundary check, max: 0x%x, size: 0x%x\n", max_size, input_size);
        return true;
    }
    return false;
}

TEE_Result tee_secure_img_duplicate_buff(const uint8_t *src, uint32_t src_size, uint8_t **dst)
{
    if (src == NULL || dst == NULL || src_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    *dst = TEE_Malloc(src_size, 0);
    if (*dst == NULL) {
        tloge(" Failed to malloc buffer for dst\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memcpy_s(*dst, src_size, src, src_size);
    if (rc != EOK) {
        tloge(" Failed to copy from src to dst\n");
        TEE_Free(*dst);
        *dst = NULL;
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_secure_img_manifest_extention_process(const uint8_t *extension, uint32_t extension_size,
    manifest_extension_t *mani_ext, struct dyn_conf_t *dyn_conf)
{
    if (extension_size == 0)
        return TEE_SUCCESS;
    if (extension == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    g_img_info.manifest_buf = (int8_t *)extension;
    TEE_Result ret = tee_secure_img_parse_manifest_extension((char *)g_img_info.manifest_buf,
        extension_size, mani_ext, dyn_conf);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to parse manifest extension\n");
        return ret;
    }

    return TEE_SUCCESS;
}

/*
 * 1.process_header func's TA header format is inconsistent in v1 & v2
 * 2.others funcs v1 & v2 is the same, so process_header is not in the struct
 */
static const struct process_version g_process_header[] = {
#ifdef DYN_TA_SUPPORT_V3
    { CIPHER_LAYER_VERSION, free_verify_v3, secure_img_copy_rsp_v3, tee_secure_img_unpack_v3, 0, 0 },
#endif
};

static TEE_Result process_header(const uint8_t *share_buf, uint32_t buf_len, uint32_t img_version)
{
    TEE_Result ret = TEE_SUCCESS;

    switch (img_version) {
#ifdef DYN_TA_SUPPORT_V3
    case CIPHER_LAYER_VERSION:
        ret = process_header_v3(share_buf, buf_len);
        break;
#endif
    default:
        tloge("Unknown image version error\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    if (ret != TEE_SUCCESS)
        tloge("process header failed, ret=0x%x, img version=%u\n", ret, img_version);

    return ret;
}

static TEE_Result secure_img_load_unpack(const elf_verify_req *req,
                                         elf_hash_data *hash_data)
{
    TEE_Result ret;
    int32_t fp = -1;

    (void)hash_data;
    fp = open(req->tmp_file, O_RDWR, RWRIGHT, (uint64_t)0);
    if (fp < 0) {
        tloge("reopen file fail\n");
        goto unpack_error;
    }

    void *file_buf = (int8_t *)vfs_mmap(fp, g_img_size, 0);
    if (file_buf == NULL) {
        tloge("remap fail, size %u\n", (uint32_t)g_img_size);
        goto unpack_error;
    }

    close(fp);
    fp = -1;

    g_img_info.img_buf = (int8_t *)file_buf;
    g_img_info.img_offset = 0;
    g_img_info.img_size = req->img_size;

    ret = process_header((const uint8_t *)g_img_info.img_buf, g_img_info.img_size, g_img_info.img_version);
    if (ret != TEE_SUCCESS)
        return ret;

    for (uint32_t i = 0; i < ARRAY_SIZE(g_process_header); ++i) {
        if (g_process_header[i].tee_secure_img_unpack != NULL &&
            g_img_info.img_version == g_process_header[i].version) {
            ret = g_process_header[i].tee_secure_img_unpack(g_process_header[i].rsa_algo_len,
                g_process_header[i].ta_hd_len, (uint8_t *)(g_img_info.img_buf),
                g_img_info.img_size, hash_data);
            if (ret != TEE_SUCCESS)
                tloge("process header failed, ret=0x%x, img version=%u\n", ret, g_img_info.img_version);

            return ret;
        }
    }

unpack_error:
    if (fp >= 0)
        close(fp);
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result unpack_copy_check_params(const elf_verify_req *req)
{
    g_img_info.img_version = req->version;
    g_img_size = PAGE_ALIGN_UP(req->img_size + ADDITIONAL_BUF_SIZE);
    if (g_img_size < req->img_size)
        return TEE_ERROR_BAD_PARAMETERS; /* overflow_check */

    uint32_t filename_len = strnlen(req->tmp_file, MAX_TAFS_NAME_LEN);
    if (filename_len == 0 || filename_len >= MAX_TAFS_NAME_LEN)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

static TEE_Result free_verify(void)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(g_process_header); ++i) {
        if (g_process_header[i].tee_free_func != NULL && g_img_info.img_version == g_process_header[i].version) {
            g_process_header[i].tee_free_func();
            return TEE_SUCCESS;
        }
    }

    tloge("Unsupported ver: %d\n", g_img_info.img_version);
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result secure_img_copy_rsp(elf_verify_reply *rep)
{
    rep->conf_registed = g_ta_payload.conf_registed;

    for (uint32_t i = 0; i < ARRAY_SIZE(g_process_header); ++i) {
        if (g_process_header[i].img_copy_rsp != NULL && g_img_info.img_version == g_process_header[i].version) {
            TEE_Result ret = g_process_header[i].img_copy_rsp(rep);
            if (ret != TEE_SUCCESS)
                tloge("process header failed, ret=0x%x, img version=%u\n", ret, g_img_info.img_version);

            return ret;
        }
    }
    tloge("Unsupported vers: %d\n", g_img_info.img_version);
    return TEE_ERROR_BAD_PARAMETERS;
}

#define HEX_BYTE_STR_LEN                  2
#define UUID_STR_FORMAT_LEN               37

static TEE_Result get_uuid_str(const TEE_UUID *uuid, char *buff, uint32_t len)
{
    if (uuid == NULL || buff == NULL || len < UUID_STR_FORMAT_LEN) {
        tloge("invalid parameter\n");
        return TEE_ERROR_GENERIC;
    }

    int ret = snprintf_s(buff, len, UUID_STR_FORMAT_LEN - 1, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0],
                         uuid->clockSeqAndNode[1], uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
                         uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6],
                         uuid->clockSeqAndNode[7]); // refer uuid format definitions
    if (ret <= 0) {
        tloge("convert uuid to string failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static void print_uuid_and_hash(TEE_UUID *uuid, uint8_t *hash_data, size_t size)
{
    if (uuid == NULL || hash_data == NULL || size > MAX_IMAGE_HASH_SIZE) {
        tloge("bad params of print_uuid_hash\n");
        return;
    }
    size_t str_buffer_len = size * HEX_BYTE_STR_LEN + 1;
    char *str_buffer = NULL;
    char *str_uuid = NULL;
    TEE_Result ret;
    str_buffer = (char*)TEE_Malloc(str_buffer_len, 0);
    if (str_buffer == NULL) {
        tloge("out of mem\n");
        goto clear;
    }
    str_uuid = (char*)TEE_Malloc(UUID_STR_FORMAT_LEN, 0);
    if (str_uuid == NULL) {
        tloge("out of mem\n");
        goto clear;
    }

    ret = get_uuid_str(uuid, str_uuid, UUID_STR_FORMAT_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("get_uuid_str failed\n");
        goto clear;
    }

    str_buffer[0] = '\0';
    /* the initial len value makes sure the first loop can run normally */
    int len = 1;
    for (uint32_t i = 0; i < size; i++) {
        if (len <= 0 || str_buffer_len - strlen(str_buffer) <= 1) {
            tloge("str_buffer is too short for hash data left\n");
            goto clear;
        }
        len = snprintf_s(str_buffer + strlen(str_buffer), str_buffer_len - strlen(str_buffer),
            str_buffer_len - strlen(str_buffer) - 1, "%02x", hash_data[i]);
    }
    if (len <= 0) {
        tloge("write hash data failed\n");
        goto clear;
    }
    /* make sure the string buffer has a '\0' */
    str_buffer[str_buffer_len - 1] = '\0';
    tlogi("[TA_UUID]%s[TA_UUID];[IMAGE_HASH]%s[IMAGE_HASH]\n", str_uuid, str_buffer);
clear:
    if (str_uuid != NULL)
        TEE_Free(str_uuid);
    if (str_buffer != NULL)
        TEE_Free(str_buffer);
}

TEE_Result secure_elf_verify(const elf_verify_req *req, elf_verify_reply *rep)
{
    TEE_Result ret, tee_ret;
    elf_hash_data hash_data;
    (void)memset_s(&hash_data, sizeof(hash_data), 0, sizeof(hash_data));

    if (req == NULL || rep == NULL) {
        tloge("bad parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (unpack_copy_check_params(req) != TEE_SUCCESS) {
        tloge("check req params failed\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto reply;
    }
    g_ta_property_ptr = &(g_img_info.manifest.mani_info.ta_property);

    hash_data.elf_hash = (uint8_t*)TEE_Malloc(MAX_IMAGE_HASH_SIZE, 0);
    hash_data.hash_size = MAX_IMAGE_HASH_SIZE;
    if (hash_data.elf_hash == NULL) {
        hash_data.hash_size = 0;
        tloge("malloc for hash data failed!\n");
    }

    ret = secure_img_load_unpack(req, &hash_data);
    if (ret != TEE_SUCCESS) {
        tloge("img unpack fail 0x%x\n", ret);
        if (g_img_info.dyn_conf_registed || g_ta_payload.conf_registed)
            (void)secure_img_copy_rsp(rep);
        goto reply;
    }

    ret = secure_img_copy_rsp(rep);
    if (ret != TEE_SUCCESS)
        tloge("copy elf verify response failed 0x%x\n", ret);
    if (hash_data.hash_size != 0 && rep != NULL)
        print_uuid_and_hash(&(rep->srv_uuid), hash_data.elf_hash, hash_data.hash_size);

reply:
    tee_ret = free_verify();
    if (hash_data.elf_hash != NULL)
        TEE_Free(hash_data.elf_hash);
    if (tee_ret != TEE_SUCCESS)
        tlogd("free verify fail\n");

    if (ret != TEE_SUCCESS)
        return ret;

    return tee_ret;
}

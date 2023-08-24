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
#include "tee_v3_elf_verify.h"
#include "securec.h"
#include "tee_log.h"
#include "tee_perm_img.h"
#include "mem_ops.h"
#include "ta_load_config.h"
#include "ta_lib_img_unpack.h"
#include "target_type.h"
#include "ta_verify_key.h"
#include "tee_elf_verify.h"
#include "ta_load_key.h"
#include "tee_comm_elf_verify.h"
#include "tee_elf_verify_inner.h"
#include "tee_crypto_hal.h"
#include "dyn_conf_common.h"
#include "drv_dyn_conf_builder.h"
#include "drv_dyn_conf_builder.h"
#include "dyn_conf_dispatch_inf.h"
#include "drvcall_dyn_conf_builder.h"
#include "check_ta_version.h"
#include "tee_load_key_ops.h"
#include "tee_elf_verify_openssl.h"
#include "ipclib.h"
#include <sys/mman.h>
#if defined(OPENSSL_ENABLE) || defined(OPENSSL3_ENABLE)
#include <openssl/obj_mac.h>
#endif

static uint32_t g_v3_cipher_layer_len = 0;
static bool g_is_encrypted_sec = true;
static ta_image_hdr_v3_t g_image_hdr_v3 = { { 0 }, 0, 0 };
static ta_cipher_layer_t g_ta_cipher_layer = { { 0 }, NULL, NULL };

ta_cipher_layer_t *get_ta_cipher_layer(void)
{
    return &g_ta_cipher_layer;
}

uint32_t get_v3_cipher_layer_len(void)
{
    return g_v3_cipher_layer_len;
}

static TEE_Result tee_secure_get_img_header_v3(const uint8_t *share_buf, uint32_t buf_len)
{
    if (buf_len <= sizeof(ta_image_hdr_v3_t)) {
        tloge("img buf len is 0x%x too small\n", buf_len);
        return TEE_ERROR_GENERIC;
    }
    errno_t rc = memcpy_s(&g_image_hdr_v3, sizeof(g_image_hdr_v3), share_buf, sizeof(ta_image_hdr_v3_t));
    if (rc != EOK) {
        tloge("copy is failed\n");
        return TEE_ERROR_SECURITY;
    }

    return TEE_SUCCESS;
}

static uint32_t tee_secure_img_get_signature_size(uint32_t signature_alg,
    const uint8_t *signature_buff, uint32_t signature_max_size)
{
    (void)signature_buff;
    (void)signature_max_size;
    uint32_t size;

    switch (signature_alg & SIGN_ALG_MASK) {
    case SIGN_ALGO_RSA_2048:
        size = RSA2048_SIGNATURE_SIZE;
        break;
    case SIGN_ALGO_RSA_4096:
        size = RSA4096_SIGNATURE_SIZE;
        break;
    case SIGN_ALGO_ECC_256:
        size = ECC256_SIGNATURE_SIZE;
        break;
    default:
        tloge("Invalid signature algorithm: 0x%x\n", signature_alg);
        size = SIGNATURE_SIZE_INVALID;
        break;
    }

    return size;
}

static TEE_Result handle_cipher_layer_len(uint32_t cipher_layer_ver)
{
    if (cipher_layer_ver <= CIPHER_LAYER_KEY_V1) {
        g_v3_cipher_layer_len = CIPHER_LAYER_LEN_256;
    } else if (cipher_layer_ver == CIPHER_LAYER_KEY_V2) {
        g_v3_cipher_layer_len = CIPHER_LAYER_LEN_384;
    } else {
        tloge("error cipher layer key version:cipher layer ver=%u\n", cipher_layer_ver);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_secure_img_header_check_v3(void)
{
    uint32_t cipher_layer_ver;

    if (overflow_check(g_image_hdr_v3.context_len, sizeof(ta_image_hdr_v3_t)))
        return TEE_ERROR_GENERIC;
    if (g_image_hdr_v3.context_len + sizeof(ta_image_hdr_v3_t) > MAX_IMAGE_LEN) {
        tloge("image hd err context len: 0x%x\n", g_image_hdr_v3.context_len);
        tloge("image hd err ta hd len: 0x%x\n", sizeof(ta_image_hdr_v3_t));
        return TEE_ERROR_GENERIC;
    }

    if (g_image_hdr_v3.ta_key_version == KEY_VER_NOT_ENCRYPT) {
        g_v3_cipher_layer_len = sizeof(ta_cipher_hdr_t);
        g_is_encrypted_sec = false;
        return TEE_SUCCESS;
    } else if ((g_image_hdr_v3.ta_key_version & KEY_VER_MASK) != SEC_IMG_TA_KEY_VERSION) {
        tloge("Invalid ta key version: 0x%x\n", g_image_hdr_v3.ta_key_version);
        return TEE_ERROR_GENERIC;
    }

    g_is_encrypted_sec = true;
    cipher_layer_ver = ((g_image_hdr_v3.ta_key_version >> KEY_VER_BITE) & KEY_VER_MASK);
    return handle_cipher_layer_len(cipher_layer_ver);
}

TEE_Result process_header_v3(const uint8_t *share_buf, uint32_t buf_len)
{
    TEE_Result tee_ret;

    if (share_buf == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tee_ret = tee_secure_get_img_header_v3(share_buf, buf_len);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    tee_ret = tee_secure_img_header_check_v3();
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to check image header");
        return tee_ret;
    }

    return TEE_SUCCESS;
}

TEE_Result judge_rsa_key_type(uint32_t rsa_cipher_size, enum ta_type *type)
{
    if (type == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (rsa_cipher_size == CIPHER_LAYER_LEN_256) {
        *type = V3_TYPE_2048;
    } else if (rsa_cipher_size == CIPHER_LAYER_LEN_384) {
        *type = V3_TYPE_3072;
    } else {
        tloge("wrong rsa cipher size:%u\n", rsa_cipher_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_secure_img_parse_cipher_layer(const uint8_t *plaintext_hdr, uint32_t plaintext_size,
                                                    ta_cipher_layer_t *cipher_layer)
{
    bool check = (plaintext_hdr == NULL || plaintext_size == 0 || cipher_layer == NULL);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;
    uint32_t off_set = 0;
    const uint8_t *iv = NULL;
    const uint8_t *key = NULL;

    if (overflow_check(off_set, sizeof(ta_cipher_hdr_t)))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + sizeof(ta_cipher_hdr_t)))
        return TEE_ERROR_GENERIC;
    errno_t rc = memcpy_s(&(cipher_layer->cipher_hdr), sizeof(ta_cipher_hdr_t), plaintext_hdr + off_set,
                          sizeof(ta_cipher_hdr_t));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;
    off_set += sizeof(ta_cipher_hdr_t);

    if (cipher_layer->cipher_hdr.iv_size == 0 && cipher_layer->cipher_hdr.key_size == 0 && !g_is_encrypted_sec) {
        tlogd("not encrypt, no need duplicate iv & key buff\n");
        return TEE_SUCCESS;
    }

    if (overflow_check(off_set, cipher_layer->cipher_hdr.key_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + cipher_layer->cipher_hdr.key_size))
        return TEE_ERROR_GENERIC;
    key = plaintext_hdr + off_set;
    off_set += cipher_layer->cipher_hdr.key_size;

    if (overflow_check(off_set, cipher_layer->cipher_hdr.iv_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + cipher_layer->cipher_hdr.iv_size))
        return TEE_ERROR_GENERIC;
    iv = plaintext_hdr + off_set;

    TEE_Result ret = tee_secure_img_duplicate_buff(iv, cipher_layer->cipher_hdr.iv_size, &(cipher_layer->iv));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to dump iv of TA image\n");
        return ret;
    }

    ret = tee_secure_img_duplicate_buff(key, cipher_layer->cipher_hdr.key_size, &(cipher_layer->key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to dump key of TA image\n");
        TEE_Free(cipher_layer->iv);
        cipher_layer->iv = NULL;
        return ret;
    }
    return TEE_SUCCESS;
}

#define OP_SIZE 1024
static TEE_Result tee_sec_img_payload_decrypt_ops(TEE_ObjectHandle key_obj, const uint8_t *src, uint32_t src_len,
                                                  uint8_t *dst, uint32_t *dst_len)
{
    if (key_obj == NULL || src == NULL || dst == NULL || src_len == 0 || !(dst_len != NULL && *dst_len >= src_len))
        return TEE_ERROR_BAD_PARAMETERS;
    TEE_OperationHandle crypto_ops = NULL;
    size_t op_size;
    size_t left_size = src_len;
    size_t out_size;
    size_t total_size = 0;

    TEE_Result ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_AES_CBC_PKCS5, TEE_MODE_DECRYPT, KEY_SIZE_MAX);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to allocate operation to decrypt TA image\n");
        return ret;
    }
    ret = TEE_SetCryptoFlag(crypto_ops, SOFT_CRYPTO);
    if (ret != TEE_SUCCESS)
        goto out;

    ret = TEE_SetOperationKey(crypto_ops, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("Set Operation Key fail\n");
        goto out;
    }

    TEE_CipherInit(crypto_ops, g_ta_cipher_layer.iv, g_ta_cipher_layer.cipher_hdr.iv_size);

    while (left_size > OP_SIZE) {
        op_size = OP_SIZE;
        out_size = op_size;
        ret = TEE_CipherUpdate(crypto_ops, src, op_size, dst, &out_size);
        if (ret != TEE_SUCCESS) {
            tloge("TEE Cipher Update fail\n");
            goto out;
        }
        src += op_size;
        left_size -= op_size;
        dst += out_size;
        total_size += out_size;
    }

    /* update remain length for dst */
    out_size = *dst_len - total_size;
    ret = TEE_CipherDoFinal(crypto_ops, src, left_size, dst, &out_size);
    if (ret != TEE_SUCCESS) {
        tloge("Cipher Dofinal fail\n");
        goto out;
    }
    total_size += out_size;
    *dst_len = total_size;
    ret = TEE_SUCCESS;
out:
    TEE_FreeOperation(crypto_ops);
    return ret;
}

static TEE_Result tee_secure_img_decrypt_payload(const uint8_t *ciphertext_payload, uint32_t ciphertext_size,
                                                 uint8_t *plaintext_payload, uint32_t *plaintext_size)
{
    bool check = (ciphertext_payload == NULL || ciphertext_size == 0 || plaintext_payload == NULL ||
        plaintext_size == NULL || *plaintext_size < ciphertext_size);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;
    TEE_ObjectHandleVar key_obj = {0};

    key_obj.Attribute = (TEE_Attribute *)TEE_Malloc(sizeof(TEE_Attribute), 0);
    if (key_obj.Attribute == NULL) {
        tloge("Failed to allocate key attribute\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    key_obj.Attribute->content.ref.buffer = g_ta_cipher_layer.key;
    key_obj.Attribute->content.ref.length = g_ta_cipher_layer.cipher_hdr.key_size;

    TEE_Result ret = tee_sec_img_payload_decrypt_ops(&key_obj, ciphertext_payload, ciphertext_size, plaintext_payload,
                                                     plaintext_size);
    TEE_Free(key_obj.Attribute);
    key_obj.Attribute = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("Failed to decrypted TA image body\n");
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result alloc_name_buffer_copy_mani_conf(const uint8_t *manifest, uint32_t manifest_size)
{
    uint32_t off_set = 0;
    load_img_info *img_info = get_img_info();
    ta_property_t *ta_property_ptr = get_ta_property_ptr();

    errno_t rc = memcpy_s(&img_info->manifest.srv_uuid,
        sizeof(img_info->manifest.srv_uuid), manifest + off_set, sizeof(TEE_UUID));
    if (rc != EOK) {
        tloge("failed to copy uuid\n");
        return TEE_ERROR_SECURITY;
    }
    off_set += sizeof(TEE_UUID);

    img_info->manifest.mani_info.service_name_len = manifest_size - sizeof(TEE_UUID) - sizeof(ta_property_t);
    img_info->manifest.service_name = TEE_Malloc(img_info->manifest.mani_info.service_name_len + 1, 0);
    if (img_info->manifest.service_name == NULL) {
        tloge("failed to allocate memory for service_name\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memcpy_s(img_info->manifest.service_name, img_info->manifest.mani_info.service_name_len + 1,
        manifest + off_set, img_info->manifest.mani_info.service_name_len);
    if (rc != EOK) {
        TEE_Free(img_info->manifest.service_name);
        img_info->manifest.service_name = NULL;
        return TEE_ERROR_SECURITY;
    }
    off_set += img_info->manifest.mani_info.service_name_len;

    rc = memcpy_s(ta_property_ptr, sizeof(*ta_property_ptr), manifest + off_set,
                  sizeof(ta_property_t));
    if (rc != EOK) {
        tloge("failed to copy manifest header\n");
        TEE_Free(img_info->manifest.service_name);
        img_info->manifest.service_name = NULL;
        return TEE_ERROR_SECURITY;
    }

    if (ta_property_ptr->single_instance == false) {
        tloge("only support single Instance as true\n");
        TEE_Free(img_info->manifest.service_name);
        img_info->manifest.service_name = NULL;
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

static int32_t handle_cryptomgr_drv_mani(struct drv_mani_t *drv_mani)
{
    if (drv_mani->hardware_type == HARDWARE_ENGINE_CRYPTO) {
        if (memcpy_s(drv_mani->service_name, DRV_NAME_MAX_LEN, "crypto_mgr", strlen("crypto_mgr") + 1) != 0) {
            tloge("memcpy service name failed\n");
            return TEE_ERROR_GENERIC;
        }
        drv_mani->service_name_size = strlen(drv_mani->service_name);
        drv_mani->srv_uuid = (struct tee_uuid)CRYPTOMGR;
    }

    return 0;
}

static int32_t set_drv_manifest(struct drv_mani_t *drv_mani)
{
    load_img_info *img_info = get_img_info();
    ta_property_t *ta_property_ptr = get_ta_property_ptr();
    /* 1.set service name */
    if (img_info->manifest.service_name != NULL) {
        if (memcpy_s(drv_mani->service_name, DRV_NAME_MAX_LEN,
                     img_info->manifest.service_name, img_info->manifest.mani_info.service_name_len) != 0) {
            tloge("memcpy service name failed\n");
            return TEE_ERROR_GENERIC;
        }
    }
    drv_mani->service_name_size = img_info->manifest.mani_info.service_name_len;

    /* 2.set uuid */
    if (memcpy_s(&drv_mani->srv_uuid, sizeof(struct tee_uuid),
                 &img_info->manifest.srv_uuid, sizeof(struct tee_uuid)) != 0) {
        tloge("set uuid to drv conf failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* 3.set keep alive */
    if (ta_property_ptr->instance_keep_alive != 0)
        drv_mani->keep_alive = true;
    else
        drv_mani->keep_alive = false;

    /* 4.set size */
    drv_mani->data_size = ta_property_ptr->heap_size;
    drv_mani->stack_size = ta_property_ptr->stack_size;
    drv_mani->hardware_type = img_info->manifest.ext.hardware_type;

    if (handle_cryptomgr_drv_mani(drv_mani) != 0)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

static int32_t handle_dyn_conf_buffer(struct dyn_conf_t *dyn_conf, uint32_t *ext_size)
{
    int32_t ret;
    load_img_info *img_info = get_img_info();

    if (dyn_conf->dyn_conf_size >= *ext_size) {
        tloge("dyn conf size is larger than ext size %u\n", dyn_conf->dyn_conf_size);
        free(dyn_conf->dyn_conf_buffer);
        dyn_conf->dyn_conf_buffer = NULL;
        return TEE_ERROR_GENERIC;
    }

    *ext_size -= dyn_conf->dyn_conf_size;

    struct drv_mani_t drv_mani;
    if (set_drv_manifest(&drv_mani) != TEE_SUCCESS) {
        free(dyn_conf->dyn_conf_buffer);
        dyn_conf->dyn_conf_buffer = NULL;
        return TEE_ERROR_GENERIC;
    }

    if (img_info->manifest.ext.target_type == DRV_TARGET_TYPE) {
        ret = register_conf(dyn_conf, install_drv_permission, &drv_mani, sizeof(drv_mani));
    } else if (img_info->manifest.ext.target_type == TA_TARGET_TYPE ||
        img_info->manifest.ext.target_type == SRV_TARGET_TYPE ||
        img_info->manifest.ext.target_type == CLIENT_TARGET_TYPE) {
        ret = register_conf(dyn_conf, install_drvcall_permission, &drv_mani.srv_uuid, sizeof(drv_mani.srv_uuid));
    } else {
        ret = TEE_ERROR_GENERIC;
        tloge("unknown target type\n");
    }

    free(dyn_conf->dyn_conf_buffer);
    dyn_conf->dyn_conf_buffer = NULL;

    return ret;
}
#define MAX_SERVICE_NAME_SIZE 64
static TEE_Result check_manifest_alloc_name(const uint8_t *manifest, uint32_t manifest_size)
{
    TEE_Result ret;
    bool check = (manifest == NULL || (manifest_size < sizeof(TEE_UUID) + sizeof(ta_property_t)) ||
        (manifest_size > sizeof(TEE_UUID) + sizeof(ta_property_t) + MAX_SERVICE_NAME_SIZE));
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = alloc_name_buffer_copy_mani_conf(manifest, manifest_size);
    if (ret != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;
}

/*
 * Process steps:
 * 1, Get the manifest UUID,
 * 2, Get the manifest stand config,
 * 3, Get the TA service name,
 * 4, Parse manifest extension config,
 */
TEE_Result tee_secure_img_parse_manifest_v3(const uint8_t *manifest_ext, uint32_t *ext_size,
                                            bool control, const uint32_t config_target_type)
{
    TEE_Result ret;
    load_img_info *img_info = get_img_info();
    bool check = ((ext_size == NULL) || !((manifest_ext != NULL && *ext_size > 0) || *ext_size == 0));
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!control) {
        tlogd("check config and manifest target type\n");
        if (config_target_type != img_info->manifest.ext.target_type) {
            tloge("diff type con_type=%d mani_type=%d\n", config_target_type, img_info->manifest.ext.target_type);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    struct dyn_conf_t dyn_conf = { 0, NULL };
    ret = tee_secure_img_manifest_extention_process(manifest_ext, *ext_size,
        &img_info->manifest.ext, &dyn_conf);

    if (img_info->manifest.ext.api_level > API_LEVEL1_2) {
        tloge("invalid ta api level:%u\n", img_info->manifest.ext.api_level);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

    if (ret != TEE_SUCCESS) {
        tloge("Manifest extension configuration is invalid\n");
        goto err;
    }

    if (dyn_conf.dyn_conf_buffer != NULL) {
        ret = (TEE_Result)handle_dyn_conf_buffer(&dyn_conf, ext_size);
        if (ret != TEE_SUCCESS) {
            tloge("register dyn conf for dyn perm failed\n");
            goto err;
        }
        img_info->dyn_conf_registed = true;
    }

    return ret;
err:
    if (dyn_conf.dyn_conf_buffer != NULL)
        free(dyn_conf.dyn_conf_buffer);
    TEE_Free(img_info->manifest.service_name);
    img_info->manifest.service_name = NULL;

    return ret;
}

/*
 * Process steps:
 * 1, Get the payload header,
 * 2, Get the manifest stand config,
 * 3, Get the manifest extension config,
 * 4, Get the TA ELF segment,
 * 5, Get the TA config segment,
 * 6, Parse manifest stand config & extension config,
 */
static TEE_Result tee_secure_img_parse_payload(uint8_t *plaintext_payload, uint32_t plaintext_size,
                                               ta_payload_layer_t *payload)
{
    uint32_t off_set = 0;
    uint8_t *mani_info = NULL;
    uint8_t *mani_ext = NULL;

    if (plaintext_payload == NULL || payload == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (overflow_check(off_set, sizeof(ta_payload_hdr_t)))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + sizeof(ta_payload_hdr_t)))
        return TEE_ERROR_GENERIC;
    errno_t rc = memcpy_s(&(payload->payload_hdr), sizeof(ta_payload_hdr_t), plaintext_payload + off_set,
                          sizeof(ta_payload_hdr_t));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;
    off_set += sizeof(ta_payload_hdr_t);

    if (overflow_check(off_set, payload->payload_hdr.mani_info_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + payload->payload_hdr.mani_info_size))
        return TEE_ERROR_GENERIC;
    mani_info = plaintext_payload + off_set;
    off_set += payload->payload_hdr.mani_info_size;

    if (overflow_check(off_set, payload->payload_hdr.mani_ext_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + payload->payload_hdr.mani_ext_size))
        return TEE_ERROR_GENERIC;
    mani_ext = plaintext_payload + off_set;
    off_set += payload->payload_hdr.mani_ext_size;

    if (overflow_check(off_set, payload->payload_hdr.ta_elf_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + payload->payload_hdr.ta_elf_size))
        return TEE_ERROR_GENERIC;
    payload->ta_elf = plaintext_payload + off_set;
    off_set += payload->payload_hdr.ta_elf_size;

    if (overflow_check(off_set, payload->payload_hdr.ta_conf_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(plaintext_size, off_set + payload->payload_hdr.ta_conf_size))
        return TEE_ERROR_GENERIC;
    payload->ta_conf = plaintext_payload + off_set;

    TEE_Result ret = check_manifest_alloc_name(mani_info, payload->payload_hdr.mani_info_size);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = tee_secure_img_parse_manifest_v3(mani_ext, &(payload->payload_hdr.mani_ext_size), true, 0);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

void get_sign_config(struct sign_config_t *config)
{
    if (config == NULL)
        return;

    uint32_t sign_alg = g_ta_cipher_layer.cipher_hdr.signature_alg;

    switch (sign_alg & SIGN_ALG_KEY_LEN_MASK) {
    case SIGN_ALGO_RSA_2048:
        config->key_len = PUB_KEY_2048_BITS;
        break;
    case SIGN_ALGO_RSA_4096:
        config->key_len = PUB_KEY_4096_BITS;
        break;
    case SIGN_ALGO_ECC_256:
        config->key_len = PUB_KEY_256_BITS;
        break;
    default:
        tloge("sign alg is invalid!");
        return;
    }
    config->hash_size = ((sign_alg & SIGN_ALG_HASH_MASK) != 0) ? SHA512_LEN : SHA256_LEN;
    config->hash_nid = (config->hash_size == SHA512_LEN) ? NID_sha512 : NID_sha256;
    config->padding = ((sign_alg & SIGN_ALG_PADD_MASK) != 0) ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
    config->key_style = ((sign_alg & SIGN_ALG_KEY_STYLE_MASK) == 0) ? PUB_KEY_DEBUG : PUB_KEY_RELEASE;
    config->sign_ta_alg = (sign_alg >> SIGN_TA_ALG_BITS) & SIGN_ALG_TA_ALG_MASK;
}

bool check_img_format_valid(struct sign_config_t *config)
{
    if (config == NULL)
        return false;

    ta_payload_layer_t *ta_payload = get_ta_payload();
    if (config->key_style == PUB_KEY_RELEASE && !g_is_encrypted_sec &&
        config->sign_ta_alg == SIGN_SEC_ALG_DEFAULT) {
        tloge("Invalid ta key version 0, release key not support only sign for sec\n");
        return false;
    }

    if (ta_payload->payload_hdr.format_version != CIPHER_LAYER_VERSION) {
        tloge("Invalid format version: 0x%x\n", ta_payload->payload_hdr.format_version);
        return false;
    }

    return true;
}

static TEE_Result get_signature_verify_key(void **key, const struct sign_config_t *config, cert_param_t *cert_param)
{
    TEE_Result ret;
    ta_payload_layer_t *ta_payload = get_ta_payload();

    struct ta_verify_key verify_key = { config->key_len, config->key_style, NULL };

    if (ta_payload->payload_hdr.ta_conf_size != 0) {
        if (ta_local_sign_check()) {
            *key = &(cert_param->public_key);
            return TEE_SUCCESS;
        } else {
            if (cert_param->cert_type == TA_DEBUG_CERT) {
                *key = &(cert_param->public_key);
                return TEE_SUCCESS;
            } else {
                ret = get_ta_verify_pubkey(&verify_key);
            }
        }
    } else {
        ret = get_ta_verify_pubkey(&verify_key);
    }

    if (ret != TEE_SUCCESS)
        return ret;

    if (verify_key.key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (is_keywest_signature() && ta_payload->payload_hdr.ta_conf_size == 0) {
        *key = TEE_Malloc(sizeof(ecc_pub_key_t), 0);
        if (*key == NULL) {
            tloge("malloc failed!");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        if (memcpy_s(*key, sizeof(ecc_pub_key_t), verify_key.key, sizeof(ecc_pub_key_t)) != 0) {
            TEE_Free(*key);
            *key = NULL;
            return TEE_ERROR_GENERIC;
        }
    } else {
        *key = (rsa_pub_key_t *)verify_key.key;
    }
    return TEE_SUCCESS;
}

static int32_t ecc_signature_verify(uint8_t *signature, uint32_t signature_size, uint8_t *hash,
    uint32_t hash_size, ecc_pub_key_t *key)
{
    uint32_t i = 0;
    for (; i < signature_size; i++) {
        if (signature[i] == 0x00)
            continue;
        break;
    }
    return ecc_verify_digest(signature + i, signature_size - i, hash, hash_size, key);
}

#define SIGNATURE_OK 1
static TEE_Result do_ta_image_verify(uint8_t *signature, uint32_t signature_size, uint8_t *hash,
    const struct sign_config_t *config, void **key)
{
    int32_t result;
    ta_payload_layer_t *ta_payload = get_ta_payload();

    if (is_keywest_signature() || config->sign_ta_alg == SIGN_SEC_ALG_ECDSA) {
        result = ecc_signature_verify(signature, signature_size, hash, config->hash_size, (ecc_pub_key_t *)*key);
        if (ta_payload->payload_hdr.ta_conf_size == 0) {
            TEE_Free(*key);
            *key = NULL;
        }
        if (result != SIGNATURE_OK) {
            tloge("verify digest failed:%d\n", result);
            return TEE_ERROR_GENERIC;
        }
    } else {
        result = rsa_verify_digest(signature, signature_size, hash, config->hash_size,
            (rsa_pub_key_t *)*key, config->hash_size, config->hash_nid, config->padding);
        if (result != 0) {
            tloge("verify digest failed:%d\n", result);
            return TEE_ERROR_GENERIC;
        }
    }

    tlogd("signature VerifyDigest success\n");
    return TEE_SUCCESS;
}

static void print_ta_sign_algorithm_info(const struct sign_config_t *config)
{
    if (config == NULL)
        return;

    ta_cipher_layer_t *ta_cipher_layer = get_ta_cipher_layer();

    tloge("sec config info:sign_alg=0x%x, key_len=%u, hash_size=%zu, hash_padding=%s, key_style=%s\n",
        ta_cipher_layer->cipher_hdr.signature_alg, config->key_len, config->hash_size,
        config->padding == RSA_PKCS1_PSS_PADDING ? "PKCS1_PSS" : "PKCS1",
        config->key_style == PUB_KEY_RELEASE ? "release" : "debug");
}

TEE_Result tee_secure_img_signature_verify(const uint8_t *plaintext_payload, uint32_t plaintext_size,
    uint8_t *signature, uint32_t signature_size, elf_hash_data *hash_data)
{
    if (plaintext_payload == NULL || signature == NULL || plaintext_size == 0 || signature_size == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t hash[HASH_LEN_MAX] = {0};
    struct sign_config_t config = {0};
    void *key = NULL;
    cert_param_t cert_param = {0};

    get_sign_config(&config);

    if (!check_img_format_valid(&config))
        return TEE_ERROR_NOT_SUPPORTED;

    TEE_Result ret = tee_secure_img_hash_ops(plaintext_payload, plaintext_size, hash, config.hash_size);
    if (ret != TEE_SUCCESS) {
        print_ta_sign_algorithm_info(&config);
        return ret;
    }

    ret = get_config_cert_param(&cert_param, &config);
    if (ret != TEE_SUCCESS) {
        print_ta_sign_algorithm_info(&config);
        return ret;
    }

    /* This is for 3rd party to developing TA with signature check off */
    if (get_ta_signature_ctrl()) {
        tloge("DEBUG_VERSION: signature VerifyDigest is OFF\n");
        return TEE_SUCCESS;
    }

    ret = get_signature_verify_key(&key, &config, &cert_param);
    if (ret != TEE_SUCCESS) {
        print_ta_sign_algorithm_info(&config);
        return ret;
    }

    if (key == NULL)
        return TEE_ERROR_IMG_VERIFY_FAIL;

    ret = do_ta_image_verify(signature, signature_size, hash, &config, &key);
    if (ret != TEE_SUCCESS) {
        print_ta_sign_algorithm_info(&config);
        return ret;
    }
    /* copy hash data out of this func if hash_data buffer is not NULL */
    copy_hash_data(hash_data, hash, config.hash_size);

    return TEE_SUCCESS;
}

static TEE_Result tee_secure_img_proc_cipher_layer(uint8_t *img_buf, uint32_t img_size,
    uint32_t *off_set, uint32_t *layer_size)
{
    /* Locate the position of cipher layer */
    if (overflow_check(*off_set, g_v3_cipher_layer_len))
        return TEE_ERROR_GENERIC;
    if (boundary_check(img_size, *off_set + g_v3_cipher_layer_len))
        return TEE_ERROR_GENERIC;

    uint8_t *cipher_layer = img_buf + *off_set;
    TEE_Result ret;

    /* Decrypt cipher layer */
    uint8_t *plaintext_layer = cipher_layer;
    if (g_is_encrypted_sec) {
        ret = tee_secure_img_decrypt_cipher_layer(cipher_layer, g_v3_cipher_layer_len, plaintext_layer, layer_size);
        if (ret != TEE_SUCCESS)
            return ret;
    } else {
        *layer_size = g_v3_cipher_layer_len;
    }

    /* Parse cipher layer to get IV, AES key & signature algorithm */
    ret = tee_secure_img_parse_cipher_layer(plaintext_layer, *layer_size, &g_ta_cipher_layer);
    if (ret != TEE_SUCCESS)
        return ret;

    *off_set += g_v3_cipher_layer_len;
    return TEE_SUCCESS;
}

static TEE_Result tee_secure_img_proc_payload(uint8_t *img_buf, uint32_t img_size,
    uint32_t off_set, uint32_t layer_size, uint32_t *plaintext_size)
{
    uint8_t *ciphertext_payload = NULL;
    uint32_t ciphertext_size = *plaintext_size;
    TEE_Result ret;
    ta_payload_layer_t *ta_payload = get_ta_payload();

    /* Locate the position of image payload encrypted in AES algorithm */
    if (overflow_check(off_set, ciphertext_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(img_size, off_set + ciphertext_size))
        return TEE_ERROR_GENERIC;
    ciphertext_payload = img_buf + off_set;

    /* Decrypt ciphertext payload */
    uint8_t *plaintext_payload = ciphertext_payload;
    if (g_is_encrypted_sec) {
        ret = tee_secure_img_decrypt_payload(ciphertext_payload, ciphertext_size, plaintext_payload, plaintext_size);
        if (ret != TEE_SUCCESS)
            return TEE_ERROR_BAD_FORMAT;
    } else {
        *plaintext_size = ciphertext_size;
    }

    /* Move identity layer, crypto layer & payload together to calculate the hash */
    if (overflow_check(sizeof(ta_image_hdr_v3_t), layer_size))
        return TEE_ERROR_GENERIC;
    if (overflow_check(sizeof(ta_image_hdr_v3_t) + layer_size, *plaintext_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(img_size, sizeof(ta_image_hdr_v3_t) + layer_size + *plaintext_size))
        return TEE_ERROR_GENERIC;
    errno_t rc = memmove_s(img_buf + sizeof(ta_image_hdr_v3_t) + layer_size,
        img_size - sizeof(ta_image_hdr_v3_t) - layer_size, plaintext_payload, *plaintext_size);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    plaintext_payload = img_buf + sizeof(ta_image_hdr_v3_t) + layer_size;
    /* Parse plaintext payload */
    return tee_secure_img_parse_payload(plaintext_payload, *plaintext_size, ta_payload);
}

/*
 * Process steps:
 * 1, find cipher layer,
 * 2, decrypt cipher layer,
 * 3, parse cipher layer
 * 4, find and copy signature
 * 5, find payload
 * 6, decrypt payload
 * 7, Move the hash context together
 * 8, parse payload: including parse stand manifest & manifest extension
 * 9, verify signature: including set config and get public key for V3.1
 */
TEE_Result tee_secure_img_unpack_v3(uint32_t rsa_algo_byte_len,
    uint32_t ta_hd_len, uint8_t *img_buf, uint32_t img_size, elf_hash_data *hash_data)
{
    (void)rsa_algo_byte_len;
    (void)ta_hd_len;
    if (img_buf == NULL || hash_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t *signature = NULL;
    uint32_t signature_size;
    uint32_t layer_size = g_v3_cipher_layer_len;
    uint32_t off_set = 0;

    /* Skip image identity layer */
    if (overflow_check(off_set, sizeof(ta_image_hdr_v3_t)))
        return TEE_ERROR_GENERIC;
    if (boundary_check(img_size, off_set + sizeof(ta_image_hdr_v3_t)))
        return TEE_ERROR_GENERIC;
    off_set += sizeof(ta_image_hdr_v3_t);

    TEE_Result ret = tee_secure_img_proc_cipher_layer(img_buf, img_size, &off_set, &layer_size);
    if (ret != TEE_SUCCESS)
        return ret;

    /* Get signature size according to signature algorithm */
    signature_size = tee_secure_img_get_signature_size(g_ta_cipher_layer.cipher_hdr.signature_alg,
        img_buf + off_set, img_size - off_set);
    if (signature_size == SIGNATURE_SIZE_INVALID)
        return TEE_ERROR_BAD_FORMAT;

    /* Locate the position of signatue */
    if (overflow_check(off_set, signature_size))
        return TEE_ERROR_GENERIC;
    if (boundary_check(img_size, off_set + signature_size))
        return TEE_ERROR_GENERIC;
    signature = TEE_Malloc(signature_size, 0);
    if (signature == NULL) {
        tloge("malloc signature failed, signature size = 0x%x\n", signature_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(signature, signature_size, img_buf + off_set, signature_size) != EOK) {
        TEE_Free(signature);
        return TEE_ERROR_SECURITY;
    }
    off_set += signature_size;

    /* Calculate the size of image payload */
    uint32_t plaintext_size = g_image_hdr_v3.context_len - g_v3_cipher_layer_len - signature_size;
    ret = tee_secure_img_proc_payload(img_buf, img_size, off_set, layer_size, &plaintext_size);
    if (ret != TEE_SUCCESS) {
        TEE_Free(signature);
        return ret;
    }

    /* Verify signature */
    ret = tee_secure_img_signature_verify(img_buf, sizeof(ta_image_hdr_v3_t) + layer_size + plaintext_size,
        signature, signature_size, hash_data);
    TEE_Free(signature);
    return ret;
}

void free_verify_v3(void)
{
    load_img_info *img_info = get_img_info();
    ta_payload_layer_t *ta_payload = get_ta_payload();

    /* do NOT free, map from tafs */
    if (img_info->img_buf != NULL) {
        (void)munmap((void *)(uintptr_t)img_info->img_buf, get_img_size());
        img_info->img_buf = NULL;
    }

    if (img_info->manifest.service_name != NULL) {
        TEE_Free(img_info->manifest.service_name);
        img_info->manifest.service_name = NULL;
    }

    if (g_ta_cipher_layer.key != NULL) {
        (void)memset_s(g_ta_cipher_layer.key, g_ta_cipher_layer.cipher_hdr.key_size, 0,
            g_ta_cipher_layer.cipher_hdr.key_size);
        TEE_Free(g_ta_cipher_layer.key);
        g_ta_cipher_layer.key = NULL;
    }
    if (g_ta_cipher_layer.iv != NULL) {
        (void)memset_s(g_ta_cipher_layer.iv, g_ta_cipher_layer.cipher_hdr.iv_size, 0,
            g_ta_cipher_layer.cipher_hdr.iv_size);
        TEE_Free(g_ta_cipher_layer.iv);
        g_ta_cipher_layer.iv = NULL;
    }

    (void)memset_s(img_info, sizeof(load_img_info), 0, sizeof(load_img_info));
    (void)memset_s(&g_image_hdr_v3, sizeof(ta_image_hdr_v3_t), 0, sizeof(ta_image_hdr_v3_t));
    (void)memset_s(ta_payload, sizeof(ta_payload_layer_t), 0, sizeof(ta_payload_layer_t));
    (void)memset_s(&g_ta_cipher_layer, sizeof(ta_cipher_layer_t), 0, sizeof(ta_cipher_layer_t));
}

TEE_Result secure_img_copy_rsp_v3(elf_verify_reply *rep)
{
    if (rep == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    load_img_info *img_info = get_img_info();
    ta_payload_layer_t *ta_payload = get_ta_payload();

    rep->ta_property = img_info->manifest.mani_info.ta_property;
    rep->service_name_len = img_info->manifest.mani_info.service_name_len;

    if (memcpy_s(rep->service_name, SERVICE_NAME_MAX_IN_MANIFEST,
                 img_info->manifest.service_name, img_info->manifest.mani_info.service_name_len + 1) != 0) {
        tloge("copy service name fail\n");
        return TEE_ERROR_GENERIC;
    }

    rep->payload_hdr = ta_payload->payload_hdr;
    rep->mani_ext = img_info->manifest.ext;
    rep->srv_uuid = img_info->manifest.srv_uuid;
    rep->dyn_conf_registed = img_info->dyn_conf_registed;

    if (ta_payload->ta_elf)
        rep->off_ta_elf = ((int8_t *)(ta_payload->ta_elf) - img_info->img_buf);
    else
        rep->off_ta_elf = INVALID_OFFSET;

    if (img_info->manifest_buf)
        rep->off_manifest_buf = (img_info->manifest_buf - img_info->img_buf);
    else
        rep->off_manifest_buf = INVALID_OFFSET;

    return TEE_SUCCESS;
}


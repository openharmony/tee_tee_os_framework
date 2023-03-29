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
#include "tee_comm_elf_verify.h"
#include "tee_log.h"
#include "securec.h"
#include "tee_elf_verify.h"
#include "ta_lib_img_unpack.h"
#include "ta_framework.h"
#include "mem_ops.h"
#include "tee_crypto_api.h"
#include "dyn_conf_dispatch_inf.h"
#include "tee_elf_verify_inner.h"
#include "ta_load_key.h"
#include "tee_load_key_ops.h"
#include "tee_crypto_hal.h"
#include <sys/mman.h>

TEE_Result tee_secure_img_header_check(uint32_t img_version)
{
    size_t ta_head_len;
    teec_image_head *image_hd = get_image_hd();

    if (img_version == TA_SIGN_VERSION)
        ta_head_len = sizeof(teec_ta_head_v1);
    else if (img_version == TA_RSA2048_VERSION)
        ta_head_len = sizeof(teec_ta_head_v2);
    else
        return TEE_ERROR_BAD_PARAMETERS;

    bool check = (image_hd->context_len + ta_head_len < image_hd->context_len) ||
        (image_hd->context_len + ta_head_len > MAX_IMAGE_LEN) ||
        (image_hd->context_len > MAX_IMAGE_LEN) ||
        (image_hd->cipher_bin_len > MAX_IMAGE_LEN - ta_head_len) ||
        (image_hd->cipher_bin_len < ELF_HEAD_SIZE) ||
        (image_hd->manifest_plain_len != MANIFEST_PLAIN_LEN) ||
        (image_hd->sign_len != RSA_SIGN_LEN) ||
        (image_hd->manifest_crypto_len > MAX_MANIFEST_SIZE) ||
        (image_hd->manifest_crypto_len < MIN_MANIFEST_SIZE) ||
        (image_hd->manifest_str_len > image_hd->manifest_crypto_len - MIN_CRYPTO_LEN) ||
        (image_hd->context_len != image_hd->cipher_bin_len + AES_CIPHER_PAD(image_hd->cipher_bin_len) +
         image_hd->sign_len + image_hd->manifest_crypto_len + SIZE_ALIGN(image_hd->manifest_crypto_len));
    if (check) {
        tloge("image hd error context_len: 0x%x\n", image_hd->context_len);
        tloge("image hd error cipher_bin_len: 0x%x\n", image_hd->cipher_bin_len);
        tloge("image hd error manifest_plain_len: 0x%x\n", image_hd->manifest_plain_len);
        tloge("image hd error sign_len: 0x%x\n", image_hd->sign_len);
        tloge("image hd error manifest_crypto_len: 0x%x\n", image_hd->manifest_crypto_len);
        tloge("image hd error manifest_str_len: 0x%x\n", image_hd->manifest_str_len);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result manifest_rsa_decry_check_version(const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data,
                                                   uint32_t *dest_len)
{
    int32_t boringssl_ret;
    load_img_info *img_info = get_img_info();
    enum ta_type type = ((img_info->img_version == TA_RSA2048_VERSION) ? V2_TYPE : V1_TYPE);

    RSA *ta_load_priv_key = get_private_key(img_info->img_version, type);
    if (ta_load_priv_key == NULL) {
        tloge("get private key fail");
        return TEE_ERROR_GENERIC;
    }
    switch (img_info->img_version) {
    case TA_SIGN_VERSION:
        boringssl_ret = RSA_private_decrypt(src_len, src_data, dest_data, ta_load_priv_key, RSA_PKCS1_PADDING);
        break;
    case TA_RSA2048_VERSION:
        boringssl_ret = RSA_private_decrypt(src_len, src_data, dest_data, ta_load_priv_key, RSA_PKCS1_OAEP_PADDING);
        break;
    default:
        tloge("Unsupported secure image version!\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    free_private_key(ta_load_priv_key);
    ta_load_priv_key = NULL;

    if (boringssl_ret <= 0) {
        tloge("Failed to decrypt TA manifest!\n");
        return TEE_ERROR_GENERIC;
    }

    *dest_len = (uint32_t)boringssl_ret;

    return TEE_SUCCESS;
}

static TEE_Result manifest_rsa_decry(const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len)
{
    TEE_Result ret = manifest_rsa_decry_check_version(src_data, src_len, dest_data, dest_len);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to decrypt TA manifest\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result cp_mani_item_inform(const uint8_t *manifest_buffer, uint32_t size, manifest_t *manifest)
{
    if (boundary_check(size, sizeof(manifest->mani_info)))
        return TEE_ERROR_GENERIC;
    manifest->mani_info = *((manifest_info_t *)manifest_buffer);

    bool check =
        (manifest->mani_info.elf_cryptkey_len > KEY_HASH_MAX || manifest->mani_info.elf_hash_len > KEY_HASH_MAX ||
         manifest->mani_info.service_name_len >= SERVICE_NAME_MAX_IN_MANIFEST);
    if (check) {
        tloge("ELF hash_len crypt_key_len or service_name_len is invalid\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}

static TEE_Result parse_manifest(uint8_t *manifest_str, uint32_t size, uint32_t rsa_algo_byte_len)
{
    if (manifest_str == NULL || size <= rsa_algo_byte_len)
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t mani_len = 0;
    uint32_t off_set = 0;
    load_img_info *img_info = get_img_info();
    /* Decrypt manifest encrypted by RSA algorithm */
    TEE_Result ret = manifest_rsa_decry(manifest_str, rsa_algo_byte_len, manifest_str, &mani_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* Copy UUID */
    if (boundary_check(mani_len, off_set + sizeof(img_info->manifest.srv_uuid)))
        return TEE_ERROR_GENERIC;
    img_info->manifest.srv_uuid = *((TEE_UUID *)(manifest_str + off_set));
    off_set += sizeof(img_info->manifest.srv_uuid);

    /* Copy and check manifest information */
    ret = cp_mani_item_inform(manifest_str + off_set, mani_len - off_set, &img_info->manifest);
    if (ret != TEE_SUCCESS)
        return ret;
    off_set += sizeof(img_info->manifest.mani_info);

    /* Copy ELF hash result */
    if (boundary_check(mani_len, off_set + img_info->manifest.mani_info.elf_hash_len))
        return TEE_ERROR_GENERIC;
    ret = tee_secure_img_duplicate_buff(manifest_str + off_set, img_info->manifest.mani_info.elf_hash_len,
                                        (uint8_t **)&img_info->manifest.hash_val);
    if (ret != TEE_SUCCESS)
        return ret;
    off_set += img_info->manifest.mani_info.elf_hash_len;

    /* Copy ELF AES key */
    if (boundary_check(mani_len, off_set + img_info->manifest.mani_info.elf_cryptkey_len))
        return TEE_ERROR_GENERIC;
    ret = tee_secure_img_duplicate_buff(manifest_str + off_set, img_info->manifest.mani_info.elf_cryptkey_len,
                                        (uint8_t **)&img_info->manifest.key_val);
    if (ret != TEE_SUCCESS)
        return ret;

    /* Allocate buffer and copy TA service name */
    off_set = rsa_algo_byte_len;
    if (boundary_check(size, off_set + img_info->manifest.mani_info.service_name_len))
        return TEE_ERROR_GENERIC;
    img_info->manifest.service_name = (int8_t *)TEE_Malloc(img_info->manifest.mani_info.service_name_len + 1, 0);
    if (img_info->manifest.service_name == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;
    errno_t eret = memcpy_s(img_info->manifest.service_name, img_info->manifest.mani_info.service_name_len + 1,
                            manifest_str + off_set, img_info->manifest.mani_info.service_name_len);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;
    off_set += img_info->manifest.mani_info.service_name_len;

    /* Process manifest extension */
    teec_image_head *image_hd = get_image_hd();
    if (boundary_check(size, off_set + image_hd->manifest_str_len))
        return TEE_ERROR_GENERIC;
    ret = tee_secure_img_manifest_extention_process(manifest_str + off_set, image_hd->manifest_str_len,
                                                    &img_info->manifest.ext, NULL);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

#define DECRYPT_ELF_LEN     (1 << DECRY_OFFSET)

static TEE_Result aes_decrypt_elf(const uint8_t *decry_in, uint32_t in_len, uint8_t *decry_dst, uint32_t dst_len,
                                  TEE_ObjectHandle key)
{
    TEE_OperationHandle crypto_ops = NULL;
    uint32_t index;
    uint32_t decry_times = (in_len >> DECRY_OFFSET);
    size_t out_len;
    size_t total_out_len = 0;
    size_t left_len = in_len;

    TEE_Result ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_DECRYPT, KEY_SIZE_MAX);
    if (ret != TEE_SUCCESS)
        return ret;
    ret = TEE_SetCryptoFlag(crypto_ops, SOFT_CRYPTO);
    if (ret != TEE_SUCCESS) {
        tloge("set soft engine failed 0x%x\n", ret);
        TEE_FreeOperation(crypto_ops);
        return ret;
    }

    ret = TEE_SetOperationKey(crypto_ops, key);
    if (ret != TEE_SUCCESS) {
        tloge("set operation key fail:0x%x\n", ret);
        TEE_FreeOperation(crypto_ops);
        return ret;
    }

    /* IV len is 16, but key-len is 32, so only need 1/2,
     * this change is corresponding to the openssl aes call in signtool.py */
    load_img_info *img_info = get_img_info();
    TEE_CipherInit(crypto_ops, img_info->manifest.key_val, img_info->manifest.mani_info.elf_cryptkey_len >> 1);

    for (index = 0; index < decry_times; index++) {
        out_len = DECRYPT_ELF_LEN;
        ret = TEE_CipherUpdate(crypto_ops, decry_in, DECRYPT_ELF_LEN, decry_dst, &out_len);
        if (ret != TEE_SUCCESS) {
            TEE_FreeOperation(crypto_ops);
            tloge("cipher update fail:0x%x\n", ret);
            return ret;
        }

        decry_in += DECRYPT_ELF_LEN;
        left_len -= DECRYPT_ELF_LEN;
        decry_dst += out_len;
        total_out_len += out_len;
    }

    out_len = dst_len - total_out_len;
    ret = TEE_CipherDoFinal(crypto_ops, decry_in, left_len, decry_dst, &out_len);
    TEE_FreeOperation(crypto_ops);
    if (ret != TEE_SUCCESS) {
        tloge("do final fail:0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result elf_decry(uint8_t *src, uint32_t in_len, uint8_t *dst, uint32_t dst_len)
{
    if (src == NULL || dst == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    TEE_ObjectHandleVar key_obj = {0};
    load_img_info *img_info = get_img_info();

    /* aes cipher init */
    key_obj.Attribute = (TEE_Attribute *)TEE_Malloc(sizeof(TEE_Attribute), 0);
    if (key_obj.Attribute == NULL) {
        tloge("Failed to allocate key attribute for TA ELF decryption\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    key_obj.Attribute->content.ref.length = img_info->manifest.mani_info.elf_cryptkey_len;
    key_obj.Attribute->content.ref.buffer = img_info->manifest.key_val;

    /* aes decrypto */
    TEE_Result tee_ret = aes_decrypt_elf(src, in_len, src, in_len, &key_obj);
    if (tee_ret != TEE_SUCCESS) {
        tloge("elf decrypt fail\n");
        TEE_Free(key_obj.Attribute);
        key_obj.Attribute = NULL;
        return tee_ret;
    }

    tee_ret = memmove_s(dst, dst_len, src, in_len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("memory move fail\n");
        TEE_Free(key_obj.Attribute);
        key_obj.Attribute = NULL;
        return tee_ret;
    }

    TEE_Free(key_obj.Attribute);
    key_obj.Attribute = NULL;
    return tee_ret;
}

static TEE_Result elf_verify(const uint8_t *hash_context, uint32_t context_len,
                             elf_hash_data *hash_data)
{
    load_img_info *img_info = get_img_info();
    if (img_info->manifest.hash_val == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    uint8_t calced_hash[SHA256_LEN] = {0};

    TEE_Result tee_ret = tee_secure_img_hash_ops(hash_context, context_len, calced_hash, sizeof(calced_hash));
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to calculate hash");
        return tee_ret;
    }

    errno_t eret = TEE_MemCompare(img_info->manifest.hash_val, calced_hash, SHA256_LEN);
    if (eret != 0) {
        tloge("elf hash verify fail!\n ");
        return TEE_ERROR_SECURITY;
    }

    /* copy hash data out of this func if hash_data ptr is not NULL */
    copy_hash_data(hash_data, calced_hash, SHA256_LEN);

    return TEE_SUCCESS;
}

/* Image process function for version 1, 2 */
TEE_Result tee_secure_img_unpack_v2(uint32_t rsa_algo_byte_len,
    uint32_t ta_hd_len, uint8_t *img_buf, uint32_t img_size, elf_hash_data *hash_data)
{
    uint32_t off_set = 0;
    (void)img_buf;
    (void)img_size;
    load_img_info *img_info = get_img_info();
    teec_image_head *image_hd = get_image_hd();

    if (hash_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /* manifest handle, if manifest crypto, this is crypto context */
    if (overflow_check(off_set, ta_hd_len))
        return TEE_ERROR_GENERIC;
    off_set += ta_hd_len;
    if (boundary_check(img_info->img_size, off_set))
        return TEE_ERROR_GENERIC;

    int8_t *manifest_str = img_info->img_buf + off_set;
    TEE_Result ret = parse_manifest((uint8_t *)manifest_str, img_info->img_size - off_set, rsa_algo_byte_len);
    if (ret != TEE_SUCCESS)
        return ret;

    if (overflow_check(off_set, (image_hd->manifest_crypto_len + SIZE_ALIGN(image_hd->manifest_crypto_len))))
        return TEE_ERROR_GENERIC;

    off_set += (image_hd->manifest_crypto_len + SIZE_ALIGN(image_hd->manifest_crypto_len));
    if (boundary_check(img_info->img_size, off_set))
        return TEE_ERROR_GENERIC;
    int8_t *sign_crypt = img_info->img_buf + off_set;

    /* rsa 2048 verify */
    ret = tee_secure_ta_release_verify((uint8_t *)img_info->manifest.hash_val,
        img_info->manifest.mani_info.elf_hash_len, (uint8_t *)sign_crypt, image_hd->sign_len);
    if (ret != TEE_SUCCESS)
        return TEE_ERROR_IMG_ELF_LOAD_FAIL;
    if (overflow_check(off_set, image_hd->sign_len))
        return TEE_ERROR_GENERIC;

    off_set += image_hd->sign_len;
    if (boundary_check(img_info->img_size, off_set))
        return TEE_ERROR_GENERIC;

    uint8_t *crypt_elf = (uint8_t *)(img_info->img_buf + off_set);

    /* elf decrypto, let plain img in img_info->img_buf */
    uint8_t *elf_plain = (uint8_t *)img_info->img_buf;

    if (img_info->img_size <= off_set)
        return TEE_ERROR_BAD_PARAMETERS;
    if (overflow_check(image_hd->cipher_bin_len, AES_CIPHER_PAD(image_hd->cipher_bin_len)))
        return TEE_ERROR_GENERIC;

    uint32_t align_elf_len = (image_hd->cipher_bin_len + AES_CIPHER_PAD(image_hd->cipher_bin_len));
    if (align_elf_len > img_info->img_size - off_set)
        return TEE_ERROR_BAD_PARAMETERS;
    if (elf_decry(crypt_elf, align_elf_len, elf_plain, img_info->img_size) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;
    return elf_verify(elf_plain, image_hd->cipher_bin_len, hash_data);
}

void free_verify_v2(void)
{
    load_img_info *img_info = get_img_info();
    teec_image_head *image_hd = get_image_hd();
    /* do NOT free it, map from tafs */
    if (img_info->img_buf != NULL) {
        (void)munmap((void *)(uintptr_t)img_info->img_buf, get_img_size());
        img_info->img_buf = NULL;
    }

    if (img_info->manifest.hash_val != NULL) {
        TEE_Free(img_info->manifest.hash_val);
        img_info->manifest.hash_val = NULL;
    }

    if (img_info->manifest.key_val != NULL) {
        (void)memset_s(img_info->manifest.key_val, img_info->manifest.mani_info.elf_cryptkey_len, 0,
            img_info->manifest.mani_info.elf_cryptkey_len);

        TEE_Free(img_info->manifest.key_val);
        img_info->manifest.key_val = NULL;
    }

    if (img_info->manifest.service_name != NULL) {
        TEE_Free(img_info->manifest.service_name);
        img_info->manifest.service_name = NULL;
    }

    (void)memset_s((void *)img_info, sizeof(load_img_info), 0, sizeof(load_img_info));
    (void)memset_s((void *)image_hd, sizeof(teec_image_head), 0, sizeof(teec_image_head));
}

TEE_Result secure_img_copy_rsp_v2(elf_verify_reply *rep)
{
    if (rep == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    load_img_info *img_info = get_img_info();
    teec_image_head *image_hd = get_image_hd();
    rep->ta_property = img_info->manifest.mani_info.ta_property;
    rep->service_name_len = img_info->manifest.mani_info.service_name_len;
    rep->mani_ext = img_info->manifest.ext;
    rep->srv_uuid = img_info->manifest.srv_uuid;

    rep->payload_hdr.mani_ext_size = image_hd->manifest_str_len;
    rep->payload_hdr.ta_elf_size = image_hd->cipher_bin_len;

    if (memcpy_s(rep->service_name, SERVICE_NAME_MAX_IN_MANIFEST, img_info->manifest.service_name,
        img_info->manifest.mani_info.service_name_len + 1) != 0) {
        tloge("copy service name fail\n");
        return TEE_ERROR_GENERIC;
    }

    rep->off_ta_elf = 0;
    if (img_info->manifest_buf)
        rep->off_manifest_buf = (img_info->manifest_buf - img_info->img_buf);
    else
        rep->off_manifest_buf = INVALID_OFFSET;

    return TEE_SUCCESS;
}

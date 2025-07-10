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
#ifndef TA_LIB_IMG_UNPACK_H
#define TA_LIB_IMG_UNPACK_H
#include "tee_defines.h"
#include "ta_framework.h"

#define KEY_VER_BITE            0X8U
#define KEY_VER_MASK            0XFFU
#define SEC_IMG_TA_KEY_VERSION  2U
/* ta's sec file only signature not encrypt */
#define KEY_VER_NOT_ENCRYPT     0
#define PERMSRV_FILE_OPT  "permsrv_file_operation"
#define PERMSRV_SAVE_FILE "permsrv_save_file"
#define INVALID_OFFSET (-1)
#define MAX_TAFS_NAME_LEN 64
#define RWRIGHT 0600
#define COUNTER_STEP_SIZE 0x1010101
#define SERVICE_NAME_MAX_IN_MANIFEST 48
#define RET_KEEP_LOADING 3
#define SIGN_ALG_MASK 0x0000FFFF
#define RWRIGHT 0600
#define LOAD_TA_TMP_FILE "%s/gt_elf_%u.msec"

#define DECIMAL_BASE         10
#define HEX_BASE             16
#define MIN_MANIFEST_SIZE    128
#define MAX_MANIFEST_SIZE    512
#define ADDITIONAL_BUF_SIZE  4096
#define TEE_RSA1024_BYTE_LEN 128
#define TEE_RSA2048_BYTE_LEN 256
#define TEE_RSA4096_BYTE_LEN 512
#define DECRY_OFFSET         10

#define CIPHER_HDR_8_BYTE  8
#define CIPHER_HDR_16_BYTE 16
#define CIPHER_HDR_32_BYTE 32
#define CIPHER_HDR_64_BYTE 64
#define SIGN_ALGO_RSA_2048 0x00002048
#define SIGN_ALGO_RSA_4096 0x00004096
#define SIGN_ALGO_ECC_256  0x00000256

#define SIGN_ALG_KEY_STYLE_MASK 0x10000000 /* 0: debug, 1: release */
#define SIGN_ALG_PADD_MASK      0x08000000 /* 0: pkcs1v5, 1: pss */
#define SIGN_ALG_HASH_MASK      0x04000000 /* 0: sha256, 1: sha512 */
#define SIGN_ALG_KEY_LEN_MASK   0x0000ffff /* only support 2048/4096bits */

#define SIGN_TA_ALG_BITS       20
#define SIGN_ALG_TA_ALG_MASK   0xF

#define RSA2048_SIGNATURE_SIZE 256
#define RSA4096_SIGNATURE_SIZE 512
#define ECC256_SIGNATURE_SIZE  72
#define MAX_SIGNATURE_SIZE     512

#define OUTPUT_MEM_REF_INDEX 2
#define INPUT_VALUE_INDEX    3

#define SIGNATURE_SIZE_INVALID 0

#define TA_HEAD_MAGIC1 0xA5A55A5A
#define TA_HEAD_MAGIC2 0xAAAA

#define IMAGE_BUF_EXTRA 4096
#define SHA1_LEN        20
#define SHA256_LEN      32 /* now use sha256 hash alg */
#define SHA512_LEN      64 /* now use sha256 hash alg */
#define HASH_UPDATA_LEN 1024 /* modify from 64 to 1024, reduce elf-load time */

#define TEE_ERROR_IMG_DECRYPTO_FAIL  0xFF01 /* *< Image decryption failed */
#define TEE_ERROR_IMG_VERIFY_FAIL    0xFF02 /* *< Image verification failed */
#define TEE_ERROR_IMG_ELF_LOAD_FAIL  0xFF03 /* *< Image loading failed */
#define TEE_ERROR_IMG_NEED_LOAD_FAIL 0xFF04 /* *< Image loading judgement failed */
#define TEE_ERROR_IMG_PARSE_FAIL     0xFF05 /* *< Image parse failed */

#define KEY_SIZE_MAX 64

#define ELF_HEAD_SIZE      0x36
#define MANIFEST_PLAIN_LEN 116
#define RSA_SIGN_LEN       256
#define MIN_CRYPTO_LEN     128
#define AES_CIPHER_PAD(p)  (16 - (p) % 16)
#define SIZE_ALIGN(p)      (4 - (p) % 4)
#define RLEN               32
#define E_KEY_SIZE         65
#define KEY_HASH_MAX                 32
#define RSA_DIGEST_LEN               KEY_HASH_MAX

#define RSA_PUB_D_SIZE     384
#define RSA_PRIV_ORIG_LEN  193
#define RSA_PUB_E_SIZE     3

#define TA_LOAD_PERM_ALLOW 1
#define TA_LOAD_PERM_DENY  0

#define UINT32_MAX_VALUE 0xFFFFFFFF

typedef enum {
    IMG_TYPE_APP         = 1,
    IMG_TYPE_LIB         = 2,
    IMG_TYPE_DYNAMIC_DRV = 3,
    IMG_TYPE_CRYPTO_DRV  = 4,
    IMG_TYPE_DYNAMIC_SRV = 5,
    IMG_TYPE_DYNAMIC_CLIENT = 6,
    IMG_TYPE_MAX         = 7,
} tee_img_type_t;

enum {
    HARDWARE_ENGINE_CRYPTO  = 1,
    HARDWARE_ENGINE_MAX,
};

/* Version 1, 2 have the same image head */
typedef struct {
    uint32_t context_len;         /* manifest_crypto_len + cipher_bin_len */
    uint32_t manifest_crypto_len; /* manifest crypto len */
    uint32_t manifest_plain_len;  /* manfiest extension + manifest binary */
    uint32_t manifest_str_len;    /* manifest extension len */
    uint32_t cipher_bin_len;
    uint32_t sign_len; /* sign file len, now rsa 2048 this len is 256 */
} teec_image_head;

typedef struct {
    uint32_t magic_num1;
    uint16_t magic_num2;
    uint16_t version_num;
} teec_image_identity;

typedef struct {
    teec_image_head img_hd;
} teec_ta_head_v1;

/* V2 & V3 have the same TA HEADER */
typedef struct {
    teec_image_identity img_identity;
    teec_image_head img_hd;
    uint8_t reserved[16]; // Reserve 16 bytes for further extension
} teec_ta_head_v2;

typedef struct {
    int32_t single_instance;
    int32_t multi_session;
    int32_t multi_command;
    uint32_t heap_size;
    uint32_t stack_size;
    int32_t instance_keep_alive;
} ta_property_t;

typedef struct {
    ta_property_t ta_property;
    uint32_t elf_hash_len;
    uint32_t elf_cryptkey_len;
    uint32_t service_name_len;
} manifest_info_t;

typedef struct {
    uint16_t distribution;
    uint16_t api_level;
    uint16_t sdk_version;
    bool is_lib;
    bool ssa_enum_enable;
    bool mem_page_align;
    bool sys_verify_ta;
    uint16_t target_type;
    uint16_t target_version;
    uint16_t hardware_type;
    bool is_need_release_ta_res;
    bool crash_callback;
    bool is_need_create_msg;
    bool is_need_release_msg;
} manifest_extension_t;

typedef struct {
    TEE_UUID srv_uuid;
    manifest_info_t mani_info;
    int8_t *hash_val;
    int8_t *key_val;
    int8_t *service_name;
    manifest_extension_t ext;
} manifest_t;

typedef struct {
    manifest_t manifest;  /* save manifest info */
    int8_t *manifest_buf; /* use malloc, save manifest extension */
    int8_t *img_buf;      /* save image */
    uint32_t img_offset;
    uint32_t img_size;
    uint32_t img_version;
    bool dyn_conf_registed; /* using for dyn perm */
} load_img_info;

typedef struct {
    uint32_t key_size;
    uint32_t iv_size;
    uint32_t signature_alg;
} ta_cipher_hdr_t;

typedef struct {
    ta_cipher_hdr_t cipher_hdr;
    uint8_t *key;
    uint8_t *iv;
} ta_cipher_layer_t;

typedef struct {
    uint32_t format_version;
    uint32_t mani_info_size;
    uint32_t mani_ext_size;
    uint32_t ta_elf_size;
    uint32_t ta_conf_size;
} ta_payload_hdr_t;

typedef struct {
    ta_payload_hdr_t payload_hdr;
    uint8_t *ta_elf;
    uint8_t *ta_conf;
    bool conf_registed;
} ta_payload_layer_t;

typedef struct {
    teec_image_identity img_identity;
    uint32_t context_len;
    uint32_t ta_key_version;
} ta_image_hdr_v3_t;

#define MAX_HEADER_SIZE       0x400
#define MANIFEST_RESERVE_SIZE 128

typedef struct {
    uint32_t img_version;
    uint32_t identity_len;
    uint32_t header_len;
    uint32_t image_len;
    uint32_t total_len;
    TEE_UUID srv_uuid;
    int8_t   *service_name;
    uint32_t service_name_len;
    int32_t  multi_instance;
    int32_t  multi_session;
    int32_t  multi_command;
    uint32_t heap_size;
    uint32_t stack_size;
    int32_t  instance_keep_alive;
    uint8_t *manifest_buf;
    uint8_t manifest_str_len;
    int8_t   *img_buf;
    uint32_t img_buf_len;
    uint32_t img_buf_offset;
} teec_image_info;

enum cipher_layer_len_ver {
    CIPHER_LAYER_LEN_256 = 256,
    CIPHER_LAYER_LEN_384 = 384,
};

enum cipher_layer_key_ver {
    CIPHER_LAYER_KEY_V1 = 1, /* 2048 bits key, default is also 2048 bits */
    CIPHER_LAYER_KEY_V2 = 2, /* 3072 bits key */
};

typedef struct {
    int8_t *ptr_manifest_buf;
    int8_t *ptr_ta_elf;
    int8_t *img_buf;
    uint32_t img_offset;
    uint32_t img_size;
    uint32_t img_version;
    int32_t img_fp; /* fp here means a special fd */
    uint32_t aligned_img_size;
    char tmp_file_name[MAX_TAFS_NAME_LEN];
    bool tmp_file_exist;
} elf_image_info;

#endif

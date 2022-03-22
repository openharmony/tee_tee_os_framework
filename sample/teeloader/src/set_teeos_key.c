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

#include "set_teeos_key.h"

#include <string.h>
#include <securec.h>

#include "tlv_sharedmem.h"
#include "teeos_uuid.h"
#include "set_teeos_cfg.h"
#include "img_load.h"

#define KEY_INFO_MAIGIC_BASE 0x5a5aa501
#define CA_RSA_MAGIC         0x5a5aa501
#define TA_RSA_MAGIC         0x5a5aa502
#define TA_CERT_MAGIC        0x5a5aa503
#define TA_CONFIG_MAGIC      0x5a5aa504
#define TA_ECIES_MAGIC       0x5a5aa505
#define TA_WB_MAGIC          0x5a5aa506

struct key_tag_info {
    char tag[MAX_TAG_LEN];
    uint32_t magic;
};

static struct key_tag_info g_teeos_key_tag[] = {
    {"ca_rsa_pub_key",  CA_RSA_MAGIC},
    {"ta_rsa_pub_2048release",  TA_RSA_MAGIC},
    {"ta_root_pub_key", TA_CERT_MAGIC},
    {"ta_config_pub_key", TA_CONFIG_MAGIC},
    {"ta_decrypt_key_eciesv3_3072", TA_ECIES_MAGIC},
    {"ta_decrypt_key_wbv3_3072", TA_WB_MAGIC},
};

static TEE_UUID g_key_perm_uuid[] = {
    TEE_SERVICE_SYSTEM,
};

#define OEMKEY_MAGIC 0x55AA55AA
#define OEMKEY_TAG   "oemkey"
#define RES_NUM      52

struct oemkey_info {
    uint32_t  head_magic;
    uint8_t   oemkey[OEMKEY_SIZE];
    uint8_t   reserved[RES_NUM];
    uint32_t  tail_magic;
} __attribute__((__packed__));

static int32_t trans_key_info_to_share_mem(struct asym_key_t *asym_key_info,
                                           void *header, struct key_tag_info *tag_info)
{
    char *buffer = header;
    int32_t ret;
    struct tlv_item_data tlv_item_data;
    if (asym_key_info->key_magic != tag_info->magic) {
        teelog("asym_key_info->key_magic is %x, tag_info->magic is %x\n",
               asym_key_info->key_magic, tag_info->magic);
        return -1;
    }

    tlv_item_data.type = tag_info->tag;
    tlv_item_data.type_size = strlen(tag_info->tag);
    tlv_item_data.owner_list = g_key_perm_uuid;
    tlv_item_data.owner_len = (uint32_t)sizeof(g_key_perm_uuid);
    tlv_item_data.value = buffer + asym_key_info->key_offset;
    tlv_item_data.value_len = asym_key_info->key_size;

    ret = put_tlv_shared_mem(tlv_item_data);
    return ret;
}

int32_t load_teeos_key_info(void *image)
{
    struct secure_img_header *img_header = image;
    struct asym_key_t *asym_key_info = img_header->teeos_key_info;
    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(g_teeos_key_tag); i++) {
        if (trans_key_info_to_share_mem(asym_key_info, image, &g_teeos_key_tag[i]) != 0)
            teelog("trans %s sharemem failed, id is %d\n", g_teeos_key_tag[i].tag, i);
        asym_key_info++;
    }

    return 0;
}

int32_t trans_oemkey(uint8_t *oemkey, uint32_t oemkey_size)
{
    if (oemkey_size != OEMKEY_SIZE || oemkey == NULL) {
        teelog("oemkey_size error\n");
        return -1;
    }
    struct oemkey_info oemkey_info;
    oemkey_info.head_magic = OEMKEY_MAGIC;
    oemkey_info.tail_magic = OEMKEY_MAGIC;

    if (memcpy_s(oemkey_info.oemkey, OEMKEY_SIZE, oemkey, OEMKEY_SIZE) != EOK) {
        teelog("oemkey_size error\n");
        return -1;
    }

    char oemkey_tag[OEMKEY_SIZE] = OEMKEY_TAG;
    struct tlv_item_data tlv_item_data;
    tlv_item_data.type = oemkey_tag;
    tlv_item_data.type_size = strlen(oemkey_tag);
    tlv_item_data.owner_list = g_key_perm_uuid;
    tlv_item_data.owner_len = (uint32_t)sizeof(g_key_perm_uuid);
    tlv_item_data.value = &oemkey_info;
    tlv_item_data.value_len = sizeof(oemkey_info);

    if (put_tlv_shared_mem(tlv_item_data) != 0) {
        teelog("put oemkey tlv failed\n");
        return -1;
    }

    return 0;
}

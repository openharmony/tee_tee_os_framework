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
#include "perm_srv_ta_crl.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <crl_api.h>
#include <crypto_wrapper.h>
#include "perm_srv_file_op.h"
#include "perm_srv_ta_cert.h"
#include "perm_srv_set_config.h"

static struct revoked_config_t g_crl_revoked_config = {
    .crl_issuer_list = dlist_head_init(g_crl_revoked_config.crl_issuer_list),
    .list_file       = "crl_cert_list_file.db",
    .issuer_count    = 0,
    .revoked_count   = 0,
    .lock            = PTHREAD_MUTEX_INITIALIZER,
};
static bool g_exist_flag = true;

#define ISSUER_MAX_COUNT     0xFF
#define REVOKED_MAX_COUNT    0xFFFF
#define ENTRY_MAX_BUFFER_LEN 128

static TEE_Result perm_srv_crl_issuer_list_add_entry(struct crl_issuer_t *issuer_entry)
{
    if (g_crl_revoked_config.issuer_count >= ISSUER_MAX_COUNT) {
        tloge("Issuer count of CRL shouldn't be over 0xFF\n");
        return TEE_ERROR_GENERIC;
    }

    g_crl_revoked_config.issuer_count++;
    dlist_insert_tail(&issuer_entry->head, &g_crl_revoked_config.crl_issuer_list);

    return TEE_SUCCESS;
}

static TEE_Result perm_srv_revoked_list_add_node(struct crl_issuer_t *issuer_entry,
                                                  struct revoked_node_t *revoked_node)
{
    if (g_crl_revoked_config.revoked_count >= REVOKED_MAX_COUNT) {
        tloge("Revoked node count of CRL shouldn't be over 0xFFFF\n");
        return TEE_ERROR_GENERIC;
    }

    g_crl_revoked_config.revoked_count++;
    dlist_insert_tail(&revoked_node->head, &(issuer_entry->revoked_node_list));

    return TEE_SUCCESS;
}

static int32_t perm_srv_tlv_to_buffer(uint8_t type, const uint8_t *value, uint32_t len,
                                      uint8_t **buf, uint32_t buf_size)
{
    bool is_invalid = (value == NULL || len == 0 || buf == NULL || *buf == NULL || (buf_size < (len + TLV_HEADER_LEN)));
    if (is_invalid)
        return -1;

    uint8_t *tmp = *buf;

    /* type */
    tmp[0] = type;
    tmp += TLV_TLEN;

    /* length */
    if (memcpy_s(tmp, buf_size - TLV_TLEN, &len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for len of TLV\n");
        return -1;
    }

    tmp += TLV_LLEN;

    if (memcpy_s(tmp, buf_size - TLV_HEADER_LEN, value, len) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        return -1;
    }
    tmp += len;

    *buf = tmp;
    return (int32_t)(len + TLV_HEADER_LEN);
}

static int32_t perm_srv_revoked_node_to_buffer(uint8_t **buf, uint32_t buf_size,
                                                const struct revoked_node_t *revoked_node)
{
    uint8_t *start = NULL;
    uint32_t value_len;
    uint32_t package_len;
    uint32_t buff_left_size;
    uint8_t entry_buff[ENTRY_MAX_BUFFER_LEN] = { 0 };
    int32_t len;

    bool is_invalid = (buf == NULL || *buf == NULL || revoked_node == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = entry_buff;
    buff_left_size = (uint32_t)sizeof(entry_buff);

    if (revoked_node->sn_size + TLV_HEADER_LEN > buff_left_size || revoked_node->sn_size > CERT_UNIVERSAL_LEN) {
        tloge("Buffer overflow for inserting serail number\n");
        return -1;
    }

    len = perm_srv_tlv_to_buffer(TYPE_BITSTRING, revoked_node->sn, revoked_node->sn_size, &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert tlv for inserting serial number\n");
        return -1;
    }

    buff_left_size -= (uint32_t)len;

    if (buff_left_size < ASN1_FORMAT_TIME_SIZE + TLV_HEADER_LEN) {
        tloge("Buffer overflow for inserting revoked date\n");
        return -1;
    }

    len = perm_srv_tlv_to_buffer(TYPE_BITSTRING, revoked_node->revoked_date, ASN1_FORMAT_TIME_SIZE,
                                 &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert tlv of revoked date\n");
        return -1;
    }

    buff_left_size -= (uint32_t)len;

    value_len = (uint32_t)(start - entry_buff);
    package_len = value_len + (uint32_t)TLV_HEADER_LEN;

    if (package_len > buf_size) {
        tloge("Buffer overflow for inserting revoked entry\n");
        return -1;
    }

    len = perm_srv_tlv_to_buffer(TYPE_SEQUENCE, entry_buff, value_len, buf, buf_size);
    if (len < 0) {
        tloge("Failed to insert revoked entry as tlv\n");
        return -1;
    }

    return (int32_t)package_len;
}

static int32_t perm_srv_crl_issuer_entry_to_buffer(uint8_t *buf, uint32_t buf_size, struct crl_issuer_t *issuer_entry)
{
    struct dlist_node *pos = NULL;
    uint8_t *start = NULL;
    uint32_t buff_left_size;
    uint32_t value_len;
    uint32_t total_len;
    int32_t len;

    bool is_invalid = (buf == NULL || issuer_entry == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = buf;
    buff_left_size = buf_size;

    /*
     * Reserve space for first tvl type and length
     * We don't fill it here because we don't know the length now
     */
    if (buff_left_size <= TLV_HEADER_LEN)
        return -1;

    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    start += TLV_HEADER_LEN;

    /* Fill the issuer section */
    len = perm_srv_tlv_to_buffer(TYPE_BITSTRING, issuer_entry->issuer, issuer_entry->issuer_size,
                                 &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert CRL cert issuer as TLV\n");
        return -1;
    }

    if (buff_left_size <= (uint32_t)len)
        return -1;

    buff_left_size -= (uint32_t)len;

    /* Fill the revoked entry with specified issuer */
    dlist_for_each(pos, &issuer_entry->revoked_node_list) {
        struct revoked_node_t *revoked_node = dlist_entry(pos, struct revoked_node_t, head);
        len = perm_srv_revoked_node_to_buffer(&start, buff_left_size, revoked_node);
        if (len < 0) {
            tloge("Failed to insert revoked entry\n");
            return len;
        }

        if (buff_left_size <= (uint32_t)len)
            return -1;

        buff_left_size -= (uint32_t)len;
    }

    total_len = (uint32_t)(start - buf);
    value_len = total_len - (uint32_t)TLV_HEADER_LEN - (uint32_t)TLV_HEADER_LEN;

    /* Refill the TLV with type 0x30 and length */
    start = buf;
    start[0] = TYPE_SEQUENCE;
    start += TLV_TLEN;
    if (memcpy_s(start, TLV_LLEN, &value_len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        return -1;
    }

    return (int32_t)total_len;
}

#ifdef LOG_ON
void perm_srv_print_buff(const uint8_t *buff, size_t buff_size)
{
    size_t i;
    uint32_t type = sizeof(uint32_t);

    bool is_invalid = (buff == NULL || buff_size == 0);

    if (is_invalid)
        return;

    tloge("Buffer size: 0x%zu\n", buff_size);
    tloge("******************buffer context start****************\n");
    for (i = 0; i < buff_size / type; i++)
        tloge("%02x, %02x, %02x, %02x\n", buff[type * i], buff[type * i + TLV_TAG_TA_BASIC_INFO],
              buff[type * i + TLV_TAG_TA_MANIFEST_INFO], buff[type * i + TLV_TAG_TA_CONTROL_INFO]);

    for (i = 0; i < buff_size % type; i++)
        tloge("0x%02x\n", buff[buff_size - buff_size % type + i]);

    tloge("******************buffer context end****************\n");
}

static void perm_srv_global_ta_crl_list_print(void)
{
    struct dlist_node *pos = NULL;

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return;
    }

    /* Search for the issuer in global crl cert list */
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct dlist_node *inner = NULL;
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);

        /* Search for the sn in the revoked_node_list with specified issuer */
        dlist_for_each(inner, &issuer_entry->revoked_node_list) {
            struct revoked_node_t *revoked_node = dlist_entry(inner, struct revoked_node_t, head);
            perm_srv_print_buff(revoked_node->sn, revoked_node->sn_size);
            tloge("Revocation date: %s\n", revoked_node->revoked_date);
        }
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
}
#else
static void perm_srv_global_ta_crl_list_print(void)
{
}
#endif

static int32_t perm_srv_get_type_len(uint8_t *type, uint32_t *len, const uint8_t *buf, uint32_t buf_size)
{
    const uint8_t *pos = buf;

    if (buf_size < TLV_HEADER_LEN)
        return -1;

    /* type */
    *type = pos[0];
    pos += TLV_TLEN;

    /* length */
    if (memcpy_s(len, TLV_LLEN, pos, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for len of TLV\n");
        return -1;
    }

    return 0;
}

static int32_t perm_srv_revoked_node_load(uint8_t *buf, uint32_t buf_size, struct revoked_node_t *revoked_node)
{
    uint8_t *start = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    uint32_t buff_left_size;
    int32_t ret;

    bool is_invalid = (buf == NULL || revoked_node == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = buf;
    buff_left_size = buf_size;

    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid)
        return -1;

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    /* load SN */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid)
        return -1;

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    if (memcpy_s(revoked_node->sn, sizeof(revoked_node->sn), start, len) != EOK) {
        tloge("Failed to do memcpy_s for serial number\n");
        return -1;
    }

    revoked_node->sn_size = len;
    start += len;
    buff_left_size -= len;

    /* load revoked date */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid =
        (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN) || len != ASN1_FORMAT_TIME_SIZE);
    if (is_invalid) {
        tloge("Failed to load revoked date, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    if (memcpy_s(revoked_node->revoked_date, sizeof(revoked_node->revoked_date), start, ASN1_FORMAT_TIME_SIZE) != EOK)
        return -1;

    start += ASN1_FORMAT_TIME_SIZE;

    return (int32_t)(start - buf);
}

static int32_t perm_srv_revoked_list_load(uint8_t **start, uint32_t left_size, struct crl_issuer_t *issuer_entry)
{
    int32_t ret;

    while (left_size > 0) {
        struct revoked_node_t *revoked_node = TEE_Malloc(sizeof(struct revoked_node_t), 0);
        if (revoked_node == NULL) {
            tloge("Failed to do tee malloc\n");
            return -1;
        }

        ret = perm_srv_revoked_node_load(*start, left_size, revoked_node);
        if (ret < 0) {
            tloge("Failed to load revoked entry\n");
            TEE_Free(revoked_node);
            return -1;
        }

        (*start) += ret;
        left_size -= (uint32_t)ret;
        if (perm_srv_revoked_list_add_node(issuer_entry, revoked_node) != TEE_SUCCESS) {
            tloge("Failed to add revoked entry\n");
            TEE_Free(revoked_node);
            return -1;
        }
    }

    return 0;
}

static int32_t perm_srv_crl_issuer_entry_load(uint8_t *buf, uint32_t buf_size, struct crl_issuer_t *issuer_entry)
{
    uint8_t *start = buf;
    uint8_t type = 0;
    uint32_t len = 0;
    uint32_t data_len;
    int32_t ret;
    bool is_invalid = false;
    uint32_t buff_left_size = buf_size;

    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    data_len = len;

    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - (TLV_HEADER_LEN + TLV_HEADER_LEN)) ||
                  (buff_left_size <= (TLV_HEADER_LEN + TLV_HEADER_LEN)));
    if (is_invalid) {
        tloge("Failed to load sequence header, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);

    is_invalid = (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid) {
        tloge("Failed to load issuer header, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    if (memcpy_s(issuer_entry->issuer, sizeof(issuer_entry->issuer), start, len) != EOK) {
        tloge("Failed to do memcpy_s for issuer\n");
        return -1;
    }

    issuer_entry->issuer_size = len;
    start += len;
    buff_left_size = data_len - len;
    ret = perm_srv_revoked_list_load(&start, buff_left_size, issuer_entry);
    if (ret != 0)
        return ret;

    return (int32_t)(start - buf);
}

static TEE_Result perm_srv_add_crl_issuer_entry(const uint8_t *issuer, uint32_t issuer_size,
                                                struct crl_issuer_t **dest_entry)
{
    struct dlist_node *pos = NULL;
    struct crl_issuer_t *temp_entry = NULL;
    TEE_Result tee_ret;
    bool is_valid = false;

    /* The issuer does exist */
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        temp_entry = dlist_entry(pos, struct crl_issuer_t, head);
        is_valid = ((issuer_size == temp_entry->issuer_size) &&
                    (TEE_MemCompare(issuer, temp_entry->issuer, issuer_size)) == 0);
        if (is_valid) {
            *dest_entry = temp_entry;
            return TEE_SUCCESS;
        }
    }

    /* Add new issuer entry */
    temp_entry = TEE_Malloc(sizeof(*temp_entry), 0);
    if (temp_entry == NULL) {
        tloge("Failed to malloc memory\n");
        *dest_entry = NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    dlist_init(&(temp_entry->revoked_node_list));
    if (memcpy_s(temp_entry->issuer, sizeof(temp_entry->issuer), issuer, issuer_size) != EOK) {
        tloge("Failed to do memcpy_s for issuer\n");
        TEE_Free(temp_entry);
        *dest_entry = NULL;
        return TEE_ERROR_GENERIC;
    }

    temp_entry->issuer_size = issuer_size;

    /* Add new allocated issuer entry to global issuer list */
    tee_ret = perm_srv_crl_issuer_list_add_entry(temp_entry);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to add issuer entry to list\n");
        TEE_Free(temp_entry);
        temp_entry = NULL;
    }
    *dest_entry = temp_entry;
    return tee_ret;
}

static TEE_Result perm_srv_add_revoked_node_to_crl_issuer_entry(struct revoked_node_t *revoked_node,
                                                                 const uint8_t *issuer, uint32_t issuer_size)
{
    struct crl_issuer_t *issuer_entry = NULL;
    TEE_Result tee_ret;

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    tee_ret = perm_srv_add_crl_issuer_entry(issuer, issuer_size, &issuer_entry);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to add issuer entry\n");
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return tee_ret;
    }

    tee_ret = perm_srv_revoked_list_add_node(issuer_entry, revoked_node);
    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return tee_ret;
}

static int32_t perm_srv_global_crl_issuer_list_update(struct revoked_node_t *revoked_node,
                        const cert_list_entry_t *cert_entry, const uint8_t *issuer, uint32_t issuer_size)
{
    TEE_Result ret;

    if (memcpy_s(revoked_node->sn, sizeof(revoked_node->sn), cert_entry->serial, cert_entry->serial_size) != EOK) {
        tloge("Failed to do memcpy for serial number\n");
        return -1;
    }

    revoked_node->sn_size = cert_entry->serial_size;
    if (memcpy_s(revoked_node->revoked_date, sizeof(revoked_node->revoked_date), cert_entry->revoked_date,
                 sizeof(cert_entry->revoked_date)) != EOK) {
        tloge("Failed to do memcpy for revoked date\n");
        return -1;
    }

    ret = perm_srv_add_revoked_node_to_crl_issuer_entry(revoked_node, issuer, issuer_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to add new revoked cert, errno: 0x%x\n", ret);
        return -1;
    }

    return EOK;
}

static TEE_Result perm_srv_crl_cert_to_list(cert_list_entry_t *crl_cert_entry, const uint8_t *issuer,
                                            uint32_t issuer_size)
{
    cert_list_entry_t *curr_cert_entry = crl_cert_entry;
    TEE_Result ret;

    bool is_invalid = (issuer == NULL || issuer_size == 0 || issuer_size >= CERT_LARGE_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    while (curr_cert_entry != NULL) {
        bool exist = false;
        ret = perm_srv_check_cert_revoked(curr_cert_entry->serial, curr_cert_entry->serial_size,
                                          issuer, issuer_size, &exist);
        if (ret != TEE_SUCCESS) {
            tloge("Failed to check if cert is revoked, errno: 0x%x\n", ret);
            return ret;
        }

        if (!exist) {
            struct revoked_node_t *revoked_node = NULL;
            revoked_node = TEE_Malloc(sizeof(*revoked_node), 0);
            if (revoked_node == NULL) {
                tloge("Failed to malloc, size: 0x%x\n", sizeof(*revoked_node));
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            if (perm_srv_global_crl_issuer_list_update(revoked_node, curr_cert_entry, issuer, issuer_size) != EOK) {
                TEE_Free(revoked_node);
                return TEE_ERROR_GENERIC;
            }
        }
        curr_cert_entry = curr_cert_entry->next;
    }

    return TEE_SUCCESS;
}

static void perm_srv_crl_revoked_cert_list_cleanup(cert_list_entry_t *crl_cert_entry)
{
    while (crl_cert_entry != NULL) {
        cert_list_entry_t *next = crl_cert_entry->next;
        TEE_Free(crl_cert_entry);
        crl_cert_entry = next;
    }
}

static void perm_srv_crl_issuer_entry_cleanup(struct crl_issuer_t *issuer_entry)
{
    if (issuer_entry == NULL)
        return;

    struct dlist_node *inner = NULL;
    struct dlist_node *next = NULL;
    struct revoked_node_t *entry = NULL;

    dlist_for_each_safe(inner, next, &issuer_entry->revoked_node_list) {
        entry = dlist_entry(inner, struct revoked_node_t, head);
        dlist_delete(&entry->head);
        TEE_Free(entry);
        entry = NULL;
    }
}

static TEE_Result perm_srv_crl_issuer_list_load(uint8_t *start, uint32_t left_size)
{
    int32_t ret;
    TEE_Result tee_ret;
    struct dlist_node *inner = NULL;
    struct dlist_node *next = NULL;

    while (left_size > 0) {
        struct crl_issuer_t *entry = NULL;
        entry = TEE_Malloc(sizeof(*entry), 0);
        if (entry == NULL) {
            tloge("Failed to malloc memory, size: 0x%x\n", sizeof(*entry));
            return TEE_ERROR_GENERIC;
        }

        dlist_init(&(entry->revoked_node_list));
        ret = perm_srv_crl_issuer_entry_load(start, left_size, entry);
        if (ret < 0) {
            tloge("Failed to load issuer entry\n");
            perm_srv_crl_issuer_entry_cleanup(entry);
            TEE_Free(entry);
            return TEE_ERROR_GENERIC;
        }

        dlist_for_each_safe(inner, next, &g_crl_revoked_config.crl_issuer_list) {
            struct crl_issuer_t *issuer_entry = dlist_entry(inner, struct crl_issuer_t, head);
            bool is_valid = ((issuer_entry->issuer_size == entry->issuer_size) &&
                (TEE_MemCompare(issuer_entry->issuer, entry->issuer, entry->issuer_size)) == 0);
            if (is_valid) {
                perm_srv_crl_issuer_entry_cleanup(issuer_entry);
                dlist_delete(&issuer_entry->head);
                TEE_Free(issuer_entry);
                issuer_entry = NULL;
            }
        }

        start += ret;
        left_size -= (uint32_t)ret;
        tee_ret = perm_srv_crl_issuer_list_add_entry(entry);
        if (tee_ret != TEE_SUCCESS) {
            tloge("Failed to add isser entry to list\n");
            perm_srv_crl_issuer_entry_cleanup(entry);
            TEE_Free(entry);
            return tee_ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result perm_srv_crl_issuer_buff_to_list(uint8_t *buff, uint32_t file_size)
{
    TEE_Result tee_ret;
    int32_t ret;
    uint32_t buff_left_size;
    uint8_t *start = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    bool is_invalid = false;

    start = buff;
    buff_left_size = file_size;
    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid) {
        tloge("Type len get error, %d, 0x%x, 0x%x, 0x%x\n", ret, type, len, buff_left_size);
        return TEE_ERROR_GENERIC;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    tee_ret = perm_srv_crl_issuer_list_load(start, buff_left_size);
    return tee_ret;
}

static bool perm_srv_is_crl_issuer_list_empty(void)
{
    if (g_exist_flag)
        return (bool)dlist_empty(&g_crl_revoked_config.crl_issuer_list);

    return false;
}

TEE_Result perm_srv_global_ta_crl_list_loading(bool check_empty)
{
    uint8_t *buff = NULL;
    TEE_Result tee_ret;
    int32_t ret;
    int32_t file_size;

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (check_empty && !perm_srv_is_crl_issuer_list_empty()) {
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_SUCCESS;
    }

    file_size = perm_srv_file_size(g_crl_revoked_config.list_file);
    if (file_size > CRL_CERT_LIST_MAX_SIZE) {
        tloge("CRL cert list file is over large\n");
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_ERROR_GENERIC;
    }

    /* CRL cert list is is empty or doesn't exist, ignore it */
    if (file_size == 0) {
        g_exist_flag = false;
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        tlogi("CRL cert list file: %s is empty or doesn't exist\n", g_crl_revoked_config.list_file);
        return TEE_SUCCESS;
    }

    if (file_size < 0) {
        tloge("Failed to get size of CRL cert list file\n");
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_ERROR_GENERIC;
    }

    buff = TEE_Malloc((uint32_t)file_size, 0);
    if (buff == NULL) {
        tloge("Failed to malloc buffer, size: %d\n", file_size);
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = perm_srv_file_read(g_crl_revoked_config.list_file, buff, (uint32_t)file_size);
    if (ret != file_size) {
        tloge("Failed to read file ret: %d, size: %d\n", ret, file_size);
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }
    tee_ret = perm_srv_crl_issuer_buff_to_list(buff, (uint32_t)file_size);

exit:
    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    TEE_Free(buff);
    return tee_ret;
}

static int32_t perm_srv_get_ta_crl_list_buffer_size(void)
{
    struct revoked_node_t revoked;
    struct crl_issuer_t issuer;
    (void)memset_s(&revoked, sizeof(revoked), 0, sizeof(revoked));
    (void)memset_s(&issuer, sizeof(issuer), 0, sizeof(issuer));

    uint8_t sn_size = (uint8_t)(sizeof(revoked.sn) + TLV_HEADER_LEN);
    uint8_t date_size = (uint8_t)(sizeof(revoked.revoked_date) + TLV_HEADER_LEN);
    uint8_t revoked_size = sn_size + date_size + (uint8_t)TLV_HEADER_LEN;
    uint16_t issuer_size = (uint16_t)(sizeof(issuer.issuer) + TLV_HEADER_LEN + TLV_HEADER_LEN);

    if (g_crl_revoked_config.issuer_count >= ISSUER_MAX_COUNT ||
        g_crl_revoked_config.revoked_count >= REVOKED_MAX_COUNT) {
        tloge("Issuer count of CRL is over 0xFF or revoked entry count of CRL is over 0xFFFF\n");
        return -1;
    }

    uint32_t total_size = revoked_size * g_crl_revoked_config.revoked_count +
                          issuer_size * g_crl_revoked_config.issuer_count + (uint32_t)TLV_HEADER_LEN;

    return (int32_t)total_size;
}

static TEE_Result perm_srv_crl_issuer_list_to_buffer(uint8_t *start, uint32_t left_size, uint32_t *value_len)
{
    struct dlist_node *pos = NULL;
    int32_t len;

    /* Search for the issuer in global crl cert list */
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);

        len = perm_srv_crl_issuer_entry_to_buffer(start, left_size, issuer_entry);
        if (len < 0) {
            tloge("Failed to store CRL items in buffer\n");
            return TEE_ERROR_GENERIC;
        }

        start += len;
        left_size -= (uint32_t)len;
        *value_len += (uint32_t)len;
    }

    return TEE_SUCCESS;
}

static TEE_Result perm_srv_global_ta_crl_list_storing(void)
{
    TEE_Result tee_ret;
    uint8_t *buff = NULL;
    uint8_t *start = NULL;
    uint32_t value_len = 0;

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_GENERIC;
    }

    int32_t len = perm_srv_get_ta_crl_list_buffer_size();
    if (len <= 0 || len > CRL_CERT_LIST_MAX_SIZE) {
        tloge("Invalid issuer list buffer size: %d\n", len);
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_ERROR_GENERIC;
    }

    buff = TEE_Malloc((uint32_t)len, 0);
    if (buff == NULL) {
        tloge("Failed to malloc buffer, size: %d\n", len);
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    start = buff;
    uint32_t buff_left_size = (uint32_t)len;

    /*
     * Reserve space for first tvl type and length
     * We don't fill it here because we don't know the length now
     */
    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    tee_ret = perm_srv_crl_issuer_list_to_buffer(start, buff_left_size, &value_len);
    if (tee_ret != TEE_SUCCESS)
        goto exit;

    uint32_t total_len = value_len + (uint32_t)TLV_HEADER_LEN;

    /* Refill the TLV with type 0x30 and length */
    start = buff;
    start[0] = TYPE_SEQUENCE;
    start += TLV_TLEN;
    if (memcpy_s(start, TLV_LLEN, &value_len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }

    if (perm_srv_file_write(g_crl_revoked_config.list_file, buff, total_len) != 0) {
        tloge("Failed to write crl revoked list to file\n");
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }
    g_exist_flag = true;
    tee_ret = TEE_SUCCESS;

exit:
    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    TEE_Free(buff);
    return tee_ret;
}

TEE_Result perm_srv_check_cert_revoked(const uint8_t *sn, uint32_t sn_size, const uint8_t *issuer, uint32_t issuer_size,
                                       bool *revoked)
{
    struct dlist_node *pos = NULL;

    bool is_invalid = (sn == NULL || issuer == NULL || revoked == NULL || sn_size == 0 ||
                       sn_size > CERT_UNIVERSAL_LEN || issuer_size == 0 || issuer_size > CERT_LARGE_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    perm_srv_global_ta_crl_list_print();
    /* Search for the issuer in global crl cert list */
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    *revoked = false;
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);
        bool is_valid = (issuer_size == issuer_entry->issuer_size &&
                         TEE_MemCompare(issuer, issuer_entry->issuer, issuer_size) == 0);
        if (!is_valid)
            continue;

        struct dlist_node *inner = NULL;
        struct dlist_node *next = NULL;

        /* Search for the sn in the revoked_node_list with specified issuer */
        dlist_for_each_safe(inner, next, &issuer_entry->revoked_node_list) {
            struct revoked_node_t *entry = dlist_entry(inner, struct revoked_node_t, head);
            is_valid = (sn_size == entry->sn_size && TEE_MemCompare(sn, entry->sn, sn_size) == 0);
            if (is_valid) {
                *revoked = true;
                goto clean;
            }
        }
    }
clean:
    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return TEE_SUCCESS;
}

TEE_Result perm_srv_ta_crl_cert_process(const uint8_t *crl_cert, uint32_t crl_cert_size)
{
    TEE_Result tee_ret = TEE_ERROR_GENERIC;
    uint8_t crl_issuer[CERT_LARGE_LEN] = { 0 };
    const uint8_t *ca_public_key = get_ca_pubkey();

    bool is_invalid = (crl_cert == NULL || crl_cert_size == 0 || ca_public_key == NULL);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Verify the CRL is signed by our CA center */
    int32_t ret = x509_crl_validate((uint8_t *)(uintptr_t)crl_cert, crl_cert_size,
                                    (uint8_t *)(uintptr_t)ca_public_key, get_ca_pubkey_size());
    if (ret <= 0) {
        uint8_t tmp_pubkey_buff[MAX_CERT_LEN] = {0};
        uint32_t ca_key_size = 0;
        if (perm_srv_get_imported_cert_pubkey(tmp_pubkey_buff, &ca_key_size) == TEE_SUCCESS) {
            if (ca_key_size != 0)
                ret = x509_crl_validate((uint8_t *)(uintptr_t)crl_cert, crl_cert_size,
                                        (uint8_t *)tmp_pubkey_buff, ca_key_size);
        }
    }
    if (ret <= 0) {
        tloge("Failed to validate certificate, errno: %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    int32_t crl_issuer_len = get_issuer_from_crl(crl_issuer, sizeof(crl_issuer), crl_cert, crl_cert_size);
    if (crl_issuer_len < 0) {
        tloge("Failed to get issuer from crl file\n");
        return TEE_ERROR_GENERIC;
    }

    cert_list_entry_t *crl_cert_entry = TEE_Malloc(sizeof(*crl_cert_entry), 0);
    if (crl_cert_entry == NULL) {
        tloge("Failed to malloc memory, size: 0x%x\n", sizeof(*crl_cert_entry));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = get_revocation_list_from_crl(crl_cert, crl_cert_size, crl_cert_entry);
    if (ret < 0) {
        tloge("Failed to get revocation list from crl\n");
        goto error_exit;
    }

    tee_ret = perm_srv_crl_cert_to_list(crl_cert_entry, crl_issuer, (uint32_t)crl_issuer_len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to update global issuer list\n");
        goto error_exit;
    }

    perm_srv_global_ta_crl_list_print();
    tee_ret = perm_srv_global_ta_crl_list_storing();

error_exit:
    perm_srv_crl_revoked_cert_list_cleanup(crl_cert_entry);
    return tee_ret;
}

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
#include "perm_srv_ta_config.h"
#include <string.h>
#include <securec.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <timer_export.h>
#include <openssl/asn1.h>
#include "target_type.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "perm_srv_ta_crl.h"
#include "permission_config.h"

#define UINT8_TYPE_BITS_LEN 8U
#define ASN1_TLV_TAG_OFFSET 1 /* 1 byte for tag */
#define TLV_LEN_OFFSET      2
#define TLV_VALUE_OFFSET    3 /* 1 byte for tag, 2 bytes for len */
#define TLV_MAX_LEN         (0xffff + TLV_VALUE_OFFSET) /* 3 is offset value */
#define POS_ARRAY_SIZE      5
#define H_L_ERROR_NUM_VAL   (-1)

#define BYTE_COUNT_IN_UUID  16
#define UUID_FORMAT_STRLEN  37

#define POLICY_VER_XML2TLV_PARSE_INDEX 1 /* tool type for parse xml */
#define XML2TLV_PY_VALUE               (1 << POLICY_VER_XML2TLV_PARSE_INDEX) /* python parse xml */
#define XML2TLV_JAR_VALUE              (0 << POLICY_VER_XML2TLV_PARSE_INDEX) /* jar parse xml */
#define XML2TLV_PARSE_BIT_MAP          (1 << POLICY_VER_XML2TLV_PARSE_INDEX)

static dlist_head(g_config_list);
static pthread_mutex_t g_config_list_lock = PTHREAD_MUTEX_INITIALIZER;

#define BITS_OF_BYTE 8
#define DYN_CONFING_TAG "gpd.ta.dynConf"

static uint32_t byte_to_integer(const uint8_t *bytes, size_t len, size_t val_size)
{
    uint32_t res = 0;
    if (bytes == NULL || len < val_size)
        return 0;

    for (size_t i = 0; i < val_size; ++i)
        res = (res << BITS_OF_BYTE) + bytes[i];

    return res;
}

#define ALP_TO_DIGIT_GAP 10
static int8_t asc2hex(char a)
{
    bool is_digital = (a >= '0' && a <= '9');
    bool is_lower_letters = (a >= 'a' && a <= 'f');
    bool is_bigger_letters = (a >= 'A' && a <= 'F');

    if (is_digital)
        return a - '0';
    else if (is_lower_letters)
        return (a - 'a') + ALP_TO_DIGIT_GAP;
    else if (is_bigger_letters)
        return (a - 'A') + ALP_TO_DIGIT_GAP;

    return PERMSRV_ERROR;
}

#define CHAR_COUNT_PER_BYTE 2
#define HALF_BYTE_SIZE      4U
static int32_t get_byte_value_from_buff(const char *buff, uint32_t len, uint8_t *res)
{
    bool check = ((buff == NULL) || (len < CHAR_COUNT_PER_BYTE));
    if (check) {
        tloge("invalid parameter\n");
        return PERMSRV_ERROR;
    }

    int8_t h_val = asc2hex(*buff);
    int8_t l_val = asc2hex(*(buff + 1));
    if (((int32_t)h_val == H_L_ERROR_NUM_VAL) || ((int32_t)l_val == H_L_ERROR_NUM_VAL))
        return PERMSRV_ERROR;

    *res = (uint8_t)(((uint8_t)h_val << HALF_BYTE_SIZE) | (uint8_t)l_val);
    return 0;
}

static int32_t perm_srv_convert_str_to_uuid(const char *buff, uint32_t len, TEE_UUID *uuid)
{
    const char *p = buff;
    uint8_t add_pos = 0;
    uint8_t tmp_val = 0;
    /* These numbers are marked '-' */
    uint8_t add_pos_array[POS_ARRAY_SIZE] = { 8, 13, 18, 23, 36 };
    uint8_t parsed_buffer[BYTE_COUNT_IN_UUID] = { 0 };
    int32_t i;
    bool is_invalid = (buff == NULL || uuid == NULL);
    if (is_invalid)
        return PERMSRV_ERROR;

    for (i = 0; i < BYTE_COUNT_IN_UUID; i++) {
        if (get_byte_value_from_buff(p, len - (uint32_t)(p - buff), &tmp_val) != 0)
            return PERMSRV_ERROR;
        parsed_buffer[i] = tmp_val;
        p += CHAR_COUNT_PER_BYTE;

        if (add_pos >= POS_ARRAY_SIZE)
            break;

        if ((uint8_t)(p - buff) == add_pos_array[add_pos]) {
            if (*p != '-')
                break;

            p++;
            add_pos++;
        }
    }
    /* not touch the end of buff */
    if (p != (buff + len))
        return PERMSRV_ERROR;

    add_pos = 0;
    uuid->timeLow = byte_to_integer(parsed_buffer, BYTE_COUNT_IN_UUID - add_pos, sizeof(uuid->timeLow));
    add_pos += (uint8_t)sizeof(uuid->timeLow);
    uuid->timeMid = (uint16_t)byte_to_integer(parsed_buffer + add_pos,
        BYTE_COUNT_IN_UUID - add_pos, sizeof(uuid->timeMid));
    add_pos += (uint8_t)sizeof(uuid->timeMid);
    uuid->timeHiAndVersion = (uint16_t)byte_to_integer(parsed_buffer +
        add_pos, BYTE_COUNT_IN_UUID - add_pos, sizeof(uuid->timeHiAndVersion));
    add_pos += (uint8_t)sizeof(uuid->timeHiAndVersion);
    for (i = 0; i < NODE_LEN; i++)
        uuid->clockSeqAndNode[i] = parsed_buffer[i + add_pos];

    return 0;
}

static int32_t parser_callee_ta_uuid(const uint8_t *buff, uint32_t len, TEE_UUID *uuid)
{
    int32_t ret;

    if (len <= (sizeof(uint16_t) + UUID_STR_LEN)) {
        tloge("invalid calleeTA uuid info\n");
        return PERMSRV_ERROR;
    }

    uint16_t value_len = (uint16_t)byte_to_integer(buff, len, sizeof(value_len));
    if (value_len != UUID_STR_LEN) {
        tloge("invalid calleeTA uuid info\n");
        return PERMSRV_ERROR;
    }

    /* can make sure buffer is bigger enough */
    ret = perm_srv_convert_str_to_uuid((const char *)buff + sizeof(value_len), value_len, uuid);
    return ret;
}

/*
 *           inner tlv format
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +----tag----+----len----+-----------value-------------+
 * +  1 byte   +  1 byte   + 1 or 2 byte(depend on len)  +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
static int32_t parse_inner_tag(const uint8_t *tlv, uint32_t tlv_len, uint8_t *total_len)
{
    bool is_invalid = (tlv == NULL || total_len == NULL || tlv_len < TLV_VALUE_OFFSET);
    if (is_invalid)
        return PERMSRV_ERROR;

    if ((int32_t)(*tlv) != V_ASN1_INTEGER)
        return PERMSRV_ERROR;

    uint8_t len = (uint8_t)(*(tlv + ASN1_TLV_TAG_OFFSET));
    if (len == ASN1_TLV_TAG_OFFSET) {
        *total_len = TLV_VALUE_OFFSET;
        return (int32_t)(*(tlv + TLV_LEN_OFFSET));
    } else if (len == TLV_LEN_OFFSET && tlv_len > TLV_VALUE_OFFSET) {
        *total_len = (uint8_t)TLV_LLEN;
        return (((int32_t)(*(tlv + TLV_VALUE_OFFSET))) +
                (((int32_t)((*(tlv + TLV_LEN_OFFSET)) << UINT8_TYPE_BITS_LEN))));
    } else {
        /* tag value is too big >= 65536 */
        return PERMSRV_ERROR;
    }
}

/*
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +--ASN1 INTEGER--+----len----+--[inner tlv][value]---+
 * +-----1 byte-----+---2 byte---+------(4+4)-----------+
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
#define COMMAND_ID_INNER_TLV_LEN 4
#define COMMAND_ID_INFO_LEN      (TLV_VALUE_OFFSET + COMMAND_ID_INNER_TLV_LEN + sizeof(uint32_t))

static int32_t parser_callee_ta_command_id(const uint8_t *buff, uint32_t len, struct callee_ta_info *callee)
{
    uint32_t offset = 0;
    uint32_t index;
    uint8_t inner_tlv_len;
    int32_t tag;
    uint32_t i = 0;

    bool is_invalid = (((len / COMMAND_ID_INFO_LEN) > MAX_CALLEE_COMMAND_COUNT) ||
        ((len % COMMAND_ID_INFO_LEN) != 0));
    if (is_invalid) {
        tloge("invalid command 0x%x\n", len);
        return PERMSRV_ERROR;
    }

    uint32_t *command_id = TEE_Malloc((len / COMMAND_ID_INFO_LEN) * sizeof(uint32_t), 0);
    if (command_id == NULL) {
        tloge("malloc command_id failed\n");
        return PERMSRV_ERROR;
    }

    while (offset < len) {
        tag = parse_inner_tag(buff + offset + TLV_VALUE_OFFSET, len - offset - TLV_VALUE_OFFSET, &inner_tlv_len);
        is_invalid = (tag != TLV_TAG_CALLEETA_COMMAND_ID || inner_tlv_len != COMMAND_ID_INNER_TLV_LEN);
        if (is_invalid) {
            TEE_Free(command_id);
            return PERMSRV_ERROR;
        }

        index = TLV_VALUE_OFFSET + inner_tlv_len;
        if ((offset + index + sizeof(uint32_t)) > len) {
            tloge("invalid callee command ID len\n");
            TEE_Free(command_id);
            return PERMSRV_ERROR;
        }
        *(command_id + i) = byte_to_integer((buff + offset + index),
            len - offset - index, sizeof(offset));

        offset += (uint32_t)COMMAND_ID_INFO_LEN;
        i++;
        if (i >= (len / COMMAND_ID_INFO_LEN) * sizeof(uint32_t))
            break;
    }

    callee->command_num = (len / (uint32_t)COMMAND_ID_INFO_LEN);
    callee->command_id = command_id;
    return PERMSRV_OK;
}

static bool is_duplicate_callee(const struct config_info *config, const struct callee_ta_info *callee_info)
{
    struct callee_ta_info *temp = config->control_info.callee_info;
    int32_t rc;

    while (temp != NULL) {
        rc = TEE_MemCompare(&temp->uuid, &callee_info->uuid, sizeof(callee_info->uuid));
        if (rc == 0)
            return true;

        temp = temp->next;
    }

    return false;
}

static int32_t parser_fill_callee(const uint8_t *buff, uint32_t len, uint32_t value_len, struct config_info *config)
{
    int32_t ret;
    int32_t tag;
    uint32_t index;
    uint8_t inner_tlv_len = 0;

    index = TLV_VALUE_OFFSET;
    if (len < index)
        return PERMSRV_ERROR;

    uint32_t command_len = len - index;
    tag = parse_inner_tag(buff + index, command_len, &inner_tlv_len);
    bool is_invalid = (tag != TLV_TAG_CALLEETA_UUID ||
        value_len <= (uint32_t)(inner_tlv_len + sizeof(uint16_t) + UUID_STR_LEN));
    if (is_invalid) {
        tloge("invalid tag value for calleeTA\n");
        return PERMSRV_ERROR;
    }

    index += inner_tlv_len;

    struct callee_ta_info *callee_info = NULL;
    callee_info = TEE_Malloc(sizeof(*callee_info), 0);
    if (callee_info == NULL) {
        tloge("malloc callee info failed\n");
        return PERMSRV_ERROR;
    }

    command_len = value_len - inner_tlv_len;
    ret = parser_callee_ta_uuid(buff + index, command_len, &callee_info->uuid);
    is_invalid = (ret != PERMSRV_OK) || (is_duplicate_callee(config, callee_info));
    if (is_invalid) {
        tloge("parser callee ta uuid failed\n");
        TEE_Free(callee_info);
        return PERMSRV_ERROR;
    }

    index += (uint32_t)sizeof(uint16_t) + UUID_STR_LEN;

    command_len = value_len - (inner_tlv_len + (uint32_t)sizeof(uint16_t) + UUID_STR_LEN);
    ret = parser_callee_ta_command_id(buff + index, command_len, callee_info);
    if (ret != PERMSRV_OK) {
        tloge("parser callee command id failed\n");
        TEE_Free(callee_info);
        return PERMSRV_ERROR;
    }

    callee_info->next = config->control_info.callee_info;
    config->control_info.callee_info = callee_info;

    return PERMSRV_OK;
}

#define CALLEE_UUID_INNER_TLV_LEN 3
/*
 * ++++++++++++++++++++++++++++++++  calleeTA info  ++++++++++++++++++++++++++++++++++
 * +--ASN1 tag--+----len----+--[inner tlv]  [[value_len][value]]  [child elements]---+
 * +---1 byte---+--2 byte---+--------------------depend on len-----------------------+
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 *
 * +++++++++++ [[value_len][value]]  [child elements]++++++++++++
 * +--value_len--+----value----+-------[child elements]---------+
 * +---2 byte---+----x bytes----+----------x bytes--------------+
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
static int32_t parser_callee_info(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    int32_t tag_type;
    uint32_t value_len;
    int32_t ret;
    uint32_t offset = 0;
    uint32_t i = 0;

    while (offset < len) {
        bool is_invalid = ((i > MAX_CALLEE_TA_COUNT) ||
            ((len - offset) < (TLV_VALUE_OFFSET + CALLEE_UUID_INNER_TLV_LEN)));
        if (is_invalid) {
            tloge("invalid len for calleeTA info\n");
            return PERMSRV_ERROR;
        }

        tag_type = *(buff + offset);
        if (tag_type != V_ASN1_SEQUENCE)
            return PERMSRV_ERROR;

        value_len = byte_to_integer(buff + offset + ASN1_TLV_TAG_OFFSET,
            len - offset - ASN1_TLV_TAG_OFFSET, sizeof(uint16_t));
        if (value_len > (len - TLV_VALUE_OFFSET)) {
            tloge("invalid value len for single calleeTA info\n");
            return PERMSRV_ERROR;
        }

        ret = parser_fill_callee(buff + offset, len - offset, value_len, config);
        if (ret != PERMSRV_OK)
            return PERMSRV_ERROR;

        i++;
        if ((UINT32_MAX - offset) <= (TLV_VALUE_OFFSET + value_len)) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        offset += (TLV_VALUE_OFFSET + value_len);
    }

    return PERMSRV_OK;
}

/*
 * ++++++++++++++++++++++++++++++++++++++++++++++++++
 * +--ASN1 tag--+----len----+--[inner tlv][value]---+
 * +---1 byte---+--2 byte---+------depend on len----+
 * ++++++++++++++++++++++++++++++++++++++++++++++++++
 */
static int32_t config_tlv_check_node(const uint8_t *buff, uint32_t len,
    uint32_t *offset, int32_t *tag, uint16_t *value_len)
{
    uint8_t inner_tlv_len = 0;

    if (len < TLV_VALUE_OFFSET) {
        tloge("invalid buff len\n");
        return PERMSRV_ERROR;
    }

    *tag = parse_inner_tag(buff + TLV_VALUE_OFFSET, len - TLV_VALUE_OFFSET, &inner_tlv_len);
    if (*tag < 0) {
        tloge("invalid tag value\n");
        return PERMSRV_ERROR;
    }

    *offset = TLV_VALUE_OFFSET + (uint32_t)inner_tlv_len;

    uint16_t tlv_value_len = (uint16_t)byte_to_integer(buff + ASN1_TLV_TAG_OFFSET,
        len - ASN1_TLV_TAG_OFFSET, sizeof(tlv_value_len));
    if (tlv_value_len <= inner_tlv_len) {
        tloge("tlv value len 0x%x\n", tlv_value_len);
        return PERMSRV_ERROR;
    }

    *value_len = tlv_value_len - (uint16_t)inner_tlv_len;
    if ((uint32_t)(*value_len) >= len) {
        tloge("invalid value len\n");
        return PERMSRV_ERROR;
    }

    if ((len - (uint32_t)(*value_len)) < (uint32_t)(*offset)) {
        tloge("invalid value len\n");
        return PERMSRV_ERROR;
    }

    return PERMSRV_OK;
}

static int32_t get_tag_uuid(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    int32_t ret;

    if (len != UUID_STR_LEN) {
        tloge("config tlv parser invalid uuid\n");
        return PERMSRV_ERROR;
    }

    /* make sure buffer is big enough */
    ret = perm_srv_convert_str_to_uuid((const char *)buff, len, &(config->uuid));
    if (ret != PERMSRV_OK) {
        tloge("invalid uuid\n");
        return PERMSRV_ERROR;
    }

    return PERMSRV_OK;
}

static int32_t config_tlv_parser_basic_info(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    int32_t ret;
    int32_t tag = 0;
    uint16_t value_len = 0;
    uint32_t offset = 0;
    uint32_t child_offset = 0;

    while (offset < len) {
        ret = config_tlv_check_node(buff + offset, len - offset, &child_offset, &tag, &value_len);
        if (ret != PERMSRV_OK) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        switch (tag) {
        case TLV_TAG_UUID:
            ret = get_tag_uuid(buff + offset + child_offset, value_len, config);
            break;
        case TLV_TAG_SERVICE_NAME:
            ret = memcpy_s(config->service_name, MAX_SERVICE_NAME_LEN, buff + offset + child_offset, value_len);
            if (ret != EOK)
                return PERMSRV_ERROR;
            config->service_name_len = value_len;
            break;
        default:
            break;
        }
        bool is_invalid = (((UINT32_MAX - offset) <= (child_offset + value_len)) || (ret != PERMSRV_OK));
        if (is_invalid) {
            tloge("invalid tlv data\n");
            config->service_name_len = 0;
            return PERMSRV_ERROR;
        }

        offset += child_offset + value_len;
    }
    return PERMSRV_OK;
}

static void config_tlv_value_to_manifest_info(const uint8_t *buff, uint32_t len, int32_t tag,
                                              struct config_info *config)
{
    switch (tag) {
    case TLV_TAG_SINGLE_INSTANCE:
        config->manifest_info.single_instance = (bool)(*buff);
        break;
    case TLV_TAG_MULTI_SESSION:
        config->manifest_info.multi_session = (bool)(*buff);
        break;
    case TLV_TAG_HEAP_SIZE:
        config->manifest_info.heap_size = byte_to_integer(buff, len, sizeof(len));
        break;
    case TLV_TAG_STACK_SIZE:
        config->manifest_info.stack_size = byte_to_integer(buff, len, sizeof(len));
        break;
    case TLV_TAG_INSTANCE_KEEP_ALIVE:
        config->manifest_info.instance_keep_alive = (bool)(*buff);
        break;
    case TLV_TAG_MEM_PAGE_ALIGN:
        config->manifest_info.mem_page_align = (bool)(*buff);
        break;
    case TLV_TAG_TARGET_TYPE:
        config->manifest_info.target_type = byte_to_integer(buff, len, sizeof(len));
        break;
    default:
        break;
    }
}

static int32_t config_tlv_parser_manifest_info(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    int32_t tag = 0;
    uint32_t offset = 0;
    uint16_t value_len = 0;
    uint32_t child_offset = 0;
    int32_t ret;

    while (offset < len) {
        ret = config_tlv_check_node(buff + offset, len - offset, &child_offset, &tag, &value_len);
        if (ret != PERMSRV_OK) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }
        bool is_invalid = ((tag == TLV_TAG_HEAP_SIZE || tag == TLV_TAG_STACK_SIZE) && (value_len != sizeof(uint32_t)));
        if (is_invalid)
            return PERMSRV_ERROR;

        config_tlv_value_to_manifest_info(buff + offset + child_offset, value_len, tag, config);

        if ((UINT32_MAX - offset) <= (child_offset + value_len)) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        offset += child_offset + value_len;
    }

    return PERMSRV_OK;
}

static int32_t config_tlv_parser_info(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    uint32_t offset = 0;
    uint16_t value_len = 0;
    uint32_t child_offset = 0;
    int32_t ret;
    int32_t tag = 0;

    while (offset < len) {
        ret = config_tlv_check_node(buff + offset, len - offset, &child_offset, &tag, &value_len);
        if (ret != PERMSRV_OK) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        switch (tag) {
        case TLV_TAG_DEBUG_DEVICE_ID:
            check_device_id(config, buff + offset + child_offset, value_len);
            break;
        default:
            break;
        }

        if ((UINT32_MAX - offset) <= (child_offset + value_len)) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        offset += child_offset + value_len;
    }

    return PERMSRV_OK;
}

#define TA_MANAGER_TRUSTONIC 1
static const char g_ta_manager_trustonic[] = "Trustonic";
static void parser_ta_manager(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    if (len == (sizeof(g_ta_manager_trustonic) - 1) && TEE_MemCompare(g_ta_manager_trustonic, buff, len) == 0)
        config->control_info.ta_manager = TA_MANAGER_TRUSTONIC;
}

static int32_t config_tlv_parser_control_info(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    uint32_t offset = 0;
    uint32_t child_offset = 0;
    int32_t ret;
    uint16_t value_len = 0;
    int32_t tag = 0;

    while (offset < len) {
        ret = config_tlv_check_node(buff + offset, len - offset, &child_offset, &tag, &value_len);
        if (ret != PERMSRV_OK) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        switch (tag) {
        case TLV_TAG_SE_INFO:
        case TLV_TAG_DEBUG_INFO:
            ret = config_tlv_parser_info(buff + offset + child_offset, value_len, config);
            break;
        case TLV_TAG_CALLEETA_INFO:
            ret = parser_callee_info(buff + offset + child_offset, value_len, config);
            break;
        case TLV_TAG_TA_MANAGER:
            parser_ta_manager(buff + offset + child_offset, value_len, config);
            break;
        default:
            break;
        }
        bool is_invalid = (ret != PERMSRV_OK || ((UINT32_MAX - offset) <= (child_offset + value_len)));
        if (is_invalid) {
            tloge("parser control info failed\n");
            return PERMSRV_ERROR;
        }

        offset += child_offset + value_len;
    }

    return PERMSRV_OK;
}

static int32_t config_tlv_parser_child_sequences(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    uint32_t offset = 0;
    uint16_t v_len = 0;
    int32_t ret;
    uint32_t child_offset = 0;
    int32_t tag = 0;

    while (offset < len) {
        ret = config_tlv_check_node(buff + offset, len - offset, &child_offset, &tag, &v_len);
        if (ret != PERMSRV_OK) {
            tloge("invalid tlv data\n");
            return PERMSRV_ERROR;
        }

        switch (tag) {
        case TLV_TAG_TA_BASIC_INFO:
            ret = config_tlv_parser_basic_info(buff + offset + child_offset, v_len, config);
            break;
        case TLV_TAG_TA_MANIFEST_INFO:
            ret = config_tlv_parser_manifest_info(buff + offset + child_offset, v_len, config);
            break;
        case TLV_TAG_TA_CONTROL_INFO:
            ret = config_tlv_parser_control_info(buff + offset + child_offset, v_len, config);
            break;
        default:
            break;
        }
        bool is_invalid = (ret != PERMSRV_OK || ((UINT32_MAX - offset) <= (child_offset + v_len)));
        if (is_invalid) {
            tloge("parser control info failed\n");
            return PERMSRV_ERROR;
        }

        offset += child_offset + v_len;
    }

    return PERMSRV_OK;
}

static int32_t parser_jar_tlv_to_config(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    uint32_t offset = 0;
    int32_t tag = 0;
    uint16_t value_len = 0;
    int32_t ret;

    if ((int32_t)(*buff) != V_ASN1_SEQUENCE) {
        tloge("invalid tag value\n");
        return PERMSRV_ERROR;
    }

    ret = config_tlv_check_node(buff, len, &offset, &tag, &value_len);
    if (ret != PERMSRV_OK) {
        tloge("invalid tlv data\n");
        return PERMSRV_ERROR;
    }

    ret = config_tlv_parser_child_sequences(buff + offset, value_len, config);
    return ret;
}

static void release_callee_info(struct callee_ta_info *info)
{
    struct callee_ta_info *temp = info;

    while (temp != NULL) {
        if (temp->command_id != NULL) {
            TEE_Free(temp->command_id);
            temp->command_id = NULL;
        }

        struct callee_ta_info *p = temp;
        temp = temp->next;
        TEE_Free(p);
        p = NULL;
    }

    info = NULL;
}

static TEE_Result check_cn_validation(const uint8_t *cn, size_t cn_size, const struct config_info *info)
{
    uint8_t buff[TA_CERT_MAX_CN_INFO_LEN] = { 0 };
    errno_t ret;

    bool param_invalid =
        (cn_size > TA_CERT_MAX_CN_INFO_LEN ||
         (info->service_name_len > (TA_CERT_MAX_CN_INFO_LEN - (UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE))));

    if (param_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cn_size != (info->service_name_len + UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE)) {
        tloge("invalid cn size: 0x%x\n", cn_size);
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_convert_uuid_to_str(&(info->uuid), (char *)buff, sizeof(buff)) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    buff[UUID_STR_LEN] = '_';
    ret = memcpy_s(&buff[UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE],
                   sizeof(buff) - UUID_STR_LEN - TA_CERT_CN_UNDERLINE_SIZE, info->service_name, info->service_name_len);
    if (ret != EOK)
        return TEE_ERROR_GENERIC;

    if (TEE_MemCompare(buff, cn, cn_size) != 0) {
        tloge("uuid or service name mismatch in TA cert and configs\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static void ta_clear_list(const struct dlist_node *task_config_list)
{
    struct dlist_node *pos = NULL;
    struct dlist_node *tmp = NULL;
    struct task_config *task_entry = NULL;

    dlist_for_each_safe(pos, tmp, task_config_list) {
        task_entry = dlist_entry(pos, struct task_config, head);
        dlist_delete(&task_entry->head);
        TEE_Free(task_entry);
        task_entry = NULL;
    }
}

static uint32_t check_contain_dynconf(const struct perm_config *perm_config)
{
    const char *dynconf_tag = DYN_CONFING_TAG;
    for (uint32_t i = 0; i < perm_config->tlv_len - strlen(dynconf_tag); i++) {
        for (uint32_t j = 0; j < strlen(dynconf_tag); j++) {
            if (*(perm_config->tlv_buf + i + j) != *(dynconf_tag + j))
                break;
            if (j == strlen(dynconf_tag) - 1)
                return perm_config->tlv_len - i;
        }
    }

    return 0;
}

static TEE_Result parse_dyntlv_buf(const TEE_UUID *uuid, const struct perm_config *perm_config,
                                 const struct config_info *config, uint32_t dynconf_len)
{
    if (dynconf_len != 0) {
        if (TEE_MemCompare(uuid, &(config->uuid), sizeof(*uuid)) == 0) {
            dynconf_len += 1;
            TEE_Result res = tee_secure_img_parse_manifest_v3(perm_config->tlv_buf + perm_config->tlv_len,
                &dynconf_len, false, config->manifest_info.target_type);
            if (res != TEE_SUCCESS)
                return TEE_ERROR_GENERIC;
        } else {
            tloge("different uuid from config and manifest_info\n");
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

static int32_t parser_python_tlv_to_ta_config(const uint8_t *buff, uint32_t len, struct config_info *config)
{
    struct dyn_conf_t dyn_conf;
    dyn_conf.dyn_conf_buffer = (char *)(uintptr_t)buff;
    dyn_conf.dyn_conf_size = len;
    return register_conf(&dyn_conf, install_ta_config, config, sizeof(*config));
}

static int32_t parse_tlv_to_ta_config(const struct perm_config *perm_config, struct config_info *config)
{
    int32_t ret;
    if ((perm_config->policy_version & XML2TLV_PARSE_BIT_MAP) == XML2TLV_JAR_VALUE)
        ret = parser_jar_tlv_to_config(perm_config->tlv_buf, perm_config->tlv_len, config);
    else if ((perm_config->policy_version & XML2TLV_PARSE_BIT_MAP) == XML2TLV_PY_VALUE)
        ret = parser_python_tlv_to_ta_config(perm_config->tlv_buf, perm_config->tlv_len, config);
    else
        ret = (int32_t)TEE_ERROR_BAD_PARAMETERS;
    if (ret != PERMSRV_OK)
        tloge("parse failed for tlv type:%u, 0-jar, 2-python\n", perm_config->policy_version & XML2TLV_PARSE_BIT_MAP);
    return ret;
}

static bool parse_config_body_check(const TEE_UUID *uuid, const struct perm_config *perm_config)
{
    bool param_invalid = (uuid == NULL || perm_config == NULL || perm_config->tlv_buf == NULL ||
        perm_config->tlv_len == 0 || perm_config->policy_version == 0 || perm_config->cn_size == 0 ||
        perm_config->tlv_len > TLV_MAX_LEN || perm_config->tlv_len < strlen(DYN_CONFING_TAG));

    return param_invalid;
}

static struct config_info *get_config_entry(const TEE_UUID *uuid)
{
    struct config_info *entry = NULL;
    struct dlist_node *pos = NULL;

    dlist_for_each_prev(pos, &g_config_list) {
        entry = dlist_entry(pos, struct config_info, head);
        if (TEE_MemCompare(uuid, &(entry->uuid), sizeof(entry->uuid)) == 0)
            return entry;
    }

    tlogd("cannot find entry uuid\n");
    return NULL;
}

static TEE_Result perm_srv_update_config_by_same_uuid(struct config_info *new_config)
{
    struct config_info *old_config = NULL;

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get config list lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    old_config = get_config_entry(&new_config->uuid);
    /*
     * remove previous one with same uuid if it exists, and retain old task_list
     * then insert the new one to list
     */
    if (old_config != NULL) {
        dlist_delete(&old_config->head);
        release_callee_info(old_config->control_info.callee_info);
        dlist_replace(&old_config->task_config_list, &new_config->task_config_list);
        TEE_Free(old_config);
    } else {
        dlist_init(&new_config->task_config_list);
    }

    dlist_insert_tail(&new_config->head, &g_config_list);

    (void)pthread_mutex_unlock(&g_config_list_lock);
    return TEE_SUCCESS;
}

TEE_Result perm_srv_parse_config_body(const TEE_UUID *uuid, struct perm_config *perm_config)
{
    struct config_info *config = NULL;
    TEE_Result ret;
    int32_t res;
    
    if (parse_config_body_check(uuid, perm_config)) {
        tloge("parse_config_body_check fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t dynconf_len = check_contain_dynconf(perm_config);
    perm_config->tlv_len = perm_config->tlv_len - dynconf_len;

    config = TEE_Malloc(sizeof(*config), 0);
    if (config == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = parse_tlv_to_ta_config(perm_config, config);
    if (res != PERMSRV_OK) {
        ret = TEE_ERROR_GENERIC;
        goto error;
    }

    if (perm_config->cert_type == TA_RELEASE_CERT) {
        ret = check_cn_validation(perm_config->cn, perm_config->cn_size, config);
        if (ret != TEE_SUCCESS)
            goto error;
        config->control_info.debug_info.valid_device = true;
    }

    config->version = perm_config->policy_version;

    ret = parse_dyntlv_buf(uuid, perm_config, config, dynconf_len);
    if (ret != TEE_SUCCESS)
        goto error;

    ret = perm_srv_update_config_by_same_uuid(config);
    if (ret != TEE_SUCCESS)
        goto error;

    return TEE_SUCCESS;
error:
    release_callee_info(config->control_info.callee_info);
    TEE_Free(config);
    return ret;
}

TEE_Result perm_srv_convert_uuid_to_str(const TEE_UUID *uuid, char *buff, uint32_t len)
{
    bool check = ((uuid == NULL) || (len < UUID_FORMAT_STRLEN) || (buff == NULL));
    if (check) {
        tloge("invalid parameter\n");
        return TEE_ERROR_GENERIC;
    }

    int ret = snprintf_s(buff, len, len - 1, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion, uuid->clockSeqAndNode[0],
                         uuid->clockSeqAndNode[1], uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
                         uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5], uuid->clockSeqAndNode[6],
                         uuid->clockSeqAndNode[7]); /* refer uuid format definitions */
    if (ret <= 0) {
        tloge("convert uuid to string failed %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result perm_srv_get_config_by_uuid(const TEE_UUID *uuid, struct config_info *config)
{
    struct config_info *entry = NULL;
    struct dlist_node *pos = NULL;

    bool is_invalid = (uuid == NULL || config == NULL);
    if (is_invalid) {
        tloge("get config by uuid bad parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get config list lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_config_list) {
        entry = dlist_entry(pos, struct config_info, head);
        if (TEE_MemCompare(uuid, &(entry->uuid), sizeof(*uuid)) == 0) {
            if (memcpy_s(config, sizeof(*config), entry, sizeof(*entry)) != EOK) {
                tloge("memcpy operation failed for config info\n");
                (void)pthread_mutex_unlock(&g_config_list_lock);
                return TEE_ERROR_GENERIC;
            }
            (void)pthread_mutex_unlock(&g_config_list_lock);
            return TEE_SUCCESS;
        }
    }

    (void)pthread_mutex_unlock(&g_config_list_lock);
    tlogd("cannot find target uuid\n");
    return TEE_ERROR_GENERIC;
}

TEE_Result perm_srv_get_config_by_taskid(uint32_t taskid, struct config_info *config)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    struct config_info *config_entry = NULL;
    struct task_config *task_entry = NULL;
    struct dlist_node *config_pos = NULL;
    struct dlist_node *task_pos = NULL;

    if (config == NULL) {
        tloge("get config by taskid bad parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get config list lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(config_pos, &g_config_list) {
        config_entry = dlist_entry(config_pos, struct config_info, head);
        dlist_for_each(task_pos, &config_entry->task_config_list) {
            task_entry = dlist_entry(task_pos, struct task_config, head);
            if (taskid != task_entry->taskid)
                continue;
            if (memcpy_s(config, sizeof(*config), config_entry, sizeof(*config_entry)) != EOK) {
                tloge("memcpy operation failed for config info\n");
                ret = TEE_ERROR_GENERIC;
            } else {
                ret = TEE_SUCCESS;
            }
            (void)pthread_mutex_unlock(&g_config_list_lock);
            return ret;
        }
    }

    (void)pthread_mutex_unlock(&g_config_list_lock);
    tlogd("cannot find target taskid\n");
    return ret;
}

static TEE_Result get_register_config_entry(struct config_info **entry, const TEE_UUID *tmp_uuid,
                                            bool *new_config_entry)
{
    tlogd("register ta not find ta\n");
    *entry = get_config_entry(tmp_uuid);
    if (*entry == NULL) {
        *entry = TEE_Malloc(sizeof(**entry), 0);
        if (*entry == NULL) {
            tloge("register ta malloc memory failed for config\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
        (void)memcpy_s(&(*entry)->uuid, sizeof(TEE_UUID), tmp_uuid, sizeof(TEE_UUID));
        (*entry)->version = 0;
        dlist_init(&(*entry)->task_config_list);

        *new_config_entry = true;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta_add_list(struct config_info *config_entry, struct task_config *tmp_task)
{
    dlist_insert_tail(&tmp_task->head, &config_entry->task_config_list);

    return TEE_SUCCESS;
}

TEE_Result perm_srv_register_ta_taskid(const TEE_UUID *uuid, uint32_t taskid, uint32_t userid)
{
    struct config_info *config_entry = NULL;
    struct task_config *tmp_task = NULL;
    bool new_config_entry = false;
    TEE_Result ret;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get config list lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    ret = get_register_config_entry(&config_entry, uuid, &new_config_entry);
    if (ret != TEE_SUCCESS) {
        (void)pthread_mutex_unlock(&g_config_list_lock);
        return ret;
    }

    if (new_config_entry)
        dlist_insert_tail(&config_entry->head, &g_config_list);

    tmp_task = TEE_Malloc(sizeof(*tmp_task), 0);
    if (tmp_task == NULL) {
        tloge("register ta malloc memory failed for task\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clean_entry;
    }

    tmp_task->taskid = taskid;
    tmp_task->userid = userid;

    ret = ta_add_list(config_entry, tmp_task);
    if (ret != TEE_SUCCESS)
        goto clean_entry;

    (void)pthread_mutex_unlock(&g_config_list_lock);
    return ret;

clean_entry:
    TEE_Free(tmp_task);
    (void)pthread_mutex_unlock(&g_config_list_lock);
    return ret;
}

TEE_Result perm_srv_unregister_ta_taskid(const TEE_UUID *uuid, uint32_t taskid)
{
    struct config_info *config_entry = NULL;
    struct task_config *task_entry = NULL;
    struct dlist_node *task_pos = NULL;
    struct dlist_node *tmp = NULL;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get task list lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    config_entry = get_config_entry(uuid);
    if (config_entry == NULL) {
        tloge("cannot find entry uuid\n");
        (void)pthread_mutex_unlock(&g_config_list_lock);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    dlist_for_each_safe(task_pos, tmp, &config_entry->task_config_list) {
        task_entry = dlist_entry(task_pos, struct task_config, head);
        if (task_entry->taskid == taskid) {
            dlist_delete(&task_entry->head);
            TEE_Free(task_entry);
            task_entry = NULL;
            (void)pthread_mutex_unlock(&g_config_list_lock);
            return TEE_SUCCESS;
        }
    }

    tloge("cannot find entry taskid is 0x%x\n", taskid);
    (void)pthread_mutex_unlock(&g_config_list_lock);
    return TEE_ERROR_ITEM_NOT_FOUND;
}

void perm_srv_clear_ta_permissions(const TEE_UUID *uuid)
{
    if (uuid == NULL)
        return;

    struct dlist_node *pos = NULL;
    struct dlist_node *tmp = NULL;
    struct config_info *config_entry = NULL;

    if (pthread_mutex_lock(&g_config_list_lock) != 0) {
        tloge("Failed to get config list lock\n");
        return;
    }

    dlist_for_each_safe(pos, tmp, &g_config_list) {
        config_entry = dlist_entry(pos, struct config_info, head);
        if (TEE_MemCompare(&config_entry->uuid, uuid, sizeof(*uuid)) == 0) {
            dlist_delete(&config_entry->head);
            ta_clear_list(&config_entry->task_config_list);
            release_callee_info(config_entry->control_info.callee_info);
            TEE_Free(config_entry);
            config_entry = NULL;
            break;
        }
    }

    (void)pthread_mutex_unlock(&g_config_list_lock);
}

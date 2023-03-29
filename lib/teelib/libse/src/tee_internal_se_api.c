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
#include "tee_internal_se_api.h"
#include <dlist.h>
#include <securec.h>

#include "tee_log.h"
#include "tee_crypto_api.h"
#include "tee_object_api.h"
#include "sesrv_api.h"
#include "se_service.h"

struct __TEE_SEServiceHandle {
    int *se_mutex;
};

struct __TEE_SEReaderHandle {
    unsigned int id;
    TEE_SEReaderProperties property;
    bool basic_channel_locked;
    unsigned short session_count;
    unsigned short atr_len;
    uint8_t atr[ATR_LEN_MAX];
    const char *name;
    struct dlist_node session_head;
    uint8_t logic_channel_bm[(SE_LOGIC_CHANNEL_MAX + BYTE_LEN - 1) / BYTE_LEN];
    int *se_channel_mutex;
};

struct __TEE_SESessionHandle {
    int8_t state; // 0 - closed, 1 - open, -1 - invalid
    unsigned char channel_count;
    short reserved;
    TEE_SEReaderHandle reader;
    struct dlist_node list;
    struct dlist_node channel_head;
};

struct __TEE_SEChannelHandle {
    TEE_SEAID se_aid;
    bool basic_channel;
    unsigned char logic_channel;
    unsigned short resp_len;
    uint8_t *resp_buffer;
    TEE_SESessionHandle session;
    struct dlist_node list;
    bool is_secure;
};

struct tee_mac_params {
    uint8_t *mcv;
    uint32_t mcv_len;
    uint8_t *apdu_buf;
    uint32_t apdu_buf_len;
};

struct se_reader_select {
    bool is_inse;
    bool is_ese;
    bool is_sec_flash;
    bool is_msp;
    bool is_lese;
    bool is_hese;
    bool is_invalid;
};

static struct __TEE_SEServiceHandle g_se_service;
static struct __TEE_SEReaderHandle g_se_reader[SCARD_MODE_MAX] = { { .name = "sSE_spi_0" },
                                                                   { .name = "eSE_spi_0" },
                                                                   { .name = "SecureFlash" },
                                                                   { .name = "msp" },
                                                                   { .name = "normal_ese" },
                                                                   { .name = "high_ese" } };

static bool g_is_se_inited = false;
static struct scp_gp_challenge g_scp_challenge;
uint8_t g_mac_chaining[SCP_CMAC_TOTAL_LENGTH];
static struct tee_scp03_state_t g_tee_scp03_state;
static pthread_mutex_t g_service_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_se_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static int mutex_lock_service(pthread_mutex_t *mutex)
{
    int ret;

    if (mutex == NULL)
        return SE_ERROR;

    ret = pthread_mutex_trylock(mutex);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mutex);

    return ret;
}

static int reset_reader(uint32_t id)
{
    if (id >= SCARD_MODE_MAX)
        return SE_ERROR;
    g_se_reader[id].atr_len = 0;
    (void)memset_s(g_se_reader[id].atr, sizeof(g_se_reader[id].atr), 0, sizeof(g_se_reader[id].atr));

    return SE_SUCCESS;
}

static bool is_session_valid(const TEE_SESessionHandle se_session_handle)
{
    uint32_t i;
    TEE_SESessionHandle pos = NULL;

    if (se_session_handle == NULL) {
        tloge("session is NULL\n");
        return false;
    }

    for (i = 0; i < sizeof(g_se_reader) / sizeof(g_se_reader[0]); i++) {
        dlist_for_each_entry(pos, &g_se_reader[i].session_head, struct __TEE_SESessionHandle, list) {
            if (pos != se_session_handle)
                continue;
            if (se_session_handle->reader == NULL) {
                tloge("session's reader is NULL\n");
                return false;
            }
            return true;
        }
    }

    tloge("se session handle is not in list\n");
    return false;
}

static bool is_channel_valid(const TEE_SEChannelHandle se_channel_handle)
{
    TEE_SEChannelHandle pos = NULL;

    if (se_channel_handle == NULL) {
        tloge("channel is NULL\n");
        return false;
    }

    if (!is_session_valid(se_channel_handle->session) || (se_channel_handle->session->state != SESSION_STATE_OPEN)) {
        tloge("se channel handle's session is invalid\n");
        return false;
    }

    dlist_for_each_entry(pos, &se_channel_handle->session->channel_head, struct __TEE_SEChannelHandle, list) {
        if (pos == se_channel_handle)
            return true;
    }

    tloge("se channel handle is not in list\n");
    return false;
}

static TEE_SEChannelHandle malloc_channel(TEE_SESessionHandle se_session_handle, const TEE_SEAID *se_aid)
{
    TEE_SEChannelHandle channel = NULL;

    if (se_aid->bufferLen > AID_LEN_MAX)
        return NULL;
    channel = TEE_Malloc(sizeof(*channel), 0);
    if (channel == NULL)
        return NULL;

    if (se_aid->bufferLen != 0) {
        channel->se_aid.buffer = TEE_Malloc(se_aid->bufferLen, 0);
        if (channel->se_aid.buffer == NULL) {
            TEE_Free(channel);
            return NULL;
        }

        (void)memcpy_s(channel->se_aid.buffer, se_aid->bufferLen, se_aid->buffer, se_aid->bufferLen);
    }

    channel->se_aid.bufferLen = se_aid->bufferLen;
    channel->session          = se_session_handle;

    dlist_insert_tail((struct dlist_node *)&channel->list, (struct dlist_node *)&se_session_handle->channel_head);
    se_session_handle->channel_count++;

    return channel;
}

static void free_channel(TEE_SEChannelHandle channel)
{
    bool is_channel_exist = false;

    if (channel == NULL)
        return;

    is_channel_exist = ((channel->basic_channel) && (channel->session != NULL) && (channel->session->reader != NULL));
    if (is_channel_exist)
        channel->session->reader->basic_channel_locked = false;
    if (channel->session != NULL)
        channel->session->channel_count--;
    dlist_delete(&(channel->list));
    if (channel->se_aid.buffer != NULL) {
        TEE_Free(channel->se_aid.buffer);
        channel->se_aid.buffer = NULL;
    }
    if (channel->resp_buffer != NULL) {
        TEE_Free(channel->resp_buffer);
        channel->resp_buffer = NULL;
    }
    TEE_Free(channel);
}

static TEE_Result get_apdu_res(TEE_SEChannelHandle channel, const uint8_t *resp_buffer, uint32_t resp_len)
{
    uint8_t *new_buffer = NULL;

    if (channel->resp_buffer != NULL) {
        TEE_Free(channel->resp_buffer);
        channel->resp_buffer = NULL;
    }
    channel->resp_len = 0;

    if (resp_len > APDU_SELECT_RESP_LEN || resp_len < SW_GP_LEN)
        return TEE_ERROR_BAD_PARAMETERS;
    new_buffer = TEE_Malloc(resp_len, 0);
    if (new_buffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    (void)memcpy_s(new_buffer, resp_len, resp_buffer, resp_len);

    channel->resp_buffer = new_buffer;
    channel->resp_len    = (unsigned short)resp_len;

    return TEE_SUCCESS;
}

static bool is_success_response(const uint8_t *resp, uint32_t len)
{
    /* sw len is 2 */
    if (len < SW_GP_LEN || len > DATA_DERIVATION_L_128BIT) {
        tloge("response length is invalid %u\n", len);
        return false;
    }
    if ((resp[len - SW_GP_LEN] == SW1_GP_SUCCESS) && (resp[len - SW2_GP_LEN] == SW2_GP_SUCCESS))
        return true;

    tloge("resp[len-2] = 0x%x, resp[len-1]=0x%x\n", resp[len - SW_GP_LEN], resp[len - SW2_GP_LEN]);
    return false;
}

static TEE_Result open_basic_channel(const TEE_SEAID *se_aid, TEE_SEChannelHandle channel,
                                     uint8_t *p_rsp, uint32_t *rsp_len)
{
    TEE_Result ret;
    struct se_transmit_info_t transmit_info = { 0 };

    transmit_info.reader_id = channel->session->reader->id;
    transmit_info.data = se_aid->buffer;
    transmit_info.data_len = se_aid->bufferLen;
    transmit_info.p_rsp = p_rsp;
    transmit_info.rsp_len = *rsp_len;
    ret = tee_se_srv_open_basic_channel(&transmit_info);
    if (ret == TEE_SUCCESS)
        *rsp_len = transmit_info.rsp_len;

    return ret;
}

static TEE_Result open_logical_channel(const TEE_SEAID *se_aid, TEE_SEChannelHandle channel,
                                       uint8_t *p_rsp, uint32_t *rsp_len)
{
    TEE_Result ret;
    struct se_transmit_info_t transmit_info = { 0 };

    transmit_info.reader_id = channel->session->reader->id;
    transmit_info.data = se_aid->buffer;
    transmit_info.data_len = se_aid->bufferLen;
    transmit_info.p_rsp = p_rsp;
    transmit_info.rsp_len = *rsp_len;
    ret = tee_se_srv_open_logical_channel(&transmit_info);
    if (ret == TEE_SUCCESS) {
        *rsp_len = transmit_info.rsp_len;
        channel->logic_channel = transmit_info.channel_id;
    }

    return ret;
}

static void scp_release_key(TEE_ObjectHandle key_object)
{
    TEE_FreeTransientObject(key_object);
}

static TEE_ObjectHandle scp_import_key(uint8_t *import_key, uint32_t keysize, uint32_t max_key_size)
{
    TEE_Attribute pattrib = { 0 };
    TEE_Result ret;
    TEE_ObjectHandle gen_key = NULL;

    if (import_key == NULL)
        return NULL;

    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, max_key_size, &gen_key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute allocate transient object:0x%x\n", ret);
        return NULL;
    }
    TEE_InitRefAttribute(&pattrib, TEE_ATTR_SECRET_VALUE, import_key, keysize);

    ret = TEE_PopulateTransientObject(gen_key, &pattrib, ATTRIBUTE_COUNT);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute populate transient object:0x%x\n", ret);
        TEE_FreeTransientObject(gen_key);
        return NULL;
    }
    return gen_key;
}

static TEE_Result tee_scp_crypto_aes(struct tee_scp03_cipher_params *cipher_data, const uint8_t *data,
                                     uint32_t data_len, uint8_t *data_out, uint32_t data_out_len)
{
    TEE_ObjectHandle key_object    = NULL;
    TEE_OperationHandle crypto_ops = NULL;
    TEE_Result ret;
    size_t data_out_len_temp = (size_t)data_out_len;
    bool params = ((data == NULL) || (data_out == NULL));
    if (params) {
        tloge("Err invalid input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_object = scp_import_key(cipher_data->key, sizeof(cipher_data->key), MAX_KEY_SIZE);
    if (key_object == NULL) {
        tloge("Err input KEY\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Call init aes function */
    ret = TEE_AllocateOperation(&crypto_ops, cipher_data->algorithm, cipher_data->operation_mode, MAX_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation\n");
        goto tee_scp_crypto_aes_error;
    }

    ret = TEE_SetOperationKey(crypto_ops, key_object);
    if (ret != TEE_SUCCESS) {
        tloge("set OperationKey\n");
        goto tee_scp_crypto_aes_error_free;
    }

    /* iv can be null */
    TEE_CipherInit(crypto_ops, cipher_data->iv, cipher_data->iv_len);
    ret = TEE_CipherDoFinal(crypto_ops, data, data_len, data_out, &data_out_len_temp);
    if (ret != TEE_SUCCESS) {
        tloge("cipher do final\n");
        goto tee_scp_crypto_aes_error_free;
    }
    ret = TEE_SUCCESS;
tee_scp_crypto_aes_error_free:
    TEE_FreeOperation(crypto_ops);
tee_scp_crypto_aes_error:
    scp_release_key(key_object);
    return ret;
}

static void set_default_icv_counter(void)
{
    errno_t ret;
    uint8_t command_counter[SCP_KEY_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    ret = memcpy_s(g_tee_scp03_state.session.counter, SCP_KEY_SIZE, command_counter, SCP_KEY_SIZE);
    if (ret != EOK)
        tloge("set default icv counter fail\n");
}

static void scp_inc_command_counter(void)
{
    int i = SCP_KEY_SIZE - 1;
    while (i > 0) {
        if (g_tee_scp03_state.session.counter[i] < TEE_SCP03_COMMAND_MAX_LEN) {
            g_tee_scp03_state.session.counter[i]++;
            break;
        } else {
            g_tee_scp03_state.session.counter[i] = 0;
            i--;
        }
    }
}

static TEE_Result tee_scp_cipher_data_init(uint32_t operation_mode, struct tee_scp03_cipher_params *cipher_data)
{
    cipher_data->iv_len         = SCP_KEY_SIZE;
    cipher_data->algorithm      = TEE_ALG_AES_CBC_NOPAD;
    cipher_data->operation_mode = operation_mode;
    cipher_data->iv             = TEE_Malloc(cipher_data->iv_len, 0);
    if (cipher_data->iv == NULL) {
        tloge("buf buffer is null\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    return TEE_SUCCESS;
}
static TEE_Result tee_scp_init_icv_data(uint32_t operation_mode, struct tee_scp03_cipher_params *cipher_data)
{
    cipher_data->iv_len         = 0;
    cipher_data->algorithm      = TEE_ALG_AES_ECB_NOPAD;
    cipher_data->operation_mode = operation_mode;
    cipher_data->iv             = NULL;

    return TEE_SUCCESS;
}

static void tee_scp_cipher_data_free(struct tee_scp03_cipher_params *cipher_data)
{
    TEE_Free(cipher_data->iv);
    cipher_data->iv = NULL;
}

static TEE_Result tee_scp_get_command_icv(uint8_t *icv, uint32_t len)
{
    TEE_Result ret;
    struct session_state_t session = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };
    struct tee_scp03_cipher_params cipher_data = { 0 };

    ret = tee_scp_init_icv_data(TEE_MODE_ENCRYPT, &cipher_data);
    if (ret != TEE_SUCCESS)
        goto clean;

    if (memcpy_s(&session, sizeof(session), &(g_tee_scp03_state.session), sizeof(g_tee_scp03_state.session)) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    if (memcpy_s(cipher_data.key, sizeof(cipher_data.key), session.enc, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    ret = tee_scp_crypto_aes(&cipher_data, session.counter, SCP_KEY_SIZE, icv, len);

clean:
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    (void)memset_s(&session, sizeof(session), 0, sizeof(session));
    return ret;
}

static TEE_Result tee_scp_rmac_cipher_heler(TEE_OperationHandle crypto_ops, uint8_t *cmd, uint16_t cmd_len,
                                            const struct tee_mac_params *mac_params)
{
    TEE_Result ret;
    uint8_t sw[SW_GP_LEN] = { 0 };
    size_t len_mcv        = SCP_MCV_LEN;
    size_t len_data       = (mac_params->apdu_buf_len - SCP_COMMAND_MAC_SIZE - SW_GP_LEN) > 0 ?
                          (mac_params->apdu_buf_len - SCP_COMMAND_MAC_SIZE - SW_GP_LEN) :
                          0;
    size_t len_mac = SCP_CMAC_SIZE;

    if (memcpy_s(sw, SW_GP_LEN, mac_params->apdu_buf + mac_params->apdu_buf_len - SW_GP_LEN, SW_GP_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    TEE_CipherInit(crypto_ops, NULL, 0);

    if (len_mcv > cmd_len) {
        tloge("params is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = TEE_CipherUpdate(crypto_ops, mac_params->mcv, mac_params->mcv_len, cmd, &len_mcv);
    if (ret != TEE_SUCCESS) {
        tloge("cipher update\n");
        return ret;
    }

    if ((len_mcv + len_data) > cmd_len) {
        tloge("params is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_CipherUpdate(crypto_ops, mac_params->apdu_buf, len_data, cmd + len_mcv, &len_data);
    if (ret != TEE_SUCCESS) {
        tloge("cipher update err\n");
        return ret;
    }

    if ((len_mcv + len_data + len_mac) > cmd_len) {
        tloge("params is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = TEE_CipherDoFinal(crypto_ops, sw, SW_GP_LEN, cmd + len_mcv + len_data, &len_mac);
    if (ret != TEE_SUCCESS) {
        tloge("cipher do final\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result tee_scp_rmac_cipher(const struct tee_mac_params *mac_params, uint8_t *srmac, uint32_t srmac_len,
                                      uint8_t *cmd, uint16_t cmd_len)
{
    TEE_ObjectHandle key_object    = NULL;
    TEE_OperationHandle crypto_ops = NULL;
    TEE_Result ret;
    key_object = scp_import_key(srmac, srmac_len, MAX_KEY_SIZE);
    if (key_object == NULL) {
        tloge("Err input KEY\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* Call init aes function */
    ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_AES_CMAC, TEE_MODE_MAC, MAX_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation\n");
        goto tee_scp_rmac_cipher_error;
    }
    ret = TEE_SetOperationKey(crypto_ops, key_object);
    if (ret != TEE_SUCCESS) {
        tloge("set OperationKey\n");
        goto tee_scp_rmac_cipher_error_free;
    }

    ret = tee_scp_rmac_cipher_heler(crypto_ops, cmd, cmd_len, mac_params);
    if (ret != TEE_SUCCESS) {
        tloge("scp rmac cipher failed\n");
        goto tee_scp_rmac_cipher_error_free;
    }

tee_scp_rmac_cipher_error_free:
    TEE_FreeOperation(crypto_ops);
tee_scp_rmac_cipher_error:
    scp_release_key(key_object);
    return ret;
}

static TEE_Result scp_calculate_rmac(uint8_t *srmac, uint32_t srmac_len, struct tee_mac_params *mac_params,
                                     uint8_t *cal_mac, uint32_t cal_mac_len)
{
    uint8_t *cmd = NULL;
    uint16_t cmd_length;
    uint8_t mcv[SCP_CMAC_SIZE] = { 0 };
    TEE_Result ret;
    // mac_params->apdu_buf_len has been checked in caller
    uint32_t len = mac_params->apdu_buf_len - SCP_COMMAND_MAC_SIZE - SW_GP_LEN;

    if (memcpy_s(mcv, SCP_CMAC_SIZE, g_tee_scp03_state.session.mcv, SCP_CMAC_SIZE) != EOK)
        return TEE_ERROR_SECURITY;

    cmd_length = SCP_MCV_LEN + mac_params->apdu_buf_len - SCP_COMMAND_MAC_SIZE - SW_GP_LEN + SCP_CMAC_SIZE;
    cmd_length = (cmd_length / SCP_CMAC_SIZE + 1) * SCP_CMAC_SIZE;
    if (cmd_length > DATA_DERIVATION_L_128BIT)
        return TEE_ERROR_BAD_PARAMETERS;

    cmd = TEE_Malloc(cmd_length, 0);
    if (cmd == NULL) {
        tloge("malloc err\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    mac_params->mcv     = mcv;
    mac_params->mcv_len = SCP_MCV_LEN;
    ret                 = tee_scp_rmac_cipher(mac_params, srmac, srmac_len, cmd, cmd_length);
    if (ret != TEE_SUCCESS) {
        tloge("scp rmac cipher fail\n");
        goto scp_calculate_rmac_error;
    }

    if (memcpy_s(cal_mac, cal_mac_len, cmd + SCP_MCV_LEN + len, SCP_COMMAND_MAC_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto scp_calculate_rmac_error;
    }
    if (memcpy_s(g_tee_scp03_state.session.mcv, SCP_KEY_SIZE, mac_params->mcv, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto scp_calculate_rmac_error;
    }
scp_calculate_rmac_error:
    TEE_Free(cmd);
    return ret;
}

static TEE_Result tee_scp_verify_rmac(uint8_t *srmac, uint32_t srmac_len, uint8_t *response_apdu,
                                      const uint32_t *length)
{
    uint8_t rmac[SCP_CMAC_TOTAL_LENGTH] = { 0 };
    TEE_Result ret;
    struct tee_mac_params mac_params = { 0 };

    if ((response_apdu == NULL) || (srmac == NULL) || (length == NULL)) {
        tloge("response apdu is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    mac_params.apdu_buf     = response_apdu;
    mac_params.apdu_buf_len = *length;
    ret                     = scp_calculate_rmac(srmac, srmac_len, &mac_params, rmac, SCP_CMAC_TOTAL_LENGTH);
    if (ret != TEE_SUCCESS) {
        tloge("crypto AES CMAC failed 0x%x\n", ret);
        (void)memset_s(rmac, sizeof(rmac), 0, sizeof(rmac));
        return ret;
    }

    // length has been checked in caller
    if (memcmp(response_apdu + *length - SCP_COMMAND_MAC_SIZE - SW_GP_LEN, rmac, SCP_COMMAND_MAC_SIZE) == 0)
        ret = TEE_SUCCESS;
    else
        ret = TEE_ERROR_GENERIC;

    (void)memset_s(rmac, sizeof(rmac), 0, sizeof(rmac));
    return ret;
}

static TEE_Result tee_scp_get_reponse_icv(uint8_t *icv, uint32_t len)
{
    TEE_Result ret;
    struct tee_scp03_cipher_params cipher_data = { 0 };
    uint8_t command_counter[SCP_KEY_SIZE]      = { 0 };
    struct session_state_t session = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    if (memcpy_s(&session, sizeof(session), &(g_tee_scp03_state.session), sizeof(g_tee_scp03_state.session)) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    if (memcpy_s(command_counter, SCP_KEY_SIZE, session.counter, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }
    command_counter[0] = SCP_PADDING_HEAD; // Section 6.2.7 of SCP03 spec

    ret = tee_scp_init_icv_data(TEE_MODE_ENCRYPT, &cipher_data);
    if (ret != TEE_SUCCESS)
        goto clean;

    if (memcpy_s(cipher_data.key, sizeof(cipher_data.key), session.enc, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    ret = tee_scp_crypto_aes(&cipher_data, command_counter, SCP_KEY_SIZE, icv, len);
clean:
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    (void)memset_s(&session, sizeof(session), 0, sizeof(session));
    return ret;
}

static TEE_Result tee_restoresw_res_apdu(uint8_t *rsp_buf, uint32_t *rsp_buf_len, uint8_t *plaintext_response,
                                         uint32_t plaintext_resp_len)
{
    uint32_t i             = plaintext_resp_len;
    bool remove_padding_ok = false;
    uint8_t sw[SW_GP_LEN]  = { 0 };

    if (memcpy_s(sw, SW_GP_LEN, rsp_buf + *rsp_buf_len - SW_GP_LEN, SW_GP_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    while ((i > 1) && (i > (plaintext_resp_len - SCP_KEY_SIZE))) {
        if (plaintext_response[i - 1] == SCP_NO_PADDING) {
            i--;
        } else if (plaintext_response[i - 1] == SCP_PADDING_HEAD) {
            // We have found padding delimitor
            if (memcpy_s(plaintext_response + i - 1, plaintext_resp_len - (i - 1), sw, SW_GP_LEN) != EOK)
                return TEE_ERROR_SECURITY;
            if (memcpy_s(rsp_buf, *rsp_buf_len, plaintext_response, i + 1) != EOK)
                return TEE_ERROR_SECURITY;
            *rsp_buf_len      = i + 1;
            remove_padding_ok = true;
            break;
        } else {
            // We've found a non-padding character while removing padding
            // Most likely the cipher text was not properly decoded
            break;
        }
    }
    if (!remove_padding_ok)
        return TEE_ERROR_GENERIC;
    return TEE_SUCCESS;
}

static TEE_Result tee_scp_response_aes(uint8_t *response_apdu, uint32_t *response_length,
                                       const struct session_state_t *session)
{
    uint8_t iv[SCP_KEY_SIZE]                    = { 0 };
    uint8_t plaintetx_response[SCP_BUFFER_SIZE] = { 0 };
    uint8_t res_buffer[SCP_BUFFER_SIZE]         = { 0 };
    uint32_t res_len;
    TEE_Result ret;
    struct tee_scp03_cipher_params cipher_data = { 0 };

    // response_length has been checked in caller
    res_len = *response_length - (SCP_COMMAND_MAC_SIZE + SW_GP_LEN);
    if (res_len > sizeof(plaintetx_response)) {
        tloge("res len is bigger\n");
        return TEE_ERROR_GENERIC;
    }
    ret = tee_scp_get_reponse_icv(iv, SCP_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("scp get response icv fail\n");
        return TEE_ERROR_GENERIC;
    }

    if (memcpy_s(res_buffer, SCP_BUFFER_SIZE, response_apdu, res_len) != EOK)
        return TEE_ERROR_SECURITY;

    ret = tee_scp_cipher_data_init(TEE_MODE_DECRYPT, &cipher_data);
    if (ret != TEE_SUCCESS)
        return ret;

    if (memcpy_s(cipher_data.iv, cipher_data.iv_len, iv, SCP_KEY_SIZE) != EOK) {
        tee_scp_cipher_data_free(&cipher_data);
        return TEE_ERROR_SECURITY;
    }
    if (memcpy_s(cipher_data.key, sizeof(cipher_data.key), session->enc, SCP_KEY_SIZE) != EOK) {
        tee_scp_cipher_data_free(&cipher_data);
        return TEE_ERROR_SECURITY;
    }
    ret = tee_scp_crypto_aes(&cipher_data, res_buffer, res_len, plaintetx_response, SCP_BUFFER_SIZE);
    tee_scp_cipher_data_free(&cipher_data);
    cipher_data.iv = NULL;
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    if (ret != TEE_SUCCESS) {
        tloge("scp crypto aes fail\n");
        return TEE_ERROR_GENERIC;
    }
    ret = tee_restoresw_res_apdu(response_apdu, response_length, plaintetx_response, res_len);
    if (ret != TEE_SUCCESS) {
        tloge("restoresw res apdu fail\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_scp_response_process(uint8_t *response_apdu, uint32_t *response_length)
{
    TEE_Result ret;
    uint8_t sw[SW_GP_LEN]          = { 0 };
    struct session_state_t session = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    if ((response_apdu == NULL) || (response_length == NULL)) {
        tloge("response apdu is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*response_length > (SCP_COMMAND_MAC_SIZE + SW_GP_LEN)) {
        if (memcpy_s(&session, sizeof(session), &(g_tee_scp03_state.session), sizeof(g_tee_scp03_state.session)) != EOK)
            return TEE_ERROR_SECURITY;

        ret = tee_scp_verify_rmac(session.rmac, sizeof(session.rmac), response_apdu, response_length);
        if (ret != TEE_SUCCESS) {
            (void)memset_s(&session, sizeof(session), 0, sizeof(session));
            tloge("scp verify rmac fail\n");
            return TEE_ERROR_GENERIC;
        }
        ret = tee_scp_response_aes(response_apdu, response_length, &session);
        (void)memset_s(&session, sizeof(session), 0, sizeof(session));
        if (ret != TEE_SUCCESS)
            return ret;
        tlogd("plaintetx_response %u\n", *response_length);
    } else if ((*response_length >= SW_GP_LEN) && (*response_length <= (SCP_COMMAND_MAC_SIZE + SW_GP_LEN))) {
        if (memcpy_s(sw, SW_GP_LEN, response_apdu + *response_length - SW_GP_LEN, SW_GP_LEN) != EOK)
            return TEE_ERROR_SECURITY;
        if (memset_s(response_apdu, *response_length, 0, *response_length) != EOK)
            return TEE_ERROR_SECURITY;
        if (memcpy_s(response_apdu, *response_length, sw, SW_GP_LEN) != EOK)
            return TEE_ERROR_SECURITY;
        *response_length = SW_GP_LEN;
    } else {
        // We're receiving a response with an unexpected response length
        tloge("Unexpected Response Length %u\n", *response_length);
    }
    scp_inc_command_counter();
    return TEE_SUCCESS;
}

static uint16_t scp_pad_data(struct apdu_t *apdu)
{
    uint16_t zero_bytes_to_pad = 0;
    uint16_t bytes_to_pad      = 0;
    // pad the payload and adjust the length of the APDU
    // payload present => padding needed
    if (!apdu->has_extended_length) {
        if (apdu->buflen > APDU_CDATA) {
            apdu->command_buf[apdu->buflen++] = SCP_PADDING_HEAD;
            zero_bytes_to_pad = (SCP_KEY_SIZE - ((apdu->buflen - APDU_CDATA) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;
        }
    } else {
        if (apdu->buflen > (APDU_CDATA + SW_GP_LEN)) {
            apdu->command_buf[apdu->buflen++] = SCP_PADDING_HEAD;
            zero_bytes_to_pad =
                (SCP_KEY_SIZE - ((apdu->buflen - (APDU_CDATA + SW_GP_LEN)) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;
        }
    }
    bytes_to_pad += zero_bytes_to_pad;
    while ((zero_bytes_to_pad > 0) && (apdu->buflen < apdu->command_buf_len)) {
        apdu->command_buf[apdu->buflen++] = 0x00;
        zero_bytes_to_pad--;
    }
    apdu->offset = apdu->buflen;
    return (bytes_to_pad + 1);
}

static void set_lc(struct apdu_t *apdu, uint16_t lc)
{
    // apdu->lc_length was set to its proper value in a call to ReserveLc(...)
    if (apdu->has_data) {
        if (apdu->has_extended_length) {
            apdu->command_buf[APDU_LC]          = SCP_PADDING_CONTENT;
            apdu->command_buf[APDU_LCC_PADDING] = (uint8_t)(lc >> SCP_COMMAND_MAC_SIZE);
            apdu->command_buf[APDU_LCC_MAC]     = (uint8_t)(lc & SET_LOW_8BIT);
        } else {
            apdu->command_buf[APDU_LC] = (uint8_t)(lc & SET_LOW_8BIT);
        }
    }
}

static void sm_apdu_adapt_lc(struct apdu_t *apdu, uint16_t lc)
{
    set_lc(apdu, lc);
}

static TEE_Result tee_scp_add_lcc(struct apdu_t *apdu, uint8_t *le, int *payload_offset)
{
    uint16_t lcc;
    uint16_t pad_offset;
    uint32_t buffer_len;

    /*
     * Prior to encrypting the data, the data shall be padded as defined in section 4.1.4.
     * This padding becomes part of the data field.
     */
    lcc        = apdu->command_buf[APDU_LC];
    buffer_len = lcc + APDU_CDATA;
    if (apdu->buflen > buffer_len) {
        *le = apdu->command_buf[apdu->buflen - 1];
        apdu->buflen -= 1;
        pad_offset = scp_pad_data(apdu);
    } else {
        pad_offset = scp_pad_data(apdu);
    }

    if (lcc > UINT16_T_MAX - pad_offset - SCP_COMMAND_MAC_SIZE) {
        tloge("lc is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* The final Lc value (Lcc) is the sum of: initial Lc + length of the padding + length of C-MAC */
    lcc += pad_offset + SCP_COMMAND_MAC_SIZE;

    sm_apdu_adapt_lc(apdu, lcc);

    if (apdu->has_extended_length)
        *payload_offset = APDU_LC + 3; // (3 bytes reserved for LC field)
    else
        *payload_offset = APDU_LC + 1; // (1 byte reserved for LC field)

    return TEE_SUCCESS;
}

static TEE_Result tee_scp_transmit_aes(struct apdu_t *apdu, uint8_t *le)
{
    int payload_offset = 0;
    TEE_Result ret;
    uint8_t iv[SCP_KEY_SIZE]                          = { 0 };
    uint8_t payload_to_encrypt[MAX_CHUNK_LENGTH_LINK] = { 0 };
    struct tee_scp03_cipher_params cipher_data        = { 0 };
    struct session_state_t session = { { 0 }, { 0 }, { 0 }, { 0 }, { 0 } };

    ret = tee_scp_add_lcc(apdu, le, &payload_offset);
    if (ret != TEE_SUCCESS) {
        tloge("bad params\n");
        return ret;
    }
    ret = tee_scp_get_command_icv(iv, SCP_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("scp get command icv fail, ret = 0x%x\n", ret);
        return ret;
    }
    if (memcpy_s(payload_to_encrypt, MAX_CHUNK_LENGTH_LINK, apdu->command_buf + payload_offset,
                 (apdu->buflen - payload_offset)) != EOK)
        return TEE_ERROR_SECURITY;

    // we don't need le lenth for enc, but the TA need transmit the le lengh
    ret = tee_scp_cipher_data_init(TEE_MODE_ENCRYPT, &cipher_data);
    if (ret != TEE_SUCCESS)
        return ret;
    if (memcpy_s(cipher_data.iv, cipher_data.iv_len, iv, SCP_KEY_SIZE) != EOK) {
        tee_scp_cipher_data_free(&cipher_data);
        return TEE_ERROR_SECURITY;
    }
    if (memcpy_s(&session, sizeof(session), &(g_tee_scp03_state.session), sizeof(g_tee_scp03_state.session)) != EOK) {
        tee_scp_cipher_data_free(&cipher_data);
        return TEE_ERROR_SECURITY;
    }
    if (memcpy_s(cipher_data.key, sizeof(cipher_data.key), session.enc, SCP_KEY_SIZE) != EOK) {
        tee_scp_cipher_data_free(&cipher_data);
        (void)memset_s(&session, sizeof(session), 0, sizeof(session));
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(&session, sizeof(session), 0, sizeof(session));
    ret = tee_scp_crypto_aes(&cipher_data, payload_to_encrypt, (apdu->buflen - payload_offset),
                             apdu->command_buf + payload_offset, (apdu->buflen - payload_offset));
    tee_scp_cipher_data_free(&cipher_data);
    cipher_data.iv = NULL;
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    if (ret != TEE_SUCCESS) {
        tloge("scp crypto aes fail, ret = 0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_scp_cipher_helper(TEE_OperationHandle crypto_ops, const struct tee_mac_params *cipher_params,
                                        uint8_t *cmd, uint16_t cmd_length)
{
    TEE_Result ret;
    size_t len_mcv  = SCP_MCV_LEN;
    size_t len_data = cmd_length - SCP_MCV_LEN;

    TEE_CipherInit(crypto_ops, NULL, 0);

    if (len_mcv > cmd_length) {
        tloge("params is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_CipherUpdate(crypto_ops, cipher_params->mcv, cipher_params->mcv_len, cmd, &len_mcv);
    if (ret != TEE_SUCCESS) {
        tloge("cipher update\n");
        return ret;
    }

    if ((len_mcv + len_data) > cmd_length) {
        tloge("params is too long\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        return ret;
    }
    ret = TEE_CipherDoFinal(crypto_ops, cipher_params->apdu_buf, cipher_params->apdu_buf_len, cmd + len_mcv, &len_data);
    if (ret != TEE_SUCCESS) {
        tloge("cipher do final\n");
        return ret;
    }

    return ret;
}

static TEE_Result tee_scp_cipher(const struct tee_mac_params *cipher_params, uint8_t *cmd, uint16_t cmd_length)
{
    uint8_t session_mac_key[SCP_KEY_SIZE] = { 0 };
    TEE_ObjectHandle key_object           = NULL;
    TEE_OperationHandle crypto_ops        = NULL;
    TEE_Result ret;

    if (memcpy_s(session_mac_key, SCP_KEY_SIZE, g_tee_scp03_state.session.mac, SCP_KEY_SIZE) != EOK)
        return TEE_ERROR_SECURITY;

    key_object = scp_import_key(session_mac_key, SCP_KEY_SIZE, MAX_KEY_SIZE);
    if (key_object == NULL) {
        tloge("Err input KEY\n");
        (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* Call init aes function */
    ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_AES_CMAC, TEE_MODE_MAC, MAX_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation\n");
        goto tee_scp_cipher_error;
    }

    ret = TEE_SetOperationKey(crypto_ops, key_object);
    if (ret != TEE_SUCCESS) {
        tloge("set OperationKey\n");
        goto tee_scp_cipher_error_free;
    }

    ret = tee_scp_cipher_helper(crypto_ops, cipher_params, cmd, cmd_length);
    if (ret != TEE_SUCCESS) {
        tloge("scp cipher failed\n");
        goto tee_scp_cipher_error_free;
    }

tee_scp_cipher_error_free:
    TEE_FreeOperation(crypto_ops);
tee_scp_cipher_error:
    scp_release_key(key_object);
    (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
    return ret;
}

static TEE_Result scp_calculate_cmac(uint8_t *apdu_buf, uint32_t apdu_buf_len, uint32_t data_length)
{
    uint8_t *cmd = NULL;
    uint16_t cmd_length = ((data_length + SCP_MCV_LEN) / SCP_KEY_SIZE + 1) * SCP_KEY_SIZE;
    TEE_Result ret;
    uint8_t mcv[SCP_KEY_SIZE]           = { 0 };
    struct tee_mac_params cipher_params = { 0 };

    if (apdu_buf == NULL || cmd_length > DATA_DERIVATION_L_128BIT) {
        tloge("apdubuf pointer is NULL or data length is too large\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cmd = TEE_Malloc(cmd_length, 0);
    if (cmd == NULL) {
        tloge("malloc err\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (memcpy_s(mcv, SCP_KEY_SIZE, g_tee_scp03_state.session.mcv, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto scp_calculate_cmac_error;
    }

    cipher_params.mcv          = mcv;
    cipher_params.mcv_len      = SCP_KEY_SIZE;
    cipher_params.apdu_buf     = apdu_buf;
    cipher_params.apdu_buf_len = data_length;
    ret                        = tee_scp_cipher(&cipher_params, cmd, cmd_length);
    if (ret != TEE_SUCCESS) {
        tloge("cipher fail, ret = 0x%x\n", ret);
        goto scp_calculate_cmac_error;
    }
    apdu_buf[APDU_CLA] = CLA_GP_SEC_CHANNEL1; // Send apdu buf need used 85 one channel

    if ((data_length + SCP_COMMAND_MAC_SIZE) > apdu_buf_len) {
        tloge("data length is too long\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto scp_calculate_cmac_error;
    }
    if (memcpy_s(apdu_buf + data_length, apdu_buf_len - data_length, cmd + SCP_MCV_LEN, SCP_COMMAND_MAC_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto scp_calculate_cmac_error;
    }
    if (memcpy_s(g_tee_scp03_state.session.mcv, SCP_KEY_SIZE, cmd + SCP_MCV_LEN, SCP_KEY_SIZE) != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto scp_calculate_cmac_error;
    }
scp_calculate_cmac_error:
    (void)memset_s(mcv, sizeof(mcv), 0, sizeof(mcv));
    TEE_Free(cmd);
    return ret;
}

static TEE_Result tee_scp_transform_command(struct se_transmit_info_t *transmit_info, struct apdu_t *apdu)
{
    TEE_Result ret;
    uint16_t lcc;
    uint8_t le = SCP_NO_LE;

    tlogd("scp transform command entry\n");
    if (apdu->has_data) {
        ret = tee_scp_transmit_aes(apdu, &le);
        if (ret != TEE_SUCCESS) {
            tloge("scp transmit aes fail\n");
            return ret;
        }
    } else {
        /* C-MAC in the data field of the command message. */
        lcc = SCP_COMMAND_MAC_SIZE;
        // The MAC will become the payload of the APDU. so indicate there is a datapayload
        apdu->has_data             = true;
        apdu->lc_length            = 1;
        le                         = apdu->command_buf[apdu->buflen - 1];
        apdu->command_buf[APDU_LC] = 0;
        sm_apdu_adapt_lc(apdu, lcc);
    }
    ret = scp_calculate_cmac(apdu->command_buf, apdu->command_buf_len, apdu->buflen);
    if (ret != TEE_SUCCESS) {
        tloge("scp calculate cmac fail, ret = 0x%x\n", ret);
        return ret;
    }

    apdu->buflen += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;
    apdu->offset = apdu->buflen;

    if (le != SCP_NO_LE) {
        apdu->buflen += 1;
        apdu->command_buf[apdu->buflen - 1] = le;
    }
    transmit_info->data = apdu->command_buf;
    transmit_info->data_len = apdu->buflen;
    ret = tee_se_srv_transmit(transmit_info);
    if (ret != TEE_SUCCESS) {
        tloge("se transmit fail, ret = 0x%x\n", ret);
        return ret;
    }
    ret = tee_scp_response_process(transmit_info->p_rsp, &(transmit_info->rsp_len));
    if (ret != TEE_SUCCESS) {
        tloge("scp response process fail, ret = 0x%x\n", ret);
        return ret;
    }
    return ret;
}

static TEE_Result tee_scp_transmit(struct se_transmit_info_t *transmit_info)
{
    struct apdu_t apdu = { 0 };
    TEE_Result result;
    uint8_t *cla = transmit_info->data;
    uint32_t command_len = transmit_info->data_len;

    if ((command_len < APDU_CDATA) || (command_len > DATA_DERIVATION_L_128BIT)) {
        tloge("command len is short\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cla[0] |= SET_THIRD_BIT; // identification bit of (un)secure message, 0/1:unsecure/secure
    apdu.buflen          = command_len;
    apdu.command_buf     = TEE_Malloc(DATA_DERIVATION_L_128BIT, 0);
    apdu.command_buf_len = DATA_DERIVATION_L_128BIT;
    if (apdu.command_buf == NULL) {
        tloge("buf buffer is null\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(apdu.command_buf, DATA_DERIVATION_L_128BIT, cla, command_len) != EOK) {
        tloge("SE channel transmit cpy fail\n");
        TEE_Free(apdu.command_buf);
        return TEE_ERROR_SECURITY;
    }

    apdu.has_extended_length = false;
    if (command_len > APDU_CDATA)
        apdu.has_data = true;
    else
        apdu.has_data = false;

    result = tee_scp_transform_command(transmit_info, &apdu);
    TEE_Free(apdu.command_buf);
    return result;
}

static void scp_set_data_derication_arry(struct tee_dda_params *dda_data, const uint8_t *context, uint16_t context_len)
{
    errno_t ret;

    if (dda_data->dda_len < (DD_LABEL_LEN + APDU_LC)) {
        tloge("dda len is too short\n");
        return;
    }
    if (context_len > UINT16_T_MAX - DD_LABEL_LEN - APDU_LC) {
        tloge("context len is too long\n");
        return;
    }
    // SCPO3 spec p9&10
    ret = memset_s(dda_data->dda, sizeof(dda_data->dda), 0, DD_LABEL_LEN - 1);
    if (ret != EOK)
        tloge("derication array cpy error\n");
    dda_data->dda[DDA_CONSTANT_INDEX]     = dda_data->constant;
    dda_data->dda[DDA_SEPARATION_INDEX]   = 0x0;
    dda_data->dda[DDA_DERIVED_DATA_INDEX] = (uint8_t)(dda_data->len >> SCP_COMMAND_MAC_SIZE);
    dda_data->dda[DDA_LEN_INDEX]          = (uint8_t)dda_data->len;
    dda_data->dda[DDA_COUNTER_INDEX]      = dda_data->counter;

    ret = memcpy_s(dda_data->dda + DD_LABEL_LEN + APDU_LC, dda_data->dda_len - DD_LABEL_LEN - APDU_LC, context,
                   context_len);
    if (ret != EOK)
        tloge("derication array cpy error\n");

    dda_data->dda_len = DD_LABEL_LEN + APDU_LC + context_len;
}

static void tee_scp_init_dda(struct tee_dda_params *dda_data)
{
    if (dda_data != NULL)
        (void)memset_s(dda_data, sizeof(*dda_data), 0, sizeof(*dda_data));;
}

static TEE_Result tee_scp_calculate_cryptogram(uint8_t *card_cryptogram, uint32_t card_cryptogram_len, bool is_host)
{
    uint16_t context_len                       = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;
    uint8_t context[DATA_DERIVATION_L_128BIT]  = { 0 };
    uint8_t session_mac_key[SCP_KEY_SIZE]      = { 0 };
    struct tee_scp03_cipher_params cipher_data = { 0 };
    struct tee_dda_params dda_data;
    TEE_Result ret;

    tee_scp_init_dda(&dda_data);
    if (memcpy_s(context, DATA_DERIVATION_L_128BIT, g_scp_challenge.host_challenge, SCP_GP_HOST_CHALLENGE_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    if (memcpy_s(context + SCP_GP_HOST_CHALLENGE_LEN, DATA_DERIVATION_L_128BIT - SCP_GP_HOST_CHALLENGE_LEN,
                 g_scp_challenge.card_challenge, SCP_GP_CARD_CHALLENGE_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    if (memcpy_s(session_mac_key, SCP_KEY_SIZE, g_tee_scp03_state.session.mac, SCP_KEY_SIZE) != EOK)
        return TEE_ERROR_SECURITY;

    if (is_host)
        dda_data.constant = DATA_HOST_CRYPTOGRAM;
    else
        dda_data.constant = DATA_CARD_CRYPTOGRAM;
    dda_data.len      = DATA_DERIVATION_L_64BIT;
    dda_data.counter  = DATA_DERIVATION_KDF_CTR;
    dda_data.dda_len  = DATA_DERIVATION_L_128BIT;
    scp_set_data_derication_arry(&dda_data, context, context_len);

    (void)memset_s(context, sizeof(context), 0, sizeof(context));
    cipher_data.iv_len         = 0;
    cipher_data.iv             = NULL;
    cipher_data.algorithm      = TEE_ALG_AES_CMAC;
    cipher_data.operation_mode = TEE_MODE_MAC;
    if (memcpy_s(cipher_data.key, sizeof(cipher_data.key), session_mac_key, SCP_KEY_SIZE) != EOK) {
        (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
    ret = tee_scp_crypto_aes(&cipher_data, dda_data.dda, dda_data.dda_len, card_cryptogram, card_cryptogram_len);
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    if (ret != TEE_SUCCESS) {
        (void)memset_s(card_cryptogram, card_cryptogram_len, 0, card_cryptogram_len);
        tloge("scp crypto aes cmac fail\n");
        return ret;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : verify the card cryptogram get from security flash (card).
 * @param[in] : NA.
 * @return    : success of failure
 */
static TEE_Result tee_scp_verify_card_cryptogram(void)
{
    uint8_t card_cryptogram[SCP_KEY_SIZE] = { 0 };
    TEE_Result ret;

    ret = tee_scp_calculate_cryptogram(card_cryptogram, SCP_KEY_SIZE, false);
    if (ret != TEE_SUCCESS) {
        tloge("tee scp calculate cryptogram failed\n");
        return ret;
    }
    /* verify */
    if (memcmp(g_scp_challenge.card_cryptogram, card_cryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN) == 0) {
        (void)memset_s(card_cryptogram, sizeof(card_cryptogram), 0, sizeof(card_cryptogram));
        return TEE_SUCCESS;
    }
    (void)memset_s(card_cryptogram, sizeof(card_cryptogram), 0, sizeof(card_cryptogram));
    tloge("scp verify card cryptogram Failed\n");
    return TEE_ERROR_MAC_INVALID;
}

static TEE_Result tee_scp_initialze_update(TEE_SEChannelHandle se_channel_handle)
{
    uint8_t apdu[SCP_INITIALIZE_UPDATE_CMD_LEN]     = { 0 };
    uint8_t response_apdu[DATA_DERIVATION_L_128BIT] = { 0 };
    uint32_t response_length                        = DATA_DERIVATION_L_128BIT;
    TEE_Result ret;
    uint16_t parse_pos;
    struct se_transmit_info_t transmit_info = { 0 };

    /* initialize update cmd */
    apdu[APDU_CLA] = CLA_GP_CHANNEL1; // channel one
    apdu[APDU_INS] = INS_GP_INITIALIZE_UPDATE;
    apdu[APDU_P1]  = P1_GP_INITIALIZE_UPDATE;
    apdu[APDU_P2]  = P2_GP_INITIALIZE_UPDATE;
    apdu[APDU_LC]  = SCP_GP_HOST_CHALLENGE_LEN;

    if (memcpy_s(apdu + APDU_CDATA, SCP_INITIALIZE_UPDATE_CMD_LEN - APDU_CDATA, g_scp_challenge.host_challenge,
                 SCP_GP_HOST_CHALLENGE_LEN) != EOK)
        return TEE_ERROR_SECURITY;
    /* Le */
    apdu[APDU_CDATA + SCP_GP_HOST_CHALLENGE_LEN] = LE_GP_INITIALIZE_UPDATE;
    /* send cmd and get response */
    transmit_info.reader_id = se_channel_handle->session->reader->id;
    transmit_info.channel_id = se_channel_handle->logic_channel;
    transmit_info.data = apdu;
    transmit_info.data_len = SCP_INITIALIZE_UPDATE_CMD_LEN;
    transmit_info.p_rsp = response_apdu;
    transmit_info.rsp_len = response_length;
    ret = tee_se_srv_transmit(&transmit_info);
    if (ret != TEE_SUCCESS) {
        tloge("scp initialize update transmit:0x%x\n", ret);
        return ret;
    }

    response_length = transmit_info.rsp_len;
    if (!is_success_response(response_apdu, response_length)) {
        tloge("scp initialize update error response\n");
        return TEE_ERROR_COMMUNICATION;
    }
    parse_pos = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN;
    if (memcpy_s(g_scp_challenge.card_challenge, SCP_GP_CARD_CHALLENGE_LEN, response_apdu + parse_pos,
                 SCP_GP_CARD_CHALLENGE_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    parse_pos += SCP_GP_CARD_CHALLENGE_LEN;
    if (memcpy_s(g_scp_challenge.card_cryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN, response_apdu + parse_pos,
                 SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    tloge("scp initialize update success\n");
    return TEE_SUCCESS;
}

static TEE_Result tee_scp_calculate_host_cryptogram(void)
{
    uint8_t host_cryptogram[SCP_KEY_SIZE] = { 0 };
    TEE_Result ret;

    ret = tee_scp_calculate_cryptogram(host_cryptogram, SCP_KEY_SIZE, true);
    if (ret != TEE_SUCCESS) {
        tloge("tee scp calculate cryptogram failed\n");
        return ret;
    }

    if (memcpy_s(g_scp_challenge.host_cryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN, host_cryptogram,
                 SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != EOK) {
        (void)memset_s(host_cryptogram, sizeof(host_cryptogram), 0, sizeof(host_cryptogram));
        return TEE_ERROR_SECURITY;
    }

    (void)memset_s(host_cryptogram, sizeof(host_cryptogram), 0, sizeof(host_cryptogram));
    return ret;
}

static TEE_Result tee_scp_external_authenticate(TEE_SEChannelHandle se_channel_handle)
{
    uint8_t apdu[SCP_EXTERNAL_AUTHENTICATE_CMD_LEN] = { 0 };
    uint8_t response_apdu[DATA_DERIVATION_L_128BIT] = { 0 };
    uint32_t response_length                        = DATA_DERIVATION_L_128BIT;
    TEE_Result status;
    struct se_transmit_info_t transmit_info = { 0 };

    /* external authenticate cmd */
    apdu[APDU_CLA] = CLA_GP_SEC_BASIC_CHANNEL;     // Set CLA Byte 0x84
    apdu[APDU_INS] = INS_GP_EXTERNAL_AUTHENTICATE; // 0x82
    /* P1: set security level */
    apdu[APDU_P1] = TEE_SC_CR_ENC_MAC;
    apdu[APDU_P2] = P2_GP_EXTERNAL_AUTHENTICATE;
    /* The Lc value is set as-if the MAC has already been appended (SCP03 spec p16. Fig.6-1) */
    apdu[APDU_LC] = LC_GP_EXTERNAL_AUTHENTICATE;
    if (memcpy_s(apdu + APDU_CDATA, SCP_EXTERNAL_AUTHENTICATE_CMD_LEN - APDU_CDATA, g_scp_challenge.host_cryptogram,
                 SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != EOK)
        return TEE_ERROR_SECURITY;

    /* calculate the MAC value */
    (void)memset_s(g_tee_scp03_state.session.mcv, SCP_MCV_LEN, 0, SCP_MCV_LEN);

    status = scp_calculate_cmac(apdu, SCP_EXTERNAL_AUTHENTICATE_CMD_LEN, SCP_GP_IU_CARD_CRYPTOGRAM_LEN + APDU_CDATA);
    if (status != TEE_SUCCESS) {
        tloge("scp calculate cmac rror:0x%x\n", status);
        return status;
    }
    /* send cmd and get response */
    transmit_info.reader_id = se_channel_handle->session->reader->id;
    transmit_info.channel_id = se_channel_handle->logic_channel;
    transmit_info.data = apdu;
    transmit_info.data_len = SCP_EXTERNAL_AUTHENTICATE_CMD_LEN;
    transmit_info.p_rsp = response_apdu;
    transmit_info.rsp_len = response_length;
    status = tee_se_srv_transmit(&transmit_info);
    if (status != TEE_SUCCESS) {
        tloge("Err Transmit:0x%x\n", status);
        return status;
    }
    response_length = transmit_info.rsp_len;
    if (!is_success_response(response_apdu, response_length)) {
        tloge("Err sw\n");
        return TEE_ERROR_COMMUNICATION;
    }
    /* response process */
    if (response_length != SCP_EXTERNAL_AUTHENTICATE_RESP_LEN) {
        tloge("Err respLen:0x%x\n", response_length);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result tee_se_api_set_buffer(const TEE_ObjectHandle object_handle, uint8_t *state_key,
                                        uint16_t state_key_size)
{
    uint8_t *key = NULL;
    uint16_t key_size;
    bool params = ((object_handle == NULL) || (state_key == NULL) || (state_key_size == 0));
    if (params) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    key      = (uint8_t *)object_handle->Attribute[0].content.ref.buffer;
    key_size = object_handle->Attribute[0].content.ref.length;

    if ((key == NULL) || (key_size == 0)) {
        tloge("se api set buffer error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(state_key, state_key_size, key, key_size) != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

static TEE_Result tee_scp_set_key(const TEE_SC_Params *sc_params)
{
    TEE_SC_DeviceKeyRef device_key_ref = { 0 };
    TEE_SC_KeySetRef key_set_ref       = { 0 };
    TEE_Result status;

    if (sc_params == NULL) {
        tloge("para is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(&device_key_ref, sizeof(device_key_ref), &sc_params->scDeviceKeyRef,
                 sizeof(sc_params->scDeviceKeyRef)) != EOK)
        return TEE_ERROR_SECURITY;

    if (memcpy_s(&key_set_ref, sizeof(key_set_ref), &device_key_ref.__TEE_key.scKeySetRef,
                 sizeof(device_key_ref.__TEE_key.scKeySetRef)) != EOK)
        return TEE_ERROR_SECURITY;

    if (device_key_ref.scKeyType != TEE_SC_KEY_SET) {
        tloge("sc key type error\n");
        (void)memset_s(&device_key_ref, sizeof(device_key_ref), 0, sizeof(device_key_ref));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    (void)memset_s(&device_key_ref, sizeof(device_key_ref), 0, sizeof(device_key_ref));
    status = tee_se_api_set_buffer(key_set_ref.scKeyEncHandle, g_tee_scp03_state.key_enc, SCP_KEY_SIZE);
    if (status != TEE_SUCCESS) {
        tloge("scp set key cpy of enc error\n");
        (void)memset_s(&key_set_ref, sizeof(key_set_ref), 0, sizeof(key_set_ref));
        return status;
    }
    status = tee_se_api_set_buffer(key_set_ref.scKeyMacHandle, g_tee_scp03_state.key_mac, SCP_KEY_SIZE);
    if (status != TEE_SUCCESS) {
        tloge("scp set key cpy of mac error\n");
        (void)memset_s(&key_set_ref, sizeof(key_set_ref), 0, sizeof(key_set_ref));
        return status;
    }
    (void)memset_s(&key_set_ref, sizeof(key_set_ref), 0, sizeof(key_set_ref));
    return TEE_SUCCESS;
}

static TEE_Result scp_calculate_enc_key(const uint8_t *context, uint16_t context_len)
{
    TEE_Result ret;
    errno_t ret_status;
    uint8_t session_enc_key[SCP_KEY_SIZE]      = { 0 };
    struct tee_scp03_cipher_params cipher_data = { 0 };
    struct tee_dda_params dda_data;

    tee_scp_init_dda(&dda_data);
    dda_data.constant = DATA_DERIVATION_SENC;
    dda_data.len      = DATA_DERIVATION_L_128BIT;
    dda_data.counter  = DATA_DERIVATION_KDF_CTR;
    dda_data.dda_len  = DATA_DERIVATION_L_128BIT;
    scp_set_data_derication_arry(&dda_data, context, context_len);

    cipher_data.iv_len         = 0;
    cipher_data.iv             = NULL;
    cipher_data.algorithm      = TEE_ALG_AES_CMAC;
    cipher_data.operation_mode = TEE_MODE_MAC;

    ret_status = memcpy_s(cipher_data.key, sizeof(cipher_data.key), g_tee_scp03_state.key_enc, SCP_KEY_SIZE);
    if (ret_status != EOK)
        return TEE_ERROR_SECURITY;

    ret = tee_scp_crypto_aes(&cipher_data, dda_data.dda, dda_data.dda_len, session_enc_key, SCP_KEY_SIZE);
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    if (ret != TEE_SUCCESS) {
        tloge("scp crypto aes cmac fail\n");
        (void)memset_s(session_enc_key, sizeof(session_enc_key), 0, sizeof(session_enc_key));
        return ret;
    }
    ret_status = memcpy_s(g_tee_scp03_state.session.enc, SCP_KEY_SIZE, session_enc_key, SCP_KEY_SIZE);
    if (ret_status != EOK) {
        tloge("scp calculate session keys cpy error\n");
        (void)memset_s(session_enc_key, sizeof(session_enc_key), 0, sizeof(session_enc_key));
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(session_enc_key, sizeof(session_enc_key), 0, sizeof(session_enc_key));
    return TEE_SUCCESS;
}

static TEE_Result scp_calculate_mac_key(const uint8_t *context, uint16_t context_len, bool is_rmac)
{
    TEE_Result ret;
    errno_t ret_status;
    uint8_t session_mac_key[SCP_KEY_SIZE] = { 0 };
    struct tee_scp03_cipher_params cipher_data = { 0 };
    struct tee_dda_params dda_data;

    tee_scp_init_dda(&dda_data);
    if (is_rmac)
        dda_data.constant = DATA_DERIVATION_SRMAC;
    else
        dda_data.constant = DATA_DERIVATION_SMAC;
    dda_data.len      = DATA_DERIVATION_L_128BIT;
    dda_data.counter  = DATA_DERIVATION_KDF_CTR;
    dda_data.dda_len  = DATA_DERIVATION_L_128BIT;
    scp_set_data_derication_arry(&dda_data, context, context_len);

    cipher_data.iv_len         = 0;
    cipher_data.iv             = NULL;
    cipher_data.algorithm      = TEE_ALG_AES_CMAC;
    cipher_data.operation_mode = TEE_MODE_MAC;

    ret_status = memcpy_s(cipher_data.key, sizeof(cipher_data.key), g_tee_scp03_state.key_mac, SCP_KEY_SIZE);
    if (ret_status != EOK)
        return TEE_ERROR_SECURITY;

    ret = tee_scp_crypto_aes(&cipher_data, dda_data.dda, dda_data.dda_len, session_mac_key, SCP_KEY_SIZE);
    (void)memset_s(&cipher_data, sizeof(cipher_data), 0, sizeof(cipher_data));
    if (ret != TEE_SUCCESS) {
        tloge("scp crypto aes cmac fail\n");
        (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
        return ret;
    }
    if (is_rmac)
        ret_status = memcpy_s(g_tee_scp03_state.session.rmac, SCP_KEY_SIZE, session_mac_key, SCP_KEY_SIZE);
    else
        ret_status = memcpy_s(g_tee_scp03_state.session.mac, SCP_KEY_SIZE, session_mac_key, SCP_KEY_SIZE);
    if (ret_status != EOK) {
        tloge("scp calculate session keys cpy error\n");
        (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(session_mac_key, sizeof(session_mac_key), 0, sizeof(session_mac_key));
    return TEE_SUCCESS;
}

static TEE_Result tee_calculate_session_keys(const uint8_t *host_challenge, uint32_t host_challenge_len,
                                             const uint8_t *car_challenge, uint32_t car_challenge_len)
{
    uint8_t context[DATA_DERIVATION_L_128BIT] = { 0 };
    uint32_t context_len                      = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;
    TEE_Result ret;

    if ((host_challenge == NULL) || (car_challenge == NULL)) {
        tloge("param is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((host_challenge_len > SCP_GP_HOST_CHALLENGE_LEN) || (car_challenge_len > SCP_GP_CARD_CHALLENGE_LEN))
        return TEE_ERROR_BAD_PARAMETERS;
    if (memcpy_s(context, DATA_DERIVATION_L_128BIT, host_challenge, SCP_GP_HOST_CHALLENGE_LEN) != EOK) {
        tloge("scp calculate session keys cpy error\n");
        return TEE_ERROR_SECURITY;
    }
    if (memcpy_s(context + SCP_GP_HOST_CHALLENGE_LEN, DATA_DERIVATION_L_128BIT - SCP_GP_HOST_CHALLENGE_LEN,
                 car_challenge, SCP_GP_CARD_CHALLENGE_LEN) != EOK) {
        tloge("scp calculate session keys cpy error\n");
        (void)memset_s(context, sizeof(context), 0, sizeof(context));
        return TEE_ERROR_SECURITY;
    }
    // Calculate the S-ENC key
    ret = scp_calculate_enc_key(context, context_len);
    if (ret != TEE_SUCCESS) {
        tloge("scp calculate enc calculate error\n");
        (void)memset_s(context, sizeof(context), 0, sizeof(context));
        return ret;
    }
    // Calculate the S-MAC key
    ret = scp_calculate_mac_key(context, context_len, false);
    if (ret != TEE_SUCCESS) {
        tloge("scp calculate mac keys calculate error\n");
        (void)memset_s(context, sizeof(context), 0, sizeof(context));
        return ret;
    }
    // Calculate the S-RMAC key
    ret = scp_calculate_mac_key(context, context_len, true);
    if (ret != TEE_SUCCESS) {
        tloge("scp calculate ramc keys calculate error\n");
        (void)memset_s(context, sizeof(context), 0, sizeof(context));
        return ret;
    }
    (void)memset_s(context, sizeof(context), 0, sizeof(context));
    return TEE_SUCCESS;
}

static TEE_Result tee_secure_authenticate_channel(TEE_SEChannelHandle se_channel_handle, const TEE_SC_Params *sc_params)
{
    TEE_Result status;

    tlogd("secure authenticate channel START\n");
    status = tee_scp_set_key(sc_params);
    if (status != TEE_SUCCESS) {
        tloge("secure authenticate channel fail\n");
        return status;
    }
    /* get host challenge */
    TEE_GenerateRandom(g_scp_challenge.host_challenge, SCP_GP_HOST_CHALLENGE_LEN);

    /* initialize update and response process */
    status = tee_scp_initialze_update(se_channel_handle);
    if (status != TEE_SUCCESS) {
        tloge("Err initialize update:0x%x\n", status);
        return status;
    }
    /* cauculate session keys */
    status = tee_calculate_session_keys(g_scp_challenge.host_challenge, SCP_GP_HOST_CHALLENGE_LEN,
                                        g_scp_challenge.card_challenge, SCP_GP_HOST_CHALLENGE_LEN);
    if (status != TEE_SUCCESS) {
        tloge("Err calculate key:0x%x\n", status);
        return status;
    }
    /* verify card cryptogram through g_session_key */
    status = tee_scp_verify_card_cryptogram();
    if (status != TEE_SUCCESS) {
        tloge("Err verifyCard:0x%x\n", status);
        return status;
    }

    /* calculate host cryptogram through g_session_key */
    status = tee_scp_calculate_host_cryptogram();
    if (status != TEE_SUCCESS) {
        tloge("Err calcHost:0x%x\n", status);
        return status;
    }
    set_default_icv_counter();
    /* external authenticate and response process */
    status = tee_scp_external_authenticate(se_channel_handle);
    if (status != TEE_SUCCESS) {
        tloge("Err external_auth:0x%x\n", status);
        return status;
    }
    se_channel_handle->is_secure = true;
    return status;
}

static TEE_Result service_get_readers_init(struct se_reader_select *reader,
                                           const uint32_t *se_reader_handle_list_len)
{
    int se_type;
    bool sec_flash_status = false;

    se_type = se_srv_get_ese_type();
    tlogi("se type is %d\n", se_type);

    sec_flash_status = se_srv_get_sec_flash_status();

    reader->is_inse = ((se_type == SCARD_MODE_INSE || se_type == SCARD_MODE_BOTH) &&
                       (*se_reader_handle_list_len >= SCARD_INSE_LEN));
    reader->is_ese = ((se_type == SCARD_MODE_ESE || se_type == SCARD_MODE_BOTH) &&
                      (*se_reader_handle_list_len >= SCARD_ESE_LEN));
    reader->is_sec_flash = (sec_flash_status && *se_reader_handle_list_len >= SCARD_SECFLASH_LEN);
    reader->is_msp = (se_srv_get_msp_status() && *se_reader_handle_list_len >= SCARD_MSP_LEN);
    reader->is_lese = *se_reader_handle_list_len >= SCARD_LESE_LEN;
    reader->is_hese = *se_reader_handle_list_len >= SCARD_HESE_LEN;
    reader->is_invalid = !((reader->is_inse) || (reader->is_ese) || (reader->is_sec_flash) || (reader->is_msp) ||
        (reader->is_lese) || (reader->is_hese));
    return TEE_SUCCESS;
}

static TEE_Result session_open_channel_check(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                             TEE_SEChannelHandle *se_channel_handle)
{
    bool is_bad_param = false;

    is_bad_param = ((se_aid == NULL) || (se_channel_handle == NULL) ||
                    (se_aid->bufferLen == 0 && se_aid->buffer != NULL) ||
                    ((se_aid->bufferLen != 0) && ((se_aid->bufferLen > AID_LEN_MAX) ||
                                                  (se_aid->bufferLen < AID_LEN_MIN) || (se_aid->buffer == NULL))));
    if (is_bad_param) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((!is_session_valid(se_session_handle)) || (se_session_handle->state != SESSION_STATE_OPEN)) {
        tloge("session handle is invalid\n");
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result se_reader_check(TEE_SEReaderHandle se_reader_handle)
{
    if (se_reader_handle == NULL) {
        tloge("se reader handle is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((se_reader_handle != &g_se_reader[SCARD_MODE_INSE]) &&
        (se_reader_handle != &g_se_reader[SCARD_MODE_ESE]) &&
        (se_reader_handle != &g_se_reader[SCARD_MODE_SECURE_FLASH]) &&
        (se_reader_handle != &g_se_reader[SCARD_MODE_MSP]) &&
        (se_reader_handle != &g_se_reader[SCARD_MODE_LESE]) &&
        (se_reader_handle != &g_se_reader[SCARD_MODE_HESE])) {
        tloge("se reader handle is invalid\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    return TEE_SUCCESS;
}

static void init_tee_se_api(void)
{
    unsigned int i;

    if (mutex_lock_service(&g_se_init_mutex) != MUTEX_SUCCESS) {
        tloge("failed to get se init lock\n");
        return;
    }

    if (g_is_se_inited)
        goto UNLOCK_MUTEX;

    for (i = 0; i < SCARD_MODE_MAX; i++) {
        g_se_reader[i].id                            = i;
        g_se_reader[i].property.sePresent            = true;
        g_se_reader[i].property.teeOnly              = true;
        g_se_reader[i].property.selectResponseEnable = true;
        g_se_reader[i].basic_channel_locked          = false;
        g_se_reader[i].session_count                 = 0;
        if (reset_reader(i) != SE_SUCCESS)
            tloge("reset reader failed\n");
        dlist_init(&g_se_reader[i].session_head);
    }

    g_is_se_inited = true;

UNLOCK_MUTEX:
    if (pthread_mutex_unlock(&g_se_init_mutex))
        tloge("unlock se init mutex failed\n");
}

/*
 * -----------------------------------------------------------------------------------------------
 * APIs under the line are defined by Global Platform, need to follow Global Platform code style
 * don't change function name / return value type / parameters types / parameters names
 * -----------------------------------------------------------------------------------------------
 */
TEE_Result TEE_SEServiceOpen(TEE_SEServiceHandle *se_service_handle)
{
    init_tee_se_api();

    if ((se_service_handle == NULL) || (!g_is_se_inited)) {
        tloge("params are invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (mutex_lock_service(&g_service_mutex) != MUTEX_SUCCESS) {
        tloge("mutex_lock_service fail\n");
        return TEE_ERROR_ACCESS_CONFLICT;
    }
    *se_service_handle = &g_se_service;

    return TEE_SUCCESS;
}

void TEE_SEServiceClose(TEE_SEServiceHandle se_service_handle)
{
    if (!g_is_se_inited)
        return;
    if (se_service_handle == &g_se_service) {
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_INSE]);
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_ESE]);
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_SECURE_FLASH]);
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_MSP]);
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_LESE]);
        TEE_SEReaderCloseSessions(&g_se_reader[SCARD_MODE_HESE]);
        (void)pthread_mutex_unlock(&g_service_mutex);
    }
}

TEE_Result TEE_SEServiceGetReaders(TEE_SEServiceHandle se_service_handle, TEE_SEReaderHandle *se_reader_handle_list,
                                   uint32_t *se_reader_handle_list_len)
{
    struct se_reader_select reader = { 0 };
    TEE_Result ret;

    if ((se_reader_handle_list == NULL) || (se_reader_handle_list_len == NULL)) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (se_service_handle != &g_se_service) {
        tloge("se service handle is invalid\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    ret = service_get_readers_init(&reader, se_reader_handle_list_len);
    if (ret != TEE_SUCCESS)
        return ret;
    if (reader.is_invalid)
        return TEE_ERROR_SHORT_BUFFER;
    if (reader.is_inse) {
        se_reader_handle_list[SCARD_MODE_INSE] = &g_se_reader[SCARD_MODE_INSE];
        *se_reader_handle_list_len             = SCARD_INSE_LEN;
    }
    if (reader.is_ese) {
        se_reader_handle_list[SCARD_MODE_ESE]  = &g_se_reader[SCARD_MODE_ESE];
        *se_reader_handle_list_len             = SCARD_ESE_LEN;
    }
    if (reader.is_sec_flash) {
        se_reader_handle_list[SCARD_MODE_SECURE_FLASH] = &g_se_reader[SCARD_MODE_SECURE_FLASH];
        *se_reader_handle_list_len                     = SCARD_SECFLASH_LEN;
    }
    if (reader.is_msp) {
        se_reader_handle_list[SCARD_MODE_MSP] = &g_se_reader[SCARD_MODE_MSP];
        *se_reader_handle_list_len            = SCARD_MSP_LEN;
    }
    if (reader.is_lese) {
        se_reader_handle_list[SCARD_MODE_LESE] = &g_se_reader[SCARD_MODE_LESE];
        *se_reader_handle_list_len            = SCARD_LESE_LEN;
    }
    if (reader.is_hese) {
        se_reader_handle_list[SCARD_MODE_HESE] = &g_se_reader[SCARD_MODE_HESE];
        *se_reader_handle_list_len            = SCARD_HESE_LEN;
    }

    return TEE_SUCCESS;
}

void TEE_SEReaderGetProperties(TEE_SEReaderHandle se_reader_handle, TEE_SEReaderProperties *reader_properties)
{
    if ((se_reader_check(se_reader_handle) != TEE_SUCCESS) || (reader_properties == NULL)) {
        tloge("params are invalid\n");
        return;
    }
    *reader_properties = se_reader_handle->property;
}

TEE_Result TEE_SEReaderGetName(TEE_SEReaderHandle se_reader_handle, char *reader_name, uint32_t *reader_name_len)
{
    bool is_bad_param = false;
    TEE_Result ret;

    ret = se_reader_check(se_reader_handle);
    if (ret != TEE_SUCCESS)
        return ret;

    is_bad_param = ((reader_name == NULL) || (reader_name_len == NULL));
    if (is_bad_param) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (se_reader_handle->name == NULL) {
        tloge("se reader handle name is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (strnlen(se_reader_handle->name, READER_NAME_LEN + 1) > READER_NAME_LEN) {
        tloge("se reader name is invalid\n");
        return TEE_ERROR_BAD_FORMAT;
    }
    if (*reader_name_len < (strlen(se_reader_handle->name) + 1)) {
        tloge("reader name len is invalid\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    (void)memset_s(reader_name, *reader_name_len, 0, *reader_name_len);
    if (strncpy_s(reader_name, *reader_name_len, se_reader_handle->name, strlen(se_reader_handle->name)) != EOK)
        return TEE_ERROR_SECURITY;
    *reader_name_len = strlen(se_reader_handle->name) + 1;

    return TEE_SUCCESS;
}

TEE_Result TEE_SEReaderOpenSession(TEE_SEReaderHandle se_reader_handle, TEE_SESessionHandle *se_session_handle)
{
    TEE_Result ret;
    struct __TEE_SESessionHandle *session = NULL;

    ret = se_reader_check(se_reader_handle);
    if (ret != TEE_SUCCESS)
        return ret;

    if (se_session_handle == NULL) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    session = TEE_Malloc(sizeof(*session), 0);
    if (session == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    if (se_reader_handle->id >= SCARD_MODE_MAX) {
        tloge("se reader id is invalid\n");
        TEE_Free(session);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (se_reader_handle->session_count == 0) {
        /*
         * init SE with communication
         * atr & atrlen not implement in SE driver
         */
        uint32_t len_int = ATR_LEN_MAX;

        ret = se_srv_connect(se_reader_handle->id, se_reader_handle->atr, &len_int);
        if (ret != TEE_SUCCESS) {
            tloge("se srv connect failed\n");
            TEE_Free(session);
            return ret;
        }
        se_reader_handle->atr_len = (unsigned short)len_int;
    }

    se_reader_handle->session_count++;

    session->reader = se_reader_handle;
    dlist_init(&session->channel_head);
    session->state = SESSION_STATE_OPEN;
    dlist_insert_tail((struct dlist_node *)&session->list, (struct dlist_node *)&se_reader_handle->session_head);

    *se_session_handle = session;

    return TEE_SUCCESS;
}

void TEE_SEReaderCloseSessions(TEE_SEReaderHandle se_reader_handle)
{
    TEE_SESessionHandle pos  = NULL;
    TEE_SESessionHandle n    = NULL;

    if (se_reader_check(se_reader_handle) != TEE_SUCCESS)
        return;

    dlist_for_each_entry_safe(pos, n, &se_reader_handle->session_head, struct __TEE_SESessionHandle, list)
        TEE_SESessionClose(pos);
}

/* atr & atr_len not implement in SE driver */
TEE_Result TEE_SESessionGetATR(TEE_SESessionHandle se_session_handle, void *atr, uint32_t *atr_len)
{
    if (!is_session_valid(se_session_handle) || (se_session_handle->state != SESSION_STATE_OPEN)) {
        tloge("session is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (atr == NULL || atr_len == NULL) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (se_session_handle->reader->atr_len > ATR_LEN_MAX) {
        tloge("session handle's atr len is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (*atr_len < se_session_handle->reader->atr_len) {
        tloge("atr len is too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(atr, *atr_len, se_session_handle->reader->atr, se_session_handle->reader->atr_len) != EOK) {
        tloge("cpy atr failed\n");
        return TEE_ERROR_SECURITY;
    }
    *atr_len = (uint32_t)se_session_handle->reader->atr_len;

    return TEE_SUCCESS;
}

TEE_Result TEE_SESessionIsClosed(TEE_SESessionHandle se_session_handle)
{
    if (!is_session_valid(se_session_handle))
        return TEE_SUCCESS;

    /* check with communication */
    if (se_session_handle->state == SESSION_STATE_INVALID)
        return TEE_ERROR_COMMUNICATION;
    else if (se_session_handle->state == SESSION_STATE_OPEN)
        return TEE_ERROR_BAD_STATE;
    else
        return TEE_SUCCESS;
}

void TEE_SESessionClose(TEE_SESessionHandle se_session_handle)
{
    if (!is_session_valid(se_session_handle) || (se_session_handle->state != SESSION_STATE_OPEN)) {
        tloge("failed to close a invalid session\n");
        return;
    }

    TEE_SESessionCloseChannels(se_session_handle);
    if (se_session_handle->reader->id >= SCARD_MODE_MAX)
        return;

    if (se_session_handle->reader->session_count > 0)
        se_session_handle->reader->session_count--;
    dlist_delete((struct dlist_node *)&se_session_handle->list);

    if (se_session_handle->reader->session_count == 0) {
        /* de-init SE with communication */
        TEE_Result ret;
        ret = se_srv_disconnect(se_session_handle->reader->id);
        if (ret != TEE_SUCCESS)
            tloge("scard disconnect failed, ret=0x%x\n", ret);
        if (reset_reader(se_session_handle->reader->id) != SE_SUCCESS)
            tloge("reset reader %u failed\n", se_session_handle->reader->id);
    }
    se_session_handle->reader = NULL;
    TEE_Free(se_session_handle);
}

void TEE_SESessionCloseChannels(TEE_SESessionHandle se_session_handle)
{
    TEE_SEChannelHandle pos = NULL;
    TEE_SEChannelHandle n   = NULL;

    if (!is_session_valid(se_session_handle) || (se_session_handle->state != SESSION_STATE_OPEN)) {
        tloge("failed to close a invalid session\n");
        return;
    }

    dlist_for_each_entry_safe(pos, n, &se_session_handle->channel_head, struct __TEE_SEChannelHandle, list)
        TEE_SEChannelClose(pos);
}

TEE_Result TEE_SESessionOpenBasicChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                         TEE_SEChannelHandle *se_channel_handle)
{
    TEE_Result ret;
    TEE_SEChannelHandle channel = NULL;
    uint8_t p_rsp[APDU_SELECT_RESP_LEN] = { 0 };
    uint32_t rsp_len = APDU_SELECT_RESP_LEN;

    ret = session_open_channel_check(se_session_handle, se_aid, se_channel_handle);
    if (ret != TEE_SUCCESS) {
        tloge("session open channel check failed\n");
        return ret;
    }

    if (se_session_handle->reader->basic_channel_locked) {
        tloge("basic channel is locked\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    channel = malloc_channel(se_session_handle, se_aid);
    if (channel == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;
    channel->basic_channel = true;
    channel->logic_channel = 0;

    ret = open_basic_channel(se_aid, channel, p_rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("open basic channel failed\n");
        free_channel(channel);
        return ret;
    }
    ret = get_apdu_res(channel, p_rsp, rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("get apdu res ret=0x%x\n", ret);
        TEE_SEChannelClose(channel);
        return ret;
    }

    se_session_handle->reader->basic_channel_locked = true;
    *se_channel_handle = channel;

    return TEE_SUCCESS;
}

TEE_Result TEE_SESessionOpenLogicalChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                           TEE_SEChannelHandle *se_channel_handle)
{
    TEE_Result ret;
    TEE_SEChannelHandle channel = NULL;
    uint8_t p_rsp[APDU_SELECT_RESP_LEN] = { 0 };
    uint32_t rsp_len = APDU_SELECT_RESP_LEN;

    ret = session_open_channel_check(se_session_handle, se_aid, se_channel_handle);
    if (ret != TEE_SUCCESS) {
        tloge("session open channel check failed\n");
        return ret;
    }

    channel = malloc_channel(se_session_handle, se_aid);
    if (channel == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    ret = open_logical_channel(se_aid, channel, p_rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("open logical channel failed\n");
        free_channel(channel);
        return ret;
    }
    ret = get_apdu_res(channel, p_rsp, rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("get apdu res ret=0x%x\n", ret);
        TEE_SEChannelClose(channel);
        return ret;
    }

    *se_channel_handle = channel;

    return TEE_SUCCESS;
}

void TEE_SEChannelClose(TEE_SEChannelHandle se_channel_handle)
{
    struct se_transmit_info_t transmit_info = { 0 };

    if (!is_channel_valid(se_channel_handle))
        return;

    transmit_info.reader_id = se_channel_handle->session->reader->id;
    transmit_info.channel_id = se_channel_handle->logic_channel;
    tee_se_srv_close_channel(&transmit_info);

    free_channel(se_channel_handle);
}

TEE_Result TEE_SEChannelSelectNext(TEE_SEChannelHandle se_channel_handle)
{
    uint8_t p_rsp[APDU_SELECT_RESP_LEN] = { 0 };
    uint32_t rsp_len = APDU_SELECT_RESP_LEN;
    bool is_bad_param = false;
    TEE_Result ret;
    struct se_transmit_info_t transmit_info = { 0 };

    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    is_bad_param =
        ((se_channel_handle->se_aid.bufferLen == 0 && se_channel_handle->se_aid.buffer != NULL) ||
         ((se_channel_handle->se_aid.bufferLen != 0) &&
          ((se_channel_handle->se_aid.bufferLen > AID_LEN_MAX) || (se_channel_handle->se_aid.bufferLen < AID_LEN_MIN) ||
           (se_channel_handle->se_aid.buffer == NULL))));
    if (is_bad_param) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    transmit_info.reader_id = se_channel_handle->session->reader->id;
    transmit_info.channel_id = se_channel_handle->logic_channel;
    transmit_info.data = se_channel_handle->se_aid.buffer;
    transmit_info.data_len = se_channel_handle->se_aid.bufferLen;
    transmit_info.p_rsp = p_rsp;
    transmit_info.rsp_len = rsp_len;
    ret = tee_se_srv_select_channel(&transmit_info);
    rsp_len = transmit_info.rsp_len;
    if (ret != TEE_SUCCESS) {
        tloge("select channel failed\n");
        return ret;
    }
    ret = get_apdu_res(se_channel_handle, p_rsp, rsp_len);
    if (ret != TEE_SUCCESS)
        tloge("get apdu res ret=0x%x\n", ret);
    return ret;
}

TEE_Result TEE_SEChannelGetSelectResponse(TEE_SEChannelHandle se_channel_handle, void *response, uint32_t *response_len)
{
    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (response == NULL || response_len == NULL) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((*response_len < se_channel_handle->resp_len) || (se_channel_handle->resp_buffer == NULL)) {
        tloge("params are invalid\n");
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(response, *response_len, se_channel_handle->resp_buffer, se_channel_handle->resp_len) != EOK) {
        tloge("cpy response failed\n");
        return TEE_ERROR_SECURITY;
    }
    *response_len = (uint32_t)se_channel_handle->resp_len;

    return TEE_SUCCESS;
}

TEE_Result TEE_SEChannelTransmit(TEE_SEChannelHandle se_channel_handle, void *command, uint32_t command_len,
                                 void *response, uint32_t *response_len)
{
    TEE_Result ret;
    bool is_bad_param = false;
    struct se_transmit_info_t transmit_info = { 0 };

    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    is_bad_param = ((command == NULL) || (command_len == 0) ||
        (response == NULL) || (response_len == NULL) || (*response_len == 0));
    if (is_bad_param) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (command_len < APDU_LEN_MIN) {
        tloge("command len is too short\n");
        return TEE_ERROR_COMMUNICATION;
    }

    transmit_info.reader_id = se_channel_handle->session->reader->id;
    transmit_info.channel_id = se_channel_handle->logic_channel;
    transmit_info.data = command;
    transmit_info.data_len = command_len;
    transmit_info.p_rsp = response;
    transmit_info.rsp_len = *response_len;
    if (se_channel_handle->is_secure)
        ret = tee_scp_transmit(&transmit_info);
    else
        ret = tee_se_srv_transmit(&transmit_info);
    if (ret != TEE_SUCCESS) {
        tloge("SE channel transmit ret=0x%x\n", ret);
        return ret;
    }
    *response_len = transmit_info.rsp_len;

    return TEE_SUCCESS;
}

TEE_Result TEE_SESecureChannelOpen(TEE_SEChannelHandle se_channel_handle, TEE_SC_Params *sc_params)
{
    TEE_Result ret;

    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sc_params == NULL) {
        tloge("sc params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((sc_params->scSecurityLevel != TEE_SC_CR_ENC_MAC) || (sc_params->scType != TEE_SC_TYPE_SCP03)) {
        tloge("se security level is not support\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    (void)memset_s(&g_scp_challenge, sizeof(g_scp_challenge), 0, sizeof(g_scp_challenge));
    (void)memset_s(g_mac_chaining, SCP_CMAC_TOTAL_LENGTH, 0, SCP_CMAC_TOTAL_LENGTH);

    ret = tee_secure_authenticate_channel(se_channel_handle, sc_params);
    if (ret != TEE_SUCCESS) {
        tloge("secure authenticate channel fail, ret = 0x%x\n", ret);
        (void)memset_s(&g_tee_scp03_state, sizeof(g_tee_scp03_state), 0, sizeof(g_tee_scp03_state));
    }
    return ret;
}

void TEE_SESecureChannelClose(TEE_SEChannelHandle se_channel_handle)
{
    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return;
    }

    se_channel_handle->is_secure = false;
    (void)memset_s(&g_tee_scp03_state, sizeof(g_tee_scp03_state), 0, sizeof(g_tee_scp03_state));
    (void)memset_s(&g_scp_challenge, sizeof(g_scp_challenge), 0, sizeof(g_scp_challenge));
    (void)memset_s(g_mac_chaining, SCP_CMAC_TOTAL_LENGTH, 0, SCP_CMAC_TOTAL_LENGTH);
}

TEE_Result TEE_SEChannelGetID(TEE_SEChannelHandle se_channel_handle, uint8_t *channel_id)
{
    if (!is_channel_valid(se_channel_handle)) {
        tloge("channel is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (channel_id == NULL) {
        tloge("channel id is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *channel_id = se_channel_handle->logic_channel;

    return TEE_SUCCESS;
}

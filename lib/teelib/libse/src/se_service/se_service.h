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
#ifndef SE_SERVICE_SE_SERVICE_H
#define SE_SERVICE_SE_SERVICE_H

#include "tee_defines.h"
#include "tee_msg_type.h"

#define SE_PATH "seservice"

#define SE_ERROR      (-1)
#define SE_SUCCESS    0
#define MUTEX_SUCCESS 0

#define TA_PARAM_MAX              4
#define READER_NAME_LEN           12   /* length of "sSE_spi_0" or "eSE_spi_0" */
#define APDU_LEN_MIN              4
#define APDU_LEN_MAX              32768
#define APDU_SELECT_RESP_LEN      258U /* Initial length of buffer to receive SELECT response */
#define MAX_KEY_SIZE              256U
#define TEE_SCP03_COMMAND_MAX_LEN 255U
#define UINT16_T_MAX              0xffff

/* Copied from se_hal.h, as src can't access trustedcore include. */
/* scard_support_mode return value defines */
#define SCARD_MODE_SYNC  0
#define SCARD_MODE_SYNC2 1
#define SCARD_MODE_ASYNC 2
#define ASYNC_SLICE      10U          /* ms */
#define ASYNC_MAX_COUNT  (60U * 100U) /* total sync time = 60s */

/* scard_get_status return value defines */
#define SCARD_STATUS_RECEIVE_NOT_READY 0
#define SCARD_STATUS_RECEIVE_READY     1

#define CLA_MASK_B1B2B7              0xBC
#define CLA_MASK_B1B2B3B4B7          0xB0
#define CLA_BASIC_CHANNEL            0x00
#define CLA_MANAGE_CHANNEL           0x00
#define INS_SELECT                   0xA4
#define INS_MANAGE_CHANNEL           0x70
#define P1_SELECT                    0x04
#define P1_MANAGE_CHANNEL_OPEN       0x00
#define P1_MANAGE_CHANNEL_CLOSE      0x80
#define P2_SELECT                    0x00
#define P2_MANAGE_CHANNEL_OPEN       0x00
#define LE_GP_LEN                    1
#define LE_MANAGE_CHANNEL_OPEN       0x01
#define LE_SELECT                    0x00
#define RSP_MANAGE_CHANNEL           0
#define SW1_GP_SUCCESS               0x90
#define SW1_GP_WARNING1              0x62
#define SW1_GP_WARNING2              0x63
#define SW1_GP_REFUSE                0x8F
#define SW1_GP_LEN                   1U
#define SW2_GP_SUCCESS               0x00
#define SW2_GP_REFUSE                0xFF
#define SW2_GP_LEN                   1U
#define SW_GP_LEN                    (SW1_GP_LEN + SW2_GP_LEN)
#define APDU_MANAGE_CHANNEL_RESP_LEN 3U

/* session state: 0-closed, 1-open, -1-invalid */
#define SESSION_STATE_CLOASED 0
#define SESSION_STATE_OPEN    1
#define SESSION_STATE_INVALID (-1)

#define DDA_CONSTANT_INDEX       11
#define DDA_SEPARATION_INDEX     12
#define DDA_DERIVED_DATA_INDEX   13
#define DDA_LEN_INDEX            14
#define DDA_COUNTER_INDEX        15
#define DD_LABEL_LEN             12U
#define DATA_CARD_CRYPTOGRAM     0x00
#define DATA_HOST_CRYPTOGRAM     0x01
#define DATA_DERIVATION_SENC     0x04
#define DATA_DERIVATION_SMAC     0x06
#define DATA_DERIVATION_SRMAC    0x07
#define DATA_DERIVATION_L_64BIT  0x0040
#define DATA_DERIVATION_L_128BIT 0x0080
#define DATA_DERIVATION_KDF_CTR  0x01

/* host/card Challenge byte length */
#define SCP_GP_IU_KEY_DIV_DATA_LEN    10U /* SCP GP Init Update key Div length */
#define SCP_GP_IU_KEY_INFO_LEN        3U  /* SCP GP Init Update key info length */
#define SCP_GP_CARD_CHALLENGE_LEN     8U  /* SCP GP Card Challenge length */
#define SCP_GP_HOST_CHALLENGE_LEN     8U  /* SCP GP Host Challenge length */
#define SCP_GP_IU_CARD_CRYPTOGRAM_LEN 8U  /* SCP GP Card Cryptogram length */
#define SCP_COMMAND_MAC_SIZE          8U  /* length of the MAC appended in the APDU payload (8 'MSB's) */
#define SCP_PADDING_HEAD              0x80
#define SCP_PADDING_CONTENT           0x00
#define SCP_NO_PADDING                0x00
#define SCP_NO_LE                     0

#define CLA_GP_CHANNEL1              0x81
#define CLA_GP_SEC_BASIC_CHANNEL     0x84
#define CLA_GP_SEC_CHANNEL1          0x85
#define INS_GP_INITIALIZE_UPDATE     0x50 /* Global platform defined instruction */
#define INS_GP_EXTERNAL_AUTHENTICATE 0x82 /* Global platform defined instruction */
#define P1_GP_INITIALIZE_UPDATE      0x35
#define P2_GP_INITIALIZE_UPDATE      0x00
#define P2_GP_EXTERNAL_AUTHENTICATE  0x00
#define LC_GP_EXTERNAL_AUTHENTICATE  0x10
#define LE_GP_INITIALIZE_UPDATE      0x00

#define SET_THIRD_BIT   0x4
#define SET_FIR_SEC_BIT 0x03
#define SET_LOW_8BIT    0xFF

/*
 * INITIALIZE UPDATE cmd length
 * '5': CLA-Lc; '8': challenge; '1': Le
 */
#define SCP_INITIALIZE_UPDATE_CMD_LEN 14U
/*
 * INITIALIZE UPDATE Response length
 * '10': Secure Flash Information; '3': Key information
 * '16': 2 challenge; '2': sw;
 */
#define SCP_INITIALIZE_UPDATE_RESP_LEN 31U
#define SCP_KDF_MESSAGE_LEN            32U

/*
 * KDF parameters used in SCP03 calc (if key length is 128bits)
 * [i] || Label || 0x00 || Context || [L]
 * 1      12       1        16        2   bytes
 */
#define SCP_LABLE_LEN         12U
#define SCP_BLOCK_BYTE_LEN    16U
#define SCP_ICV_BYTE_LEN      16U
#define SCP_CMAC_TOTAL_LENGTH 16U
/*
 * EXTERNAL AUTHENTICATE cmd length
 * '5': CLA-Lc; '16': host crypogram and C-MAC;
 */
#define SCP_EXTERNAL_AUTHENTICATE_CMD_LEN 21U
/*
 * EXTERNAL AUTHENTICATE Response length
 * '2': sw;
 */
#define SCP_EXTERNAL_AUTHENTICATE_RESP_LEN 2U

/* length of the CMAC calculated (and used as MAC chaining value) */
#define SCP_CMAC_SIZE         16U
#define SCP_KEY_SIZE          16U
#define SCP_MCV_LEN           16U  /* MAC Chaining Length */
#define MAX_CHUNK_LENGTH_LINK 256U /* Limited by A71CH applet capability */
#define SCP_BUFFER_SIZE       (MAX_CHUNK_LENGTH_LINK + SCP_KDF_MESSAGE_LEN + SW_GP_LEN)
#define ATTRIBUTE_COUNT       1U

#define APDU_LCC_PADDING          (APDU_LC + 1)
#define APDU_LCC_MAC              (APDU_LC + 2)

enum reader_len {
    SCARD_INSE_LEN = 1,
    SCARD_ESE_LEN,
    SCARD_SECFLASH_LEN,
    SCARD_MSP_LEN,
    SCARD_LESE_LEN,
    SCARD_HESE_LEN,
    SCARD_MAX_LEN
};

#define SCARD_MODE_BOTH 2            /* inse&ese */
enum SE_Type {
    SCARD_MODE_INSE         = 0, /* inse */
    SCARD_MODE_ESE          = 1, /* ese */
    SCARD_MODE_SECURE_FLASH = 2, /* secure flash */
    SCARD_MODE_MSP          = 3,
    SCARD_MODE_LESE         = 4,
    SCARD_MODE_HESE         = 5,
    SCARD_MODE_MAX          = 6,
};
struct session_state_t {
    uint8_t enc[SCP_KEY_SIZE];     /* SCP03 session channel encryption key */
    uint8_t mac[SCP_KEY_SIZE];     /* SCP03 session command authentication key */
    uint8_t rmac[SCP_KEY_SIZE];    /* SCP03 session response authentication key */
    uint8_t mcv[SCP_MCV_LEN];      /* SCP03 MAC chaining value */
    uint8_t counter[SCP_KEY_SIZE]; /* SCP03 command counter */
};

struct tee_scp03_state_t {
    uint8_t key_enc[SCP_KEY_SIZE];  /* SCP03 static secure channel encryption key */
    uint8_t key_mac[SCP_KEY_SIZE];  /* SCP03 static secure channel authentication key */
    uint8_t key_dek[SCP_KEY_SIZE];  /* SCP03 data encryption key */
    struct session_state_t session; /* SCP03 session state */
};

struct apdu_t {
    uint8_t *command_buf;
    uint32_t command_buf_len;
    uint32_t buflen;
    bool has_extended_length;
    bool has_data;
    uint8_t lc_length;
    uint8_t has_le;
    uint16_t le;
    uint8_t le_length;
    uint32_t offset;
};

struct tee_scp03_cipher_params {
    uint8_t *iv;
    uint32_t iv_len;
    uint8_t key[SCP_KEY_SIZE];
    uint32_t algorithm;
    uint32_t operation_mode;
};

struct tee_dda_params {
    uint8_t dda[DATA_DERIVATION_L_128BIT];
    uint16_t dda_len;
    uint8_t constant;
    uint16_t len;
    uint8_t counter;
};

struct scp_gp_challenge {
    uint8_t host_challenge[SCP_GP_HOST_CHALLENGE_LEN];
    uint8_t card_challenge[SCP_GP_CARD_CHALLENGE_LEN];
    uint8_t card_cryptogram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    uint8_t host_cryptogram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
};

enum apdu_cmd_offset {
    APDU_CLA = 0,
    APDU_INS,
    APDU_P1,
    APDU_P2,
    APDU_LC,
    APDU_CDATA
};

enum se_commands_id {
    CMD_SESRV_CONNECT = 0x100,
    CMD_SESRV_DISCONNECT = 0x101,
    CMD_SESRV_TRANSMIT = 0x102,
    CMD_SESRV_GET_ESE_TYPE = 0x103,
    CMD_SESRV_OPEN_BASIC_CHANNEL = 0x104,
    CMD_SESRV_OPEN_LOGICAL_CHANNEL = 0x105,
    CMD_SESRV_CLOSE_CHANNEL = 0x106,
    CMD_SESRV_SELECT_CHANNEL = 0x107,
    CMD_SESRV_UNREGISTER_TA = 0x108,
    CMD_SESRV_GET_MSP_STATUS = 0x109,
    CMD_SESRV_GET_SEC_FLASH_STATUS = 0x10A,
    CMD_SESRV_SET_AID = 0x10B,
    CMD_SESRV_SET_DEACTIVE = 0x10C,
};

struct connect_msg_t {
    uint32_t reader_id;
    uint64_t p_atr;
    uint32_t atr_len;
};

struct disconnect_msg_t {
    uint32_t reader_id;
};

struct transmit_msg_t {
    uint32_t reader_id;
    uint64_t p_cmd;
    uint32_t cmd_len;
    uint64_t p_rsp;
    uint32_t rsp_len;
    uint8_t channel_id;
};

struct open_basic_channel_msg_t {
    uint32_t reader_id;
    uint64_t se_aid;
    uint32_t se_aid_len;
    uint64_t p_rsp;
    uint32_t rsp_len;
};

struct open_logical_channel_msg_t {
    uint32_t reader_id;
    uint64_t se_aid;
    uint32_t se_aid_len;
    uint64_t p_rsp;
    uint32_t rsp_len;
};

struct close_channel_msg_t {
    uint32_t reader_id;
    uint8_t channel_id;
};

struct select_channel_msg_t {
    uint32_t reader_id;
    uint64_t se_aid;
    uint32_t se_aid_len;
    uint64_t p_rsp;
    uint32_t rsp_len;
    uint8_t channel_id;
};

struct reg_ta_info_msg_t {
    uint32_t taskid;
};

struct set_aid_msg_t {
    uint64_t seaid_list;
    uint32_t seaid_list_len;
};

struct set_deactive_msg_t {
    bool deactive;
};

union se_srv_msg_data_t {
    struct connect_msg_t connect_msg;
    struct disconnect_msg_t disconnect_msg;
    struct transmit_msg_t transmit_msg;
    struct open_basic_channel_msg_t open_basic_channel_msg;
    struct open_logical_channel_msg_t open_logical_channel_msg;
    struct close_channel_msg_t close_channel_msg;
    struct select_channel_msg_t select_channel_msg;
    struct reg_ta_info_msg_t reg_ta_info_msg;
    struct set_aid_msg_t set_aid_msg;
    struct set_deactive_msg_t set_deactive_msg;
};

struct type_rsp_t {
    int type;
};

struct connect_rsp_t {
    uint32_t atr_len;
};

struct transmit_rsp_t {
    uint32_t rsp_len;
};

struct open_basic_channel_rsp_t {
    uint32_t rsp_len;
};

struct open_logical_channel_rsp_t {
    uint32_t rsp_len;
    uint8_t logic_channel_id;
};

struct select_channel_rsp_t {
    uint32_t rsp_len;
};

struct msp_status_rsp_t {
    bool msp_status;
};

struct sec_flash_status_rsp_t {
    bool sec_flash_status;
};

struct se_srv_rsp_data_t {
    TEE_Result ret;
    union {
        struct type_rsp_t type_rsp;
        struct connect_rsp_t connect_rsp;
        struct transmit_rsp_t transmit_rsp;
        struct open_basic_channel_rsp_t open_basic_channel_rsp;
        struct open_logical_channel_rsp_t open_logical_channel_rsp;
        struct select_channel_rsp_t select_channel_rsp;
        struct msp_status_rsp_t msp_status_rsp;
        struct sec_flash_status_rsp_t sec_flash_status_rsp;
    };
};

struct se_srv_msg_t {
    msg_header header;
    union se_srv_msg_data_t data;
} __attribute__((__packed__));

struct se_srv_rsp_t {
    msg_header header;
    struct se_srv_rsp_data_t data;
} __attribute__((__packed__));

#endif

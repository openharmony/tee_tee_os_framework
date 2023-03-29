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
#ifndef TEE_INTERNAL_SE_API_H
#define TEE_INTERNAL_SE_API_H

#include "tee_defines.h"

/*
 * below definitions are defined by Global Platform
 * for compatibility:
 * don't make any change to the content below
 */
struct __TEE_SEServiceHandle;
struct __TEE_SEReaderHandle;
struct __TEE_SESessionHandle;
struct __TEE_SEChannelHandle;

typedef struct __TEE_SEServiceHandle *TEE_SEServiceHandle;
typedef struct __TEE_SEReaderHandle *TEE_SEReaderHandle;
typedef struct __TEE_SESessionHandle *TEE_SESessionHandle;
typedef struct __TEE_SEChannelHandle *TEE_SEChannelHandle;

#define ATR_LEN_MAX 32U
#define AID_LEN_MIN 5U
#define AID_LEN_MAX 16U

#define SE_LOGIC_CHANNEL_MAX 8U // 0 is for basic channel
#define TEE_SC_TYPE_SCP03    0x01
#define BYTE_LEN             8

typedef struct __TEE_SEReaderProperties {
    bool sePresent;            // true if an SE is present in the reader
    bool teeOnly;              // true if this reader is only accessible via the TEE
    bool selectResponseEnable; // true if the response to a SELECT is available in the TEE
} TEE_SEReaderProperties;

typedef struct __TEE_SEAID {
    uint8_t *buffer;    // the value of the applet's AID
    uint32_t bufferLen; // length of the applet's AID
} TEE_SEAID;

typedef enum {
    TEE_SC_BASE_KEY = 0, // A base key acc. to SCP02
    TEE_SC_KEY_SET  = 1  // A key set (key-ENC, key-MAC) acc. to SCP02, SCP03
} TEE_SC_KeyType;

typedef struct __TEE_SC_KeySetRef {
    TEE_ObjectHandle scKeyEncHandle; // Key-ENC (static encryption key)
    TEE_ObjectHandle scKeyMacHandle; // Key-MAC (static MAC key)
} TEE_SC_KeySetRef;

typedef enum {
    TEE_SC_NO_SECURE_MESSAGING = 0x00, // Nothing will be applied
    TEE_SC_AUTHENTICATE        = 0x80, // Command, Response APDU not be secured
    TEE_SC_C_MAC               = 0x01, // Command APDU shall be MAC protected
    TEE_SC_R_MAC               = 0x10, // Response APDU shall be MAC protected
    TEE_SC_CR_MAC              = 0x11, // Command, Response APDU shall be MAC
    // protected
    TEE_SC_C_ENC_MAC = 0x03, // Command APDU shall be encrypted and
    // MAC protected
    TEE_SC_R_ENC_MAC  = 0x30, // Response APDU encrypted, MAC protected
    TEE_SC_CR_ENC_MAC = 0x33, // Command, Response APDU encrypted and
    // MAC protected
    TEE_SC_C_ENC_CR_MAC = 0x13 // Command APDU encrypted; Command, Response APDU MAC protected
} TEE_SC_SecurityLevel;

#define TEE_AUTHENTICATE TEE_SC_AUTHENTICATE // deprecated: Command, Response APDU not secured
typedef struct __TEE_SC_CardKeyRef {
    uint8_t scKeyID;      // key identifier of the SC card key
    uint8_t scKeyVersion; // key version of the SC card key
} TEE_SC_CardKeyRef;

typedef struct __TEE_SC_DeviceKeyRef {
    TEE_SC_KeyType scKeyType; // type of SC keys
    union {
        TEE_ObjectHandle scBaseKeyHandle; // SC base key (acc. to SCP02)
        TEE_SC_KeySetRef scKeySetRef;     // Key-ENC, Key-MAC (acc. to SCP02, SCP03)
    } __TEE_key;
} TEE_SC_DeviceKeyRef;

typedef struct __TEE_SC_OID {
    uint8_t *buffer;    // the value of the OID
    uint32_t bufferLen; // length of the SC OID
} TEE_SC_OID;

typedef struct __TEE_SC_Params {
    uint8_t scType;                       // the SC type
    TEE_SC_OID scOID;                     // the SC type defined by OID
    TEE_SC_SecurityLevel scSecurityLevel; // the SC security level
    TEE_SC_CardKeyRef scCardKeyRef;       // reference to SC card keys
    TEE_SC_DeviceKeyRef scDeviceKeyRef;   // reference to SC device keys
} TEE_SC_Params;

TEE_Result TEE_SEServiceOpen(TEE_SEServiceHandle *se_service_handle);
void TEE_SEServiceClose(TEE_SEServiceHandle se_service_handle);
TEE_Result TEE_SEServiceGetReaders(TEE_SEServiceHandle se_service_handle, TEE_SEReaderHandle *se_reader_handle_list,
                                   uint32_t *se_reader_handle_list_len);
void TEE_SEReaderGetProperties(TEE_SEReaderHandle se_reader_handle, TEE_SEReaderProperties *reader_properties);
TEE_Result TEE_SEReaderGetName(TEE_SEReaderHandle se_reader_handle, char *reader_name, uint32_t *reader_name_len);
TEE_Result TEE_SEReaderOpenSession(TEE_SEReaderHandle se_reader_handle, TEE_SESessionHandle *se_session_handle);
void TEE_SEReaderCloseSessions(TEE_SEReaderHandle se_reader_handle);
TEE_Result TEE_SESessionGetATR(TEE_SESessionHandle se_session_handle, void *atr, uint32_t *atrLen);
TEE_Result TEE_SESessionIsClosed(TEE_SESessionHandle se_session_handle);
void TEE_SESessionClose(TEE_SESessionHandle se_session_handle);
void TEE_SESessionCloseChannels(TEE_SESessionHandle se_session_handle);
TEE_Result TEE_SESessionOpenBasicChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                         TEE_SEChannelHandle *se_channel_handle);
TEE_Result TEE_SESessionOpenLogicalChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                           TEE_SEChannelHandle *se_channel_handle);
void TEE_SEChannelClose(TEE_SEChannelHandle se_channel_handle);
TEE_Result TEE_SEChannelSelectNext(TEE_SEChannelHandle se_channel_handle);
TEE_Result TEE_SEChannelGetSelectResponse(TEE_SEChannelHandle se_channel_handle, void *response,
                                          uint32_t *response_len);
TEE_Result TEE_SEChannelTransmit(TEE_SEChannelHandle se_channel_handle, void *command, uint32_t command_len,
                                 void *response, uint32_t *response_len);
TEE_Result TEE_SESecureChannelOpen(TEE_SEChannelHandle se_channel_handle, TEE_SC_Params *sc_params);
void TEE_SESecureChannelClose(TEE_SEChannelHandle se_channel_handle);
TEE_Result TEE_SEChannelGetID(TEE_SEChannelHandle se_channel_handle, uint8_t *channel_id);
#endif

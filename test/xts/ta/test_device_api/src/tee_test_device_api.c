/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <string.h>
#include <securec.h>
#include "tee_core_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_internal_se_api.h"
#include "tee_tui_gp_api.h"
#include "rpmb_fcntl.h"
#include "rpmb_driver_rw_api.h"
#include "tee_hw_ext_api.h"
#include "tee_hw_ext_api_legacy.h"
#include "tee_crypto_api.h"
#include "oemkey.h"
#include "tee_test_device_api.h"
#include "tee_object_api.h"

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_device_api"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_device_api"
#define CA_UID 0
#define SCP03_KEY_SIZE 16

static int is_success_response(char *resp, uint32_t len)
{
    if ((uint8_t)resp[len - 2] == 0x90 && resp[len - 1] == 0x0)
        return 1;
    return 0;
}

static TEE_Result CmdTestSEAPI(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    TEE_Result ret;
    TEE_SEServiceHandle service = NULL;

    TEE_SEReaderHandle reader = NULL;
    char reader_name[16] = { 0 };
    uint32_t reader_len, name_len;
    TEE_SESessionHandle session1, session2;
    TEE_SEChannelHandle channel1, channel2;
    int open_session_count = 3;
    char rsp[256] = { 0 };
    uint32_t rsp_len = 256;
    char atr[100] = { 0 };
    uint32_t atr_len = 100;
    tlogi("[%s] begin --\n", __func__);

    ret = TEE_SEServiceOpen(&service);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceOpen is failed! ret = 0x%x\n", ret);
        //return ret;
    }
    tlogi("test TEE_SEServiceOpen is success!\n");
    
    reader_len = sizeof(reader);
    ret = TEE_SEServiceGetReaders(service, &reader, &reader_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceGetReaders is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEServiceGetReaders is success!\n");

    name_len = 16;
    ret = TEE_SEReaderGetName(reader, reader_name, &name_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEReaderGetName is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEReaderGetName is success!\n");

    TEE_SEReaderProperties property;
    TEE_SEReaderGetProperties(reader, &property);
    tlogi("afterTEE_SEReaderGetProperties,property.sePresent=%d,property.teeOnly=%d,property.selectResponseEnable=%d\n",
        property.sePresent, property.teeOnly, property.selectResponseEnable);

open_session:
    ret = TEE_SEReaderOpenSession(reader, &session1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEReaderOpenSession for session1 is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEReaderOpenSession for session1 is success!\n");
    ret = TEE_SESessionGetATR(session1, atr, &atr_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionGetATR is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SESessionGetATR is success! atr_len =%d\n", atr_len);

    ret = TEE_SEReaderOpenSession(reader, &session2);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEReaderOpenSession for session2 is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEReaderOpenSession for session2 is success!\n");

    open_session_count--;
    if (open_session_count) {
        if (open_session_count % 2) {
            TEE_SEReaderCloseSessions(reader);
        } else {
            TEE_SESessionClose(session1);
            TEE_SESessionClose(session2);
        }
        goto open_session;
    }

    TEE_SEAID good_aid = { NULL, 0 }; // bufferlen should be within 5 to 16, or 0
    ret = TEE_SESessionOpenBasicChannel(session1, &good_aid, &channel1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionOpenBasicChannel is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SESessionOpenBasicChannel is success!\n");

    ret = TEE_SEChannelGetSelectResponse(channel1, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelGetSelectResponse is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEChannelGetSelectResponse is success!\n");
    if (!is_success_response(rsp, rsp_len)) {
        tloge("is not success response!\n");
        //goto clean;
    }
    uint8_t channel_id;
    ret = TEE_SEChannelGetID(channel1, &channel_id);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelGetID is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEChannelGetID is success! channel_id = %d\n", channel_id);

    ret = TEE_SESessionOpenLogicalChannel(session2, &good_aid, &channel2);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionOpenLogicalChannel is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SESessionOpenLogicalChannel is success!\n");

    char hex_cmd_basic[] = { 0x80, 0xca, 0x9f, 0x7f, 0x00 };
    char hex_cmd_logic[] = { 0x81, 0xca, 0x9f, 0x7f, 0x00 };

    rsp_len = 256;
    ret = TEE_SEChannelTransmit(channel1, hex_cmd_basic, sizeof(hex_cmd_basic), rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelTransmit for basic channel is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEChannelTransmit for basic channel is success!\n");

    rsp_len = 256;
    ret = TEE_SEChannelTransmit(channel2, hex_cmd_logic, sizeof(hex_cmd_logic), rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelTransmit for logic channel is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    tlogi("test TEE_SEChannelTransmit for logic channel is success!\n");

    TEE_SESessionClose(session1);
    ret = TEE_SESessionIsClosed(session2);
    if (ret != TEE_ERROR_BAD_STATE) {
        tloge("test TEE_SESessionIsClosed for session2 is failed! ret = 0x%x\n", ret);
        ret = TEE_ERROR_GENERIC;
        //goto clean;
    }
    ret = TEE_SESessionIsClosed(session1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionIsClosed for session1 is failed! ret = 0x%x\n", ret);
        //goto clean;
    }
    ret = TEE_SESessionIsClosed(NULL);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionIsClosed for NULL is failed! ret = 0x%x\n", ret);
        goto clean;
    }

    TEE_SEChannelClose(channel1);
    TEE_SESessionCloseChannels(session2);

clean:
    if (reader)
        TEE_SEReaderCloseSessions(reader);
    if (service)
        TEE_SEServiceClose(service);

    return ret;
}

static TEE_Result CmdTestSEChannelSelectNext(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    TEE_Result ret;
    TEE_SEServiceHandle service = NULL;
    TEE_SEReaderHandle reader = NULL;
    uint32_t reader_len = 1;
    TEE_SESessionHandle session1;
    TEE_SEChannelHandle channel1;

    tlogi("[%s] begin --\n", __func__);

    ret = TEE_SEServiceOpen(&service);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceOpen is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_SEServiceOpen is success!\n");
    
    ret = TEE_SEServiceGetReaders(service, &reader, &reader_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceGetReaders is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SEServiceGetReaders is success!\n");

    ret = TEE_SEReaderOpenSession(reader, &session1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEReaderOpenSession for session1 is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SEReaderOpenSession for session1 is success!\n");

    uint8_t ppse_id[] = {0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31};
    TEE_SEAID aid = { ppse_id, sizeof(ppse_id) };
    ret = TEE_SESessionOpenBasicChannel(session1, &aid, &channel1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionOpenBasicChannel is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SESessionOpenBasicChannel is success!\n");

    ret = TEE_SEChannelSelectNext(channel1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelSelectNext is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SEChannelSelectNext is success!\n");
 
    TEE_SEChannelClose(channel1);
    TEE_SESessionClose(session1);

clean:
    if (reader)
        TEE_SEReaderCloseSessions(reader);
    if (service)
        TEE_SEServiceClose(service);

    return ret;
}

static TEE_ObjectHandle scp_import_key(uint8_t *import_key, uint32_t keysize)
{
    TEE_Attribute pattr;
    TEE_Result ret;
    uint32_t max_object_size = 512;
    TEE_ObjectHandle gen_key;

    if (!import_key) {
        tloge("import_key is null!\n");
        return NULL;
    }

    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, max_object_size, &gen_key);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_AllocateTransientObject is failed! ret = 0x%x\n", ret);
        return NULL;
    }
    TEE_InitRefAttribute(&pattr, TEE_ATTR_SECRET_VALUE, import_key, keysize);
    ret = TEE_PopulateTransientObject(gen_key, &pattr, 1);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_PopulateTransientObject is failed! ret = 0x%x\n", ret);
        TEE_FreeTransientObject(gen_key);
        return NULL;
    }

    return gen_key;
}

static TEE_Result CmdTestSESecureChannelOpenClose(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    TEE_Result ret;
    TEE_SEServiceHandle service = NULL;
    TEE_SEReaderHandle reader = NULL;
    uint32_t reader_len = 1;
    TEE_SESessionHandle session1;
    TEE_SEChannelHandle channel1;
    char rsp[261] = { 0 };
    uint32_t rsp_len = 261;

    tlogi("[%s] begin --\n", __func__);

    ret = TEE_SEServiceOpen(&service);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceOpen is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_SEServiceOpen is success!\n");
    
    ret = TEE_SEServiceGetReaders(service, &reader, &reader_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEServiceGetReaders is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SEServiceGetReaders is success!\n");

    ret = TEE_SEReaderOpenSession(reader, &session1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEReaderOpenSession for session1 is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SEReaderOpenSession for session1 is success!\n");

    uint8_t test_aid[] = { 0xf0, 0xbb, 0xaa, 0xce, 0xaa, 0x68, 0x77, 0x5f, 0x77, 0x65, 0x61, 0x76, 0x65, 0x72, 0x00, 0x00 };
    TEE_SEAID aid = { test_aid, sizeof(test_aid) };
    ret = TEE_SESessionOpenLogicalChannel(session1, &aid, &channel1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESessionOpenLogicalChannel is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_SESessionOpenLogicalChannel is success!\n");

    ret = TEE_SEChannelGetSelectResponse(channel1, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SEChannelGetSelectResponse is failed! ret = 0x%x\n", ret);
        goto clean2;
    }
    tlogi("test TEE_SEChannelGetSelectResponse is success!\n");
    if (!is_success_response(rsp, rsp_len)) {
        tloge("TEE_SEChannelGetSelectResponse response error! len=%d, value is 0x%2x 0x%2x\n", rsp_len, rsp[0], rsp[1]);
        goto clean2;
    }

    uint8_t keys[SCP03_KEY_SIZE * 3] = {
        0xe9, 0x49, 0x2c, 0x33, 0xf7, 0x48, 0x96, 0x05, 0x6f, 0xc5, 0xb9, 0x65, 0xf4, 0x5a, 0x4e, 0xf8,
        0x69, 0x36, 0x1d, 0xa3, 0xd5, 0x32, 0x11, 0x56, 0xc4, 0x82, 0xfb, 0x02, 0x48, 0x18, 0xff, 0x1b,    
    };

    TEE_ObjectHandle encKeyhandle = scp_import_key(keys, SCP03_KEY_SIZE);
    TEE_ObjectHandle macKeyhandle = scp_import_key(keys + SCP03_KEY_SIZE, SCP03_KEY_SIZE);
    if ( encKeyhandle == NULL || macKeyhandle == NULL) {
        tloge("scp_import_key failed!\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto clean2;
    }

    TEE_SC_Params scParam = {
        .scType = 0x01,   // type_scp03
        .scOID = {
            .buffer = (void *)"\x06\x08\x2A\x86\x48\x86\xFC\x6B\x04\x03",
            .bufferLen = 10,
        },
        .scSecurityLevel = TEE_SC_CR_ENC_MAC,
        .scCardKeyRef = {
            .scKeyID = 0,
            .scKeyVersion = 0,
        },
        .scDeviceKeyRef = {
            .scKeyType = TEE_SC_KEY_SET,
            .__TEE_key.scKeySetRef = {
                .scKeyEncHandle = encKeyhandle,
                .scKeyMacHandle = macKeyhandle,
            },
        },
    };
    ret = TEE_SESecureChannelOpen(channel1, &scParam);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_SESecureChannelOpen is failed! ret = 0x%x\n", ret);
        goto clean3;
    }
    TEE_SESecureChannelClose(channel1);

clean3:
    if (encKeyhandle) {
        TEE_FreeTransientObject(encKeyhandle);
        encKeyhandle = NULL;
    }
    if (macKeyhandle) {
        TEE_FreeTransientObject(macKeyhandle);
        macKeyhandle = NULL;
    }
clean2: 
    TEE_SEChannelClose(channel1);
    TEE_SESessionClose(session1);
clean:
    if (reader)
        TEE_SEReaderCloseSessions(reader);
    if (service)
        TEE_SEServiceClose(service);

    return ret;
}

static TEE_Result test_TEE_TUICheckTextFormat()
{
    static char *labeltext1 = "Welcome to TUI ";
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t labelIndex = 0;   

    TEE_Result ret = TEE_TUICheckTextFormat(labeltext1, &width, &height, &labelIndex);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUICheckTextFormat is failed! ret = 0x%x, labelIndex= %d\n", ret, labelIndex);
    } else {
        tlogi("test TEE_TUICheckTextFormat is success!\n");
    }
    return ret;
}

static TEE_Result CmdTestTUIAPI(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    TEE_Result ret;
    TEE_TUIScreenInfo myScreenInfo;
    TEE_TUIScreenConfiguration myScreenConfig;
    TEE_TUIEntryField myEntryFields[3];
    TEE_TUIButtonType myKeyPressed;
    char myLogin[26] = { 0 };
    char myPassword[26] = { 0 };
    char *pic;
    uint32_t pic_len = 0;
    uint32_t e_num = 3;
    uint32_t font_type = 0;
    char *lable_text = u_lable_text;
    char *entry_text1 = u_entry_text1;
    char *entry_text2 = u_entry_text2;
    char *entry_text3 = u_entry_text3;

    tlogi("[%s] begin --\n", __func__);

    ret = TEE_TUIGetScreenInfo(TEE_TUI_PORTRAIT, e_num, &myScreenInfo);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUIGetScreenInfo is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_TUIGetScreenInfo is success!\n");
    
    if (myScreenInfo.labelWidth == 1080) {
        pic = pic1080s;
        pic_len = sizeof(pic1080s);
    } else {
        pic = pic1440s;
        pic_len = sizeof(pic1440s);
    }
    /* prepare the screen */
    myScreenConfig.screenOrientation = TEE_TUI_PORTRAIT;
    myScreenConfig.label.textColor[0] = 50;
    myScreenConfig.label.textColor[1] = 50;
    myScreenConfig.label.textColor[2] = 245;
    myScreenConfig.label.text = lable_text;
    myScreenConfig.label.textXOffset = 80;
    myScreenConfig.label.textYOffset = 260;
    myScreenConfig.label.imageXOffset = 3;
    myScreenConfig.label.imageYOffset = 3;
    myScreenConfig.label.image.source = TEE_TUI_REF_SOURCE;
    myScreenConfig.label.image.ref.image = pic;
    myScreenConfig.label.image.ref.imageLength = pic_len;
    myScreenConfig.label.image.width = myScreenInfo.labelWidth;
    myScreenConfig.label.image.height = myScreenInfo.labelHeight;
    myScreenConfig.buttons[TEE_TUI_VALIDATE] = NULL;
    myScreenConfig.buttons[TEE_TUI_CANCEL] = NULL;
    myScreenConfig.buttons[TEE_TUI_CORRECTION] = NULL;
    myScreenConfig.buttons[TEE_TUI_NEXT] = NULL;
    myScreenConfig.buttons[TEE_TUI_PREVIOUS] = NULL;
    myScreenConfig.buttons[TEE_TUI_OK] = NULL;
    myScreenConfig.requestedButtons[TEE_TUI_VALIDATE] = true;
    myScreenConfig.requestedButtons[TEE_TUI_CANCEL] = true;
    myScreenConfig.requestedButtons[TEE_TUI_CORRECTION] = true;
    myScreenConfig.requestedButtons[TEE_TUI_NEXT] = false;
    myScreenConfig.requestedButtons[TEE_TUI_PREVIOUS] = true;
    myScreenConfig.requestedButtons[TEE_TUI_OK] = false;

    myEntryFields[0].type = TEE_TUI_ALPHANUMERICAL;
    myEntryFields[0].mode = TEE_TUI_CLEAR_MODE;
    myEntryFields[0].label = entry_text1;
    myEntryFields[0].minExpectedLength = 6;
    myEntryFields[0].maxExpectedLength = 10;
    myEntryFields[0].buffer = myLogin;
    myEntryFields[0].bufferLength = 26;

    myEntryFields[1].type = TEE_TUI_ALPHANUMERICAL;
    myEntryFields[1].mode = TEE_TUI_TEMPORARY_CLEAR_MODE;
    myEntryFields[1].label = entry_text2;
    myEntryFields[1].minExpectedLength = 6;
    myEntryFields[1].maxExpectedLength = 25;
    myEntryFields[1].buffer = myPassword;
    myEntryFields[1].bufferLength = 26;

    myEntryFields[2].type = TEE_TUI_ALPHANUMERICAL;
    myEntryFields[2].mode = TEE_TUI_TEMPORARY_CLEAR_MODE;
    myEntryFields[2].label = entry_text3;
    myEntryFields[2].minExpectedLength = 6;
    myEntryFields[2].maxExpectedLength = 25;
    myEntryFields[2].buffer = myPassword;
    myEntryFields[2].bufferLength = 26;

    ret = TEE_TUIInitSession();
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUIInitSession is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_TUIInitSession is success!\n");
 
    ret = TEE_TUISetInfo(font_type);  // utf-8
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUISetInfo is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_TUISetInfo is success!\n");

    /* prepare for new lable */
    TEE_TUIScreenLabel backgroundLable = { 0 };
    uint32_t len = sizeof(TEE_TUIScreenLabel);
    backgroundLable.text = "test text for new lable";
    backgroundLable.textXOffset = 0;
    backgroundLable.textYOffset = 0;
    backgroundLable.textColor[0] = 0;
    backgroundLable.textColor[1] = 0;
    backgroundLable.textColor[2] = 0;
    backgroundLable.image.source = TEE_TUI_REF_SOURCE;
    backgroundLable.image.ref.image = back_png;
    backgroundLable.image.ref.imageLength = sizeof(back_png);
    backgroundLable.imageXOffset = 0;
    backgroundLable.imageYOffset = 50;

    ret = TEE_TUISetLabel(&backgroundLable, len);  
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUISetLabel is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_TUISetLabel is success!\n");

    ret = TEE_TUIDisplayScreen(&myScreenConfig, false, myEntryFields, e_num, &myKeyPressed);  
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUIDisplayScreen is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_TUIDisplayScreen is success!\n");

    if (myKeyPressed == TEE_TUI_VALIDATE) {
        if (!strcmp(myPassword, "12345678") && !strcmp(myLogin, "qwertyui")) {
            tlogi("your input is right!\n");
        } else {
            tloge("your input is wrong!\n");
        }
    }
    
    ret = test_TEE_TUICheckTextFormat();
    if (ret != TEE_SUCCESS) {
        goto clean;
    }

    ret = TEE_TUINotify_fp();  
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUINotify_fp is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_TUINotify_fp is success!\n");

    ret = TEE_TUICloseSession();
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUICloseSession is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_TUICloseSession is success!\n");

    ret = TEE_TUISendEvent(TUI_EXIT);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_TUISendEvent is failed! ret = 0x%x\n", ret);
        return ret;
    }
    tlogi("test TEE_TUISendEvent is success!\n");
    return ret;

clean:
    TEE_TUICloseSession();
    return ret;
}

#define RPMB_BLOCK_SIZE 256
#define BUFFERLEN 400
static TEE_Result TestNonceAPI()
{
    TEE_Result ret;
    uint8_t buffer1[BUFFERLEN + 1] = { 0 };  
    uint8_t buffer2[BUFFERLEN + 1] = { 0 };   

    (void)memset_s(buffer1, BUFFERLEN, 'a', BUFFERLEN);

    ret = tee_ext_rpmb_driver_write(buffer1, BUFFERLEN, 0, 0);
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_rpmb_driver_write is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test tee_ext_rpmb_driver_write is success\n");
    }

    ret = tee_ext_rpmb_driver_remove(RPMB_BLOCK_SIZE, 0, 0);
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_rpmb_driver_remove is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test tee_ext_rpmb_driver_remove is success\n");
    }

    ret = memset_s(buffer1, BUFFERLEN, 0, RPMB_BLOCK_SIZE);
    if (ret != 0) {
        tloge("memset failed! ret = 0x%x\n", ret);
        goto clean;
    }
       
    ret = tee_ext_rpmb_driver_read(buffer2, BUFFERLEN, 0, 0);
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_rpmb_driver_read is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test tee_ext_rpmb_driver_read is success\n");
    }

    ret = TEE_MemCompare(buffer1, buffer2, BUFFERLEN);
    if (ret != 0) {
        tloge("TEE_MemCompare failed, ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("TEE_MemCompare success\n");
    } 

clean:
    return ret;
}

static TEE_Result CmdTestRPMBAPI(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    
    char *file_hello = "hello";
    char *file_test = "test";
    char *test_string = "Welcome to China!";
    uint32_t read_size = 0;
    uint8_t buffer[RPMB_BLOCK_SIZE] = { 0 };

    TEE_Result ret = TEE_RPMB_KEY_Status();
    if (ret != TEE_RPMB_KEY_SUCCESS) {
        tloge("test TEE_RPMB_KEY_Status is failed! ret = 0x%x\n", ret);
    } else {
        tlogi("test TEE_RPMB_KEY_Status is success, ret = 0x%x\n", ret);
    }

    ret = TEE_RPMB_FS_Init();
    if (ret != TEE_ERROR_ACCESS_DENIED) {
        tloge("test TEE_RPMB_FS_Init is failed! ret = 0x%x\n", ret);
    } else {
        tlogi("test TEE_RPMB_FS_Init is success, this ta no permission, ret = 0x%x\n", ret);
    }

    struct rpmb_fs_statdisk stat = { 0 };
    ret = TEE_RPMB_FS_StatDisk(&stat);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_StatDisk is failed! ret = 0x%x\n", ret);
    } else {
        tlogi("test TEE_RPMB_FS_StatDisk is success, current TA Total=0x%x, used=0x%x, free=0x%x\n", stat.disk_size,
            stat.ta_used_size, stat.free_size);
    }

    // write file 
    ret = TEE_RPMB_FS_Write(file_hello, (const uint8_t *)test_string, strlen(test_string));
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Write is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Write is success\n");
    }

    struct rpmb_fs_stat file_st = { 0 };
    ret = TEE_RPMB_FS_Stat(file_hello, &file_st);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Stat is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        if ( file_st.size != strlen(test_string)) {
            tloge("test TEE_RPMB_FS_Stat failed! get file size wrong, file_st.size = %d strlen of test_string = %d\n", 
                ret, file_st.size, strlen(test_string));
            goto clean;
        } else {
            tlogi("test TEE_RPMB_FS_Stat is success, file size = %d\n", file_st.size);
        }
    }

    ret = TEE_RPMB_FS_Read(file_hello, buffer, sizeof(buffer), &read_size);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Read is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        if (TEE_MemCompare(buffer, test_string, read_size) != 0) {
            tloge("test TEE_RPMB_FS_Read failed! get file context wrong\n");
            goto clean;
        } else {
            tlogi("test TEE_RPMB_FS_Read is success\n");
        }       
    }

    ret = TEE_RPMB_FS_Rename(file_hello, file_test);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Rename is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Rename is success\n");
    }

    // set non_erasure
    ret = TEE_RPMB_FS_SetAttr(file_test, TEE_RPMB_FMODE_NON_ERASURE);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_SetAttr is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_SetAttr is success\n");
    }

    ret = TEE_RPMB_FS_Erase();
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Erase is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Erase is success\n");
    }
    // read after erase, should read success
    ret = TEE_RPMB_FS_Read(file_test, buffer, sizeof(buffer), &read_size);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Read after erase is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        if ( TEE_MemCompare(buffer, test_string, read_size) != 0) {
            tloge("test TEE_RPMB_FS_Read after erase failed! get file context wrong\n");
            goto clean;
        } else {
            tlogi("test TEE_RPMB_FS_Read after erase is success\n");
        }       
    }

    ret = TEE_RPMB_FS_Rm(file_test);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Rm is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Rm is success\n");
    }
    // this api should be replace by TEE_EXT_TA_version_check
    ret = TEE_RPMB_TAVERSION_Process(1);
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_TAVERSION_Process is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_TAVERSION_Process is success\n");
    }
    // write file 
    ret = TEE_RPMB_FS_Write(file_hello, (const uint8_t *)test_string, strlen(test_string));
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Write is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Write is success\n");
    }

    ret = TEE_RPMB_FS_Format();
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_RPMB_FS_Format is failed! ret = 0x%x\n", ret);
        goto clean;
    } else {
        tlogi("test TEE_RPMB_FS_Format is success\n");
    }

    // read file not exist
    ret = TEE_RPMB_FS_Read(file_hello, buffer, sizeof(buffer), &read_size);
    if (ret != TEE_ERROR_RPMB_FILE_NOT_FOUND) {
        tloge("test TEE_RPMB_FS_Read for file not exist is failed! ret = 0x%x\n", ret);
    } else {
        tlogi("test TEE_RPMB_FS_Read for file not exist is success\n");
    }

    ret = TestNonceAPI();
    if (ret != TEE_SUCCESS) {
        tloge("test TestNonceAPI is failed! ret = 0x%x\n", ret);
    } else {
        tlogi("test TestNonceAPI is success,  ret = 0x%x\n", ret);
    }
    return ret;
clean:
    TEE_RPMB_FS_Rm(file_hello);
    TEE_RPMB_FS_Rm(file_test);
    return ret;
}

#define SIZE_KOEM 16
#define SIZE_DIEID 32
#define SECRET_LEN 16
#define KEY_LEN 32
static TEE_Result CmdTestHUKAPI(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    (void)pParams;
    TEE_Result ret;
    uint8_t k_oem[SIZE_KOEM];
    tlogi("[%s] begin --\n", __func__);

    ret = tee_hal_get_provision_key(k_oem, SIZE_KOEM);
    if (ret != TEE_ERROR_NOT_SUPPORTED) {
        tloge("test tee_hal_get_provision_key is failed! this ta should no permission. ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    tlogi("test tee_hal_get_provision_key is success, match expect, this ta should no permission.\n");

    uint8_t die_id[SIZE_DIEID] = { 0 };
    uint32_t die_id_size = sizeof(die_id);
    ret = tee_ext_get_device_unique_id(die_id, &die_id_size);
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_get_device_unique_id is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test tee_ext_get_device_unique_id is success! die_id_size = %d\n", die_id_size);

    uint8_t pSecret[SECRET_LEN] = { 0 };
    uint8_t pKey[KEY_LEN] = { 0 };
    TEE_GenerateRandom(pSecret, SECRET_LEN);
    struct meminfo_t salt = { 0 };
    salt.buffer = (uintptr_t)pSecret;
    salt.size = SECRET_LEN;
    struct meminfo_t key = { 0 };
    key.buffer = (uintptr_t)pKey;
    key.size = KEY_LEN;
    ret = tee_ext_derive_key_iter(&salt, &key, 500, 10);  // user should check out key should not all zero 
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_derive_key_iter is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test tee_ext_derive_key_iter is success!\n");
#if 0
    // test huk2 must teeos support huk2, else will fail
    ret = tee_ext_derive_key_iter_by_huk2(&salt, &key, 500, 10);  // user should check out key should not all zero 
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_derive_key_iter_by_huk2 is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test tee_ext_derive_key_iter_by_huk2 is success!\n");
#endif
    uint8_t salt1[16] = "123";
    uint8_t salt2[16] = "456";
    uint8_t key1[32] = { 0 };
    uint8_t key2[32] = { 0 };
    uint8_t key3[32] = { 0 };
    uint8_t key4[32] = { 0 };
    ret = TEE_EXT_DeriveTARootKey(salt1, sizeof(salt1), key1, sizeof(key1));
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_EXT_DeriveTARootKey use salt1 is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    ret = TEE_EXT_DeriveTARootKey(salt2, sizeof(salt2), key2, sizeof(key2));
    if (ret != TEE_SUCCESS) {
        tloge("test TEE_EXT_DeriveTARootKey use salt2 is failed! ret = 0x%x\n", ret);
        goto clean;
    }

    ret = TEE_MemCompare(key1, key2, sizeof(key1));
    if (ret != 0) {
        tloge("TEE_MemCompare failed, key1 is same as key2, it is wrong. ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test TEE_EXT_DeriveTARootKey is success!\n");

    // test huk2 must teeos support huk2, else will fail
    ret = tee_ext_derive_ta_root_key_by_huk2(salt1, sizeof(salt1), key3, sizeof(key3));
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_derive_ta_root_key_by_huk2 use salt1 is failed! ret = 0x%x\n", ret);
        goto clean;
    }
    ret = tee_ext_derive_ta_root_key_by_huk2(salt2, sizeof(salt2), key4, sizeof(key4));
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_derive_ta_root_key_by_huk2 use salt2 is failed! ret = 0x%x\n", ret);
        goto clean;
    }

    ret = TEE_MemCompare(key3, key4, sizeof(key3));
    if (ret != 0) {
        tloge("TEE_MemCompare failed, key1 is same as key2, it is wrong. ret = 0x%x\n", ret);
        goto clean;
    }
    tlogi("test tee_ext_derive_ta_root_key_by_huk2 is success!\n");    

    // test huk2 must teeos support huk2, else will fail, user should check out key should not all zero
    ret = tee_ext_root_derive_key2_by_huk2(pSecret, SECRET_LEN, key3, KEY_LEN); 
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_root_derive_key2_by_huk2 is failed! ret = 0x%x\n", ret);
        goto clean;
    }    
    tlogi("test tee_ext_root_derive_key2_by_huk2 is success!\n");

    // test huk2 must teeos support huk2, else will fail, user should check out key should not all zero
    ret = tee_ext_root_uuid_derive_key_by_huk2(pSecret, SECRET_LEN, key4, KEY_LEN); 
    if (ret != TEE_SUCCESS) {
        tloge("test tee_ext_root_uuid_derive_key_by_huk2 is failed! ret = 0x%x\n", ret);
        goto clean;
    }    
    tlogi("test tee_ext_root_uuid_derive_key_by_huk2 is success!\n");

clean:
    return ret;
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret;

    ret = AddCaller_CA_exec(CA_PKGN_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("device_api ta add caller failed, ret: 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_PKGN_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("device_api ta add caller failed, ret: 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)params;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");

    return TEE_SUCCESS;
}

typedef TEE_Result (*func)(uint32_t nParamTypes, TEE_Param pParams[4]);

struct testFunc {
    uint32_t cmdId;
    func funcName;
};

struct testFunc g_testTable[] = {
    { CMD_ID_TEST_SE_API, CmdTestSEAPI },
    { CMD_ID_TEST_SECHANNELSELECTNEXT_API, CmdTestSEChannelSelectNext },
    { CMD_ID_TEST_SESECURECHANNELOPENCLOSE_API, CmdTestSESecureChannelOpenClose },
    { CMD_ID_TEST_TUI_API, CmdTestTUIAPI },
    { CMD_ID_TEST_RPMB_API, CmdTestRPMBAPI },
    { CMD_ID_TEST_HUK_API, CmdTestHUKAPI },
};

uint32_t g_testTableSize = sizeof(g_testTable) / sizeof(g_testTable[0]);

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    uint32_t i;
    tlogi("---- TA invoke command ----------- command id: 0x%x", cmd);

    for (i = 0; i < g_testTableSize; i++) {
        if (cmd == g_testTable[i].cmdId) {
            ret = g_testTable[i].funcName(parmType, params);
            if (ret != TEE_SUCCESS) {
                tloge("invoke command with cmdId: 0x%x failed! ret: 0x%x", cmd, ret);
            } else {
                tlogi("invoke command with cmdId: 0x%x success! ret: 0x%x", cmd, ret);
            }
            return ret;
        }
    }

    tloge("not support this invoke command! cmdId: 0x%x", cmd);
    return TEE_ERROR_GENERIC;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ----");
}

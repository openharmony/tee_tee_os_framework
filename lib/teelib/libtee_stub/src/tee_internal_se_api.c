#include "tee_internal_se_api.h"

TEE_Result TEE_SEServiceOpen(TEE_SEServiceHandle *se_service_handle)
{
    (void)se_service_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SEServiceClose(TEE_SEServiceHandle se_service_handle)
{
    (void)se_service_handle;
}

TEE_Result TEE_SEServiceGetReaders(TEE_SEServiceHandle se_service_handle, TEE_SEReaderHandle *se_reader_handle_list,
                                   uint32_t *se_reader_handle_list_len)
{
    (void)se_service_handle;
    (void)se_reader_handle_list;
    (void)se_reader_handle_list_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SEReaderGetProperties(TEE_SEReaderHandle se_reader_handle, TEE_SEReaderProperties *reader_properties)
{
    (void)se_reader_handle;
    (void)reader_properties;
}

TEE_Result TEE_SEReaderGetName(TEE_SEReaderHandle se_reader_handle, char *reader_name, uint32_t *reader_name_len)
{
    (void)se_reader_handle;
    (void)reader_name;
    (void)reader_name_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SEReaderOpenSession(TEE_SEReaderHandle se_reader_handle, TEE_SESessionHandle *se_session_handle)
{
    (void)se_reader_handle;
    (void)se_session_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SEReaderCloseSessions(TEE_SEReaderHandle se_reader_handle)
{
    (void)se_reader_handle;
}

TEE_Result TEE_SESessionGetATR(TEE_SESessionHandle se_session_handle, void *atr, uint32_t *atrLen)
{
    (void)se_session_handle;
    (void)atr;
    (void)atrLen;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SESessionIsClosed(TEE_SESessionHandle se_session_handle)
{
    (void)se_session_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SESessionClose(TEE_SESessionHandle se_session_handle)
{
    (void)se_session_handle;
}

void TEE_SESessionCloseChannels(TEE_SESessionHandle se_session_handle)
{
    (void)se_session_handle;
}

TEE_Result TEE_SESessionOpenBasicChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                         TEE_SEChannelHandle *se_channel_handle)
{
    (void)se_session_handle;
    (void)se_aid;
    (void)se_channel_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SESessionOpenLogicalChannel(TEE_SESessionHandle se_session_handle, TEE_SEAID *se_aid,
                                           TEE_SEChannelHandle *se_channel_handle)
{
    (void)se_session_handle;
    (void)se_aid;
    (void)se_channel_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SEChannelClose(TEE_SEChannelHandle se_channel_handle)
{
    (void)se_channel_handle;
}

TEE_Result TEE_SEChannelSelectNext(TEE_SEChannelHandle se_channel_handle)
{
    (void)se_channel_handle;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SEChannelGetSelectResponse(TEE_SEChannelHandle se_channel_handle, void *response,
                                          uint32_t *response_len)
{
    (void)se_channel_handle;
    (void)response;
    (void)response_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SEChannelTransmit(TEE_SEChannelHandle se_channel_handle, void *command, uint32_t command_len,
                                 void *response, uint32_t *response_len)
{
    (void)se_channel_handle;
    (void)command;
    (void)command_len;
    (void)response;
    (void)response_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_SESecureChannelOpen(TEE_SEChannelHandle se_channel_handle, TEE_SC_Params *sc_params)
{
    (void)se_channel_handle;
    (void)sc_params;
    return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_SESecureChannelClose(TEE_SEChannelHandle se_channel_handle)
{
    (void)se_channel_handle;
}

TEE_Result TEE_SEChannelGetID(TEE_SEChannelHandle se_channel_handle, uint8_t *channel_id)
{
    (void)se_channel_handle;
    (void)channel_id;
    return TEE_ERROR_NOT_SUPPORTED;
}
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

#ifndef __TEE_EXT_TRUSTED_STORAGE_API_H
#define __TEE_EXT_TRUSTED_STORAGE_API_H

#include "tee_defines.h"
#include "tee_ext_trusted_storage_api_legacy.h"
/*
 * Create a new persist object for target TA by SDTA and store it in the perso partition.
 * The data flow and TEE_Attribute can be initialized.
 * Users can use the returned handle to access the TEE_Attribute and data flow of the object.
 *
 * @param target[IN]: uuid of the target TA, which is managed by SDTA. The file to be created belongs to target TA.
 * @param storageID[IN]: Storage space of each application. Only TEE_OBJECT_STORAGE_PERSO is supported.
 * @param objectID[IN]: Name of the object to be created.
 * @param objectIDLen[IN]: Length of the name of the object to be created.
 * @param flags[IN]: flags after object creation. The value can be one or more of Data_Flag_Constants
 * or Handle_Flag_Constants.
 * @param attributes[IN]:TEE_ObjectHandle of the temporary object, which is used to initialize
 * the TEE_Attribute of the object.
 * @param initialData[IN]:Initial data, which is used to initialize data flow data.
 * @param initialDataLen[IN]: Initial data length(byte)
 * @param object[OUT]: TEE_ObjectHandle returned after the function is successfully executed
 *
 * @return TEE_SUCCESS: In case of success
 * @return TEE_ERROR_ITEM_NOT_FOUND: The storageID does not exist
 * @return TEE_ERROR_ACCESS_CONFLICT: Access permission conflict
 * @return TEE_ERROR_OUT_OF_MEMORY: There are not enough resources to complete the operation
 * @return TEE_ERROR_STORAGE_NO_SPACE: The disk does not have sufficient space to create objects
 * @return TEE_ERROR_ACCESS_DENIED: Permission verification error. e.g. a non-SDTA invokes this interface
 * @return TEE_ERROR_GENERIC: Generic error
 */
TEE_Result tee_ext_create_persistent_object(TEE_UUID target, uint32_t storageID, const void *objectID,
    size_t objectIDLen, uint32_t flags, TEE_ObjectHandle attributes, const void *initialData,
    size_t initialDataLen, TEE_ObjectHandle *object);

/*
 * Open a persist object by SDTA.
 * Users can use the returned handle to access the TEE_Attribute and data flow of the object.
 *
 * @param target[IN]: uuid of the target TA, which is managed by SDTA. The file to be opened belongs to target TA.
 * @param storageID[IN]: Storage space of each application. Only TEE_OBJECT_STORAGE_PERSO is supported.
 * @param objectID[IN]: Name of the object to be opened.
 * @param objectIDLen[IN]: Length of the name of the object to be opened.
 * @param flags[IN]: flags after object open. The value can be one or more of Data_Flag_Constants
 * or Handle_Flag_Constants.
 * @param object[OUT]: TEE_ObjectHandle returned after the function is successfully executed
 *
 * @return TEE_SUCCESS: In case of success.
 * @return TEE_ERROR_ITEM_NOT_FOUND: The storageID or object does not exist.
 * @return TEE_ERROR_ACCESS_CONFLICT: Access permission conflict.
 * @return TEE_ERROR_OUT_OF_MEMORY: There are not enough resources to complete the operation.
 * @return TEE_ERROR_STORAGE_NO_SPACE: The disk does not have sufficient space to create objects.
 * @return TEE_ERROR_STORAGE_EMFILE: For the process, the number of open files has reached the maximum.
 * @return TEE_ERROR_GENERIC: Generic error.
 */
TEE_Result tee_ext_open_persistent_object(TEE_UUID target, uint32_t storageID, const void *objectID,
    size_t objectIDLen, uint32_t flags, TEE_ObjectHandle *object);

/*
 * Delete the files of the managed TA, including the perso partition and private partition.
 *
 * @param target[IN]: uuid of the managed TA. The uuid specifies the TA of the file to be deleted.
 *
 * @return TEE_SUCCESS: In case of success.
 */
TEE_Result tee_ext_delete_all_objects(TEE_UUID target);

#endif

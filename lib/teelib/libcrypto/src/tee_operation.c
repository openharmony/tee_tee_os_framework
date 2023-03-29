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

#include "tee_operation.h"
#include <dlist.h>
#include <tee_log.h>
#include <pthread.h>
#include <errno.h>

#define LOCK_UNLOCK_OK 0
static dlist_head(g_operation_list);
static pthread_mutex_t g_operation_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    struct dlist_node list_node;
    TEE_OperationHandle operation;
} operation_node;

static int32_t operation_lock_ops(pthread_mutex_t *mtx)
{
    int32_t ret = pthread_mutex_lock(mtx);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

TEE_Result add_operation(TEE_OperationHandle operation)
{
    if (operation == NULL) {
        tloge("The operation is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    operation_node *valid_operation = TEE_Malloc(sizeof(*valid_operation), TEE_MALLOC_FILL_ZERO);
    if (valid_operation == NULL) {
        tloge("Malloc operation node failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    valid_operation->operation = operation;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        TEE_Free(valid_operation);
        return TEE_ERROR_GENERIC;
    }
    dlist_insert_head(&(valid_operation->list_node), &g_operation_list);
    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        dlist_delete(&(valid_operation->list_node));
        TEE_Free(valid_operation);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void delete_operation(const TEE_OperationHandle operation)
{
    if (operation == NULL)
        return;

    operation_node *valid_operation = NULL;
    operation_node *tmp             = NULL;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        return;
    }

    dlist_for_each_entry_safe(valid_operation, tmp, &g_operation_list, operation_node, list_node) {
        if (valid_operation->operation == operation) {
            dlist_delete(&(valid_operation->list_node));
            TEE_Free(valid_operation);
            valid_operation = NULL;
            break;
        }
    }
    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        return;
    }

    return;
}

TEE_Result check_operation(const TEE_OperationHandle operation)
{
    TEE_Result ret                  = TEE_ERROR_GENERIC;
    operation_node *valid_operation = NULL;

    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (operation_lock_ops(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Lock operation mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    dlist_for_each_entry(valid_operation, &g_operation_list, operation_node, list_node) {
        if (valid_operation->operation == operation) {
            ret = TEE_SUCCESS;
            break;
        }
    }

    if (pthread_mutex_unlock(&g_operation_mutex) != LOCK_UNLOCK_OK) {
        tloge("Unlock operation mutex failed\n");
        return TEE_ERROR_GENERIC;
    }

    return ret;
}

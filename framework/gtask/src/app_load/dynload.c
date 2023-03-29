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
#include "dynload.h"
#include <inttypes.h>
#include <string.h>
#include <securec.h>
#include <fileio.h>
#include <ta_framework.h>
#include <tee_common.h>
#include <tee_log.h>
#include <tee_config.h>
#include <tee_config.h>
#include "uuid2path.h"
#include "tee_load_lib.h"
#include "gtask_core.h" /* for find_service */
#include "gtask_inner.h"
#include "service_manager.h"
#include "session_manager.h"
#include "tee_app_load_srv.h"
#include "spawn_init.h"
#include <spawn_ext.h>

#define ELFCLASS32     1
#define ELFCLASS64     2
#define NAME_LEN 64
#define RWRIGHT 0600
#define MAX_DRV_LIB_SIZE 0x80000    /* 512K */

static uint32_t sre_dynamic_load_elf(const TEE_UUID *uuid)
{
    int ret;
    char name[MAX_TAFS_NAME_LEN] = { 0 };

    ret = uuid_to_fname(uuid, name, sizeof(name));
    if (ret < 0) {
        tloge("from uuid to fname error!\n");
        return 1;
    }

    if (rename_tmp_file(name, sizeof(name)) != TEE_SUCCESS)
        return 1;

    return 0;
}

static uint32_t sre_dynamic_del_elf(const TEE_UUID *uuid)
{
    int ret;
    char name[NAME_LEN] = { 0 };

    ret = uuid_to_fname(uuid, name, NAME_LEN);
    if (ret < 0) {
        tloge("uuid_to_fname error!\n");
        return TEE_ERROR_GENERIC;
    }

    if (unlink(name) == -1) {
        tloge("unlink fail!!!\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

uint32_t sre_release_dynamic_region(const TEE_UUID *uuid, uint32_t release)
{
    if (release == TA_REGION_FOR_REUSE)
        return TEE_SUCCESS;

    struct service_struct *service = NULL;

    if (find_service(uuid, 0, &service) == -1) {
        tloge("release dynamic: can't find service!!!\n");
        return TEE_ERROR_GENERIC;
    }
    service->elf_state = ELF_NOT_EXIST;
    return sre_dynamic_del_elf(uuid);
}

#define ELF_TYPE_OFFSET 4
TEE_Result varify_elf_arch(const char *elf, int file_size, bool *ta_64bit)
{
    if (elf == NULL || ta_64bit == NULL) {
        tloge("Parameters is null\n");
        return TEE_ERROR_GENERIC;
    }
    if (file_size < (int)(ELF_TYPE_OFFSET * sizeof(uint8_t) + sizeof(uint8_t))) {
        tloge("file size is invalid\n");
        return TEE_ERROR_GENERIC;
    }

    uint8_t *elf_type = (uint8_t *)elf + ELF_TYPE_OFFSET;

    if (*elf_type == ELFCLASS32) {
        *ta_64bit = false;
    } else if (*elf_type == ELFCLASS64) {
        *ta_64bit = true;
    } else {
        tloge("Unknown elf architecture %d\n", (int)(*elf_type));
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

int elf_param_check(uint32_t stack_size, uint32_t heap_size, uint32_t mani_ext_size)
{
    stack_size = PAGE_ALIGN_UP(stack_size);
    if ((stack_size == 0) || (stack_size > MAX_STACK_SIZE) || (heap_size == 0) || mani_ext_size > NOTIFY_MAX_LEN) {
        tloge("Parameters check failed. stack size = %u, heap size = %u, manifest extend size = %u\n",
              stack_size, heap_size, mani_ext_size);
        return -1;
    }
    return 0;
}

TEE_Result load_elf_to_tee(const TEE_UUID *uuid, const char *task_name, bool buildin,
                           bool dyn_conf_registed, struct service_attr *service_attr)
{
    TEE_Result ret;
    uint32_t uw_ret;
    if (uuid == NULL || task_name == NULL || service_attr == NULL) {
        tloge("check Parameters failed\n");
    /* cmd no need to check. */
        return TEE_ERROR_GENERIC;
    }

    /* check if dynamic service already exist */
    if (dynamic_service_exist(uuid, buildin))
        return TEE_ERROR_GENERIC;

    tlogd("task name is %s, ta_64bit:%d\n", task_name, ta_64bit);

    uw_ret = sre_dynamic_load_elf(uuid);
    if (uw_ret != 0)
        return TEE_ERROR_GENERIC;

    ret = register_service(task_name, uuid, dyn_conf_registed, service_attr);
    if (ret != 0)
        tloge("register service \"%s\" fail: 0x%x\n", task_name, ret);

    return ret;
}

static int is_param_valid(const load_elf_func_params *param, bool is_talib, tee_img_type_t type)
{
    bool check_value = (param->fname == NULL || param->lib_name == NULL || param->fname_size > LIB_NAME_MAX ||
                        strlen(param->lib_name) > MAX_NAME_LEN || param->file_buffer == NULL);
    if (check_value == true)
        return false;
    if (strchr(param->lib_name, '/') != NULL) // in case of redirect
        return false;

    if ((type != IMG_TYPE_DYNAMIC_DRV) && (!is_talib) && (param->file_size > MAX_DRV_LIB_SIZE) &&
        (type != IMG_TYPE_CRYPTO_DRV)) {
        tloge("drv-lib %s size is too big: %d\n", param->lib_name, param->file_size);
        return false;
    }

    return true;
}

static void do_err_work(int fp, const char *name)
{
    if (close(fp) != 0)
        tloge("fclose failed\n");

    if (unlink(name) != 0)
        tloge("unlink %s failed\n", name);

    return;
}

static int proc_load_lib_elf(const char *file_buffer, int file_size, uint64_t memid, const char *name)
{
    int ret;

    int fp = open(name, O_CREAT | O_RDWR, RWRIGHT, memid);
    if (fp < 0) {
        tloge("fopen failed: %d\n", fp);
        return 1;
    }

    ret = ftruncate(fp, file_size);
    if (ret < 0) {
        tloge("ftruncate failed\n");
        do_err_work(fp, name);
        return 1;
    }

    if (write(fp, file_buffer, (size_t)file_size) != file_size) {
        tloge("fwrite failed\n");
        do_err_work(fp, name);
        return 1;
    }

    if (close(fp) != 0) {
        tloge("fclose failed\n");
        if (unlink(name) != 0)
            tloge("unlink %s failed\n", name);
        return 1;
    }

    return 0;
}

static bool is_ta_lib(const TEE_UUID *uuid)
{
    TEE_UUID global_uuid = TEE_SERVICE_GLOBAL;

    if (!TEE_MemCompare(&global_uuid, uuid, sizeof(*uuid)))
        return false;

    return true;
}

#define MAX_RECORD_LIST_NUM 10
static struct dlist_node g_client_list;
static uint32_t g_client_num = 0;
static bool g_init = false;
static pthread_mutex_t g_client_list_mutex = PTHREAD_MUTEX_INITIALIZER;
struct dyn_client_t {
    struct dlist_node list_head;
    bool is_64bit;
    char client_name[CLIENT_NAME_SIZE];
};

static bool find_record(const char *client_name, uint16_t name_size, bool is_64bit)
{
    struct dyn_client_t *node = NULL;
    struct dyn_client_t *temp = NULL;
    dlist_for_each_entry_safe(node, temp, &g_client_list, struct dyn_client_t, list_head) {
        if (strnlen(node->client_name, CLIENT_NAME_SIZE) != name_size)
            continue;

        if (TEE_MemCompare(node->client_name, client_name, strnlen(client_name, name_size) == 0) &&
            node->is_64bit == is_64bit)
            return true;
    }

    return false;
}

static bool add_dyn_client_to_list(const char *client_name, uint16_t name_size, bool ta_64bit)
{
    tlogi("add_dyn_client_to_list, client_name:%s name_size:%d ta_64bit:%u\n",
        client_name, name_size, ta_64bit);

    if (pthread_mutex_lock(&g_client_list_mutex) != 0) {
        tloge("pthread lock failed\n");
        return false;
    }

    if (!g_init) {
        dlist_init(&g_client_list);
        g_init = true;
    }

    if (find_record(client_name, name_size, ta_64bit)) {
        tlogi("record already exist\n");
        (void)pthread_mutex_unlock(&g_client_list_mutex);
        return true;
    }

    if (g_client_num >= MAX_RECORD_LIST_NUM) {
        tloge("the number of list node is overstepped\n");
        (void)pthread_mutex_unlock(&g_client_list_mutex);
        return false;
    }

    struct dyn_client_t *node = NULL;
    node = TEE_Malloc(sizeof(struct dyn_client_t), 0);
    if (node == NULL) {
        tloge("malloc failed\n");
        (void)pthread_mutex_unlock(&g_client_list_mutex);
        return false;
    }

    node->is_64bit = ta_64bit;
    errno_t rc = memcpy_s(&(node->client_name), sizeof(node->client_name),
                          client_name, name_size);
    if (rc != EOK) {
        tlogw("mem copy fail!");
        TEE_Free(node);
        (void)pthread_mutex_unlock(&g_client_list_mutex);
        return false;
    }

    dlist_insert_tail(&node->list_head, &g_client_list);
    g_client_num++;
    (void)pthread_mutex_unlock(&g_client_list_mutex);
    return true;
}

bool get_dyn_client_name(bool is_64bit, char *client, uint32_t size)
{
    if (client == NULL)
        return false;

    if (pthread_mutex_lock(&g_client_list_mutex) != 0) {
        tloge("pthread lock failed\n");
        return false;
    }

    if (!g_init) {
        dlist_init(&g_client_list);
        g_init = true;
    }

    struct dyn_client_t *node = NULL;
    struct dyn_client_t *temp = NULL;
    uint32_t count = 0;

    dlist_for_each_entry_safe(node, temp, &g_client_list, struct dyn_client_t, list_head) {
        if (node->is_64bit == is_64bit) {
            if (count * CLIENT_NAME_SIZE >= size)
                break;

            if (memcpy_s(client + count * CLIENT_NAME_SIZE, size - count * CLIENT_NAME_SIZE,
                    node->client_name, strlen(node->client_name)) != 0) {
                tloge("copy client fail!");
                continue;
            }
            count++;
        }
    }

    (void)pthread_mutex_unlock(&g_client_list_mutex);
    return true;
}

static int record_client_name(const char *file_buffer, uint32_t file_size,
    const char *fname, uint32_t fname_size)
{
    bool ta_64bit = false;

    if (file_buffer == NULL || fname == NULL)
        return LOAD_FAIL;

    if (varify_elf_arch(file_buffer, file_size, &ta_64bit) != TEE_SUCCESS) {
        tloge("varify elf architecture failed\n");
        return LOAD_FAIL;
    }

    if (!add_dyn_client_to_list(fname, fname_size, ta_64bit))
        return LOAD_FAIL;

    return LOAD_SUCC;
}

int dynamic_load_lib_elf(const load_elf_func_params *param, const struct service_struct *service,
                         const TEE_UUID *uuid, uint64_t memid, tee_img_type_t type)
{
    const TEE_UUID crypto_uuid = CRYPTOMGR;
    bool is_talib = is_ta_lib(uuid);
    bool check_value = (param == NULL || uuid == NULL || service == NULL);
    if (check_value == true)
        return LOAD_FAIL;

    if (!is_param_valid(param, is_talib, type)) {
        tloge("load lib elf: param invalid!\n");
        return LOAD_FAIL;
    }

    if (uuid_to_libname(uuid, param->fname, param->fname_size, param->lib_name, type) < 0) {
        tloge("%s uuid_to_fname error!\n", param->fname);
        return LOAD_FAIL;
    }

    int ret = is_lib_loaded(service, param->fname, param->fname_size);
    if (ret == LIB_LOADED)
        return LIB_EXIST;
    else if (ret == CHECK_ERROR)
        return LOAD_FAIL;

    if (proc_load_lib_elf(param->file_buffer, param->file_size, memid, param->fname) != 0)
        return LOAD_FAIL;

    if (type == IMG_TYPE_DYNAMIC_CLIENT) {
        ret = record_client_name(param->file_buffer, param->file_size,
            param->fname, param->fname_size);
        if (ret != LOAD_SUCC)
            (void)unlink(param->fname);
        return ret;
    }
    /*
     * new driver binary is set with ".elf" because it will be dlopend by drvloader
     * so no need to set uid since the file whose name not end with ".so" can only be dlopend by loader
     */
    if (type == IMG_TYPE_DYNAMIC_DRV)
        return LOAD_SUCC;

    if (type == IMG_TYPE_CRYPTO_DRV)
        (void)memcpy_s((void *)uuid, sizeof(*uuid), &crypto_uuid, sizeof(*uuid));

    return LOAD_SUCC;
}

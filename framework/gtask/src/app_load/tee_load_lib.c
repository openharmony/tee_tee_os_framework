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
#include "tee_load_lib.h"
#include <stdlib.h>
#include <fileio.h>
#include "securec.h"
#include "tee_inner_uuid.h"
#include "gtask_core.h" /* for find_service */
#include "tee_time_api.h"
#include "service_manager.h"
#include "session_manager.h"
#include "init.h"

#define PREFIX_LEN           6 /* prefix: /tafs/ */
#define LIB_AGED_TIME_LIMIT  10000U /* unit: millis */
#define LIB_LIMIT_COUNT      5U

static uint32_t get_lib_count(const struct service_struct *service)
{
    uint32_t count = 0;
    struct lib_info *cur = NULL;

    cur = service->lib_list_head.next;

    while ((cur != NULL) && (cur->type != IMG_TYPE_DYNAMIC_DRV) &&
           (cur->type != IMG_TYPE_CRYPTO_DRV)) {
        count++;
        cur = cur->next;
    }

    return count;
}

static bool is_aged_lib(const struct lib_info *libinfo)
{
    TEE_Time current = { 0, 0 };
    uint64_t interval;

    if (libinfo == NULL) {
        tloge("invalid param\n");
        return false;
    }

    /* for dynamic_drv, donnot need aged */
    if (libinfo->type == IMG_TYPE_DYNAMIC_DRV || libinfo->type == IMG_TYPE_CRYPTO_DRV ||
        libinfo->type == IMG_TYPE_DYNAMIC_CLIENT)
        return false;

    TEE_GetSystemTime(&current);

    get_interval(&current, &libinfo->load_elf_time, &interval);

    if (interval > LIB_AGED_TIME_LIMIT) {
        tlogi("aged lib: name is %s, and seconds interval =%llu, max interval = %u\n",
              libinfo->name, (unsigned long long)interval, LIB_AGED_TIME_LIMIT);
        return true;
    }
    return false;
}

void do_age_timeout_lib(struct service_struct *service)
{
    struct lib_info *cur = NULL;
    struct lib_info *pre = NULL;
    struct lib_info *tmp = NULL;

    if (service == NULL)
        return;

    pre = &service->lib_list_head;
    cur = pre->next;
    while (cur != NULL) {
        if (is_aged_lib(cur)) {
            tmp = cur->next;
            if (unlink(cur->name) != 0)
                tloge("unlink %s failed\n", cur->name);
            free(cur);
            pre->next = tmp;
            cur = pre->next;
        } else {
            pre = cur;
            cur = cur->next;
        }
    }
}

int is_lib_loaded(const struct service_struct *service, const char *name, size_t name_size)
{
    int ret = LIB_NOT_LOADED;
    struct lib_info *cur = NULL;

    if (service == NULL || name == NULL || name_size > LIB_NAME_MAX) {
        tloge("input param is null\n");
        return CHECK_ERROR;
    }

    cur = service->lib_list_head.next;
    while (cur != NULL) {
        /* compare length add 1 in order to include "\0" */
        if (strncmp(name, cur->name, (strlen(cur->name) + 1)) == 0) {
            tlogi("already in the list, file_name = %s\n", name);
            ret = LIB_LOADED;
            break;
        } else {
            cur = cur->next;
        }
    }

    return ret;
}

TEE_Result tee_add_libinfo(struct service_struct *service, const char *name, size_t name_size,
                           tee_img_type_t type)
{
    struct lib_info *libinfo = NULL;
    bool check_value = (service == NULL || name == NULL);
    if (check_value == true) {
        tloge("params error\n");
        return TEE_ERROR_GENERIC;
    }
    if (is_lib_loaded(service, name, name_size) != LIB_NOT_LOADED) {
        tloge("already in the list or param is invalid!\n");
        return TEE_ERROR_GENERIC;
    }

    /* dynamic_drv lib should not be limited by IMG_TYPE_DYNAMIC_DRV and CRYPTO_DRV */
    if ((type != IMG_TYPE_DYNAMIC_DRV) && (get_lib_count(service) > LIB_LIMIT_COUNT) &&
        (type != IMG_TYPE_CRYPTO_DRV)) {
        tlogi("already load %u lib, caution!\n", LIB_LIMIT_COUNT);
        return TEE_ERROR_GENERIC;
    }

    libinfo = (struct lib_info *)malloc(sizeof(*libinfo));
    if (libinfo == NULL) {
        tloge("libinfo malloc failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (strcpy_s(libinfo->name, sizeof(libinfo->name), name) != EOK) { /* with /tafs/ prefix */
        free(libinfo);
        return TEE_ERROR_GENERIC;
    }

    TEE_GetSystemTime(&libinfo->load_elf_time);
    libinfo->type = type;
    tlogd("libinfo add node: %s at sec: %u is drv: %d\n",
          libinfo->name, libinfo->load_elf_time.seconds, (int32_t)libinfo->type);
    libinfo->next = service->lib_list_head.next;
    service->lib_list_head.next = libinfo;

    return TEE_SUCCESS;
}

void tee_delete_all_libinfo(struct service_struct *service)
{
    struct lib_info *libinfo = NULL;
    struct lib_info *next    = NULL;

    if (service == NULL) {
        tloge("params error\n");
        return;
    }
    libinfo = service->lib_list_head.next;
    while (libinfo != NULL) {
        next = libinfo->next;
        if (unlink(libinfo->name) != 0)
            tloge("unlink %s failed\n", libinfo->name);
        free(libinfo);
        libinfo = next;
    }
    service->lib_list_head.next = NULL;
    return;
}

static void tee_delete_single_libinfo(struct service_struct *service, const char *lib_name)
{
    struct lib_info *pre = NULL;
    struct lib_info *cur = NULL;

    if (service->lib_list_head.next == NULL) {
        tloge("no node in lib_list and %s won't be deleted!\n", lib_name);
        return;
    }
    if (strnlen(lib_name, LIB_NAME_MAX) == LIB_NAME_MAX) {
        tloge("lib name is too long\n");
        return;
    }

    pre = &service->lib_list_head;
    cur = service->lib_list_head.next;

    while (cur != NULL) {
        /*
         * compare length add 1 in order to include "\0"
         * otherwise it may delete wrong lib, for example:
         * lib1: test.so
         * lib2: testa.so
         * when input name is test, it may unlink test.so or testa.so
         */
        if (strncmp(lib_name, cur->name + PREFIX_LEN, (size_t)(strlen(lib_name) + 1)) == 0) {
            if (unlink(cur->name) != 0)
                tloge("unlink %s failed\n", cur->name);
            /*
             * for dynamic_drv, only unlink from tafs, donnot delete it from
             * lib_list, to avoid teecd was killed
             */
            if (cur->type == IMG_TYPE_DYNAMIC_DRV || cur->type == IMG_TYPE_CRYPTO_DRV)
                return;
            pre->next = cur->next;
            free(cur);
            return;
        } else {
            pre = cur;
            cur = cur->next;
        }
    }
    tloge("%s not exist in lib list!\n", lib_name);
    return;
}

static void process_unlink(const struct ta_unlink_lib_msg *ret_msg, uint32_t task_id)
{
    struct service_struct *cur_service = NULL;
    struct session_struct *cur_session = NULL;

    if (ret_msg == NULL) {
        tloge("ret_msg is NULL!\n");
        return;
    }

    if (!ret_msg->is_drvlib) {
        if (find_task(task_id, &cur_service, &cur_session) == false) {
            tloge("fail to find service or session!\n");
            return;
        }
    } else {
        TEE_UUID uuid = TEE_SERVICE_GLOBAL;
        if (find_service(&uuid, 0, &cur_service) == INVALID_SERVICE_INDEX)
            return;
    }
    tee_delete_single_libinfo(cur_service, ret_msg->lib_name);
    return;
}

int32_t handle_unlink_dynamic_drv(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    struct ta_unlink_lib_msg msg;

    (void)cmd_id;
    if (msg_size <= sizeof(msg.lib_name)) {
        tloge("msg_size:0x%x error\n", msg_size);
        return GT_ERR_END_CMD;
    }

    uint32_t drv_id;
    if (get_drvmgr_pid(&drv_id) != 0) {
        tloge("get drvmgr taskid failed\n");
        return GT_ERR_END_CMD;
    }

    if (taskid_to_pid(task_id) != drv_id) {
        tloge("task:0x%x not support unlink dynamic drv lib\n", task_id);
        return GT_ERR_END_CMD;
    }

    /*
     * for dynamic_drv, only unlink it from tafs, donot delete it's libinfo
     * from lib_list, to denied teecd was killed.
     */
    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    errno_t rc = memcpy_s(msg.lib_name, sizeof(msg.lib_name) - 1, msg_buf, sizeof(msg.lib_name) - 1);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d.\n", rc, __LINE__);
        return GT_ERR_END_CMD;
    }
    msg.lib_name[LIB_NAME_MAX - 1] = '\0';
    msg.is_drvlib = true;

    process_unlink(&msg, 0); /* taskid not used when is_drvlib is true */

    return GT_ERR_OK;
}

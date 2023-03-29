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
#ifndef TEE_DRV_INTERNAL_H
#define TEE_DRV_INTERNAL_H
#include <stdint.h>
#include <dlist.h>
#include <ipclib.h>

#define FD_COUNT_MAX 1024U

#define DRV_NAME_MAX_LEN 32U
#define DRV_FRAM_CMD_INDEX 0U
#define DRV_NAME_INDEX 3U /* used in open */
#define DRV_IOCTL_FD_INDEX 3U /* used in ioctl */
#define DRV_CLOSE_FD_INDEX 1U /* used in close */
#define DRV_CMD_ID_INDEX 4U /* used in ioctl */
#define DRV_NAME_LEN_INDEX 4U
#define DRV_PARAM_INDEX 1U /* used in open and ioctl */
#define DRV_PARAM_LEN_INDEX 2U /* used in open and ioctl */
#define DRV_PERM_INDEX 3U /* used in open */
#define DRV_CALLER_PID_INDEX 4U /* used in open and close */
#define DRV_UUID_TIME_INDEX 5U /* used in open and close */
#define DRV_UUID_CLOCK_INDEX 6U /* used in open and close */
#define DRV_REGISTER_CMD_ADDR_INDEX 0U /* used in register drv cmd */
#define DRV_REGISTER_CMD_SIZE_INDEX 1U /* used in register drv cmd */

/*
 * open return fd is : ((drv_index << DRV_INDEX_OFFSET) | fd)
 * add drv_index to fd inorder to make each fd is unique,
 * and to get drv channel by drv_index in drv api lib
 */
#define DRV_INDEX_OFFSET 32U
#define DRV_INDEX_MASK 0xFFFFFFFFULL
#define DRV_FD_MASK 0xFFFFFFFFULL

#define UUID_TIME_LOW_OFFSET 32
#define UUID_TIME_MID_OFFSET 16
#define UUID_CLOCK_OFFSET 8
#define UUID_TIME_LOW_MASK 0xFFFFFFFFULL /* uuid->timeLow */
#define UUID_TIME_MASK 0xFFFFULL /* uuid->timeMid and uuid->timeHiAndVersion */
#define UUID_TIME_CLOCK_MASK 0xFFULL /* uuid->clockSeqAndNode */
#define BITS_NUM_PER_BYTE 8

enum drv_general_cmd_id {
    CALL_DRV_OPEN = 1,
    CALL_DRV_IOCTL,
    CALL_DRV_CLOSE,
};

enum drv_msg_cmd_id {
    DRV_GENERAL_CMD_ID,
    DRV_EXCEPTION_CMD_ID,
    DRV_DUMP_CMD_ID,
    REGISTER_DRV_CONF,
    UNREGISTER_DRV_CONF,
    DUMP_DRV_CONF,
    REGISTER_DRVCALL_CONF,
    UNREGISTER_DRVCALL_CONF,
    DUMP_DRVCALL_CONF,
    REGISTER_DRV_CMD_PERM,
};

struct drv_channel {
    struct dlist_node drv_list;
    cref_t drv_channel;
    uint32_t drv_index;
    uint32_t ref_cnt;
    char drv_name[DRV_NAME_MAX_LEN];
};

struct drv_cmd_perm_info_t {
    uint32_t cmd;
    uint64_t perm;
};

void tee_drv_task_exit(uint32_t exit_pid);
void tee_drv_task_dump(void);

#endif
